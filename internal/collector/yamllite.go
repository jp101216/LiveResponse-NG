package collector

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// yamllite.go — a dependency-free parser for the YAML subset that Sigma rules
// use, so Sigma support keeps the zero-dependency Go tree. It handles block
// mappings and sequences (including a sequence at the same indent as its key,
// and a sequence of maps), plain / single-quoted / double-quoted scalars, flow
// sequences ([a, b]), block scalars (| and >), multiple documents separated by
// "---", and comments. It is NOT general YAML — anchors, aliases, tags, complex
// keys and merge keys are not supported; a rule that needs them is rejected at
// compile time rather than guessed at. Input is bounded and malformed
// indentation is an error, never a panic.

const (
	yamlMaxBytes = 8 << 20
	yamlMaxDepth = 32
)

type yamlKind int

const (
	yamlScalar yamlKind = iota
	yamlMap
	yamlSeq
)

// yamlNode is a parsed node: a scalar (Str, with Null set for YAML null), a
// mapping (Map + Keys in document order), or a sequence (Seq).
type yamlNode struct {
	Kind yamlKind
	Str  string
	Null bool
	Map  map[string]*yamlNode
	Keys []string
	Seq  []*yamlNode
}

func scalarNode(s string, null bool) *yamlNode {
	return &yamlNode{Kind: yamlScalar, Str: s, Null: null}
}

func (n *yamlNode) get(key string) *yamlNode {
	if n == nil || n.Kind != yamlMap {
		return nil
	}
	return n.Map[key]
}

// scalar returns a node's scalar text (empty for non-scalars).
func (n *yamlNode) scalar() string {
	if n == nil || n.Kind != yamlScalar {
		return ""
	}
	return n.Str
}

type yamlParser struct {
	lines []string
	i     int
	depth int
}

// parseYAMLDocuments parses a byte slice into one node per YAML document.
func parseYAMLDocuments(data []byte) ([]*yamlNode, error) {
	if len(data) > yamlMaxBytes {
		return nil, fmt.Errorf("yaml: input exceeds %d bytes", yamlMaxBytes)
	}
	var docs [][]string
	cur := []string{}
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimRight(ln, "\r")
		switch strings.TrimSpace(t) {
		case "---", "...":
			docs = append(docs, cur)
			cur = nil
		default:
			cur = append(cur, t)
		}
	}
	docs = append(docs, cur)

	var out []*yamlNode
	for _, d := range docs {
		p := &yamlParser{lines: d}
		p.skipBlank()
		if p.i >= len(p.lines) {
			continue
		}
		n, err := p.parseNode(0)
		if err != nil {
			return nil, err
		}
		if n != nil {
			out = append(out, n)
		}
	}
	return out, nil
}

func parseSubtree(lines []string) (*yamlNode, error) {
	p := &yamlParser{lines: lines}
	p.skipBlank()
	if p.i >= len(p.lines) {
		return scalarNode("", true), nil
	}
	return p.parseNode(0)
}

func (p *yamlParser) blank(i int) bool {
	t := strings.TrimSpace(stripComment(p.lines[i]))
	return t == ""
}

func (p *yamlParser) skipBlank() {
	for p.i < len(p.lines) && p.blank(p.i) {
		p.i++
	}
}

func (p *yamlParser) indentOf(i int) int {
	line := p.lines[i]
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// stripped returns line i with its indentation and any trailing comment removed.
func (p *yamlParser) stripped(i int) string {
	return strings.TrimRight(stripComment(strings.TrimLeft(p.lines[i], " ")), " ")
}

// parseNode parses a block node whose first significant line is at indent
// >= minIndent, dispatching to a sequence or a mapping.
func (p *yamlParser) parseNode(minIndent int) (*yamlNode, error) {
	if p.depth++; p.depth > yamlMaxDepth {
		return nil, errors.New("yaml: nesting too deep")
	}
	defer func() { p.depth-- }()

	p.skipBlank()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	ind := p.indentOf(p.i)
	if ind < minIndent {
		return nil, nil
	}
	content := p.stripped(p.i)
	if content == "-" || strings.HasPrefix(content, "- ") {
		return p.parseSeq(ind)
	}
	if _, _, ok := splitKeyValue(content); !ok {
		// A bare scalar block — e.g. a sequence item that is a scalar, routed
		// here via the item sub-slice. Consume the line and return it.
		p.i++
		return parseInlineValue(content)
	}
	return p.parseMap(ind)
}

func (p *yamlParser) parseMap(ind int) (*yamlNode, error) {
	node := &yamlNode{Kind: yamlMap, Map: map[string]*yamlNode{}}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		cind := p.indentOf(p.i)
		if cind < ind {
			break
		}
		if cind > ind {
			return nil, fmt.Errorf("yaml: unexpected indent at line %q", p.lines[p.i])
		}
		content := p.stripped(p.i)
		if content == "-" || strings.HasPrefix(content, "- ") {
			break // a sequence at the map's own indent belongs to the parent
		}
		key, valuePart, ok := splitKeyValue(content)
		if !ok {
			return nil, fmt.Errorf("yaml: expected 'key: value' at %q", p.lines[p.i])
		}
		p.i++
		child, err := p.parseValue(ind, valuePart)
		if err != nil {
			return nil, err
		}
		key = unquoteScalar(key)
		if _, dup := node.Map[key]; !dup {
			node.Keys = append(node.Keys, key)
		}
		node.Map[key] = child
	}
	return node, nil
}

// parseValue resolves the value of a mapping key at keyIndent: an inline scalar
// or flow value on the same line, a block scalar (| or >), a nested block
// (deeper indent), or a sequence (same or deeper indent).
func (p *yamlParser) parseValue(keyIndent int, valuePart string) (*yamlNode, error) {
	if valuePart != "" {
		if isBlockScalarIndicator(valuePart) {
			return scalarNode(p.consumeBlockScalar(keyIndent), false), nil
		}
		return parseInlineValue(valuePart)
	}
	// Empty inline value: look at what follows.
	p.skipBlank()
	if p.i >= len(p.lines) {
		return scalarNode("", true), nil
	}
	nind := p.indentOf(p.i)
	ncontent := p.stripped(p.i)
	isSeq := ncontent == "-" || strings.HasPrefix(ncontent, "- ")
	switch {
	case isSeq && nind >= keyIndent:
		return p.parseSeq(nind)
	case nind > keyIndent:
		return p.parseNode(nind)
	default:
		return scalarNode("", true), nil
	}
}

func (p *yamlParser) parseSeq(ind int) (*yamlNode, error) {
	node := &yamlNode{Kind: yamlSeq}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		cind := p.indentOf(p.i)
		if cind < ind {
			break
		}
		if cind > ind {
			return nil, fmt.Errorf("yaml: unexpected indent in sequence at %q", p.lines[p.i])
		}
		content := p.stripped(p.i)
		if content != "-" && !strings.HasPrefix(content, "- ") {
			break
		}
		var itemText string
		if content != "-" {
			itemText = strings.TrimLeft(content[1:], " ")
		}
		afterDash := content[1:]
		childIndent := ind + 1 + (len(afterDash) - len(strings.TrimLeft(afterDash, " ")))
		p.i++

		if itemText == "" {
			child, err := p.parseNode(ind + 1)
			if err != nil {
				return nil, err
			}
			if child == nil {
				child = scalarNode("", true)
			}
			node.Seq = append(node.Seq, child)
			continue
		}
		// Gather the item's continuation lines (indented deeper than the dash)
		// and parse the inline remainder plus them as one subtree — this is how
		// a "- key: v / <aligned> key2: v2" mapping item is handled.
		start := p.i
		j := start
		for j < len(p.lines) {
			if p.blank(j) {
				j++
				continue
			}
			if p.indentOf(j) <= ind {
				break
			}
			j++
		}
		sub := make([]string, 0, j-start+1)
		sub = append(sub, strings.Repeat(" ", childIndent)+itemText)
		sub = append(sub, p.lines[start:j]...)
		child, err := parseSubtree(sub)
		if err != nil {
			return nil, err
		}
		node.Seq = append(node.Seq, child)
		p.i = j
	}
	return node, nil
}

// consumeBlockScalar reads a | or > block scalar: the following lines indented
// deeper than the key, joined (newlines for |, spaces for >). The exact
// whitespace isn't important for the fields Sigma uses block scalars in.
func (p *yamlParser) consumeBlockScalar(keyIndent int) string {
	var b strings.Builder
	first := true
	for p.i < len(p.lines) {
		raw := p.lines[p.i]
		if strings.TrimSpace(raw) == "" {
			b.WriteByte('\n')
			p.i++
			continue
		}
		if p.indentOf(p.i) <= keyIndent {
			break
		}
		if !first {
			b.WriteByte('\n')
		}
		b.WriteString(strings.TrimLeft(raw, " "))
		first = false
		p.i++
	}
	return strings.TrimSpace(b.String())
}

// parseInlineValue parses an inline scalar or flow sequence/mapping.
func parseInlineValue(s string) (*yamlNode, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		node := &yamlNode{Kind: yamlSeq}
		for _, part := range splitFlow(s[1 : len(s)-1]) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			node.Seq = append(node.Seq, scalarFromToken(part))
		}
		return node, nil
	case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
		node := &yamlNode{Kind: yamlMap, Map: map[string]*yamlNode{}}
		for _, part := range splitFlow(s[1 : len(s)-1]) {
			k, v, ok := splitKeyValue(strings.TrimSpace(part))
			if !ok {
				continue
			}
			k = unquoteScalar(k)
			if _, dup := node.Map[k]; !dup {
				node.Keys = append(node.Keys, k)
			}
			node.Map[k] = scalarFromToken(strings.TrimSpace(v))
		}
		return node, nil
	default:
		return scalarFromToken(s), nil
	}
}

func scalarFromToken(s string) *yamlNode {
	if s == "" || s == "~" || s == "null" || s == "Null" || s == "NULL" {
		return scalarNode("", true)
	}
	return scalarNode(unquoteScalar(s), false)
}

// splitKeyValue splits "key: value" into key and the remainder, honouring a
// quoted key and requiring the ": " (or a trailing ":") to be outside quotes.
func splitKeyValue(s string) (key, value string, ok bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ':' && !inSingle && !inDouble:
			if i == len(s)-1 {
				return s[:i], "", true
			}
			if s[i+1] == ' ' || s[i+1] == '\t' {
				return s[:i], strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

// splitFlow splits a flow collection's body on top-level commas.
func splitFlow(s string) []string {
	var out []string
	depth := 0
	inSingle, inDouble := false, false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '[' || c == '{') && !inSingle && !inDouble:
			depth++
		case (c == ']' || c == '}') && !inSingle && !inDouble:
			depth--
		case c == ',' && depth == 0 && !inSingle && !inDouble:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// stripComment removes a trailing or whole-line comment, leaving comments that
// sit inside quotes or are not preceded by whitespace (so a '#' inside a value
// like a color code survives).
func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func isBlockScalarIndicator(s string) bool {
	switch strings.TrimSpace(s) {
	case "|", "|-", "|+", ">", ">-", ">+":
		return true
	}
	return false
}

// unquoteScalar removes single or double quotes and applies the minimal escape
// rules each uses (single: ” -> '; double: \\ \" \n \t \/ and \uXXXX).
func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return unescapeDouble(s[1 : len(s)-1])
	}
	return s
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		case '/':
			b.WriteByte('/')
		case 'u':
			if i+4 < len(s) {
				if r, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += 4
					continue
				}
			}
			b.WriteByte('\\')
			b.WriteByte('u')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
