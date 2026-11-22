package attack

import (
	"fmt"
	"strings"
)

// The report viewer (viewer/lrng-viewer.html) groups findings by tactic with
// a small technique -> tactic map of its own, since it runs in a browser with
// no access to this table. cmd/attackgen rewrites that map between these
// markers from the same table the agent embeds, and a test checks they agree.
const (
	ViewerBegin = "  // attackgen:begin"
	ViewerEnd   = "  // attackgen:end"
)

// viewerCodes are the viewer's two-letter tactic codes. Reconnaissance and
// Resource Development happen before anything touches a host, so the viewer
// has no column for them. A tactic missing here stops cmd/attackgen: a new
// matrix column needs a deliberate code, not a guessed one.
var viewerCodes = map[string]string{
	"initial-access": "ia", "execution": "ex", "persistence": "pe", "privilege-escalation": "pr",
	"stealth": "st", "defense-impairment": "dm", "credential-access": "ca", "discovery": "di",
	"lateral-movement": "lm", "collection": "co", "command-and-control": "cc", "exfiltration": "ef",
	"impact": "im",
}

var viewerSkip = map[string]bool{"reconnaissance": true, "resource-development": true}

// ViewerBlock renders the viewer's tactic list and technique map, markers
// included, ending in a newline.
func ViewerBlock(t *Table) (string, error) {
	var b strings.Builder
	b.WriteString(ViewerBegin + " (cmd/attackgen, Enterprise ATT&CK v" + t.Version + "; regenerate, don't edit)\n")
	b.WriteString("  const TACTICS = [\n")
	var row []string
	flush := func() {
		if len(row) > 0 {
			b.WriteString("    " + strings.Join(row, ", ") + ",\n")
			row = row[:0]
		}
	}
	for _, tac := range t.Tactics {
		if viewerSkip[tac.ShortName] {
			continue
		}
		code, ok := viewerCodes[tac.ShortName]
		if !ok {
			return "", fmt.Errorf("attack: tactic %s (%s) has no viewer code; add one to viewerCodes", tac.ShortName, tac.ID)
		}
		row = append(row, fmt.Sprintf("[%q, %q]", code, sentenceCase(tac.Name)))
		if len(row) == 4 {
			flush()
		}
	}
	flush()
	b.WriteString("  ];\n")
	b.WriteString("  const TACTIC_NAME = new Map(TACTICS);\n")
	b.WriteString("  // Technique -> tactics, for every Enterprise technique. A sub-technique takes its\n")
	b.WriteString("  // parent's tactics; a revoked ID takes its successor's, so older reports still place.\n")
	b.WriteString("  const TECH = new Map(Object.entries({\n")
	line := "   "
	for _, id := range t.IDs() {
		if strings.Contains(id, ".") {
			continue
		}
		res := t.Resolve(id)
		if res.ID == "" || res.Status == Deprecated {
			continue
		}
		var codes []string
		for _, s := range t.TacticsOf(res.ID) {
			if viewerSkip[s] {
				continue
			}
			code, ok := viewerCodes[s]
			if !ok {
				return "", fmt.Errorf("attack: tactic %s has no viewer code", s)
			}
			codes = append(codes, code)
		}
		if len(codes) == 0 {
			continue
		}
		entry := fmt.Sprintf(" %s: %q,", id, strings.Join(codes, " "))
		if len(line)+len(entry) > 110 {
			b.WriteString(line + "\n")
			line = "   "
		}
		line += entry
	}
	if line != "   " {
		b.WriteString(line + "\n")
	}
	b.WriteString("  }));\n")
	b.WriteString(ViewerEnd + "\n")
	return b.String(), nil
}

// ReplaceViewerBlock swaps the generated block in the viewer's source.
func ReplaceViewerBlock(html, block string) (string, error) {
	start := strings.Index(html, ViewerBegin)
	end := strings.Index(html, ViewerEnd)
	if start < 0 || end < start || strings.Count(html, ViewerBegin) != 1 || strings.Count(html, ViewerEnd) != 1 {
		return "", fmt.Errorf("attack: the viewer needs exactly one %q ... %q block", strings.TrimSpace(ViewerBegin), strings.TrimSpace(ViewerEnd))
	}
	end += len(ViewerEnd)
	if end < len(html) && html[end] == '\n' {
		end++
	}
	return html[:start] + block + html[end:], nil
}

// ExtractViewerBlock returns the generated block as it stands in the viewer.
func ExtractViewerBlock(html string) (string, error) {
	start := strings.Index(html, ViewerBegin)
	end := strings.Index(html, ViewerEnd)
	if start < 0 || end < start {
		return "", fmt.Errorf("attack: no generated block in the viewer")
	}
	end += len(ViewerEnd)
	if end < len(html) && html[end] == '\n' {
		end++
	}
	return html[start:end], nil
}

// sentenceCase turns "Command and Control" into "Command and control", the
// viewer's style.
func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	return s[:1] + strings.ToLower(s[1:])
}
