package intel

import (
	"bufio"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// parse.go — the dataset file format and its reader.
//
// The format is deliberately plain so it diffs cleanly in git, is trivial to
// generate, and can be eyeballed or hand-edited: UTF-8, one record per line,
// tab-separated. Blank lines are ignored. A line beginning with '#' is a
// comment; a comment of the form "# key: value" with a known key carries
// dataset metadata (source, generated, notes). A data line is:
//
//	CIDR <TAB> ASN <TAB> CC <TAB> CATEGORIES <TAB> ORG
//
// where ASN may be bare or "AS"-prefixed (0/empty = unknown), CC is an ISO-3166
// alpha-2 code (empty = unknown), CATEGORIES is a comma-separated subset of the
// known category names (unknown names are ignored, so an old binary tolerates a
// newer dataset), and ORG is free text. Only the CIDR is required; trailing
// fields may be omitted.
//
// Parsing is tolerant: a line with an unparseable CIDR is skipped rather than
// failing the whole load, because a single bad row in a refreshed dataset must
// never take down a live-response run. An empty dataset is valid and simply
// attributes nothing.

const maxLineBytes = 1 << 20 // 1 MiB; AS descriptions are short, this is slack

// Load reads a dataset from r and compiles it into a DB. It returns an error
// only on an I/O failure; malformed data lines are skipped.
func Load(r io.Reader) (*DB, error) {
	d := &DB{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			d.applyMetaComment(trimmed)
			continue
		}
		d.applyDataLine(line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	d.finish()
	return d, nil
}

// applyMetaComment reads "# key: value" metadata out of a comment line; any
// other comment is ignored.
func (d *DB) applyMetaComment(line string) {
	body := strings.TrimSpace(strings.TrimLeft(line, "#"))
	key, val, ok := strings.Cut(body, ":")
	if !ok {
		return
	}
	val = strings.TrimSpace(val)
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "source":
		d.meta.Source = val
	case "generated":
		d.meta.Generated = val
	case "notes", "note":
		d.meta.Notes = val
	}
}

// applyDataLine parses one tab-separated record and inserts it, skipping the
// line if the CIDR doesn't parse.
func (d *DB) applyDataLine(line string) {
	f := strings.SplitN(line, "\t", 5)
	p, err := netip.ParsePrefix(strings.TrimSpace(f[0]))
	if err != nil {
		return // tolerant: skip a bad row, keep the rest
	}
	var (
		asn  uint32
		cc   string
		cats Category
		org  string
	)
	if len(f) > 1 {
		asn = parseASN(f[1])
	}
	if len(f) > 2 {
		cc = normalizeCC(f[2])
	}
	if len(f) > 3 {
		cats = parseCategories(f[3])
	}
	if len(f) > 4 {
		org = strings.TrimSpace(f[4])
	}
	d.insert(p, asn, cc, cats, org)
}

// parseASN accepts "", "0", "AS13335" or "13335"; anything unparseable is 0.
func parseASN(s string) uint32 {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "AS")
	s = strings.TrimPrefix(s, "as")
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// normalizeCC upper-cases a two-letter country code; anything else becomes "".
func normalizeCC(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

// parseCategories ORs together the known categories in a comma-separated list,
// ignoring unknown names.
func parseCategories(s string) Category {
	var set Category
	for _, name := range strings.Split(s, ",") {
		if c, ok := ParseCategory(name); ok {
			set |= c
		}
	}
	return set
}
