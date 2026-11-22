package navigator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jp101216/liveresponse-ng/internal/attack"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

// MaxExpectedBytes bounds an expected-techniques file.
const MaxExpectedBytes = 8 << 20

// maxExpectedIDs bounds how many technique IDs one file may name.
const maxExpectedIDs = 5000

// Expected is a set of techniques an emulation or scenario should have
// produced, and the ones the analyst marked as not observable on a host.
type Expected struct {
	Name       string          // shown in the layer: the file's base name
	IDs        map[string]bool // as written in the file
	OutOfScope map[string]bool // as written; wins over IDs
}

var (
	idInText = regexp.MustCompile(`\bT\d{4}(?:\.\d{3})?\b`)
	// A line that starts (after any list marker or emphasis) with
	// "Out of scope:" or "Not observable:" marks the IDs on it out of scope.
	outOfScopeLine = regexp.MustCompile(`(?i)^[\s>*_#|\-+0-9.)]*(out[ -]of[ -]scope|not[ -]observable)\b[^:]*:`)
)

// ParseExpected reads an expected set from a Navigator layer (every listed
// technique counts; one marked "enabled": false is out of scope) or from any
// text or Markdown file (every T#### or T####.### ID counts; IDs on a line
// starting "Out of scope:" or "Not observable:" are out of scope).
func ParseExpected(data []byte, name string) (Expected, error) {
	e := Expected{Name: name, IDs: map[string]bool{}, OutOfScope: map[string]bool{}}
	if len(data) > MaxExpectedBytes {
		return e, fmt.Errorf("expected-techniques file is over %d bytes", MaxExpectedBytes)
	}
	if !utf8.Valid(data) {
		return e, errors.New("expected-techniques file is not UTF-8 text")
	}
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if bytes.HasPrefix(trimmed, []byte("{")) {
		var layer struct {
			Domain     string `json:"domain"`
			Techniques []struct {
				TechniqueID string `json:"techniqueID"`
				Enabled     *bool  `json:"enabled"`
			} `json:"techniques"`
		}
		if err := json.Unmarshal(trimmed, &layer); err != nil {
			return e, fmt.Errorf("expected-techniques file looks like JSON but isn't a Navigator layer: %w", err)
		}
		if layer.Domain != "" && layer.Domain != Domain && layer.Domain != "mitre-enterprise" {
			return e, fmt.Errorf("the expected layer is for %q; lrng reports map to %s", layer.Domain, Domain)
		}
		for _, t := range layer.Techniques {
			id := strings.TrimSpace(t.TechniqueID)
			if !attack.IDRe.MatchString(id) {
				return e, fmt.Errorf("the expected layer has a malformed techniqueID %q", t.TechniqueID)
			}
			if t.Enabled != nil && !*t.Enabled {
				e.OutOfScope[id] = true
			} else {
				e.IDs[id] = true
			}
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			ids := idInText.FindAllString(line, -1)
			target := e.IDs
			if outOfScopeLine.MatchString(line) {
				target = e.OutOfScope
			}
			for _, id := range ids {
				target[id] = true
			}
		}
	}
	if len(e.IDs)+len(e.OutOfScope) > maxExpectedIDs {
		return e, fmt.Errorf("expected-techniques file names more than %d techniques", maxExpectedIDs)
	}
	if len(e.IDs) == 0 {
		return e, errors.New("expected-techniques file names no in-scope ATT&CK technique IDs")
	}
	return e, nil
}

// Coverage states and their colors: blue against orange, which stay apart for
// color-blind readers, with partial a lighter orange and extra a gray.
const (
	stateDetected = "detected"
	statePartial  = "partial"
	stateMissed   = "missed"
	stateExtra    = "extra"
	stateOut      = "out of scope"
)

var stateColor = map[string]string{
	stateDetected: "#2b6cb0",
	statePartial:  "#fbd38d",
	stateMissed:   "#dd6b20",
	stateExtra:    "#a0aec0",
}

// CoverageStats summarizes a coverage comparison. Rates are over the expected
// techniques in scope; partial matches are reported, not counted as detected.
type CoverageStats struct {
	Stats
	Expected   int
	OutOfScope int
	Detected   int
	Partial    int
	Missed     int
	Extra      int
	// ExpectedUnknown are IDs in the expected file the ATT&CK table doesn't know.
	ExpectedUnknown []string
}

// Rate is the share of in-scope expected techniques detected, 0-100.
func (c CoverageStats) Rate() float64 {
	if c.Expected == 0 {
		return 0
	}
	return 100 * float64(c.Detected) / float64(c.Expected)
}

// Line is a one-line summary for the console.
func (c CoverageStats) Line() string {
	s := fmt.Sprintf("expected %d, detected %d (%.0f%%), partial %d, missed %d, extra %d", c.Expected, c.Detected, c.Rate(), c.Partial, c.Missed, c.Extra)
	if c.OutOfScope > 0 {
		s += fmt.Sprintf(", %d out of scope", c.OutOfScope)
	}
	return s
}

func parentOf(id string) string {
	p, _, _ := strings.Cut(id, ".")
	return p
}

// Coverage makes a coverage layer: the report's findings against exp.
func Coverage(rep output.Report, exp Expected, opts Options) (*Layer, CoverageStats, error) {
	if err := opts.validate(); err != nil {
		return nil, CoverageStats{}, err
	}
	tb, err := opts.table()
	if err != nil {
		return nil, CoverageStats{}, err
	}
	hits, st := collect(rep, opts, tb)
	cs := CoverageStats{Stats: st}

	// Resolve the expected set through the same table as the findings.
	resolve := func(in map[string]bool) (map[string]map[string]bool, []string) {
		out := map[string]map[string]bool{} // current ID -> IDs as written
		var unknown []string
		for _, id := range sortedKeys(in) {
			r := tb.Resolve(id)
			if r.ID == "" {
				unknown = append(unknown, id)
				continue
			}
			if out[r.ID] == nil {
				out[r.ID] = map[string]bool{}
			}
			out[r.ID][id] = true
		}
		return out, unknown
	}
	expected, unk1 := resolve(exp.IDs)
	outOfScope, unk2 := resolve(exp.OutOfScope)
	cs.ExpectedUnknown = append(unk1, unk2...)
	for id := range outOfScope {
		delete(expected, id) // marked out of scope: not counted either way
	}

	state := map[string]string{}
	note := map[string]string{}
	for id := range expected {
		cs.Expected++
		switch {
		case hits[id] != nil:
			state[id] = stateDetected
		case !strings.Contains(id, ".") && anySubtechnique(hits, id):
			state[id] = stateDetected
			note[id] = "through a sub-technique"
		case strings.Contains(id, ".") && hits[parentOf(id)] != nil:
			state[id] = statePartial
			note[id] = "only the parent " + parentOf(id) + " fired"
		default:
			state[id] = stateMissed
		}
		switch state[id] {
		case stateDetected:
			cs.Detected++
		case statePartial:
			cs.Partial++
		default:
			cs.Missed++
		}
	}
	for id := range hits {
		if _, ok := state[id]; ok {
			continue
		}
		switch {
		case expected[parentOf(id)] != nil:
			state[id] = stateDetected
			note[id] = "counts toward expected " + parentOf(id)
		case parentSupportsExpected(expected, id):
			state[id] = statePartial
			note[id] = "parent of an expected sub-technique"
		case outOfScope[id] != nil:
			state[id] = stateDetected
			note[id] = "marked out of scope but fired"
		default:
			state[id] = stateExtra
			cs.Extra++
		}
	}
	for id := range outOfScope {
		if _, ok := state[id]; !ok {
			state[id] = stateOut
			cs.OutOfScope++
		}
	}

	l := baseLayer(rep, tb)
	l.Name = "lrng coverage: " + rep.Host
	l.Description = fmt.Sprintf("Techniques expected by %s against findings at %s or above from liveresponse-ng %s on %s, collected %s: %s.",
		nonEmpty(exp.Name, "the expected set"), opts.min(), rep.Version, rep.Host, rep.Collected.UTC().Format("2006-01-02T15:04:05Z"), cs.Line())
	l.Sorting = 0
	l.LegendItems = []LegendItem{
		{Label: "Detected", Color: stateColor[stateDetected]},
		{Label: "Partial (only the parent fired)", Color: stateColor[statePartial]},
		{Label: "Missed", Color: stateColor[stateMissed]},
		{Label: "Extra (not expected)", Color: stateColor[stateExtra]},
	}
	for _, id := range sortedKeys(state) {
		s := state[id]
		t := Technique{TechniqueID: id, Enabled: true}
		var parts []string
		label := titleCase(s)
		if n := note[id]; n != "" {
			label += ": " + n
		}
		parts = append(parts, label)
		if written := expected[id]; written != nil {
			if ids := sortedKeys(written); len(ids) > 1 || ids[0] != id {
				parts = append(parts, "Expected as "+strings.Join(ids, ", "))
			}
		}
		if h := hits[id]; h != nil {
			parts = append(parts, h.comment(tb))
			t.Metadata = h.meta()
		}
		if s == stateOut {
			t.Enabled = false
			parts = []string{"Out of scope: marked not observable on a host"}
		} else {
			t.Color = stateColor[s]
		}
		t.Comment = strings.Join(parts, ". ")
		t.Metadata = append([]Meta{{Name: "coverage", Value: s}}, t.Metadata...)
		l.Techniques = append(l.Techniques, t)
	}
	m := reportMeta(rep, opts, tb)
	m = append(m,
		Meta{Name: "expected_file", Value: nonEmpty(exp.Name, "-")},
		Meta{Name: "expected", Value: strconv.Itoa(cs.Expected)},
		Meta{Name: "detected", Value: strconv.Itoa(cs.Detected)},
		Meta{Name: "detection_rate", Value: fmt.Sprintf("%.1f%%", cs.Rate())},
		Meta{Name: "partial", Value: strconv.Itoa(cs.Partial)},
		Meta{Name: "missed", Value: strconv.Itoa(cs.Missed)},
		Meta{Name: "extra", Value: strconv.Itoa(cs.Extra)},
		Meta{Name: "out_of_scope", Value: strconv.Itoa(cs.OutOfScope)},
	)
	if len(cs.ExpectedUnknown) > 0 {
		m = append(m, Meta{Name: "expected_unknown", Value: strings.Join(cs.ExpectedUnknown, ", ")})
	}
	l.Metadata = append(m, statsMeta(st)...)
	return l, cs, nil
}

func anySubtechnique(hits map[string]*hit, parent string) bool {
	for id := range hits {
		if strings.HasPrefix(id, parent+".") {
			return true
		}
	}
	return false
}

func parentSupportsExpected(expected map[string]map[string]bool, parent string) bool {
	if strings.Contains(parent, ".") {
		return false
	}
	for id := range expected {
		if strings.HasPrefix(id, parent+".") {
			return true
		}
	}
	return false
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
