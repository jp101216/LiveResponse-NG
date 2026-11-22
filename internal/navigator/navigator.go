// Package navigator turns an lrng report into an ATT&CK Navigator layer
// (https://github.com/mitre-attack/attack-navigator, layer format 4.5).
//
// Two kinds of layer come out of a report:
//
//   - A findings layer: one technique per distinct ATT&CK ID among the
//     report's findings at or above a severity, scored by the highest
//     severity that hit it (notable 1, suspect 2, critical 3).
//   - A coverage layer: the same findings compared against an expected set of
//     techniques (an actor profile's technique matrix, or one of MITRE's own
//     group layers), each technique colored detected, partial, missed or
//     extra, so an emulation run shows what lrng saw and what it didn't.
//
// Every technique goes through the bundled ATT&CK table (internal/attack)
// first: a revoked ID becomes its successor, so a report from an older lrng,
// or a third-party dataset still on retired IDs, lines up with the current
// matrix. A layer never carries a finding's detail text (it can hold user
// names and paths), only rule names, counts, severities and confidences, so a
// layer can be shared where the report can't. The same report always gives
// byte-identical output.
package navigator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/attack"
	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

// Navigator versions written into every layer. The 4.5 layer format needs a
// Navigator of 4.9.0 or later; 5.3.2 is the release current when this was
// written and the one the layers were checked against.
const (
	LayerFormat      = "4.5"
	NavigatorVersion = "5.3.2"
	Domain           = "enterprise-attack"
)

// Layer is a Navigator layer, limited to the members lrng writes.
type Layer struct {
	Name        string       `json:"name"`
	Versions    Versions     `json:"versions"`
	Domain      string       `json:"domain"`
	Description string       `json:"description"`
	Sorting     int          `json:"sorting"`
	Layout      Layout       `json:"layout"`
	HideDisable bool         `json:"hideDisabled"`
	Techniques  []Technique  `json:"techniques"`
	Gradient    *Gradient    `json:"gradient,omitempty"`
	LegendItems []LegendItem `json:"legendItems"`
	Metadata    []Meta       `json:"metadata"`
}

type Versions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type Layout struct {
	Layout                string `json:"layout"`
	ShowID                bool   `json:"showID"`
	ShowName              bool   `json:"showName"`
	ExpandedSubtechniques string `json:"expandedSubtechniques"`
}

// Technique is one annotated technique. With no tactic, Navigator shows the
// annotation under every tactic the technique belongs to, which is right for
// lrng: a finding doesn't say which tactic it served.
type Technique struct {
	TechniqueID string `json:"techniqueID"`
	Score       *int   `json:"score,omitempty"`
	Color       string `json:"color,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Enabled     bool   `json:"enabled"`
	Metadata    []Meta `json:"metadata,omitempty"`
}

type Gradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type LegendItem struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

type Meta struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Options control which findings count and what the layer records.
type Options struct {
	// MinSeverity is the lowest severity that counts (default notable: info
	// findings are inventory, not detections).
	MinSeverity collector.Severity
	// ReportSHA256 is the SHA-256 of the report file, when the layer is built
	// from a saved report or alongside one; recorded in the layer metadata.
	ReportSHA256 string
	// Table overrides the bundled ATT&CK table (tests).
	Table *attack.Table
}

// Severity scores and colors. Colors differ in lightness as well as hue, so
// they stay apart for readers who can't tell the hues apart.
var (
	severityScore = map[collector.Severity]int{collector.SevInfo: 0, collector.SevNotable: 1, collector.SevSuspect: 2, collector.SevCritical: 3}
	severityColor = map[collector.Severity]string{
		collector.SevInfo: "#dde6ee", collector.SevNotable: "#fde68a", collector.SevSuspect: "#f59e0b", collector.SevCritical: "#b91c1c",
	}
	severities = []collector.Severity{collector.SevInfo, collector.SevNotable, collector.SevSuspect, collector.SevCritical}
)

// ruleHits is what one rule contributed to one technique.
type ruleHits struct {
	count   int
	worst   collector.Severity
	maxConf int
}

// hit collects everything known about one (current) technique.
type hit struct {
	id         string
	rules      map[string]*ruleHits
	collectors map[string]bool
	from       map[string]int // retired IDs that were remapped here, with counts
	deprecated bool
	findings   int
	worst      collector.Severity
	maxConf    int
}

// Stats describes what went into a layer.
type Stats struct {
	Qualifying  int            // findings at or above the minimum severity
	NoTechnique int            // of those, how many name no technique
	Unknown     map[string]int // technique IDs the ATT&CK table doesn't know
	Remapped    map[string]int // "T1562.001 -> T1685" -> findings
	Techniques  int            // distinct current techniques annotated
}

func (o Options) table() (*attack.Table, error) {
	if o.Table != nil {
		return o.Table, nil
	}
	return attack.Bundled()
}

func (o Options) validate() error {
	if o.MinSeverity != "" && collector.SeverityRank(o.MinSeverity) == 0 {
		return fmt.Errorf("unknown severity %q (info, notable, suspect, critical)", o.MinSeverity)
	}
	return nil
}

func (o Options) min() collector.Severity {
	if o.MinSeverity == "" {
		return collector.SevNotable
	}
	return o.MinSeverity
}

// collect walks every finding in the report.
func collect(rep output.Report, opts Options, tb *attack.Table) (map[string]*hit, Stats) {
	min := collector.SeverityRank(opts.min())
	hits := map[string]*hit{}
	st := Stats{Unknown: map[string]int{}, Remapped: map[string]int{}}
	for _, res := range rep.Results {
		extra := sigmaTechniques(res.Meta)
		for _, rec := range res.Records {
			for _, f := range rec.Findings {
				if collector.SeverityRank(f.Severity) < min || collector.SeverityRank(f.Severity) == 0 {
					continue
				}
				st.Qualifying++
				ids := []string{}
				if f.Technique != "" {
					ids = append(ids, f.Technique)
				}
				for _, x := range extra[f.Rule] {
					if x != f.Technique {
						ids = append(ids, x)
					}
				}
				if len(ids) == 0 {
					st.NoTechnique++
					continue
				}
				for _, raw := range ids {
					id := strings.ToUpper(strings.TrimSpace(raw))
					if !attack.IDRe.MatchString(id) {
						st.Unknown[raw]++
						continue
					}
					r := tb.Resolve(id)
					if r.ID == "" {
						st.Unknown[id]++
						continue
					}
					h := hits[r.ID]
					if h == nil {
						h = &hit{id: r.ID, rules: map[string]*ruleHits{}, collectors: map[string]bool{}, from: map[string]int{}}
						hits[r.ID] = h
					}
					if r.Remapped() {
						h.from[id]++
						st.Remapped[id+" -> "+r.ID]++
					}
					h.deprecated = h.deprecated || r.Status == attack.Deprecated
					rh := h.rules[f.Rule]
					if rh == nil {
						rh = &ruleHits{}
						h.rules[f.Rule] = rh
					}
					rh.count++
					if collector.SeverityRank(f.Severity) > collector.SeverityRank(rh.worst) {
						rh.worst = f.Severity
					}
					rh.maxConf = max(rh.maxConf, f.Confidence)
					h.collectors[res.Collector] = true
					h.findings++
					if collector.SeverityRank(f.Severity) > collector.SeverityRank(h.worst) {
						h.worst = f.Severity
					}
					h.maxConf = max(h.maxConf, f.Confidence)
				}
			}
		}
	}
	st.Techniques = len(hits)
	return hits, st
}

// sigmaTechniques reads meta.sigma.techniques (rule -> every ATT&CK tag the
// Sigma rule carries) from a result, as the eventlog collector writes it.
func sigmaTechniques(meta map[string]any) map[string][]string {
	out := map[string][]string{}
	sigma, _ := meta["sigma"].(map[string]any)
	if live, ok := sigma["techniques"].(map[string][]string); ok { // straight from the collector
		for rule, list := range live {
			out[rule] = append(out[rule], list...)
		}
		return out
	}
	techs, _ := sigma["techniques"].(map[string]any) // decoded from a saved report
	for rule, v := range techs {
		switch list := v.(type) {
		case []any:
			for _, x := range list {
				if s, ok := x.(string); ok {
					out[rule] = append(out[rule], s)
				}
			}
		case []string:
			out[rule] = append(out[rule], list...)
		}
	}
	return out
}

// Build makes a findings layer.
func Build(rep output.Report, opts Options) (*Layer, Stats, error) {
	if err := opts.validate(); err != nil {
		return nil, Stats{}, err
	}
	tb, err := opts.table()
	if err != nil {
		return nil, Stats{}, err
	}
	hits, st := collect(rep, opts, tb)
	l := baseLayer(rep, tb)
	l.Name = "lrng findings: " + rep.Host
	l.Description = fmt.Sprintf("Findings at %s or above from liveresponse-ng %s on %s, collected %s. Score is the highest severity that hit the technique: %s.",
		opts.min(), rep.Version, rep.Host, rep.Collected.UTC().Format("2006-01-02T15:04:05Z"), scoreKey(opts.min()))
	l.Sorting = 3 // highest score first
	minScore := severityScore[opts.min()]
	var colors []string
	for _, s := range severities {
		if severityScore[s] >= minScore {
			colors = append(colors, severityColor[s])
			l.LegendItems = append(l.LegendItems, LegendItem{Label: titleCase(string(s)), Color: severityColor[s]})
		}
	}
	if len(colors) == 1 { // Navigator wants two gradient stops
		colors = append(colors, colors[0])
	}
	l.Gradient = &Gradient{Colors: colors, MinValue: minScore, MaxValue: 3}
	if minScore == 3 {
		l.Gradient.MinValue = 2
		l.Gradient.Colors = []string{severityColor[collector.SevSuspect], severityColor[collector.SevCritical]}
	}
	for _, id := range sortedKeys(hits) {
		h := hits[id]
		score := severityScore[h.worst]
		l.Techniques = append(l.Techniques, Technique{
			TechniqueID: id, Score: &score, Comment: h.comment(tb), Enabled: true, Metadata: h.meta(),
		})
	}
	l.Metadata = append(reportMeta(rep, opts, tb), statsMeta(st)...)
	return l, st, nil
}

func (h *hit) comment(tb *attack.Table) string {
	type rr struct {
		name string
		*ruleHits
	}
	var rules []rr
	for name, r := range h.rules {
		rules = append(rules, rr{name, r})
	}
	sort.Slice(rules, func(a, b int) bool {
		ra, rb := collector.SeverityRank(rules[a].worst), collector.SeverityRank(rules[b].worst)
		if ra != rb {
			return ra > rb
		}
		return rules[a].name < rules[b].name
	})
	var parts []string
	for i, r := range rules {
		if i == 20 {
			parts = append(parts, fmt.Sprintf("… and %d more rules", len(rules)-20))
			break
		}
		if r.count == 1 {
			parts = append(parts, fmt.Sprintf("%s (%s)", r.name, r.worst))
		} else {
			parts = append(parts, fmt.Sprintf("%s (×%d, worst %s)", r.name, r.count, r.worst))
		}
	}
	c := strings.Join(parts, ", ")
	if len(h.from) > 0 {
		c += ". Mapped from " + strings.Join(sortedKeys(h.from), ", ") + ", revoked in ATT&CK"
	}
	if h.deprecated {
		c += ". Deprecated in ATT&CK v" + tb.Version
	}
	return c
}

func (h *hit) meta() []Meta {
	var cols []string
	for c := range h.collectors {
		cols = append(cols, c)
	}
	sort.Strings(cols)
	return []Meta{
		{Name: "findings", Value: strconv.Itoa(h.findings)},
		{Name: "highest severity", Value: string(h.worst)},
		{Name: "highest confidence", Value: strconv.Itoa(h.maxConf)},
		{Name: "rules", Value: strconv.Itoa(len(h.rules))},
		{Name: "collectors", Value: strings.Join(cols, ", ")},
	}
}

func baseLayer(rep output.Report, tb *attack.Table) *Layer {
	return &Layer{
		Versions:    Versions{Attack: tb.Version, Navigator: NavigatorVersion, Layer: LayerFormat},
		Domain:      Domain,
		Layout:      Layout{Layout: "side", ShowID: true, ShowName: true, ExpandedSubtechniques: "annotated"},
		Techniques:  []Technique{},
		LegendItems: []LegendItem{},
	}
}

func reportMeta(rep output.Report, opts Options, tb *attack.Table) []Meta {
	m := []Meta{
		{Name: "host", Value: rep.Host},
		{Name: "run_id", Value: rep.RunID},
		{Name: "collected_at", Value: rep.Collected.UTC().Format("2006-01-02T15:04:05Z")},
		{Name: "tool", Value: "liveresponse-ng " + rep.Version},
		{Name: "attack_mapping", Value: "Enterprise ATT&CK v" + tb.Version + " (lrng's bundled table)"},
		{Name: "min_severity", Value: string(opts.min())},
	}
	if opts.ReportSHA256 != "" {
		m = append(m, Meta{Name: "report_sha256", Value: opts.ReportSHA256})
	}
	return m
}

func statsMeta(st Stats) []Meta {
	m := []Meta{
		{Name: "qualifying_findings", Value: strconv.Itoa(st.Qualifying)},
		{Name: "findings_without_technique", Value: strconv.Itoa(st.NoTechnique)},
	}
	if len(st.Remapped) > 0 {
		var parts []string
		for _, k := range sortedKeys(st.Remapped) {
			parts = append(parts, fmt.Sprintf("%s (×%d)", k, st.Remapped[k]))
		}
		m = append(m, Meta{Name: "remapped", Value: strings.Join(parts, "; ")})
	}
	if len(st.Unknown) > 0 {
		m = append(m, Meta{Name: "unknown_techniques", Value: strings.Join(sortedKeys(st.Unknown), ", ")})
	}
	return m
}

func scoreKey(min collector.Severity) string {
	var parts []string
	for _, s := range severities {
		if severityScore[s] >= severityScore[min] {
			parts = append(parts, fmt.Sprintf("%d %s", severityScore[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

// Encode writes a layer as indented JSON with a trailing newline. Field order
// is fixed by the structs and techniques are sorted, so the bytes depend only
// on the report.
func Encode(w io.Writer, l *Layer) error {
	if l == nil {
		return errors.New("no layer")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(l); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
