package collector

import (
	"bytes"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// builtinSigmaFS holds the bundled starter rule pack, mapped to the channels
// lrng collects, so "-sigma builtin" is useful with nothing on disk.
//
//go:embed sigmarules/*.yml
var builtinSigmaFS embed.FS

// sigma.go — a dependency-free Sigma detection engine over the parsed event
// log. Sigma (sigmahq.io) is the common YAML signature format for log events;
// this compiles a useful subset and evaluates it against each normalized
// Windows event, so an analyst's own rules run beside lrng's built-in
// detections. Rules are read with the dependency-free yamllite parser, keeping
// the zero-dependency Go tree.
//
// A rule using a construct this engine does not implement faithfully is skipped
// with a reason, never evaluated wrongly — a triage tool must not silently
// mis-score a detection. Supported:
//
//   - string matching: plain (with * and ? wildcards), |contains, |startswith,
//     |endswith, |re, |cased, and |windash (dash-variant command-line flags);
//   - |base64offset (match a value as base64 at any byte alignment);
//   - |cidr (match an IP-address field against a CIDR network);
//   - |fieldref (compare a field to another field's value, optionally with
//     |contains/|startswith/|endswith/|cased);
//   - list values (OR), or AND with |all;
//   - numeric |lt |lte |gt |gte, |exists, and null matches;
//   - a selection that is a list of maps (OR of maps), and keyword lists;
//   - conditions: and/or/not, parentheses, and "N/all/1 of them" or
//     "N/all/1 of <pattern>*";
//   - aggregation "<expr> | count|min|max|avg|sum([field]) [by <field>] <op>
//     <n>", evaluated across the whole run and emitted as a synthetic record
//     per over-threshold group; with a detection "timeframe:", a
//     count|count(field)|sum with >/>= instead slides a window of that width
//     and fires if any window crosses the threshold (burst/spray/volume);
//   - the temporal "<expr> | near <expr>" with a detection "timeframe:" window.
//
// Not supported, so the rule is skipped: the plain |base64 and |utf16/|wide
// encoding modifiers, a "| near" with no timeframe, and a timeframe on
// min/max/avg or with an operator other than >/>= (no sound sliding-window
// meaning). logsource narrows a rule to a channel/event when its service or
// category is one we map; otherwise the rule is tried against every event.

// SigmaRuleset is a compiled set of Sigma rules plus what was skipped or failed
// to parse, so the gaps are visible in the report (as YARA compile failures
// are).
type SigmaRuleset struct {
	rules   []*sigmaRule
	Loaded  int
	Skipped []string // "name: reason" for rules using unsupported constructs
	Failed  []string // files/documents that didn't parse
}

// Empty reports whether the ruleset has no usable rules.
func (rs *SigmaRuleset) Empty() bool { return rs == nil || len(rs.rules) == 0 }

type sigmaRule struct {
	id        string
	title     string
	level     Severity
	conf      int
	technique string
	logFilter func(winEvent) bool
	searches  map[string]*sigmaSearch
	cond      condNode
	agg       *aggregation // non-nil for a "| count() ..." rule; fired from the aggregator, not per-event
}

// aggregation is a Sigma aggregation that fires after the run rather than
// per-event. For the scalar functions (count/min/max/avg/sum) it reduces the
// events whose search expression matched — count of events, distinct count of a
// field, or min/max/avg/sum of a numeric field — optionally grouped "by" a
// field and compared to a threshold. Without a timeframe it is evaluated across
// the whole run; with one, a count()/count(field)/sum() with ">"/">=" is
// evaluated as a sliding window and fires if any timeframe-wide window crosses
// the threshold (brute force, password spray, exfil volume). For the temporal
// "near" it holds the expression after the pipe and the timeframe window the
// referenced selections must co-occur within.
type aggregation struct {
	fn        string // count, min, max, avg, sum, or near
	field     string // aggregated/distinct field, lower-cased ("" = count events)
	fieldRaw  string // original field name, for the finding text
	groupBy   string // group-by field, lower-cased ("" = no grouping)
	groupRaw  string // original group-by name
	op        string // >, >=, <, <=, ==
	threshold float64

	// near, and the scalar sliding window, both use timeframe:
	nearCond  condNode      // the temporal expression after "near" (near only)
	timeframe time.Duration // near: the co-occurrence window; scalar: the sliding window
}

// windowed reports whether this is a scalar aggregation carrying a sliding
// timeframe window (as opposed to whole-run, or the temporal "near").
func (a *aggregation) windowed() bool { return a.fn != "near" && a.timeframe > 0 }

type sigmaSearch struct {
	groups   []fieldGroup   // OR of these; each is an AND of its field matches
	keywords []valueMatcher // OR of these, matched against any field value
}

type fieldGroup []fieldMatch

type fieldMatch struct {
	field    string // lower-cased
	all      bool   // |all: every matcher must match; otherwise any
	null     bool   // value is null: the field must be absent/empty
	exists   *bool  // |exists: field presence requirement
	matchers []valueMatcher
}

type matchOp int

const (
	opEquals matchOp = iota
	opContains
	opStartsWith
	opEndsWith
	opRegex
	opGt
	opGte
	opLt
	opLte
	opCIDR     // |cidr: the field value (an IP) falls inside a CIDR network
	opFieldRef // |fieldref: compare the field to another field's value
)

type valueMatcher struct {
	op      matchOp
	cased   bool
	literal string         // string ops without wildcards (lower-cased unless cased)
	re      *regexp.Regexp // string ops with wildcards, or |re
	num     float64        // numeric ops
	prefix  netip.Prefix   // opCIDR: the network to test membership of
	// opFieldRef: the other field to compare against (lower-cased) and how
	// (refOp is one of opEquals/opContains/opStartsWith/opEndsWith).
	refField string
	refOp    matchOp
}

// match evaluates one rule against an event (fields is the lower-cased field
// map, values its values for keyword scanning).
func (r *sigmaRule) match(ev winEvent, fields map[string]string, values []string) bool {
	if r.logFilter != nil && !r.logFilter(ev) {
		return false
	}
	ctx := &condCtx{matched: make(map[string]bool, len(r.searches)), names: make([]string, 0, len(r.searches))}
	for name, s := range r.searches {
		ctx.matched[name] = s.eval(fields, values)
		ctx.names = append(ctx.names, name)
	}
	return r.cond.eval(ctx)
}

func (s *sigmaSearch) eval(fields map[string]string, values []string) bool {
	for _, kw := range s.keywords {
		for _, v := range values {
			if matchValue(kw, v) {
				return true
			}
		}
	}
	for _, g := range s.groups {
		if len(g) == 0 {
			continue
		}
		ok := true
		for _, fm := range g {
			if !fm.eval(fields) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (fm fieldMatch) eval(fields map[string]string) bool {
	val, present := fields[fm.field]
	if fm.exists != nil {
		return present == *fm.exists
	}
	if fm.null {
		return !present || val == ""
	}
	if !present {
		return false
	}
	if fm.all {
		for _, m := range fm.matchers {
			if !m.matchIn(val, fields) {
				return false
			}
		}
		return len(fm.matchers) > 0
	}
	for _, m := range fm.matchers {
		if m.matchIn(val, fields) {
			return true
		}
	}
	return false
}

// matchIn evaluates one matcher against a field's value, consulting the whole
// (lower-cased) field map for the matchers that need another field: |cidr tests
// the value as an IP against a network, |fieldref compares the value to a second
// field's value. Everything else defers to matchValue.
func (m valueMatcher) matchIn(val string, fields map[string]string) bool {
	switch m.op {
	case opCIDR:
		addr, err := netip.ParseAddr(strings.TrimSpace(val))
		if err != nil {
			return false
		}
		return m.prefix.Contains(addr.Unmap())
	case opFieldRef:
		other, ok := fields[m.refField]
		if !ok {
			return false
		}
		hay, needle := val, other
		if !m.cased {
			hay = strings.ToLower(hay)
			needle = strings.ToLower(needle)
		}
		switch m.refOp {
		case opContains:
			return strings.Contains(hay, needle)
		case opStartsWith:
			return strings.HasPrefix(hay, needle)
		case opEndsWith:
			return strings.HasSuffix(hay, needle)
		default:
			return hay == needle
		}
	default:
		return matchValue(m, val)
	}
}

func matchValue(m valueMatcher, s string) bool {
	switch m.op {
	case opRegex:
		return m.re != nil && m.re.MatchString(s)
	case opEquals, opContains, opStartsWith, opEndsWith:
		if m.re != nil {
			return m.re.MatchString(s)
		}
		hay := s
		if !m.cased {
			hay = strings.ToLower(s)
		}
		switch m.op {
		case opEquals:
			return hay == m.literal
		case opContains:
			return strings.Contains(hay, m.literal)
		case opStartsWith:
			return strings.HasPrefix(hay, m.literal)
		case opEndsWith:
			return strings.HasSuffix(hay, m.literal)
		}
	case opGt, opGte, opLt, opLte:
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return false
		}
		switch m.op {
		case opGt:
			return f > m.num
		case opGte:
			return f >= m.num
		case opLt:
			return f < m.num
		case opLte:
			return f <= m.num
		}
	}
	return false
}

// match builds the finding list for one event across all rules.
func (rs *SigmaRuleset) match(ev winEvent) []Finding {
	if rs == nil || len(rs.rules) == 0 {
		return nil
	}
	fields := ev.sigmaFields()
	values := make([]string, 0, len(fields))
	for _, v := range fields {
		values = append(values, v)
	}
	var out []Finding
	for _, r := range rs.rules {
		if r.agg != nil {
			continue // aggregation rules fire from the aggregator after the run, not per-event
		}
		if r.match(ev, fields, values) {
			out = append(out, Finding{
				Rule:       "sigma." + r.id,
				Severity:   r.level,
				Technique:  r.technique,
				Confidence: r.conf,
				Detail:     "Sigma rule matched: " + r.title,
			})
		}
	}
	return out
}

// hasAggregations reports whether any rule carries run-wide state: a
// count/min/max/avg/sum aggregation or a temporal "near".
func (rs *SigmaRuleset) hasAggregations() bool {
	if rs == nil {
		return false
	}
	for _, r := range rs.rules {
		if r.agg != nil {
			return true
		}
	}
	return false
}

// sigmaAggregator accumulates per-group counts for the aggregation rules over a
// collection run, then flushes the groups that cross their threshold as records.
type sigmaAggregator struct {
	states []*aggState
}

type aggState struct {
	rule     *sigmaRule
	counts   map[string]int             // group value -> matching-event count
	distinct map[string]map[string]bool // group value -> set of field values (for count(field))
	// numeric accumulators for min/max/avg/sum, keyed by group value:
	numN   map[string]int
	numSum map[string]float64
	numMin map[string]float64
	numMax map[string]float64
	// near: per-selection match timestamps over the run, and whether the record
	// cap was hit.
	nearTimes map[string][]time.Time
	nearTrunc bool
	// windowed scalar aggregation: per-group timestamped observations, swept at
	// flush, and whether the per-group cap was hit.
	obs      map[string][]windowObs
	obsTrunc bool
}

// windowObs is one matching event's contribution to a windowed aggregation: its
// time, the numeric value (sum), and the field value (distinct count). Only the
// field the rule's function needs is populated.
type windowObs struct {
	t   time.Time
	num float64
	str string
}

// nearMaxTimes bounds how many match timestamps a single selection records for a
// temporal "near" rule, so a broad selection on a huge log can't grow without
// limit. Past it the rule is still evaluated, and the result is flagged.
const nearMaxTimes = 200000

// aggWindowMaxObs bounds the observations a single group retains for a windowed
// scalar aggregation, so a broad selection on a huge log can't grow without
// limit. Past it the group keeps its earlier observations (so a burst that
// already crossed the threshold still fires) and the result is flagged.
const aggWindowMaxObs = 200000

// newAggregator returns an accumulator for this ruleset's aggregation rules, or
// nil if there are none.
func (rs *SigmaRuleset) newAggregator() *sigmaAggregator {
	if !rs.hasAggregations() {
		return nil
	}
	a := &sigmaAggregator{}
	for _, r := range rs.rules {
		if r.agg != nil {
			a.states = append(a.states, &aggState{
				rule:      r,
				counts:    map[string]int{},
				distinct:  map[string]map[string]bool{},
				numN:      map[string]int{},
				numSum:    map[string]float64{},
				numMin:    map[string]float64{},
				numMax:    map[string]float64{},
				nearTimes: map[string][]time.Time{},
				obs:       map[string][]windowObs{},
			})
		}
	}
	return a
}

// observe folds one event into every aggregation rule whose search expression
// it matches.
func (a *sigmaAggregator) observe(ev winEvent) {
	if a == nil {
		return
	}
	fields := ev.sigmaFields()
	values := make([]string, 0, len(fields))
	for _, v := range fields {
		values = append(values, v)
	}
	for _, st := range a.states {
		if st.rule.agg.fn == "near" {
			st.observeNear(ev, fields, values)
			continue
		}
		if st.rule.agg.windowed() {
			st.observeWindowed(ev, fields, values)
			continue
		}
		if !st.rule.match(ev, fields, values) {
			continue
		}
		group := ""
		if st.rule.agg.groupBy != "" {
			group = fields[st.rule.agg.groupBy]
		}
		st.counts[group]++
		switch st.rule.agg.fn {
		case "count":
			if st.rule.agg.field != "" {
				if st.distinct[group] == nil {
					st.distinct[group] = map[string]bool{}
				}
				if v, ok := fields[st.rule.agg.field]; ok {
					st.distinct[group][v] = true
				}
			}
		case "min", "max", "avg", "sum":
			v, ok := fields[st.rule.agg.field]
			if !ok {
				continue
			}
			f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				continue
			}
			if st.numN[group] == 0 || f < st.numMin[group] {
				st.numMin[group] = f
			}
			if st.numN[group] == 0 || f > st.numMax[group] {
				st.numMax[group] = f
			}
			st.numSum[group] += f
			st.numN[group]++
		}
	}
}

// observeWindowed records a matching event's contribution to a windowed scalar
// aggregation, keyed by its group. An event with no timestamp can't be placed
// in a window, so it is skipped; an event missing the aggregated field (for
// sum/count(field)) contributes nothing, as in the whole-run path.
func (st *aggState) observeWindowed(ev winEvent, fields map[string]string, values []string) {
	if ev.TimeCreated.IsZero() || !st.rule.match(ev, fields, values) {
		return
	}
	group := ""
	if st.rule.agg.groupBy != "" {
		group = fields[st.rule.agg.groupBy]
	}
	if len(st.obs[group]) >= aggWindowMaxObs {
		st.obsTrunc = true
		return
	}
	o := windowObs{t: ev.TimeCreated}
	switch st.rule.agg.fn {
	case "sum":
		v, ok := fields[st.rule.agg.field]
		if !ok {
			return
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return
		}
		o.num = f
	case "count":
		if st.rule.agg.field != "" { // count(field): distinct values within the window
			v, ok := fields[st.rule.agg.field]
			if !ok {
				return
			}
			o.str = v
		}
	}
	st.obs[group] = append(st.obs[group], o)
}

// observeNear records, for a temporal "near" rule, the timestamp of this event
// against every selection it matches, so the window check can run at flush.
func (st *aggState) observeNear(ev winEvent, fields map[string]string, values []string) {
	if st.rule.logFilter != nil && !st.rule.logFilter(ev) {
		return
	}
	if ev.TimeCreated.IsZero() {
		return // a near correlation is meaningless without a timestamp
	}
	for name, s := range st.rule.searches {
		if !s.eval(fields, values) {
			continue
		}
		if len(st.nearTimes[name]) >= nearMaxTimes {
			st.nearTrunc = true
			continue
		}
		st.nearTimes[name] = append(st.nearTimes[name], ev.TimeCreated)
	}
}

// flush returns one record per group that crossed its rule's threshold.
func (a *sigmaAggregator) flush() []Record {
	if a == nil {
		return nil
	}
	var out []Record
	for _, st := range a.states {
		ag := st.rule.agg
		if ag.fn == "near" {
			out = append(out, st.flushNear()...)
			continue
		}
		if ag.windowed() {
			out = append(out, st.flushWindowed()...)
			continue
		}
		groups := make([]string, 0, len(st.counts))
		for g := range st.counts {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		for _, g := range groups {
			metric, ok := st.metric(g)
			if !ok || !aggSatisfied(ag.op, metric, ag.threshold) {
				continue
			}
			f := map[string]any{
				"sigma_aggregation": true,
				"rule":              "sigma." + st.rule.id,
				"metric":            cleanMetric(metric),
			}
			if ag.groupBy != "" {
				f["group_by"] = ag.groupRaw
				f["group_value"] = g
			}
			out = append(out, Record{
				Fields: f,
				Findings: []Finding{{
					Rule:       "sigma." + st.rule.id,
					Severity:   st.rule.level,
					Technique:  st.rule.technique,
					Confidence: st.rule.conf,
					Detail:     "Sigma aggregation matched: " + st.rule.title + " — " + ag.describe(g, metric),
				}},
			})
		}
	}
	return out
}

// flushWindowed evaluates a scalar aggregation that carries a timeframe: for
// each group it sweeps a sliding window of that width over the group's
// timestamped observations and fires once if any window's metric crosses the
// threshold. count (events and distinct) and sum are non-decreasing as the
// window grows, so the maximal window ending at each observation — what the two
// pointers give — is the largest metric for a window ending there; checking
// each is exact for ">"/">=" (the only operators parsing allows here). sum
// assumes non-negative values (byte/count fields); a negative value can only
// make it under-report, never over-fire.
func (st *aggState) flushWindowed() []Record {
	ag := st.rule.agg
	groups := make([]string, 0, len(st.obs))
	for g := range st.obs {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	var out []Record
	for _, g := range groups {
		obs := st.obs[g]
		sort.Slice(obs, func(i, j int) bool { return obs[i].t.Before(obs[j].t) })

		var sum float64
		distinct := map[string]int{} // value -> occurrences currently in the window
		left := 0
		var metric float64
		var start, end time.Time
		fired := false
		for right := 0; right < len(obs) && !fired; right++ {
			sum += obs[right].num
			if ag.fn == "count" && ag.field != "" {
				distinct[obs[right].str]++
			}
			for obs[right].t.Sub(obs[left].t) > ag.timeframe {
				sum -= obs[left].num
				if ag.fn == "count" && ag.field != "" {
					if distinct[obs[left].str]--; distinct[obs[left].str] == 0 {
						delete(distinct, obs[left].str)
					}
				}
				left++
			}
			var m float64
			switch {
			case ag.fn == "sum":
				m = sum
			case ag.field != "": // count(field): distinct values in the window
				m = float64(len(distinct))
			default: // count(): events in the window
				m = float64(right - left + 1)
			}
			if aggSatisfied(ag.op, m, ag.threshold) {
				metric, start, end, fired = m, obs[left].t, obs[right].t, true
			}
		}
		if !fired {
			continue
		}
		f := map[string]any{
			"sigma_aggregation": true,
			"rule":              "sigma." + st.rule.id,
			"metric":            cleanMetric(metric),
			"timeframe":         ag.timeframe.String(),
			"window_start":      start.UTC().Format(time.RFC3339),
			"window_end":        end.UTC().Format(time.RFC3339),
		}
		if ag.groupBy != "" {
			f["group_by"] = ag.groupRaw
			f["group_value"] = g
		}
		if st.obsTrunc {
			f["truncated"] = true
		}
		detail := fmt.Sprintf("Sigma aggregation matched: %s — %s within %s",
			st.rule.title, ag.describe(g, metric), ag.timeframe)
		out = append(out, Record{
			Fields: f,
			Findings: []Finding{{
				Rule:       "sigma." + st.rule.id,
				Severity:   st.rule.level,
				Technique:  st.rule.technique,
				Confidence: st.rule.conf,
				Detail:     detail,
			}},
		})
	}
	return out
}

// metric computes the scalar aggregation's value for one group. ok is false for
// a group with no numeric observations under min/max/avg/sum, so an empty group
// never fires.
func (st *aggState) metric(group string) (float64, bool) {
	switch st.rule.agg.fn {
	case "count":
		if st.rule.agg.field != "" {
			return float64(len(st.distinct[group])), true
		}
		return float64(st.counts[group]), true
	case "sum":
		if st.numN[group] == 0 {
			return 0, false
		}
		return st.numSum[group], true
	case "min":
		if st.numN[group] == 0 {
			return 0, false
		}
		return st.numMin[group], true
	case "max":
		if st.numN[group] == 0 {
			return 0, false
		}
		return st.numMax[group], true
	case "avg":
		if st.numN[group] == 0 {
			return 0, false
		}
		return st.numSum[group] / float64(st.numN[group]), true
	}
	return 0, false
}

// flushNear evaluates a temporal "near" rule: it fires once if there is a
// timeframe-wide window in which the referenced selections co-occur such that
// the rule's expression (the part before the pipe, AND the near expression)
// holds, each selection counting as true when it has a match inside the window.
func (st *aggState) flushNear() []Record {
	type stamp struct {
		t   time.Time
		sel string
	}
	var stamps []stamp
	for sel, ts := range st.nearTimes {
		for _, t := range ts {
			stamps = append(stamps, stamp{t, sel})
		}
	}
	if len(stamps) == 0 {
		return nil
	}
	sort.Slice(stamps, func(i, j int) bool { return stamps[i].t.Before(stamps[j].t) })

	win := map[string]int{}
	left := 0
	satisfied := false
	for right := 0; right < len(stamps) && !satisfied; right++ {
		win[stamps[right].sel]++
		for stamps[right].t.Sub(stamps[left].t) > st.rule.agg.timeframe {
			win[stamps[left].sel]--
			if win[stamps[left].sel] == 0 {
				delete(win, stamps[left].sel)
			}
			left++
		}
		satisfied = st.rule.evalNear(win)
	}
	if !satisfied {
		return nil
	}

	names := make([]string, 0, len(st.rule.searches))
	for n := range st.rule.searches {
		names = append(names, n)
	}
	sort.Strings(names)
	f := map[string]any{
		"sigma_aggregation": true,
		"sigma_temporal":    true,
		"rule":              "sigma." + st.rule.id,
		"timeframe":         st.rule.agg.timeframe.String(),
	}
	if st.nearTrunc {
		f["truncated"] = true
	}
	return []Record{{
		Fields: f,
		Findings: []Finding{{
			Rule:       "sigma." + st.rule.id,
			Severity:   st.rule.level,
			Technique:  st.rule.technique,
			Confidence: st.rule.conf,
			Detail: fmt.Sprintf("Sigma temporal match: %s — %s within %s",
				st.rule.title, strings.Join(names, ", "), st.rule.agg.timeframe),
		}},
	}}
}

// evalNear evaluates the rule's expression and its near expression treating a
// selection as true when it has at least one match in the current window.
func (r *sigmaRule) evalNear(win map[string]int) bool {
	ctx := &condCtx{matched: make(map[string]bool, len(r.searches)), names: make([]string, 0, len(r.searches))}
	for name := range r.searches {
		ctx.matched[name] = win[name] > 0
		ctx.names = append(ctx.names, name)
	}
	return r.cond.eval(ctx) && r.agg.nearCond.eval(ctx)
}

// cleanMetric renders an aggregation metric as an int when it is whole (counts,
// sums of integers) and a float otherwise (a fractional average), for clean JSON.
func cleanMetric(f float64) any {
	if i := int64(f); float64(i) == f {
		return i
	}
	return f
}

func aggSatisfied(op string, metric, threshold float64) bool {
	switch op {
	case ">":
		return metric > threshold
	case ">=":
		return metric >= threshold
	case "<":
		return metric < threshold
	case "<=":
		return metric <= threshold
	case "==", "=":
		return metric == threshold
	}
	return false
}

func (ag *aggregation) describe(group string, metric float64) string {
	var subject string
	switch ag.fn {
	case "count":
		if ag.fieldRaw != "" {
			subject = fmt.Sprintf("%g distinct %s", metric, ag.fieldRaw)
		} else {
			subject = fmt.Sprintf("%g events", metric)
		}
	default: // min/max/avg/sum
		subject = fmt.Sprintf("%s(%s)=%g", ag.fn, ag.fieldRaw, metric)
	}
	s := fmt.Sprintf("%s %s %g", subject, ag.op, ag.threshold)
	if ag.groupBy != "" {
		s += fmt.Sprintf(" for %s=%q", ag.groupRaw, group)
	}
	return s
}

// sigmaFields renders an event as a lower-cased field map for Sigma matching:
// the common System fields under their Sigma names, plus every EventData and
// UserData value.
func (ev winEvent) sigmaFields() map[string]string {
	f := map[string]string{}
	put := func(k, v string) {
		if v != "" {
			f[strings.ToLower(k)] = v
		}
	}
	put("EventID", strconv.Itoa(ev.EventID))
	put("Channel", ev.Channel)
	put("Provider_Name", ev.Provider)
	put("Provider", ev.Provider)
	put("Computer", ev.Computer)
	if ev.Level != 0 {
		put("Level", strconv.Itoa(ev.Level))
	}
	if ev.Task != 0 {
		put("Task", strconv.Itoa(ev.Task))
	}
	put("SecurityUserID", ev.SecurityUser)
	if ev.ProcessID != 0 {
		put("ProcessId", strconv.Itoa(ev.ProcessID))
	}
	if ev.ThreadID != 0 {
		put("ThreadId", strconv.Itoa(ev.ThreadID))
	}
	for k, v := range ev.Data {
		put(k, v)
	}
	for k, v := range ev.UserData {
		put(k, v)
	}
	return f
}

// LoadSigmaSpec compiles a comma-separated spec of rule sources, merged into
// one ruleset. Each entry is either "builtin" (the embedded starter pack) or a
// .yml/.yaml file or directory path — so "-sigma builtin", "-sigma ./rules",
// and "-sigma builtin,./rules" all work. Rules using unsupported constructs are
// recorded in Skipped and files that don't parse in Failed; an error is
// returned only when a named source can't be read or holds no rules.
func LoadSigmaSpec(spec string) (*SigmaRuleset, error) {
	rs := &SigmaRuleset{}
	seen := false
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		seen = true
		if strings.EqualFold(entry, "builtin") {
			if err := rs.loadBuiltinInto(); err != nil {
				return nil, err
			}
			continue
		}
		if err := rs.loadPathInto(entry); err != nil {
			return nil, err
		}
	}
	if !seen {
		return nil, errors.New("sigma: empty rule spec")
	}
	return rs, nil
}

// LoadSigmaRules compiles the rules at a single path (a .yml/.yaml file or a
// directory searched recursively).
func LoadSigmaRules(path string) (*SigmaRuleset, error) {
	rs := &SigmaRuleset{}
	if err := rs.loadPathInto(path); err != nil {
		return nil, err
	}
	return rs, nil
}

// LoadBuiltinSigmaRules compiles the embedded starter pack.
func LoadBuiltinSigmaRules() (*SigmaRuleset, error) {
	rs := &SigmaRuleset{}
	if err := rs.loadBuiltinInto(); err != nil {
		return nil, err
	}
	return rs, nil
}

func (rs *SigmaRuleset) loadPathInto(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	var files []string
	if info.IsDir() {
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".yml", ".yaml":
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		if len(files) == 0 {
			return fmt.Errorf("sigma: no .yml/.yaml rules under %s", path)
		}
	} else {
		files = []string{path}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			rs.Failed = append(rs.Failed, filepath.Base(file)+": "+err.Error())
			continue
		}
		rs.compileFile(filepath.Base(file), data)
	}
	return nil
}

func (rs *SigmaRuleset) loadBuiltinInto() error {
	entries, err := builtinSigmaFS.ReadDir("sigmarules")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		data, err := builtinSigmaFS.ReadFile("sigmarules/" + n)
		if err != nil {
			rs.Failed = append(rs.Failed, n+": "+err.Error())
			continue
		}
		rs.compileFile("builtin:"+n, data)
	}
	return nil
}

// compileFile parses one rule file's bytes and merges its rules, skips and
// failures into rs.
func (rs *SigmaRuleset) compileFile(name string, data []byte) {
	docs, err := parseYAMLDocuments(data)
	if err != nil {
		rs.Failed = append(rs.Failed, name+": "+err.Error())
		return
	}
	for _, doc := range docs {
		r, reason := compileSigmaRule(doc)
		switch {
		case reason != "":
			rs.Skipped = append(rs.Skipped, sigmaName(doc)+" ("+name+"): "+reason)
		case r != nil:
			rs.rules = append(rs.rules, r)
			rs.Loaded++
		}
	}
}

func sigmaName(doc *yamlNode) string {
	if t := doc.get("title").scalar(); t != "" {
		return t
	}
	if id := doc.get("id").scalar(); id != "" {
		return id
	}
	return "(untitled)"
}

// compileSigmaRule turns one YAML document into a rule, or returns a non-empty
// reason to skip it.
func compileSigmaRule(doc *yamlNode) (*sigmaRule, string) {
	if doc == nil || doc.Kind != yamlMap {
		return nil, "not a mapping"
	}
	detection := doc.get("detection")
	if detection == nil || detection.Kind != yamlMap {
		return nil, "no detection block"
	}
	condNodeRaw := detection.get("condition")
	if condNodeRaw == nil {
		return nil, "no condition"
	}
	var condStr string
	if condNodeRaw.Kind == yamlSeq {
		var parts []string
		for _, it := range condNodeRaw.Seq {
			parts = append(parts, "("+it.scalar()+")")
		}
		condStr = strings.Join(parts, " or ")
	} else {
		condStr = condNodeRaw.scalar()
	}

	searches := map[string]*sigmaSearch{}
	for _, key := range detection.Keys {
		if key == "condition" || key == "timeframe" {
			continue
		}
		s, reason := compileSearch(detection.Map[key])
		if reason != "" {
			return nil, reason
		}
		searches[key] = s
	}
	if len(searches) == 0 {
		return nil, "detection has no search identifiers"
	}

	// A "| count() ... " aggregation may follow the search expression.
	exprStr, aggStr := splitAggregation(condStr)
	cond, err := parseCondition(exprStr)
	if err != nil {
		return nil, err.Error()
	}
	if reason := validateCondIdents(cond, searches); reason != "" {
		return nil, reason
	}
	var agg *aggregation
	if aggStr != "" {
		a, reason := parseAggregation(aggStr, searches, detection.get("timeframe").scalar())
		if reason != "" {
			return nil, reason
		}
		agg = a
	}
	// The near window sweep checks maximal windows, which is exact only for
	// monotone conditions; a "not" can be satisfied by a smaller window the
	// sweep skips, so a near rule using negation is skipped rather than
	// mis-evaluated.
	if agg != nil && agg.fn == "near" && (condHasNot(cond) || condHasNot(agg.nearCond)) {
		return nil, "near does not support 'not' (its window check assumes monotone conditions)"
	}

	level, conf := sigmaLevel(doc.get("level").scalar())
	title := doc.get("title").scalar()
	id := slug(title)
	if id == "" {
		id = slug(doc.get("id").scalar())
	}
	if id == "" {
		id = "unnamed"
	}
	return &sigmaRule{
		id:        id,
		title:     firstNonEmpty(title, doc.get("id").scalar(), "(untitled)"),
		level:     level,
		conf:      conf,
		technique: sigmaTechnique(doc.get("tags")),
		logFilter: compileLogFilter(doc.get("logsource")),
		searches:  searches,
		cond:      cond,
		agg:       agg,
	}, ""
}

// splitAggregation splits a condition on its top-level aggregation pipe into the
// search expression and the aggregation clause (empty if there is none).
func splitAggregation(s string) (expr, agg string) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
			}
		}
	}
	return s, ""
}

// aggRe parses "count([field]) [by group] op number". Only count() is
// supported; other functions and the temporal "near" are rejected by the
// caller so the rule is skipped rather than mis-evaluated.
var aggRe = regexp.MustCompile(`^\s*([a-zA-Z]+)\s*\(\s*([A-Za-z0-9_.\-]*)\s*\)\s*(?:by\s+([A-Za-z0-9_.\-]+)\s+)?(>=|<=|==|=|>|<)\s*([0-9]+(?:\.[0-9]+)?)\s*$`)

func parseAggregation(s string, searches map[string]*sigmaSearch, timeframe string) (*aggregation, string) {
	if isNearAgg(s) {
		return parseNear(s, searches, timeframe)
	}
	m := aggRe.FindStringSubmatch(s)
	if m == nil {
		return nil, "unsupported aggregation condition: " + s
	}
	fn := strings.ToLower(m[1])
	switch fn {
	case "count", "min", "max", "avg", "sum":
	default:
		return nil, "unsupported aggregation function: " + m[1] + "()"
	}
	if fn != "count" && m[2] == "" {
		return nil, fn + "() needs a field"
	}
	threshold, err := strconv.ParseFloat(m[5], 64)
	if err != nil {
		return nil, "bad aggregation threshold: " + m[5]
	}
	// A detection "timeframe:" turns a scalar aggregation into a sliding window.
	// It is only sound for the monotone, non-decreasing metrics (count, distinct
	// count, sum) with ">"/">=" — "at least N within the window". min/max would
	// collapse to the whole-run value, and "<"/"<="/"==" are trivially satisfied
	// by a small window, so those are skipped rather than mis-scored.
	var tf time.Duration
	if timeframe != "" {
		d, ok := parseTimeframe(timeframe)
		if !ok {
			return nil, "unsupported timeframe: " + timeframe
		}
		if fn != "count" && fn != "sum" {
			return nil, "timeframe is only supported with count() or sum(), not " + fn + "()"
		}
		if m[4] != ">" && m[4] != ">=" {
			return nil, "timeframe is only supported with the > and >= operators, not " + m[4]
		}
		tf = d
	}
	return &aggregation{
		fn:        fn,
		field:     strings.ToLower(m[2]),
		fieldRaw:  m[2],
		groupBy:   strings.ToLower(m[3]),
		groupRaw:  m[3],
		op:        m[4],
		threshold: threshold,
		timeframe: tf,
	}, ""
}

func isNearAgg(s string) bool {
	ls := strings.ToLower(strings.TrimSpace(s))
	return ls == "near" || strings.HasPrefix(ls, "near ")
}

// parseNear compiles a temporal "near <expr>" aggregation: the expression names
// the selections that must co-occur, and detection's "timeframe:" sets the
// window they must fall within. A near with no timeframe is skipped (it has no
// defined window), as is one whose expression names an unknown selection.
func parseNear(s string, searches map[string]*sigmaSearch, timeframe string) (*aggregation, string) {
	rest := strings.TrimSpace(strings.TrimSpace(s)[len("near"):])
	if rest == "" {
		return nil, "near needs a temporal expression"
	}
	if timeframe == "" {
		return nil, "near requires a timeframe"
	}
	d, ok := parseTimeframe(timeframe)
	if !ok {
		return nil, "unsupported timeframe: " + timeframe
	}
	cond, err := parseCondition(rest)
	if err != nil {
		return nil, err.Error()
	}
	if reason := validateCondIdents(cond, searches); reason != "" {
		return nil, reason
	}
	return &aggregation{fn: "near", nearCond: cond, timeframe: d}, ""
}

// parseTimeframe parses a Sigma timeframe like "30s", "15m", "2h" or "7d".
func parseTimeframe(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, false
	}
	switch s[len(s)-1] {
	case 's':
		return time.Duration(n) * time.Second, true
	case 'm':
		return time.Duration(n) * time.Minute, true
	case 'h':
		return time.Duration(n) * time.Hour, true
	case 'd':
		return time.Duration(n) * 24 * time.Hour, true
	}
	return 0, false
}

func compileSearch(node *yamlNode) (*sigmaSearch, string) {
	if node == nil {
		return nil, "empty search"
	}
	s := &sigmaSearch{}
	switch node.Kind {
	case yamlMap:
		g, reason := compileFieldGroup(node)
		if reason != "" {
			return nil, reason
		}
		s.groups = append(s.groups, g)
	case yamlScalar:
		m, err := compileStringMatcher(node.Str, opContains, false, false)
		if err != nil {
			return nil, err.Error()
		}
		s.keywords = append(s.keywords, m)
	case yamlSeq:
		allScalar, allMap := true, true
		for _, it := range node.Seq {
			if it.Kind != yamlScalar {
				allScalar = false
			}
			if it.Kind != yamlMap {
				allMap = false
			}
		}
		switch {
		case allScalar:
			for _, it := range node.Seq {
				if it.Null {
					continue
				}
				m, err := compileStringMatcher(it.Str, opContains, false, false)
				if err != nil {
					return nil, err.Error()
				}
				s.keywords = append(s.keywords, m)
			}
		case allMap:
			for _, it := range node.Seq {
				g, reason := compileFieldGroup(it)
				if reason != "" {
					return nil, reason
				}
				s.groups = append(s.groups, g)
			}
		default:
			return nil, "unsupported mixed selection list"
		}
	}
	return s, ""
}

func compileFieldGroup(m *yamlNode) (fieldGroup, string) {
	var g fieldGroup
	for _, key := range m.Keys {
		fm, reason := compileFieldMatch(key, m.Map[key])
		if reason != "" {
			return nil, reason
		}
		g = append(g, fm)
	}
	return g, ""
}

func compileFieldMatch(key string, val *yamlNode) (fieldMatch, string) {
	parts := strings.Split(key, "|")
	fm := fieldMatch{field: strings.ToLower(strings.TrimSpace(parts[0]))}

	op := opEquals
	cased := false
	exists := false
	windash := false
	b64 := false
	cidr := false
	fieldref := false
	for _, mod := range parts[1:] {
		switch strings.ToLower(strings.TrimSpace(mod)) {
		case "contains":
			op = opContains
		case "startswith":
			op = opStartsWith
		case "endswith":
			op = opEndsWith
		case "re":
			op = opRegex
		case "cased":
			cased = true
		case "all":
			fm.all = true
		case "exists":
			exists = true
		case "windash":
			windash = true
		case "base64offset":
			b64 = true
		case "cidr":
			cidr = true
		case "fieldref":
			fieldref = true
		case "lt":
			op = opLt
		case "lte":
			op = opLte
		case "gt":
			op = opGt
		case "gte":
			op = opGte
		default:
			return fm, "unsupported modifier |" + mod
		}
	}

	if exists {
		b := sigmaBool(val.scalar())
		fm.exists = &b
		return fm, ""
	}

	// Gather the value(s).
	var raw []string
	switch {
	case val == nil || (val.Kind == yamlScalar && val.Null):
		fm.null = true
		return fm, ""
	case val.Kind == yamlScalar:
		raw = []string{val.Str}
	case val.Kind == yamlSeq:
		for _, it := range val.Seq {
			if it.Kind != yamlScalar {
				return fm, "unsupported non-scalar in a value list"
			}
			raw = append(raw, it.Str)
		}
	default:
		return fm, "unsupported value type"
	}

	// cidr: each value is a CIDR network (or a bare IP, taken as a host route);
	// the field value is matched as an IP falling inside it. The values are OR'd
	// (AND with |all), like any other value list.
	if cidr {
		if op != opEquals || windash || b64 || fieldref {
			return fm, "|cidr cannot combine with another value modifier"
		}
		for _, v := range raw {
			p, reason := parseCIDR(v)
			if reason != "" {
				return fm, reason
			}
			fm.matchers = append(fm.matchers, valueMatcher{op: opCIDR, prefix: p})
		}
		return fm, ""
	}

	// fieldref: compare this field to another field's value. It may pair with a
	// string operator (|fieldref|contains, …) and |cased, but not with regex,
	// numeric, windash or base64offset.
	if fieldref {
		switch op {
		case opEquals, opContains, opStartsWith, opEndsWith:
		default:
			return fm, "|fieldref supports only an equals/contains/startswith/endswith comparison"
		}
		if windash || b64 {
			return fm, "|fieldref cannot combine with |windash or |base64offset"
		}
		for _, v := range raw {
			ref := strings.ToLower(strings.TrimSpace(v))
			if ref == "" {
				return fm, "|fieldref needs a field name"
			}
			fm.matchers = append(fm.matchers, valueMatcher{op: opFieldRef, cased: cased, refField: ref, refOp: op})
		}
		return fm, ""
	}

	// base64offset: match the value as it would appear base64-encoded at any of
	// the three byte alignments. It is a substring (contains) match on the
	// case-sensitive encoded form; the three offsets are OR'd.
	if b64 {
		if fm.all {
			return fm, "|base64offset cannot combine with |all"
		}
		for _, v := range raw {
			if hasWildcard(v) {
				return fm, "|base64offset cannot combine with wildcards"
			}
			for _, enc := range base64OffsetVariants(v) {
				fm.matchers = append(fm.matchers, valueMatcher{op: opContains, cased: true, literal: enc})
			}
		}
		return fm, ""
	}

	for _, v := range raw {
		switch op {
		case opGt, opGte, opLt, opLte:
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return fm, "non-numeric value for a numeric modifier"
			}
			fm.matchers = append(fm.matchers, valueMatcher{op: op, num: n})
		default:
			m, err := compileStringMatcher(v, op, cased, windash)
			if err != nil {
				return fm, err.Error()
			}
			fm.matchers = append(fm.matchers, m)
		}
	}
	return fm, ""
}

// compileStringMatcher builds a matcher for one string value. windash treats
// every '-' and '/' in the value as any Windows command-line dash variant
// (-, /, en/em dash, horizontal bar).
func compileStringMatcher(value string, op matchOp, cased, windash bool) (valueMatcher, error) {
	if op == opRegex {
		re, err := regexp.Compile(value)
		if err != nil {
			return valueMatcher{}, fmt.Errorf("bad regex %q", value)
		}
		return valueMatcher{op: opRegex, re: re, cased: cased}, nil
	}
	if hasWildcard(value) || windash {
		re, err := patternRegex(value, op, cased, windash)
		if err != nil {
			return valueMatcher{}, fmt.Errorf("bad pattern %q", value)
		}
		return valueMatcher{op: op, re: re, cased: cased}, nil
	}
	lit := unescapeWildcards(value)
	if !cased {
		lit = strings.ToLower(lit)
	}
	return valueMatcher{op: op, literal: lit, cased: cased}, nil
}

// base64OffsetVariants returns the value's base64 encoding as it appears at each
// of the three byte alignments (offset 0/1/2), trimmed to the alignment-stable
// core — matching the SigmaHQ base64offset modifier.
func base64OffsetVariants(s string) []string {
	b := []byte(s)
	starts := [3]int{0, 2, 3}
	trimEnd := [3]int{0, 3, 2}
	var out []string
	for i := 0; i < 3; i++ {
		data := append(bytes.Repeat([]byte(" "), i), b...)
		enc := base64.StdEncoding.EncodeToString(data)
		start, end := starts[i], len(enc)-trimEnd[i]
		if start < end && start >= 0 && end <= len(enc) {
			out = append(out, enc[start:end])
		}
	}
	return out
}

// parseCIDR parses a Sigma |cidr value: a CIDR network like "10.0.0.0/8", or a
// bare IP taken as a host route (/32 or /128). The prefix is returned masked so
// Prefix.Contains is canonical.
func parseCIDR(v string) (netip.Prefix, string) {
	v = strings.TrimSpace(v)
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Masked(), ""
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), ""
	}
	return netip.Prefix{}, "bad CIDR " + v
}

func hasWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '*' || s[i] == '?' {
			return true
		}
	}
	return false
}

func unescapeWildcards(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if n := s[i+1]; n == '*' || n == '?' || n == '\\' {
				b.WriteByte(n)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func patternRegex(value string, op matchOp, cased, windash bool) (*regexp.Regexp, error) {
	var b strings.Builder
	if !cased {
		b.WriteString("(?i)")
	}
	if op == opEquals || op == opStartsWith {
		b.WriteString("^")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\\' && i+1 < len(value) {
			n := value[i+1]
			if n == '*' || n == '?' || n == '\\' {
				b.WriteString(regexp.QuoteMeta(string(n)))
				i++
				continue
			}
		}
		switch {
		case c == '*':
			b.WriteString(".*")
		case c == '?':
			b.WriteString(".")
		case windash && (c == '-' || c == '/'):
			b.WriteString(`[-/\x{2013}\x{2014}\x{2015}]`) // -, /, en dash, em dash, horizontal bar
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if op == opEquals || op == opEndsWith {
		b.WriteString("$")
	}
	return regexp.Compile(b.String())
}

func sigmaBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1":
		return true
	}
	return false
}

func sigmaLevel(s string) (Severity, int) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical, 90
	case "high":
		return SevSuspect, 75
	case "medium":
		return SevSuspect, 60
	case "low":
		return SevNotable, 40
	case "informational", "info":
		return SevInfo, 25
	}
	return SevNotable, 40
}

func sigmaTechnique(tags *yamlNode) string {
	if tags == nil || tags.Kind != yamlSeq {
		return ""
	}
	for _, t := range tags.Seq {
		s := strings.ToLower(t.scalar())
		if strings.HasPrefix(s, "attack.t") {
			return strings.ToUpper(strings.TrimPrefix(s, "attack."))
		}
	}
	return ""
}

func slug(s string) string {
	var b strings.Builder
	under := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			under = false
		} else if !under {
			b.WriteByte('_')
			under = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// ---- logsource → event predicate ----

func compileLogFilter(ls *yamlNode) func(winEvent) bool {
	if ls == nil || ls.Kind != yamlMap {
		return nil
	}
	chanPred := serviceChannelPred(strings.ToLower(ls.get("service").scalar()))
	catPred := categoryPred(strings.ToLower(ls.get("category").scalar()))
	if chanPred == nil && catPred == nil {
		return nil // unmapped: try against every event
	}
	return func(ev winEvent) bool {
		if chanPred != nil && !chanPred(ev) {
			return false
		}
		if catPred != nil && !catPred(ev) {
			return false
		}
		return true
	}
}

func channelContains(sub string) func(winEvent) bool {
	return func(ev winEvent) bool { return strings.Contains(strings.ToLower(ev.Channel), sub) }
}

func serviceChannelPred(service string) func(winEvent) bool {
	switch service {
	case "":
		return nil
	case "security":
		return channelContains("security")
	case "system":
		return channelContains("system")
	case "application":
		return channelContains("application")
	case "powershell":
		return channelContains("powershell/operational")
	case "powershell-classic":
		return channelContains("windows powershell")
	case "sysmon":
		return channelContains("sysmon")
	case "taskscheduler":
		return channelContains("taskscheduler")
	case "wmi":
		return channelContains("wmi-activity")
	case "windefend":
		return channelContains("defender")
	case "terminalservices-localsessionmanager", "terminalservices-remoteconnectionmanager":
		return channelContains("terminalservices")
	}
	return nil // unknown service: don't narrow
}

func categoryPred(category string) func(winEvent) bool {
	eid := func(ids ...int) func(winEvent) bool {
		set := map[int]bool{}
		for _, i := range ids {
			set[i] = true
		}
		return func(ev winEvent) bool { return set[ev.EventID] }
	}
	switch category {
	case "":
		return nil
	case "process_creation":
		return eid(4688, 1)
	case "network_connection":
		return eid(3, 5156)
	case "image_load":
		return eid(7)
	case "pipe_created":
		return eid(17, 18)
	case "registry_set", "registry_add", "registry_event", "registry_delete":
		return eid(12, 13, 14)
	case "ps_script":
		return eid(4104)
	case "ps_module":
		return eid(4103)
	}
	return nil // unknown category: don't narrow
}

// ---- condition parser ----

type condCtx struct {
	matched map[string]bool
	names   []string
}

type condNode interface{ eval(*condCtx) bool }

type condIdent struct{ name string }
type condNot struct{ x condNode }
type condAnd struct{ a, b condNode }
type condOr struct{ a, b condNode }
type condQuant struct {
	min     int
	all     bool
	pattern string // "them" or an identifier, possibly ending in '*'
}

func (n condIdent) eval(c *condCtx) bool { return c.matched[n.name] }
func (n condNot) eval(c *condCtx) bool   { return !n.x.eval(c) }
func (n condAnd) eval(c *condCtx) bool   { return n.a.eval(c) && n.b.eval(c) }
func (n condOr) eval(c *condCtx) bool    { return n.a.eval(c) || n.b.eval(c) }

func (n condQuant) eval(c *condCtx) bool {
	var names []string
	if n.pattern == "them" || n.pattern == "*" {
		names = c.names
	} else {
		for _, name := range c.names {
			if matchIdentPattern(name, n.pattern) {
				names = append(names, name)
			}
		}
	}
	trues := 0
	for _, name := range names {
		if c.matched[name] {
			trues++
		}
	}
	if n.all {
		return len(names) > 0 && trues == len(names)
	}
	min := n.min
	if min < 1 {
		min = 1
	}
	return trues >= min
}

// condHasNot reports whether a condition tree contains a negation, which makes
// it non-monotone (and so unsafe for the near window sweep).
func condHasNot(n condNode) bool {
	switch c := n.(type) {
	case condNot:
		return true
	case condAnd:
		return condHasNot(c.a) || condHasNot(c.b)
	case condOr:
		return condHasNot(c.a) || condHasNot(c.b)
	}
	return false
}

func matchIdentPattern(name, pattern string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return name == pattern
}

func parseCondition(s string) (condNode, error) {
	toks := tokenizeCond(s)
	if len(toks) == 0 {
		return nil, errors.New("sigma: empty condition")
	}
	p := &condParser{toks: toks}
	n, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("sigma: unexpected %q in condition", p.toks[p.pos])
	}
	return n, nil
}

func tokenizeCond(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(' || r == ')':
			flush()
			toks = append(toks, string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

type condParser struct {
	toks []string
	pos  int
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) peekAt(n int) string {
	if p.pos+n < len(p.toks) {
		return p.toks[p.pos+n]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func kw(t, k string) bool { return strings.EqualFold(t, k) }

func (p *condParser) parseExpr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for kw(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = condOr{left, right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for kw(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = condAnd{left, right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if kw(p.peek(), "not") {
		p.next()
		x, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return condNot{x}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (condNode, error) {
	t := p.peek()
	if t == "" {
		return nil, errors.New("sigma: unexpected end of condition")
	}
	if t == "(" {
		p.next()
		x, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, errors.New("sigma: missing ')'")
		}
		return x, nil
	}
	if (kw(t, "all") || isNumber(t)) && kw(p.peekAt(1), "of") {
		count := p.next()
		p.next() // "of"
		target := p.next()
		if target == "" {
			return nil, errors.New("sigma: 'of' needs a target")
		}
		q := condQuant{pattern: target}
		if kw(target, "them") {
			q.pattern = "them"
		}
		if kw(count, "all") {
			q.all = true
		} else {
			q.min, _ = strconv.Atoi(count)
		}
		return q, nil
	}
	if kw(t, "and") || kw(t, "or") || kw(t, "not") || kw(t, "of") || kw(t, "them") || t == ")" {
		return nil, fmt.Errorf("sigma: unexpected %q in condition", t)
	}
	p.next()
	return condIdent{name: t}, nil
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// validateCondIdents rejects a condition that names a search identifier the
// detection doesn't define (a typo, or a construct we don't support), so the
// rule is skipped rather than silently never matching.
func validateCondIdents(n condNode, searches map[string]*sigmaSearch) string {
	switch c := n.(type) {
	case condIdent:
		if _, ok := searches[c.name]; !ok {
			return "condition references unknown search " + c.name
		}
	case condNot:
		return validateCondIdents(c.x, searches)
	case condAnd:
		if r := validateCondIdents(c.a, searches); r != "" {
			return r
		}
		return validateCondIdents(c.b, searches)
	case condOr:
		if r := validateCondIdents(c.a, searches); r != "" {
			return r
		}
		return validateCondIdents(c.b, searches)
	case condQuant:
		if c.pattern != "them" && c.pattern != "*" {
			found := false
			for name := range searches {
				if matchIdentPattern(name, c.pattern) {
					found = true
					break
				}
			}
			if !found {
				return "condition pattern " + c.pattern + " matches no search"
			}
		}
	}
	return ""
}
