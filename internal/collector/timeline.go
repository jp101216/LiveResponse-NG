package collector

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// timeline.go — a unified super-timeline: every timestamped artifact the other
// collectors gathered, merged into one chronological view and emitted as a
// synthetic "timeline" collector result. Each collector sees one slice of the
// host at one set of times — a prefetch run, a service key's last write, a
// scheduled task's cache write, an account's last logon, an event's creation.
// Pulled onto one timeline they read as a sequence: what ran, what was
// installed, what changed, in order.
//
// No build tag: it works on the structured results (before serialisation, where
// timestamps are still time.Time), so it is portable and unit-tested. It is a
// post-pass, invoked after Correlate, so an entry whose source record carries a
// finding is flagged in time. Entries carry no findings of their own, so the
// report's finding counts are not inflated by the timeline view.

// timelineMax bounds the entries kept (the most recent beyond it are kept and
// the rest dropped, with truncation noted in meta).
const timelineMax = 100000

// timelineSkipFields are record fields that hold a derived/annotation time
// rather than an independent artifact timestamp, so the timeline ignores them
// (they would just duplicate the entry they describe).
var timelineSkipFields = map[string]bool{
	"surviving_earliest": true,
	"surviving_latest":   true,
}

type timelineEntry struct {
	t         time.Time
	collector string
	artifact  string // the field the timestamp came from (run_times, key_last_write, ...)
	detail    string
	recordIdx int
	topRule   string
	topSev    Severity
}

// BuildTimeline merges the timestamped artifacts across results into one sorted
// Result. It skips the timeline result itself and times outside a sane window.
func BuildTimeline(results []Result) Result {
	res := NewResult("timeline")
	res.SetMeta("note", "every timestamped artifact from the other collectors, merged and sorted oldest-first; "+
		"each entry names its source collector, the artifact timestamp, and points back to the source record")

	floor := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	ceil := time.Now().UTC().AddDate(1, 0, 0)

	var entries []timelineEntry
	bySource := map[string]int{}
	for ri := range results {
		r := &results[ri]
		if r.Collector == "timeline" {
			continue
		}
		for i := range r.Records {
			rec := r.Records[i]
			detail := timelineDetail(rec)
			rule, sev := topFinding(rec)
			add := func(t time.Time, artifact string) {
				t = t.UTC()
				if t.IsZero() || t.Before(floor) || t.After(ceil) {
					return
				}
				entries = append(entries, timelineEntry{
					t: t, collector: r.Collector, artifact: artifact,
					detail: detail, recordIdx: i, topRule: rule, topSev: sev,
				})
				bySource[r.Collector]++
			}
			for _, key := range sortedFieldKeys(rec.Fields) {
				if timelineSkipFields[key] {
					continue // a derived annotation, not an artifact timestamp
				}
				collectTimes(rec.Fields[key], key, add)
			}
		}
	}

	sort.SliceStable(entries, func(a, b int) bool {
		if !entries[a].t.Equal(entries[b].t) {
			return entries[a].t.Before(entries[b].t)
		}
		return entries[a].collector < entries[b].collector
	})

	total := len(entries)
	truncated := false
	if len(entries) > timelineMax {
		entries = entries[len(entries)-timelineMax:] // keep the most recent
		truncated = true
	}
	for _, e := range entries {
		f := map[string]any{
			"time":          e.t,
			"source":        e.collector,
			"artifact":      e.artifact,
			"source_record": e.recordIdx,
		}
		if e.detail != "" {
			f["detail"] = e.detail
		}
		if e.topRule != "" {
			f["has_finding"] = true
			f["top_rule"] = e.topRule
			f["top_severity"] = e.topSev
		}
		res.Add(f)
	}

	res.SetMeta("entries", len(entries))
	res.SetMeta("entries_total", total)
	res.SetMeta("by_source", bySource)
	if truncated {
		res.SetMeta("truncated", true)
		res.SetMeta("truncation_note", "oldest entries dropped; raise the cap or narrow the collectors for the full span")
	}
	return res.Finish()
}

// collectTimes emits the timestamp(s) carried by one field value.
func collectTimes(v any, key string, add func(time.Time, string)) {
	switch x := v.(type) {
	case time.Time:
		add(x, key)
	case []time.Time:
		for _, t := range x {
			add(t, key)
		}
	case string:
		if t, ok := parseEvtxTime(x); ok {
			add(t, key)
		}
	}
}

// timelineDetailKeys are the identifying fields used to label a timeline entry,
// in priority order; the first couple present are joined.
var timelineDetailKeys = []string{
	"name", "executable", "image", "image_path", "path", "file",
	"command_line", "command", "service_name", "provider", "channel",
	"event_id", "target_user_name", "user", "account",
}

func timelineDetail(rec Record) string {
	var parts []string
	for _, k := range timelineDetailKeys {
		if v, ok := rec.Fields[k]; ok {
			s := strings.TrimSpace(fmt.Sprintf("%v", v))
			if s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) >= 2 {
			break
		}
	}
	return excerpt(strings.Join(parts, " · "), 160)
}

// topFinding returns the highest-severity finding on a record (rule id and
// severity), or empty.
func topFinding(rec Record) (string, Severity) {
	var rule string
	var sev Severity
	best := 0
	for _, f := range rec.Findings {
		if r := sevRank(f.Severity); r > best {
			best = r
			rule, sev = f.Rule, f.Severity
		}
	}
	return rule, sev
}

func sortedFieldKeys(f map[string]any) []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
