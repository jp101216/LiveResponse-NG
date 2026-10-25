package collector

import (
	"testing"
	"time"
)

func TestBuildTimelineMergesAndSorts(t *testing.T) {
	t1 := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC)
	t3 := time.Date(2026, 10, 3, 10, 0, 0, 0, time.UTC)
	results := []Result{
		{Collector: "prefetch", Records: []Record{
			{Fields: map[string]any{"executable": "EVIL.EXE", "last_run": t3, "run_times": []time.Time{t3, t1}}},
		}},
		{Collector: "eventlog", Records: []Record{
			{
				Fields:   map[string]any{"event_id": 7045, "provider": "Service Control Manager", "time_created": t2},
				Findings: []Finding{{Rule: "eventlog.service_installed", Severity: SevSuspect, Confidence: 70, Detail: "x"}},
			},
		}},
		{Collector: "localaccounts", Records: []Record{
			{Fields: map[string]any{"name": "svc", "last_logon": time.Time{}}}, // zero time → skipped
		}},
	}

	tl := BuildTimeline(results)
	if tl.Collector != "timeline" {
		t.Fatalf("collector = %q", tl.Collector)
	}
	// prefetch: last_run (t3) + run_times (t3, t1) = 3; eventlog: time_created (t2) = 1; zero skipped.
	if len(tl.Records) != 4 {
		t.Fatalf("entries = %d, want 4", len(tl.Records))
	}
	first := tl.Records[0].Fields["time"].(time.Time)
	last := tl.Records[len(tl.Records)-1].Fields["time"].(time.Time)
	if !first.Equal(t1) {
		t.Errorf("first entry = %v, want %v", first, t1)
	}
	if !last.Equal(t3) {
		t.Errorf("last entry = %v, want %v", last, t3)
	}

	var sawEventlog bool
	for _, r := range tl.Records {
		if r.Fields["source"] == "eventlog" {
			sawEventlog = true
			if r.Fields["has_finding"] != true || r.Fields["top_rule"] != "eventlog.service_installed" {
				t.Errorf("eventlog entry should flag its finding: %+v", r.Fields)
			}
			if r.Fields["artifact"] != "time_created" {
				t.Errorf("eventlog artifact = %v", r.Fields["artifact"])
			}
		}
	}
	if !sawEventlog {
		t.Error("no eventlog entry on the timeline")
	}
	if bs, ok := tl.Meta["by_source"].(map[string]int); !ok || bs["prefetch"] != 3 || bs["eventlog"] != 1 {
		t.Errorf("by_source = %v", tl.Meta["by_source"])
	}
}

func TestBuildTimelineSkipsTimelineAndOutOfRange(t *testing.T) {
	future := time.Now().UTC().AddDate(5, 0, 0)
	ancient := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC) // FILETIME epoch: a null time
	results := []Result{
		{Collector: "x", Records: []Record{
			{Fields: map[string]any{"a": future, "b": ancient, "c": time.Now().UTC().Add(-time.Hour)}},
		}},
		{Collector: "timeline", Records: []Record{ // a prior timeline result must be ignored
			{Fields: map[string]any{"time": time.Now().UTC()}},
		}},
	}
	tl := BuildTimeline(results)
	if len(tl.Records) != 1 {
		t.Fatalf("entries = %d, want 1 (only the in-range value)", len(tl.Records))
	}
	if tl.Records[0].Fields["artifact"] != "c" {
		t.Errorf("artifact = %v, want c", tl.Records[0].Fields["artifact"])
	}
}
