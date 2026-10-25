package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/sidecar"
)

func TestSelectMemoryTargets(t *testing.T) {
	procs := []procInfo{
		{PID: 400, Name: "evil.exe", Path: `C:\Users\Public\evil.exe`},
		{PID: 4, Name: "System", Kernel: true},
		{PID: 100, Name: "lrng.exe", Path: `E:\tools\lrng.exe`},
		{PID: 300, Name: "lrng-sidecar.exe", Path: `E:\tools\lrng-sidecar.exe`},
		{PID: 200, Name: "notepad.exe", Path: `C:\Windows\notepad.exe`},
	}
	targets, skipped := selectMemoryTargets(procs, nil, 100, []string{`E:\tools\lrng-sidecar.exe`})
	if len(targets) != 2 || targets[0].PID != 200 || targets[1].PID != 400 {
		t.Fatalf("targets %+v", targets)
	}
	reasons := map[int]string{}
	for _, s := range skipped {
		reasons[s.proc.PID] = s.reason
	}
	if reasons[100] != "lrng itself" || !strings.Contains(reasons[4], "kernel") || reasons[300] != "lrng component" {
		t.Fatalf("skips %+v", reasons)
	}

	// -mem-pids restricts the set and reports PIDs that don't exist.
	targets, skipped = selectMemoryTargets(procs, []int{400, 999}, 100, nil)
	if len(targets) != 1 || targets[0].PID != 400 {
		t.Fatalf("targets %+v", targets)
	}
	if len(skipped) != 1 || skipped[0].proc.PID != 999 || skipped[0].reason != "no such process" {
		t.Fatalf("skipped %+v", skipped)
	}
}

func TestMemoryRecordsCoverEveryProcess(t *testing.T) {
	targets := []procInfo{{PID: 20, Name: "a"}, {PID: 30, Name: "b"}, {PID: 40, Name: "c"}}
	skipped := []memSkip{{procInfo{PID: 4, Name: "System"}, "kernel process"}}
	resp := map[int]*sidecar.Response{
		20: {OK: true, Meta: map[string]any{"pid": 20.0, "status": "scanned", "bytes_scanned": 1000.0,
			"unbacked_exec_regions": 2.0, "prompt_verdict": "low",
			"yara": map[string]any{"rules_loaded": 12.0, "matched_rules": 1.0}},
			Hits: []sidecar.Hit{{Rule: "yara:x", Severity: "critical", Offset: 0x7ff60000, Confidence: 90,
				Region: &sidecar.HitRegion{Base: 0x7ff60000, Size: 65536, Protect: "RWX", Kind: "private"}}}},
		30: {OK: false, Error: "pid 30: access denied", Meta: map[string]any{"pid": 30.0, "status": "access_denied"}},
		// 40 never answered (sidecar killed by the collector timeout).
	}
	recs, counts, rules := memoryRecords(targets, skipped, resp)
	if len(recs) != 4 {
		t.Fatalf("want a record per process, got %d", len(recs))
	}
	order := []int{4, 20, 30, 40}
	for i, r := range recs {
		if r.Fields["pid"] != order[i] {
			t.Fatalf("record %d is pid %v, want %d", i, r.Fields["pid"], order[i])
		}
	}
	if recs[1].Fields["status"] != "scanned" || len(recs[1].Findings) != 1 ||
		recs[1].Fields["unbacked_exec_regions"] != 2.0 || recs[1].Fields["prompt_verdict"] != "low" {
		t.Fatalf("scanned record: %+v", recs[1])
	}
	if recs[2].Fields["status"] != "access_denied" || recs[3].Fields["status"] != "not_reached" {
		t.Fatalf("statuses: %v %v", recs[2].Fields["status"], recs[3].Fields["status"])
	}
	if counts["scanned"] != 1 || counts["access_denied"] != 1 || counts["not_reached"] != 1 || counts["skipped"] != 1 {
		t.Fatalf("counts %+v", counts)
	}
	if m := rules.(map[string]any); m["rules_loaded"] != 12.0 || m["matched_rules"] != nil {
		t.Fatalf("rules meta should keep run-wide fields only: %+v", m)
	}
}

func TestHitToFinding(t *testing.T) {
	f := hitToFinding(sidecar.Hit{
		Rule: "yara:cobalt_like", Severity: "bogus", Offset: 0x1f0000, Confidence: 250,
		Context: "ruleset demo | 2 match(es): $a(2)",
		Region:  &sidecar.HitRegion{Base: 0x1f0000, Size: 3 << 20, Protect: "RWX", Kind: "private"},
	})
	if f.Severity != SevSuspect || f.Confidence != 100 {
		t.Fatalf("severity/confidence not sanitised: %+v", f)
	}
	want := "at 0x1f0000 in private RWX region 0x1f0000 (3.0 MiB): ruleset demo"
	if !strings.HasPrefix(f.Detail, want) {
		t.Fatalf("detail %q", f.Detail)
	}
	cond := hitToFinding(sidecar.Hit{Rule: "yara:c", Severity: "notable"})
	if !strings.Contains(cond.Detail, "condition-only") {
		t.Fatalf("detail %q", cond.Detail)
	}
}

func TestMemoryCollectorIsOptInWithOwnTimeout(t *testing.T) {
	for _, c := range Defaults() {
		if c.Name() == "memory" {
			t.Fatal("memory collector must not run by default")
		}
	}
	m := &memoryCollector{}
	m.Configure(RunOptions{Memory: MemoryOptions{Timeout: 7 * time.Minute}})
	if m.Timeout() != 7*time.Minute {
		t.Fatal("timeout override not applied")
	}
}

type slowCollector struct{ d time.Duration }

func (slowCollector) Name() string             { return "slow" }
func (slowCollector) Platforms() []string      { return []string{"all"} }
func (s slowCollector) Timeout() time.Duration { return s.d }
func (slowCollector) Collect(context.Context) (Result, error) {
	time.Sleep(150 * time.Millisecond)
	return Result{}, nil
}

func TestDispatcherHonoursTimeoutOverride(t *testing.T) {
	// Dispatcher-wide 20ms would abandon it; its own 2s override lets it finish.
	res := (&Dispatcher{Timeout: 20 * time.Millisecond, Grace: 10 * time.Millisecond}).
		Run(context.Background(), []Collector{slowCollector{2 * time.Second}})
	if len(res[0].Errors) != 0 {
		t.Fatalf("override ignored: %+v", res[0].Errors)
	}
}
