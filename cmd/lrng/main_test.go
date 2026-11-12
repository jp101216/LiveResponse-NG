package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

// The test binary doubles as a portable sidecar fixture: the client launches
// it with no arguments, including on Windows where a shell script won't run.
func TestMain(m *testing.M) {
	if mode := os.Getenv("LRNG_TEST_MEMSCAN_SIDECAR"); mode != "" {
		if mode != "empty" {
			fmt.Println(`{"op":"scan_memory","ok":true,"meta":{"pid":4242,"status":"scanned"}}`)
		}
		switch mode {
		case "exit":
			os.Exit(7)
		case "malformed":
			fmt.Println("not JSON")
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMemScanPropagatesStreamErrors(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"valid", ""},
		{"exit", "exit status 7"},
		{"malformed", "decode response"},
		{"empty", "no result"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("LRNG_TEST_MEMSCAN_SIDECAR", tc.mode)
			cfg := config.Default()
			cfg.SidecarPath = exe
			cfg.MemBudget = time.Second
			err := doMemScan(context.Background(), cfg, 4242)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	ok := config.Default()
	if err := validate(ok, nil, 0, ""); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		mut  func(*config.Config)
		args []string
		pid  int
		want string
	}{
		{func(c *config.Config) {}, []string{"stray"}, 0, "unexpected argument"},
		{func(c *config.Config) { c.Workers = 0 }, nil, 0, "-workers"},
		{func(c *config.Config) { c.MemWorkers = 0 }, nil, 0, "-mem-workers"},
		{func(c *config.Config) { c.Timeout = -time.Second }, nil, 0, "negative"},
		{func(c *config.Config) { c.Format = "xml" }, nil, 0, "-format"},
		{func(c *config.Config) {}, nil, -4, "-mem-scan"},
		{func(c *config.Config) { c.FailOn = "high" }, nil, 0, "-fail-on"},
		{func(c *config.Config) { c.TraceOnly = true }, nil, 0, "requires -agent-trace"},
		{func(c *config.Config) { c.CloudOnly = true }, nil, 0, "requires -cloud-audit"},
		{func(c *config.Config) { c.CloudOnly = true; c.CloudAudit = "audit.json"; c.Adaptive = true }, nil, 0, "live run"},
		{func(c *config.Config) {
			c.CloudOnly = true
			c.CloudAudit = "audit.json"
			c.Collectors = []string{"processes"}
		}, nil, 0, "cannot be combined"},
		{func(c *config.Config) { c.LLMBurst = 0 }, nil, 0, "-llm-burst"},
		{func(c *config.Config) { c.LLMBurst = 100001 }, nil, 0, "-llm-burst"},
		{func(c *config.Config) { c.TraceOnly = true; c.AgentTrace = "trace.jsonl"; c.Adaptive = true }, nil, 0, "live run"},
		{func(c *config.Config) { c.AdaptiveBudget = 0 }, nil, 0, "-adaptive-budget"},
		{func(c *config.Config) { c.AdaptiveMaxFiles = 201 }, nil, 0, "-adaptive-max-files"},
		{func(c *config.Config) { c.TraceOnly = true; c.AgentTrace = "trace.jsonl" }, nil, 42, "cannot be combined"},
	}
	for _, b := range bad {
		c := config.Default()
		b.mut(&c)
		if err := validate(c, b.args, b.pid, ""); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("want error containing %q, got %v", b.want, err)
		}
	}
}

func TestAgentTraceOfflineIncludesGraphWithoutHostCollection(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace.jsonl")
	data := `{"trace_id":"11111111111111111111111111111111","span_id":"1111111111111111","operation":"execute_tool","tool":"read_file"}`
	if err := os.WriteFile(trace, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.AgentTrace = trace
	cfg.TraceOnly = true
	cfg.Quiet = true
	cfg.Format = output.FormatHTML
	cfg.Output = filepath.Join(dir, "case.html")
	rep, err := doEvtxOffline(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host != "(offline)" || rep.HostInfo != nil || !rep.Run.Graph || rep.Run.DNSLookups || len(rep.Results) != 2 || rep.Results[0].Collector != "agenttrace" || rep.Results[1].Collector != "evidence_graph" {
		t.Fatalf("offline mode collected host state: %+v", rep)
	}
	if _, err = os.Stat(cfg.Output + ".sha256"); err != nil {
		t.Fatal("report checksum missing", err)
	}
	if rep.Summary.Findings != 0 {
		t.Fatal("imported telemetry must not itself imply a malicious finding")
	}
}

func TestParsePIDs(t *testing.T) {
	got, err := parsePIDs(" 4242, 5120,4242 ")
	if err != nil || len(got) != 2 || got[0] != 4242 || got[1] != 5120 {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"0", "-1", "abc", "12x"} {
		if _, err := parsePIDs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSelectCollectorsAddsMemoryForYara(t *testing.T) {
	cfg := config.Default()
	cfg.Collectors = []string{"memory"}
	cfg.YaraRules = "rules"
	sel, err := selectCollectors(cfg)
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("memory collector is Windows/Linux only")
	}
	if err != nil || len(sel) != 1 || sel[0].Name() != "memory" {
		t.Fatalf("memory named and implied must appear once: %v %v", sel, err)
	}
	cfg.Collectors = []string{"nope"}
	if _, err := selectCollectors(cfg); err == nil {
		t.Fatal("unknown collector accepted")
	}
}

func TestFailOn(t *testing.T) {
	s := output.Summary{BySeverity: map[collector.Severity]int{collector.SevSuspect: 2, collector.SevCritical: 0}}
	cases := map[string]bool{"": false, "notable": true, "suspect": true, "critical": false}
	for th, want := range cases {
		if got := failOnMet(s, th); got != want {
			t.Errorf("failOnMet(%q) = %v, want %v", th, got, want)
		}
	}
}

// -evtx is an offline mode: a live option beside it would be silently ignored,
// so it is refused instead.
func TestValidateRejectsLiveOptionsWithEvtx(t *testing.T) {
	base := config.Default()
	if err := validate(base, nil, 0, "Security.evtx"); err != nil {
		t.Fatalf("-evtx alone rejected: %v", err)
	}
	sigma := base
	sigma.SigmaRules, sigma.Timeline, sigma.IOCs = "builtin", true, true
	if err := validate(sigma, nil, 0, "Security.evtx"); err != nil {
		t.Fatalf("-evtx with offline analysis options rejected: %v", err)
	}
	collectors, yara, pids := base, base, base
	collectors.Collectors = []string{"processes"}
	yara.YaraRules = "rules"
	pids.MemPIDs = []int{4}
	for name, c := range map[string]config.Config{"-collectors": collectors, "-yara": yara, "-mem-pids": pids} {
		if err := validate(c, nil, 0, "Security.evtx"); err == nil {
			t.Errorf("-evtx with %s accepted", name)
		}
	}
	if err := validate(base, nil, 4242, "Security.evtx"); err == nil {
		t.Error("-evtx with -mem-scan accepted")
	}
}

// A directory given to -evtx is listed, not globbed: brackets in its name are
// literal, and the extension's case doesn't matter.
func TestExpandEvtxPathsReadsDirectoriesLiterally(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "IR[42] logs")
	if err := os.MkdirAll(filepath.Join(dir, "nested.evtx"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"System.evtx", "Security.EVTX", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := expandEvtxPaths(dir + "," + filepath.Join(dir, "System.evtx"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "Security.EVTX"), filepath.Join(dir, "System.evtx")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}
