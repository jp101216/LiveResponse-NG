package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/casefile"
	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func caseInputs(t *testing.T) []string {
	t.Helper()
	var paths []string
	for i, id := range []string{"before", "after"} {
		path := filepath.Join(t.TempDir(), id+".json")
		rep := output.Report{Schema: "1.2", Tool: "liveresponse-ng", RunID: id, Host: "LAB", OS: "windows", Arch: "amd64", Collected: time.Date(2026, 11, 1, i+1, 0, 0, 0, time.UTC), Results: []collector.Result{{Collector: "services", Records: []collector.Record{{Fields: map[string]any{"name": "Example", "image_path": id + ".exe"}, Findings: []collector.Finding{{Rule: "demo.rule", Severity: collector.SevSuspect, Confidence: 70}}}}}}}
		data, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestCaseCLIOutputAndEvidenceOverwritePolicy(t *testing.T) {
	paths := caseInputs(t)
	for _, format := range []string{"json", "html"} {
		cfg := config.Default()
		cfg.Quiet, cfg.Format = true, format
		cfg.Output = filepath.Join(t.TempDir(), "case."+format)
		summary, err := doCase(context.Background(), cfg, paths, "IR-42", true, true)
		if err != nil || summary.Findings != 2 || !failOnMet(summary, "suspect") {
			t.Fatalf("offline case failed: %+v %v", summary, err)
		}
		if _, err := os.Stat(cfg.Output + ".sha256"); err != nil {
			t.Fatal(err)
		}
		if format == "json" {
			data, _ := os.ReadFile(cfg.Output)
			var c casefile.Case
			if err := json.Unmarshal(data, &c); err != nil || c.Comparison == nil || len(c.Sources) != 2 {
				t.Fatalf("invalid case output: %v", err)
			}
		}
		if _, err := doCase(context.Background(), cfg, paths, "IR-42", true, true); err == nil {
			t.Fatal("overwrote existing evidence without -force")
		}
		cfg.Force, cfg.Output = true, paths[0]
		if _, err := doCase(context.Background(), cfg, paths, "IR-42", false, false); err == nil {
			t.Fatal("replaced an input report even though -force applies only to output")
		}
	}
}

func TestCaseRejectsLiveFlagsAndIncompleteComparison(t *testing.T) {
	paths := []string{"one.json", "two.json"}
	cfg := config.Default()
	if err := validateCaseOptions(cfg, paths, "IR-42", true, true, []string{"case-report", "compare", "same-host", "out", "quiet", "fail-on"}); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"collectors", "evtx", "agent-trace", "cloud-audit", "adaptive", "yara", "mem-scan", "sigma", "intel", "timeline", "list", "version", "no-dns", "workers"} {
		if err := validateCaseOptions(cfg, paths, "", false, false, []string{"case-report", flag}); err == nil {
			t.Fatalf("accepted ignored or live -%s option", flag)
		}
	}
	if err := validateCaseOptions(cfg, paths, "", true, false, nil); err == nil {
		t.Fatal("inferred same-machine identity")
	}
	if err := validateCaseOptions(cfg, nil, "IR-42", false, false, nil); err == nil {
		t.Fatal("ignored case name without sources")
	}
	cfg.Format = "jsonl"
	if err := validateCaseOptions(cfg, paths, "", false, false, nil); err == nil {
		t.Fatal("accepted multiple runs in single-run JSONL format")
	}
}

func TestCaseCommandRunsOfflineAndHonorsFailOn(t *testing.T) {
	// The real executable validates flag dispatch, exit codes and report
	// boundaries. Its only output must be a case made from these two files.
	exe := filepath.Join(t.TempDir(), "lrng.exe")
	build := exec.Command("go", "build", "-o", exe, ".")
	if data, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, data)
	}
	paths := caseInputs(t)
	out := filepath.Join(t.TempDir(), "case.json")
	cmd := exec.Command(exe, "-case-report", paths[0], "-case-report", paths[1], "-compare", "-same-host", "-quiet", "-fail-on", "suspect", "-out", out)
	if data, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitFindings {
		t.Fatalf("fail-on exit: %v %s", err, data)
	}
	data, err := os.ReadFile(out)
	if err != nil || strings.Contains(string(data), `"collector": "network"`) || strings.Contains(string(data), `"collector": "hostinfo"`) {
		t.Fatalf("case output missing or included host collection: %v", err)
	}
	cmd = exec.Command(exe, "-case-report", paths[0], "-adaptive", "-out", out, "-force")
	if data, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitUsage || !strings.Contains(string(data), "cannot be combined") {
		t.Fatalf("conflicting flags didn't stop before collection: %v %s", err, data)
	}
}
