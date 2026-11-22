package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/navigator"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func TestNavigatorOptionValidation(t *testing.T) {
	ok := []struct {
		n        navOptions
		explicit []string
	}{
		{navOptions{}, nil},
		{navOptions{Out: "layer.json"}, []string{"navigator", "out", "collectors", "fail-on"}},
		{navOptions{Out: "layer.json", Min: "suspect"}, []string{"navigator", "navigator-min"}},
		{navOptions{From: "host.json"}, []string{"navigator-from"}},
		{navOptions{From: "host.json", Out: "l.json", Expect: "p.md", ExpectMin: 60, ExpectSet: true}, []string{"navigator-from", "navigator", "expect", "expect-min", "force", "quiet"}},
		{navOptions{Out: "l.json", Expect: "p.md", ExpectMin: 0, ExpectSet: true}, []string{"navigator", "expect", "expect-min"}},
		{navOptions{Out: "l.json", Expect: "p.md", ExpectMin: 100, ExpectSet: true}, []string{"navigator", "expect", "expect-min"}},
	}
	for _, c := range ok {
		if err := validateNavigatorOptions(c.n, c.explicit); err != nil {
			t.Errorf("%+v %v: %v", c.n, c.explicit, err)
		}
	}
	bad := []struct {
		n        navOptions
		explicit []string
		want     string
	}{
		{navOptions{Min: "suspect"}, []string{"navigator-min"}, "need -navigator"},
		{navOptions{Expect: "p.md"}, []string{"expect"}, "need -navigator"},
		// An explicitly empty value is still a flag the user meant to use.
		{navOptions{}, []string{"expect"}, "need -navigator"},
		{navOptions{ExpectSet: true}, []string{"expect-min"}, "need -navigator"},
		{navOptions{Out: "l.json", ExpectMin: 50, ExpectSet: true}, []string{"navigator", "expect-min"}, "needs -expect"},
		{navOptions{Out: "l.json", Expect: "p.md", ExpectMin: 101, ExpectSet: true}, []string{"navigator", "expect", "expect-min"}, "percentage"},
		{navOptions{Out: "l.json", Expect: "p.md", ExpectMin: -1, ExpectSet: true}, []string{"navigator", "expect", "expect-min"}, "percentage"},
		{navOptions{Out: "l.json", Min: "high"}, []string{"navigator", "navigator-min"}, "must be one of"},
		{navOptions{From: "h.json"}, []string{"navigator-from", "navigator"}, "needs a file path"},
		{navOptions{Out: "l.json"}, []string{"navigator", "mem-scan"}, "doesn't produce a report"},
		{navOptions{Out: "l.json"}, []string{"navigator", "version"}, "doesn't produce a report"},
		{navOptions{From: "h.json"}, []string{"navigator-from", "list"}, "doesn't produce a report"},
	}
	for _, c := range bad {
		err := validateNavigatorOptions(c.n, c.explicit)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v %v: got %v, want %q", c.n, c.explicit, err, c.want)
		}
	}
	// Offline: every flag that would collect this host or change the run is
	// rejected, so a mistyped command can't turn into a live collection.
	for _, flag := range []string{"collectors", "out", "evtx", "case-report", "adaptive", "intel", "sigma", "yara", "fail-on", "format", "ui", "workers"} {
		err := validateNavigatorOptions(navOptions{From: "h.json"}, []string{"navigator-from", flag})
		if err == nil || !strings.Contains(err.Error(), "offline -navigator-from") {
			t.Errorf("-navigator-from accepted -%s: %v", flag, err)
		}
	}
}

func TestCheckLayerPath(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "host.json")
	if err := os.WriteFile(report, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "alias.json")
	if err := os.Link(report, link); err != nil {
		t.Logf("no hard links here: %v", err)
		link = ""
	}
	for _, layer := range []string{report, report + ".sha256", filepath.Join(dir, ".", "host.json")} {
		if err := checkLayerPath(layer, report); err == nil {
			t.Errorf("layer %s accepted over report %s", layer, report)
		}
	}
	// host.json.sha256 as the layer would be replaced by the layer's own
	// checksum file when the report is host.json.sha256 — both directions.
	if err := checkLayerPath(strings.TrimSuffix(report, ".json"), strings.TrimSuffix(report, ".json")+".sha256"); err == nil {
		t.Error("layer checksum would replace the report")
	}
	if link != "" {
		if err := checkLayerPath(link, report); err == nil {
			t.Error("hard link to the report accepted as the layer path")
		}
	}
	for _, c := range [][2]string{{"", report}, {filepath.Join(dir, "layer.json"), report}, {filepath.Join(dir, "layer.json"), ""}} {
		if err := checkLayerPath(c[0], c[1]); err != nil {
			t.Errorf("checkLayerPath(%q, %q): %v", c[0], c[1], err)
		}
	}
}

// navigatorReport writes a saved report with findings that name a current,
// a retired and no technique, and returns its path.
func navigatorReport(t *testing.T) string {
	t.Helper()
	rep := output.Report{Schema: "1.2", Tool: "liveresponse-ng", Version: "0.21.0", RunID: "run-1", Host: "LAB", OS: "windows", Arch: "amd64",
		Collected: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC),
		Results: []collector.Result{{Collector: "processes", Records: []collector.Record{{
			Fields: map[string]any{"name": "rclone.exe", "user": "alice"},
			Findings: []collector.Finding{
				{Rule: "proc.rclone", Severity: collector.SevSuspect, Technique: "T1567.002", Confidence: 80, Detail: "copy to a personal bucket"},
				{Rule: "defense.av_disabled", Severity: collector.SevCritical, Technique: "T1562.001", Confidence: 90},
				{Rule: "proc.unsigned", Severity: collector.SevNotable, Confidence: 40},
			},
		}}}},
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNavigatorFromCommand(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "lrng.exe")
	if data, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, data)
	}
	report := navigatorReport(t)
	dir := t.TempDir()
	layerPath := filepath.Join(dir, "layer.json")

	cmd := exec.Command(exe, "-navigator-from", report, "-navigator", layerPath)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("findings layer: %v\n%s", err, data)
	}
	data, err := os.ReadFile(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	var layer navigator.Layer
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, tech := range layer.Techniques {
		ids[tech.TechniqueID] = true
	}
	if !ids["T1567.002"] || !ids["T1685"] || ids["T1562.001"] || len(ids) != 2 {
		t.Fatalf("layer techniques = %v, want T1567.002 and T1685 (remapped from T1562.001)", ids)
	}
	sum, err := output.FileSHA256(report)
	if err != nil {
		t.Fatal(err)
	}
	if !layerMeta(layer, "report_sha256", sum) {
		t.Errorf("layer doesn't record the source report's SHA-256 %s", sum)
	}
	if strings.Contains(string(data), "alice") || strings.Contains(string(data), "personal bucket") {
		t.Error("layer carries record fields or finding detail")
	}
	if _, err := os.Stat(layerPath + ".sha256"); err != nil {
		t.Errorf("no checksum beside the layer: %v", err)
	}

	// Existing files are kept unless -force is given.
	cmd = exec.Command(exe, "-navigator-from", report, "-navigator", layerPath)
	if out, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitError {
		t.Fatalf("overwrote the layer without -force: %v %s", err, out)
	}

	// Coverage below -expect-min exits 3, like -fail-on, and still writes.
	expect := filepath.Join(dir, "profile.md")
	if err := os.WriteFile(expect, []byte("Uses T1567.002 and T1219.\nOut of scope: T1566.004 (phone calls)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cover := filepath.Join(dir, "coverage.json")
	cmd = exec.Command(exe, "-navigator-from", report, "-expect", expect, "-expect-min", "60", "-navigator", cover)
	out, err := cmd.CombinedOutput()
	if err == nil || cmd.ProcessState.ExitCode() != exitFindings {
		t.Fatalf("coverage under -expect-min: %v %s", err, out)
	}
	if !strings.Contains(string(out), "expected 2, detected 1 (50%)") || !strings.Contains(string(out), "below -expect-min 60%") {
		t.Errorf("coverage summary = %s", out)
	}
	if _, err := os.Stat(cover); err != nil {
		t.Errorf("coverage layer not written when under the threshold: %v", err)
	}
	cmd = exec.Command(exe, "-navigator-from", report, "-expect", expect, "-expect-min", "50", "-quiet")
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("coverage at -expect-min to stdout: %v", err)
	}
	if err := json.Unmarshal(out, &layer); err != nil || !strings.HasPrefix(layer.Name, "lrng coverage:") {
		t.Fatalf("stdout isn't a coverage layer: %v", err)
	}

	// Offline mode refuses collection flags before doing anything.
	cmd = exec.Command(exe, "-navigator-from", report, "-collectors", "processes", "-navigator", filepath.Join(dir, "x.json"))
	if out, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitUsage || !strings.Contains(string(out), "offline -navigator-from") {
		t.Fatalf("collection flag with -navigator-from: %v %s", err, out)
	}
	// The layer never replaces the report it was made from.
	cmd = exec.Command(exe, "-navigator-from", report, "-navigator", report, "-force")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "would overwrite") {
		t.Fatalf("layer over its own report: %v %s", err, out)
	}
}

func layerMeta(l navigator.Layer, name, value string) bool {
	for _, m := range l.Metadata {
		if m.Name == name && m.Value == value {
			return true
		}
	}
	return false
}
