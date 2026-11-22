package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/navigator"
	"github.com/jp101216/liveresponse-ng/internal/output"
	"github.com/jp101216/liveresponse-ng/internal/watch"
)

func TestWatchOptionValidation(t *testing.T) {
	def := watchOptions{MinEvents: 6}
	ok := []struct {
		w        watchOptions
		explicit []string
	}{
		{def, nil},
		{watchOptions{Duration: 15 * time.Minute, MinEvents: 6}, []string{"watch", "out", "collectors", "navigator", "fail-on"}},
		{watchOptions{Duration: time.Minute, Only: true, Raw: "e.jsonl", MinEvents: 8, AllowBeacon: "x.exe"}, []string{"watch", "watch-only", "watch-raw", "watch-min-events", "allow-beacon"}},
		{watchOptions{From: "e.jsonl", MinEvents: 6}, []string{"watch-from", "out", "fail-on", "navigator", "intel", "allow-beacon"}},
	}
	for _, c := range ok {
		if err := validateWatchOptions(c.w, c.explicit); err != nil {
			t.Errorf("%+v %v: %v", c.w, c.explicit, err)
		}
	}
	bad := []struct {
		w        watchOptions
		explicit []string
		want     string
	}{
		{watchOptions{Duration: 30 * time.Second, MinEvents: 6}, []string{"watch"}, "duration from"},
		{watchOptions{Duration: 25 * time.Hour, MinEvents: 6}, []string{"watch"}, "duration from"},
		{watchOptions{Duration: 0, MinEvents: 6}, []string{"watch"}, "duration from"},
		{watchOptions{Only: true, MinEvents: 6}, []string{"watch-only"}, "need -watch"},
		{watchOptions{Raw: "e.jsonl", MinEvents: 6}, []string{"watch-raw"}, "need -watch"},
		{watchOptions{MinEvents: 8}, []string{"watch-min-events"}, "need -watch or -watch-from"},
		{watchOptions{AllowBeacon: "a.exe", MinEvents: 6}, []string{"allow-beacon"}, "need -watch or -watch-from"},
		{watchOptions{Duration: time.Hour, From: "e.jsonl", MinEvents: 6}, []string{"watch", "watch-from"}, "use one"},
		{watchOptions{Duration: time.Hour, MinEvents: 3}, []string{"watch", "watch-min-events"}, "4 to 512"},
		{watchOptions{Duration: time.Hour, MinEvents: 6}, []string{"watch", "evtx"}, "cannot be combined with -watch"},
		{watchOptions{Duration: time.Hour, MinEvents: 6}, []string{"watch", "case-report"}, "cannot be combined with -watch"},
		{watchOptions{From: "e.jsonl", MinEvents: 6}, []string{"watch-from", "collectors"}, "offline -watch-from"},
		{watchOptions{From: "e.jsonl", MinEvents: 6}, []string{"watch-from", "yara"}, "offline -watch-from"},
	}
	for _, c := range bad {
		err := validateWatchOptions(c.w, c.explicit)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v %v: got %v, want %q", c.w, c.explicit, err, c.want)
		}
	}
	if err := checkDistinctOutputs([][2]string{{"out", "a.json"}, {"watch-raw", "a.json.sha256"}}); err == nil {
		t.Error("-watch-raw over the report's checksum was accepted")
	}
	if err := checkDistinctOutputs([][2]string{{"out", "a.json"}, {"watch-raw", "e.jsonl"}, {"navigator", ""}}); err != nil {
		t.Error(err)
	}
}

// writeStream saves a recorded window with one regular beacon.
func writeStream(t *testing.T, path string) {
	t.Helper()
	t0 := time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w, err := watch.NewStreamWriter(f, watch.Header{Host: "LAB-WS01", OS: "windows", Source: "etw", Started: t0, Duration: "15m0s", SelfPID: 9})
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.Write(watch.Event{Time: t0, Kind: watch.ProcSeen, PID: 4100, Image: `C:\Users\Public\Libraries\svc.exe`}))
	must(w.Write(watch.Event{Time: t0.Add(time.Second), Kind: watch.DNS, PID: 4100, Query: "sync.cdn-relay.net", QType: 1, Answers: []string{"203.0.113.50"}}))
	remote := netip.MustParseAddrPort("203.0.113.50:443")
	for i := 0; i < 15; i++ {
		at := t0.Add(time.Duration(i)*time.Minute + time.Duration(i%3)*time.Second)
		must(w.Write(watch.Event{Time: at, Kind: watch.TCPConnect, PID: 4100, Local: netip.MustParseAddrPort("10.0.0.5:51000"), Remote: remote}))
	}
	must(w.Close(watch.Trailer{Ended: t0.Add(15 * time.Minute)}))
}

func TestWatchFromCommand(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "lrng.exe")
	if data, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, data)
	}
	dir := t.TempDir()
	stream := filepath.Join(dir, "events.jsonl")
	writeStream(t, stream)
	out := filepath.Join(dir, "rescored.json")
	layerPath := filepath.Join(dir, "layer.json")
	cmd := exec.Command(exe, "-watch-from", stream, "-out", out, "-fail-on", "suspect", "-navigator", layerPath, "-quiet")
	if data, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitFindings {
		t.Fatalf("-watch-from with -fail-on suspect: %v\n%s", err, data)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var rep output.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Host != "LAB-WS01" || len(rep.Results) != 1 || rep.Results[0].Collector != "watch" {
		t.Fatalf("report host %q, results %d", rep.Host, len(rep.Results))
	}
	found := false
	for _, rec := range rep.Results[0].Records {
		for _, f := range rec.Findings {
			found = found || f.Rule == watch.RuleBeacon && f.Technique == "T1071.001"
		}
	}
	if !found {
		t.Fatalf("no beacon finding in %s", data)
	}
	if rep.Results[0].Meta["stream_sha256"] == nil || rep.Results[0].Meta["replayed_from"] != stream {
		t.Errorf("meta = %v", rep.Results[0].Meta)
	}
	ld, err := os.ReadFile(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	var layer navigator.Layer
	if err := json.Unmarshal(ld, &layer); err != nil || len(layer.Techniques) != 1 || layer.Techniques[0].TechniqueID != "T1071.001" {
		t.Fatalf("layer: %v %s", err, ld)
	}
	// Offline replay refuses collection flags; a corrupt stream is an error.
	cmd = exec.Command(exe, "-watch-from", stream, "-collectors", "processes")
	if d, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitUsage {
		t.Fatalf("collection flag with -watch-from: %v %s", err, d)
	}
	bad := filepath.Join(dir, "bad.jsonl")
	_ = os.WriteFile(bad, []byte(`{"type":"lrng-watch","version":1}`+"\n"), 0o600)
	cmd = exec.Command(exe, "-watch-from", bad)
	if d, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != exitError {
		t.Fatalf("a stream without a start time: %v %s", err, d)
	}
	switch {
	case runtime.GOOS == "linux" && os.Geteuid() != 0:
		cmd = exec.Command(exe, "-watch", "1m", "-watch-only")
		if d, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(d), "watch mode needs root on Linux") {
			t.Fatalf("-watch without root: %v %s", err, d)
		}
	case runtime.GOOS != "windows" && runtime.GOOS != "linux":
		cmd = exec.Command(exe, "-watch", "1m", "-watch-only")
		if d, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(d), "watch mode records on Windows and Linux") {
			t.Fatalf("-watch elsewhere: %v %s", err, d)
		}
	}
}
