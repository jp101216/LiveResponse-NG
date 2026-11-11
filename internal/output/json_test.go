package output

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

func TestForcedArtifactFailurePreservesEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	for _, p := range []string{path, path + ".sha256"} {
		if err := os.WriteFile(p, []byte("original evidence"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("write failed")
	_, err := WriteArtifact(path, true, func(w io.Writer) error {
		_, _ = io.WriteString(w, "incomplete replacement")
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("writer error lost: %v", err)
	}
	for _, p := range []string{path, path + ".sha256"} {
		data, err := os.ReadFile(p)
		if err != nil || string(data) != "original evidence" {
			t.Fatalf("failed replacement changed existing evidence: %s: %q %v", p, data, err)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("failed replacement left temporary files: %v", entries)
	}
}

func TestForcedArtifactReplacesLinksWithoutChangingTargets(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.json")
			for _, p := range []string{path, path + ".sha256"} {
				target := p + ".original"
				if err := os.WriteFile(target, []byte("original evidence"), 0o600); err != nil {
					t.Fatal(err)
				}
				link := os.Symlink
				if kind == "hardlink" {
					link = os.Link
				}
				if err := link(target, p); err != nil {
					t.Skipf("%s unavailable: %v", kind, err)
				}
			}
			if _, err := WriteFile(path, Report{}, FormatJSON, false, true); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{path, path + ".sha256"} {
				data, err := os.ReadFile(p + ".original")
				if err != nil || string(data) != "original evidence" {
					t.Fatalf("forced output followed a %s: %q %v", kind, data, err)
				}
				info, err := os.Lstat(p)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("output was not replaced with a regular file: %v", err)
				}
			}
		})
	}
}

func TestForcedArtifactUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode-bit permissions")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	for _, p := range []string{path, path + ".sha256"} {
		if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := WriteFile(path, Report{}, FormatJSON, false, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".sha256"} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("forced output retained public permissions: %s: %v %v", p, info, err)
		}
	}
}

func sampleResults() []collector.Result {
	return []collector.Result{
		{Collector: "processes", Records: []collector.Record{
			{Fields: map[string]any{"pid": 1}},
			{Fields: map[string]any{"pid": 2}, Findings: []collector.Finding{
				{Rule: "process.unusual_path", Severity: collector.SevSuspect, Confidence: 50, Detail: "a"},
				{Rule: "exec.download_execute", Severity: collector.SevCritical, Confidence: 90, Detail: "b"},
			}},
		}},
		{Collector: "services", Errors: []string{"x"}, Records: []collector.Record{
			{Fields: map[string]any{"name": "s"}, Findings: []collector.Finding{
				{Rule: "persistence.service_unquoted_path", Severity: collector.SevNotable, Confidence: 40, Detail: "c"},
				{Rule: "process.unusual_path", Severity: collector.SevSuspect, Confidence: 70, Detail: "d"},
			}},
		}},
	}
}

func TestWriteFileRefusesOverwriteAndWritesChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.json")
	rep := Report{Schema: SchemaVersion, Results: []collector.Result{}}

	sum, err := WriteFile(path, rep, FormatJSON, true, false)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	want := sha256.Sum256(data)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatal("returned hash does not match file contents")
	}
	side, _ := os.ReadFile(path + ".sha256")
	if string(side) != sum+"  host.json\n" {
		t.Fatalf("checksum file = %q", side)
	}

	if _, err := WriteFile(path, rep, FormatJSON, true, false); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusal to overwrite, got %v", err)
	}
	if _, err := WriteFile(path, rep, FormatJSON, false, true); err != nil {
		t.Fatalf("-force should overwrite: %v", err)
	}
	if _, err := WriteFile(filepath.Join(dir, "x.json"), rep, "xml", false, false); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestWriteFilePreservesExistingChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.json")
	const oldChecksum = "previous evidence checksum\n"
	if err := os.WriteFile(path+".sha256", []byte(oldChecksum), 0o600); err != nil {
		t.Fatal(err)
	}
	rep := Report{Schema: SchemaVersion, Results: []collector.Result{}}
	sum, err := WriteFile(path, rep, FormatJSON, false, false)
	if err == nil || sum == "" || !strings.Contains(err.Error(), "report written, but checksum file failed") {
		t.Fatalf("want a checksum collision with the written report's hash, got %q %v", sum, err)
	}
	data, err := os.ReadFile(path + ".sha256")
	if err != nil || string(data) != oldChecksum {
		t.Fatalf("existing checksum changed: %q %v", data, err)
	}
	if _, err := WriteFile(path, rep, FormatJSON, false, true); err != nil {
		t.Fatalf("-force should replace the report and checksum: %v", err)
	}
	data, _ = os.ReadFile(path + ".sha256")
	if string(data) == oldChecksum {
		t.Fatal("-force did not replace the checksum")
	}
}

func TestSummarise(t *testing.T) {
	s := Summarise(sampleResults())
	if s.Records != 3 || s.Findings != 4 || s.Errors != 1 || s.BySeverity[collector.SevSuspect] != 2 ||
		s.ByRule["process.unusual_path"] != 2 || len(s.CollectorsWithErrors) != 1 {
		t.Fatalf("%+v", s)
	}
	// Most severe first; equal severity by confidence.
	order := []string{"exec.download_execute", "process.unusual_path", "process.unusual_path", "persistence.service_unquoted_path"}
	for i, f := range s.TopFindings {
		if f.Rule != order[i] {
			t.Fatalf("top[%d] = %s, want %s", i, f.Rule, order[i])
		}
	}
	if top := s.TopFindings[1]; top.Confidence != 70 || top.Collector != "services" || top.Result != 1 || top.Record != 0 {
		t.Fatalf("top[1] = %+v", top)
	}
	if empty := Summarise(nil); empty.TopFindings == nil || empty.ByRule == nil {
		t.Fatal("empty summary must serialise as [] / {} not null")
	}
}

func TestJSONLEvents(t *testing.T) {
	rep := Report{Schema: SchemaVersion, RunID: "r1", Host: "h", Results: sampleResults()}
	rep.Summary = Summarise(rep.Results)
	var buf bytes.Buffer
	if err := Write(&buf, rep, FormatJSONL, true); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var ev map[string]any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line is not JSON: %s", sc.Text())
		}
		if ev["run_id"] != "r1" {
			t.Fatalf("event without run_id: %s", sc.Text())
		}
		counts[ev["type"].(string)]++
	}
	if counts["run"] != 1 || counts["collector"] != 2 || counts["record"] != 3 || counts["finding"] != 4 {
		t.Fatalf("event counts %v", counts)
	}
}

// The html format is the viewer with the JSON envelope inside: the same
// report, readable back from the page's data block.
func TestHTMLReport(t *testing.T) {
	rep := Report{Schema: SchemaVersion, RunID: "r1", Host: `<b>h</b>`, Results: sampleResults()}
	rep.Summary = Summarise(rep.Results)
	var buf bytes.Buffer
	if err := Write(&buf, rep, FormatHTML, true); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	open := `<script type="application/json" id="lrng-report">`
	i := strings.Index(page, open)
	if !strings.HasPrefix(page, "<!doctype html>") || i < 0 {
		t.Fatalf("not the viewer page: %.120q", page)
	}
	data := page[i+len(open):]
	data = data[:strings.Index(data, "</script>")]
	var back Report
	if err := json.Unmarshal([]byte(data), &back); err != nil {
		t.Fatalf("embedded report: %v", err)
	}
	if back.RunID != "r1" || back.Host != "<b>h</b>" || len(back.Results) != 2 || back.Summary.Findings != 4 {
		t.Fatalf("embedded report = %+v", back)
	}
	if strings.Contains(data, "<b>") {
		t.Fatal("markup in the report reached the page unescaped")
	}
	path := filepath.Join(t.TempDir(), "host.html")
	if _, err := WriteFile(path, rep, FormatHTML, false, false); err != nil {
		t.Fatal(err)
	}
}

func TestNewRunID(t *testing.T) {
	a, b := NewRunID(), NewRunID()
	if a == b || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(a) {
		t.Fatalf("run ids %q %q", a, b)
	}
}

func TestConsoleSummary(t *testing.T) {
	rep := Report{Results: sampleResults()}
	rep.Summary = Summarise(rep.Results)
	var buf bytes.Buffer
	WriteConsoleSummary(&buf, rep, 2)
	out := buf.String()
	if !strings.Contains(out, "4 finding(s) (1 critical, 2 suspect, 1 notable)") ||
		!strings.Contains(out, "exec.download_execute") || !strings.Contains(out, "... 2 more") ||
		!strings.Contains(out, "incomplete coverage: services") {
		t.Fatalf("summary:\n%s", out)
	}
}
