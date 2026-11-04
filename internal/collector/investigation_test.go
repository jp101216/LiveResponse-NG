package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func graphEdges(r Result, relation string) []Record {
	var edges []Record
	for _, rec := range r.Records {
		if rec.Fields["kind"] == "edge" && rec.Fields["relation"] == relation {
			edges = append(edges, rec)
		}
	}
	return edges
}

func TestGraphReferencesAndPIDReuse(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	results := []Result{
		{Collector: "processes", Records: []Record{
			{Fields: map[string]any{"pid": uint32(10), "created_at": start, "image_path": `C:\Tools\app.exe`}},
			{Fields: map[string]any{"pid": uint32(20), "ppid": uint32(10), "created_at": start.Add(time.Second)}},
			{Fields: map[string]any{"pid": 30, "ppid": 10, "created_at": start.Add(-time.Second)}},
			{Fields: map[string]any{"pid": 40, "ppid": 10, "parent_pid_reused": true}},
		}},
		{Collector: "network", Records: []Record{{Fields: map[string]any{"pid": uint32(20), "remote_addr": "203.0.113.10", "remote_port": uint16(443)}}}},
		{Collector: "autoruns", Records: []Record{{Fields: map[string]any{"image": `c:\tools\APP.exe`}, Findings: []Finding{{Rule: "test", Severity: SevSuspect}}}}},
	}
	g := BuildEvidenceGraph(results, "host")
	if got := graphEdges(g, "reported_parent"); len(got) != 1 || got[0].Fields["from"] != "r0:0" || got[0].Fields["to"] != "r0:1" {
		t.Fatalf("parent edges: %+v", got)
	}
	if got := graphEdges(g, "same_pid"); len(got) != 1 || got[0].Fields["basis"] != "inferred" {
		t.Fatalf("PID edges: %+v", got)
	}
	if len(graphEdges(g, "same_path")) != 1 {
		t.Fatal("Windows paths must match independent of parser OS")
	}
	for _, rec := range g.Records {
		if len(rec.Findings) > 0 {
			t.Fatal("graph duplicated source findings")
		}
		if rec.Fields["kind"] == "node" {
			ref := rec.Fields["source_ref"].(EvidenceRef)
			if results[ref.Result].Collector != rec.Fields["source_collector"] || ref.Record >= len(results[ref.Result].Records) {
				t.Fatal("invalid evidence reference")
			}
		}
	}
	if len(results[2].Records[0].Findings) != 1 {
		t.Fatal("input mutated")
	}
}

func TestGraphPathsAndUnverifiedParent(t *testing.T) {
	r := []Result{{Collector: "processes", Records: []Record{
		{Fields: map[string]any{"pid": 1, "image_path": "/tmp/A", "image_sha256": "a"}},
		{Fields: map[string]any{"pid": 2, "ppid": 1, "image_path": "/tmp/a", "image_sha256": "a"}},
		{Fields: map[string]any{"pid": 3, "image_path": "/tmp/A", "image_sha256": "b"}},
	}}}
	g := BuildEvidenceGraph(r, "")
	if len(graphEdges(g, "same_path")) != 0 {
		t.Fatal("case-distinct paths or conflicting hashes must not match")
	}
	if len(graphEdges(g, "candidate_parent")) != 1 || len(graphEdges(g, "reported_parent")) != 0 {
		t.Fatal("missing start times must remain an inference")
	}
}

func TestGraphTraceScopingAndMissingParents(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	traces := []Record{
		{Fields: map[string]any{"trace_id": "a", "span_id": "1", "host": "other", "pid": 10, "process_created_at": start}},
		{Fields: map[string]any{"trace_id": "a", "span_id": "2", "parent_span_id": "1", "host": "host", "pid": 10}},
		{Fields: map[string]any{"trace_id": "b", "span_id": "3", "parent_span_id": "1", "host": "host", "pid": 10, "process_created_at": start}},
	}
	r := []Result{{Collector: "processes", Records: []Record{{Fields: map[string]any{"pid": 10, "created_at": start}}}}, {Collector: "agenttrace", Records: traces}}
	g := BuildEvidenceGraph(r, "host")
	if len(graphEdges(g, "reported_trace_parent")) != 1 || len(graphEdges(g, "trace_process")) != 1 || g.Meta["missing_trace_parents"] != 1 {
		t.Fatalf("unsafe trace correlation: %+v", g)
	}
	r[1].Records = append(traces, traces[0])
	if len(graphEdges(BuildEvidenceGraph(r, "host"), "reported_trace_parent")) != 0 {
		t.Fatal("ambiguous duplicate spans must not establish parent links")
	}
}

func TestGraphBoundedAndSyntheticResultsExcluded(t *testing.T) {
	records := make([]Record, graphMaxNodes+5)
	for i := range records {
		records[i] = Record{Fields: map[string]any{"pid": i + 1}}
	}
	g := BuildEvidenceGraph([]Result{{Collector: "processes", Records: records}, {Collector: "timeline", Records: records}}, "")
	if g.Meta["nodes"] != graphMaxNodes || g.Meta["source_records"] != len(records) || g.Meta["truncated"] != true {
		t.Fatalf("bad bounds: %+v", g.Meta)
	}
}

func TestGraphPreservesFindingsAndContextOverLargeLog(t *testing.T) {
	logs := make([]Record, graphMaxNodes+10)
	for i := range logs {
		logs[i] = Record{Fields: map[string]any{"event_id": 1}}
	}
	logs[len(logs)-1].Findings = []Finding{{Rule: "important", Severity: SevCritical}}
	g := BuildEvidenceGraph([]Result{{Collector: "eventlog", Records: logs}, {Collector: "processes", Records: []Record{{Fields: map[string]any{"pid": 1}}}}}, "")
	var important, process bool
	for _, rec := range g.Records {
		important = important || rec.Fields["top_rule"] == "important"
		process = process || rec.Fields["source_collector"] == "processes"
	}
	if !important || !process {
		t.Fatal("ordinary log records crowded out findings or process context")
	}
}

func TestGraphEventsDestinationsAndFollowUpSources(t *testing.T) {
	r := []Result{
		{Collector: "services", Records: []Record{{Fields: map[string]any{"name": "LabService", "image": `C:\lab.exe`}}}},
		{Collector: "eventlog", Records: []Record{{Fields: map[string]any{"event_data": map[string]string{"ServiceName": "LabService", "Image": `C:\lab.exe`}}}}},
		{Collector: "network", Records: []Record{
			{Fields: map[string]any{"remote_addr": "203.0.113.1", "remote_port": uint16(443)}},
			{Fields: map[string]any{"remote_addr": "203.0.113.1", "remote_port": 443}},
		}},
		{Collector: "adaptive", Records: []Record{{Fields: map[string]any{"source_refs": []EvidenceRef{{0, 0}}, "path": `C:\lab.exe`}}}},
	}
	g := BuildEvidenceGraph(r, "")
	for _, relation := range []string{"same_service_name", "same_destination", "triggered_follow_up"} {
		if len(graphEdges(g, relation)) != 1 {
			t.Fatalf("missing relationship: %s", relation)
		}
	}
	if len(graphEdges(g, "same_path")) < 1 {
		t.Fatal("event image paths were not linked")
	}
}

func writeTraceFixture(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const traceOne = `{"trace_id":"11111111111111111111111111111111","span_id":"1111111111111111","operation":"invoke_agent","agent":"lab-agent","timestamp":"2026-11-01T12:00:00Z","input":"secret original prompt","headers":{"Authorization":"secret authorization"},"environment":{"TOKEN":"secret env"}}`
const traceTwo = `{"trace_id":"11111111111111111111111111111111","span_id":"2222222222222222","parent_span_id":"1111111111111111","operation":"execute_tool","tool":"read_file","arguments":{"path":"secret argument"},"output":"secret output"}`

func TestTraceImportPreservesSourcesButOmitsContent(t *testing.T) {
	text := traceOne + "\n" + traceTwo + "\ninvalid secret malformed payload\n"
	p := writeTraceFixture(t, text)
	r := ParseAgentTraceFiles(context.Background(), []string{p})
	if len(r.Records) != 2 || len(r.Errors) != 1 || r.Meta["rejected_records"] != 1 {
		t.Fatalf("unexpected import: %+v", r)
	}
	data, _ := json.Marshal(r)
	for _, secret := range []string{"secret original", "secret authorization", "secret env", "secret argument", "secret output", "secret malformed"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("content escaped metadata policy: %s", secret)
		}
	}
	digest := sha256.Sum256([]byte(text))
	if r.Records[0].Fields["source_sha256"] != hex.EncodeToString(digest[:]) || r.Records[1].Fields["source_line"] != 2 || r.Records[0].Fields["input_sha256"] == nil {
		t.Fatal("source locator or content fingerprint missing")
	}
	if len(graphEdges(BuildEvidenceGraph([]Result{r}, ""), "reported_trace_parent")) != 1 {
		t.Fatal("imported chain lost")
	}
}

func TestOTLPImportUsesResourceIdentityAndAllowlistedAttributes(t *testing.T) {
	text := `{"resourceSpans":[{"resource":{"attributes":[{"key":"host.name","value":{"stringValue":"lab-host"}},{"key":"process.pid","value":{"intValue":"42"}},{"key":"secret","value":{"stringValue":"secret resource"}}]},"scopeSpans":[{"spans":[{"traceId":"11111111111111111111111111111111","spanId":"1111111111111111","startTimeUnixNano":"1793534400000000000","attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},{"key":"gen_ai.tool.name","value":{"stringValue":"read_file"}},{"key":"gen_ai.tool.call.arguments","value":{"stringValue":"secret args"}}]}]}]}]}`
	r := ParseAgentTraceFiles(context.Background(), []string{writeTraceFixture(t, text)})
	if len(r.Records) != 1 || len(r.Errors) != 0 {
		t.Fatalf("OTLP import failed: %+v", r)
	}
	f := r.Records[0].Fields
	if f["host"] != "lab-host" || graphPID(f["pid"]) != "42" || f["tool"] != "read_file" || f["source_span"] != 1 || f["timestamp"] == nil {
		t.Fatalf("resource identity missing: %+v", f)
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "secret resource") || strings.Contains(string(data), "secret args") {
		t.Fatal("OTLP content leaked")
	}
}

func TestTraceImportRejectsBadIDsTrailingJSONAndOversizeFiles(t *testing.T) {
	text := strings.Replace(traceOne, "1111111111111111\"", "bad\"", 1) + "\n" + traceTwo + " {}\n"
	r := ParseAgentTraceFiles(context.Background(), []string{writeTraceFixture(t, text)})
	if len(r.Records) != 0 || len(r.Errors) == 0 {
		t.Fatal("invalid records accepted")
	}
	p := filepath.Join(t.TempDir(), "large.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(traceMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	r = ParseAgentTraceFiles(context.Background(), []string{p})
	if len(r.Records) != 0 || len(r.Errors) == 0 {
		t.Fatal("oversize input accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = ParseAgentTraceFiles(ctx, []string{writeTraceFixture(t, traceOne)})
	if len(r.Records) != 0 || len(r.Errors) == 0 {
		t.Fatal("cancelled import read content")
	}
}

func suspectFile(path string) Record {
	return Record{Fields: map[string]any{"image_path": path}, Findings: []Finding{{Rule: "test.suspect", Severity: SevSuspect}}}
}

func TestAdaptiveOnlyTargetsLiveLocalExecutablePaths(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(p, []byte("harmless fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	r := []Result{{Collector: "agenttrace", Records: []Record{suspectFile(p)}}, {Collector: "eventlog", Records: []Record{suspectFile(p)}}}
	if len(planAdaptive(r)) != 0 {
		t.Fatal("imported evidence scheduled a host read")
	}
	r = append(r, Result{Collector: "processes", Records: []Record{suspectFile(p), suspectFile(p)}})
	got := RunAdaptive(context.Background(), r, AdaptiveOptions{NoSign: true})
	if len(got.Records) != 1 || got.Records[0].Fields["status"] != "collected" || got.Records[0].Fields["sha256"] == nil || len(got.Records[0].Findings) != 0 {
		t.Fatalf("follow-up failed: %+v", got)
	}
	digest := sha256.Sum256([]byte("harmless fixture"))
	if got.Records[0].Fields["sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatal("incorrect follow-up digest")
	}
	got = RunAdaptive(context.Background(), r, AdaptiveOptions{NoHash: true, NoSign: true})
	if got.Records[0].Fields["sha256"] != nil || got.Records[0].Fields["hash_status"] != "disabled" {
		t.Fatal("-no-hash ignored")
	}
}

func TestAdaptiveLimitsAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	var records []Record
	for _, name := range []string{"a", "b", "c"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		records = append(records, suspectFile(p))
	}
	got := RunAdaptive(context.Background(), []Result{{Collector: "services", Records: records}}, AdaptiveOptions{MaxFiles: 1, NoSign: true})
	if len(got.Records) != 1 || got.Meta["uncollected_files"] != 2 {
		t.Fatal("file limit ignored")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(filepath.Join(dir, "a"), link); err != nil {
			t.Fatal(err)
		}
		got = RunAdaptive(context.Background(), []Result{{Collector: "processes", Records: []Record{suspectFile(link), suspectFile("/dev/zero"), suspectFile("/proc/1/mem")}}}, AdaptiveOptions{NoSign: true})
		if len(got.Records) != 1 || got.Records[0].Fields["status"] != "skipped" {
			t.Fatal("special file followed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = RunAdaptive(ctx, []Result{{Collector: "services", Records: records}}, AdaptiveOptions{NoSign: true})
	if len(got.Errors) == 0 || len(got.Records) != 0 {
		t.Fatal("cancelled follow-up started")
	}
}

func TestAdaptiveHashRejectsChangedMetadata(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(p, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, []byte("different length"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := adaptiveHash(context.Background(), p, before, 1024); got.SHA256 != "" || got.Err == "" {
		t.Fatal("changed file produced a digest paired with stale metadata")
	}
}

func TestAdaptiveByteBudgetIncludesSmallAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	var records []Record
	for i := range 12 {
		p := filepath.Join(dir, fmt.Sprint(i))
		data := []byte("a")
		if i == 0 {
			data = nil
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		records = append(records, suspectFile(p))
	}
	r := RunAdaptive(context.Background(), []Result{{Collector: "services", Records: records}}, AdaptiveOptions{NoSign: true})
	if len(r.Records) != 12 || r.Meta["hash_bytes_reserved"] != int64(11) {
		t.Fatalf("small files wasted the byte budget: %+v", r.Meta)
	}
	for _, rec := range r.Records {
		if rec.Fields["sha256"] == nil {
			t.Fatal("small/empty regular file was not hashed")
		}
	}
}
