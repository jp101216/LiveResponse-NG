package casefile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func sample(id string, hour int) output.Report {
	return output.Report{Schema: "1.2", Tool: "liveresponse-ng", Version: "test", RunID: id, Host: "HOST01", OS: "windows", Arch: "amd64", Collected: time.Date(2026, 11, 1, hour, 0, 0, 0, time.UTC), Results: []collector.Result{}}
}

func rec(fields map[string]any) collector.Record { return collector.Record{Fields: fields} }
func service(name, image string) collector.Record {
	return rec(map[string]any{"name": name, "image_path": image, "start": "automatic"})
}
func writeSample(t testing.TB, path string, rep output.Report) []byte {
	t.Helper()
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCasePreservesBoundariesHashesAndOriginalFields(t *testing.T) {
	dir := t.TempDir()
	a, b := sample("run-a", 1), sample("run-b", 2)
	a.Results = []collector.Result{{Collector: "processes", Records: []collector.Record{rec(map[string]any{"pid": 42, "name": "before"})}}}
	b.Results = []collector.Result{{Collector: "processes", Records: []collector.Record{rec(map[string]any{"pid": 42, "name": "different process"})}}}
	b.Results[0].Records[0].Findings = []collector.Finding{{Rule: "demo.rule", Severity: collector.SevSuspect, Confidence: 80}}
	b.Summary.Findings = 999 // untrusted rollup must not drive the case summary
	p, q := filepath.Join(dir, "before.json"), filepath.Join(dir, "after.json")
	data := writeSample(t, p, a)
	writeSample(t, q, b)
	// Unknown source data survives import, even though the typed view does not
	// use it for analysis. The digest identifies these exact original bytes.
	data = bytes.Replace(data, []byte(`"tool_version"`), []byte(`"extra":{"large":9007199254740993},"tool_version"`), 1)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Build(context.Background(), []string{p, q}, Options{Name: "</script><script>untrusted</script>"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if len(c.Sources) != 2 || c.Sources[0].SHA256 != hex.EncodeToString(digest[:]) || !bytes.Equal(c.Sources[0].Report, data) || c.Sources[0].Name != "before.json" || c.Sources[1].Summary.Findings != 1 || c.Comparison != nil {
		t.Fatalf("case lost source boundaries or provenance: %+v", c)
	}
	for _, format := range []string{"json", "html"} {
		var out bytes.Buffer
		if err := Write(&out, c, format, false); err != nil {
			t.Fatal(err)
		}
		if format == "json" && !json.Valid(out.Bytes()) || format == "html" && strings.Contains(out.String(), c.Name) {
			t.Fatal("invalid JSON or unescaped HTML case data")
		}
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, data) {
		t.Fatal("import modified the original evidence")
	}
	if err := Write(&bytes.Buffer{}, c, "jsonl", false); err == nil {
		t.Fatal("multi-run JSONL must not masquerade as one run")
	}
}

func TestComparisonSeparatesConfigurationCoverageAndAmbiguity(t *testing.T) {
	dir := t.TempDir()
	a, b := sample("before", 1), sample("after", 2)
	a.Results = []collector.Result{{Collector: "services", Records: []collector.Record{
		service("Changed", `C:\Example\v1.exe`), service("Same", "same.exe"), service("OnlyBefore", "old.exe"), service("Duplicate", "one.exe"), service("duplicate", "two.exe"), service("Coverage", "c.exe"), rec(map[string]any{"name": "NoFields"}),
	}}, {Collector: "processes", Records: []collector.Record{rec(map[string]any{"pid": 100, "image_path": "a.exe"})}}}
	b.Results = []collector.Result{{Collector: "services", Records: []collector.Record{
		service("CHANGED", `C:\Example\v2.exe`), service("same", "same.exe"), service("OnlyAfter", "new.exe"), service("DUPLICATE", "one.exe"), service("coverage", "c.exe"), rec(map[string]any{"name": "NoFields"}),
	}}, {Collector: "processes", Records: []collector.Record{rec(map[string]any{"pid": 100, "image_path": "b.exe"})}}}
	a.Results[0].Records[1].Fields["key_last_write"] = "2026-10-01T01:00:00Z"
	b.Results[0].Records[1].Fields["key_last_write"] = "2026-11-01T02:00:00Z"
	b.Results[0].Records[4].Fields["account"] = "LocalService" // missing before is unknown, not a blank account
	b.Results[0].Records[1].Findings = []collector.Finding{{Rule: "new.detector", Severity: collector.SevInfo}}
	p, q := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	writeSample(t, p, a)
	writeSample(t, q, b)
	c, err := Build(context.Background(), []string{p, q}, Options{Compare: true, SameHost: true})
	if err != nil {
		t.Fatal(err)
	}
	g := c.Comparison.Collectors[0]
	kinds := map[string]int{}
	for _, change := range g.Changes {
		kinds[change.Kind]++
		if change.Kind == "changed" && !reflect.DeepEqual(change.Fields, []string{"image_path"}) {
			t.Fatalf("wrong configuration projection: %+v", change)
		}
		for _, ref := range append(change.Before, change.After...) {
			if ref.Source != c.Sources[0].ID && ref.Source != c.Sources[1].ID || ref.Result != 0 || ref.Record < 0 {
				t.Fatalf("invalid source reference: %+v", ref)
			}
		}
	}
	want := map[string]int{"changed": 1, "ambiguous": 1, "field_coverage": 1, "only_before": 1, "only_after": 1}
	if !reflect.DeepEqual(kinds, want) || g.Unchanged != 1 || g.Uncompared != 1 || g.Coverage != "observations" || len(c.Comparison.Collectors) != 4 || c.Comparison.Collectors[1].Coverage != "unavailable" {
		t.Fatalf("bad comparison: %+v; kinds %+v", g, kinds)
	}
	// Reused process IDs aren't compared, and interruption/errors must change
	// unmatched observations into unresolved coverage rather than removals.
	b.Run.Interrupted = true
	b.Results[0].Errors = []string{"access denied"}
	writeSample(t, q, b)
	c, err = Build(context.Background(), []string{p, q}, Options{Compare: true, SameHost: true})
	if err != nil {
		t.Fatal(err)
	}
	g = c.Comparison.Collectors[0]
	if g.Coverage != "partial" || len(g.Reasons) == 0 {
		t.Fatalf("partial coverage hidden: %+v", g)
	}
	for _, change := range g.Changes {
		if change.Kind == "only_before" || change.Kind == "only_after" {
			t.Fatal("partial collections presented as ordinary unmatched observations")
		}
	}
}

func TestComparisonCannotGuessMachineIdentityOrTimeOrder(t *testing.T) {
	dir := t.TempDir()
	p, q := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	a, b := sample("a", 1), sample("b", 2)
	writeSample(t, p, a)
	writeSample(t, q, b)
	if _, err := Build(context.Background(), []string{p, q}, Options{Compare: true}); err == nil {
		t.Fatal("hostname matching silently asserted machine identity")
	}
	for _, mutate := range []func(*output.Report){
		func(r *output.Report) { r.Host = "another-host" },
		func(r *output.Report) { r.OS = "linux" },
		func(r *output.Report) { r.Arch = "arm64" },
		func(r *output.Report) { r.Collected = a.Collected },
		func(r *output.Report) { r.Collected = a.Collected.Add(-time.Second) },
		func(r *output.Report) { r.Host = "(offline)" },
	} {
		other := b
		mutate(&other)
		writeSample(t, q, other)
		if _, err := Build(context.Background(), []string{p, q}, Options{Compare: true, SameHost: true}); err == nil {
			t.Fatalf("accepted incompatible scope: %+v", other)
		}
	}
}

func TestCaseRejectsAmbiguousMalformedAndExcessiveInput(t *testing.T) {
	dir := t.TempDir()
	p, q := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	a := sample("a", 1)
	a.Results = []collector.Result{{Collector: "services", Records: []collector.Record{service("Example", "example.exe")}}}
	data := writeSample(t, p, a)
	for _, input := range [][]byte{
		append(append([]byte{}, data...), data...),
		bytes.Replace(data, []byte(`"run_id":"a"`), []byte(`"run_id":"a","run_id":"b"`), 1),
		bytes.Replace(data, []byte(`"run_id":"a"`), []byte(`"run_id":"a","RUN_ID":"b"`), 1),
		bytes.Replace(data, []byte(`"collector":`), []byte(`"Collector":`), 1),
		bytes.Replace(data, []byte(`"schema_version":"1.2"`), []byte(`"schema_version":"9.9"`), 1),
		bytes.Replace(data, []byte(`"fields":{`), []byte(`"Fields":{`), 1),
		bytes.Replace(data, []byte(`"run":{`), []byte(`"Run":{`), 1),
		[]byte(`{"type":"run","run_id":"a"}` + "\n" + `{"type":"collector","collector":"services"}`),
		[]byte(`{"bad":` + strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70) + "}"),
		{0xff, '{', '}'},
	} {
		if err := os.WriteFile(q, input, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(context.Background(), []string{q}, Options{}); err == nil {
			t.Fatalf("accepted ambiguous or malformed report: %.150s", input)
		}
	}
	if _, err := Build(context.Background(), []string{p, p}, Options{}); err == nil {
		t.Fatal("accepted duplicate file")
	}
	a.Version = "other export"
	writeSample(t, q, a)
	if _, err := Build(context.Background(), []string{p, q}, Options{}); err == nil {
		t.Fatal("accepted conflicting exports with the same run ID")
	}
	a.RunID = "duplicate-collectors"
	a.Results = append(a.Results, a.Results[0])
	writeSample(t, q, a)
	if _, err := Build(context.Background(), []string{q}, Options{}); err == nil {
		t.Fatal("accepted ambiguous collector names")
	}
	if _, err := Build(context.Background(), []string{dir}, Options{}); err == nil {
		t.Fatal("read a non-regular input")
	}
	f, err := os.Create(q)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(MaxFileBytes + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), []string{q}, Options{}); err == nil {
		t.Fatal("accepted oversized file")
	}
	if _, err := Build(context.Background(), make([]string, MaxSources+1), Options{}); err == nil {
		t.Fatal("accepted excessive source count")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, []string{p}, Options{}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestArtifactKeysRespectUserAndLinuxPathScope(t *testing.T) {
	a := map[string]any{"kind": "run", "location": `HKU\Software\Run`, "name": "Example", "user_sid": "S-1-5-21-1"}
	b := map[string]any{"kind": "run", "location": `HKU\Software\Run`, "name": "Example", "user_sid": "S-1-5-21-2"}
	if artifactKey("autoruns", a, "windows") == artifactKey("autoruns", b, "windows") {
		t.Fatal("different users were merged")
	}
	a = map[string]any{"kind": "systemd_unit", "source": "/etc/systemd/system", "unit": "Example.service"}
	b = map[string]any{"kind": "systemd_unit", "source": "/etc/systemd/system", "unit": "example.service"}
	if artifactKey("autoruns", a, "linux") == artifactKey("autoruns", b, "linux") || artifactKey("processes", map[string]any{"pid": 42}, "windows") != "" {
		t.Fatal("case-sensitive paths or volatile IDs were incorrectly normalized")
	}
}

func TestTasksDriverBindingsAndLinuxPersistence(t *testing.T) {
	a, z := sample("a", 1), sample("z", 2)
	a.Results = []collector.Result{
		{Collector: "scheduledtasks", Records: []collector.Record{rec(map[string]any{"task_path": `\Example`, "actions": []any{map[string]any{"command": "example.exe", "arguments": "--old"}}})}},
		{Collector: "drivers", Records: []collector.Record{
			rec(map[string]any{"kind": "driver", "path": `C:\Windows\example.sys`, "loaded": true, "services": []any{"ExampleA", "ExampleB"}, "start": "automatic"}),
			rec(map[string]any{"kind": "driver", "path": `C:\Windows\unloaded.sys`, "loaded": true}),
		}},
	}
	z.Results = []collector.Result{
		{Collector: "scheduledtasks", Records: []collector.Record{rec(map[string]any{"task_path": `\EXAMPLE`, "actions": []any{map[string]any{"command": "example.exe", "arguments": "--new"}}})}},
		{Collector: "drivers", Records: []collector.Record{
			rec(map[string]any{"kind": "driver", "path": `C:\WINDOWS\EXAMPLE.SYS`, "loaded": true, "services": []any{"EXAMPLEB", "examplea"}, "start": "manual"}),
			rec(map[string]any{"kind": "driver", "path": `C:\Windows\unloaded.sys`, "loaded": false}),
		}},
	}
	c, err := compare(Source{ID: "before", decoded: a}, Source{ID: "after", decoded: z})
	if err != nil {
		t.Fatal(err)
	}
	tasks, drivers := c.Collectors[1], c.Collectors[3]
	if len(tasks.Changes) != 1 || !reflect.DeepEqual(tasks.Changes[0].Fields, []string{"actions"}) || len(drivers.Changes) != 1 || drivers.Unchanged != 1 || !reflect.DeepEqual(drivers.Changes[0].Fields, []string{"loaded"}) {
		t.Fatalf("task action or binding order semantics lost: %+v %+v", tasks, drivers)
	}
	// Do not mutate the original binding order while normalizing for comparison.
	if !reflect.DeepEqual(a.Results[1].Records[0].Fields["services"], []any{"ExampleA", "ExampleB"}) {
		t.Fatal("comparison mutated source fields")
	}
	a.OS, z.OS = "linux", "linux"
	a.Results = []collector.Result{{Collector: "autoruns", Records: []collector.Record{
		rec(map[string]any{"kind": "systemd_unit", "source": "/etc/systemd/system", "unit": "example.service", "exec_start": []any{"/usr/bin/example --old"}}),
		rec(map[string]any{"kind": "cron", "source": "/etc/crontab", "command": "/usr/bin/example"}),
	}}}
	z.Results = []collector.Result{{Collector: "autoruns", Records: []collector.Record{
		rec(map[string]any{"kind": "systemd_unit", "source": "/etc/systemd/system", "unit": "example.service", "exec_start": []any{"/usr/bin/example --new"}}),
		rec(map[string]any{"kind": "cron", "source": "/etc/crontab", "command": "/usr/bin/example --new"}),
	}}}
	c, err = compare(Source{ID: "before", decoded: a}, Source{ID: "after", decoded: z})
	if err != nil {
		t.Fatal(err)
	}
	linux := c.Collectors[2]
	if len(linux.Changes) != 1 || !reflect.DeepEqual(linux.Changes[0].Fields, []string{"exec_start"}) || linux.UnkeyedBefore != 1 || linux.UnkeyedAfter != 1 {
		t.Fatalf("unsupported Linux artifacts were silently paired: %+v", linux)
	}
}

func TestCaseRecordBudget(t *testing.T) {
	rep := sample("large", 1)
	records := make([]collector.Record, MaxRecords+1)
	for i := range records {
		records[i] = rec(map[string]any{})
	}
	rep.Results = []collector.Result{{Collector: "services", Records: records}}
	path := filepath.Join(t.TempDir(), "large.json")
	writeSample(t, path, rep)
	if _, err := Build(context.Background(), []string{path}, Options{}); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("record budget not enforced: %v", err)
	}
}

func BenchmarkComparePersistence(b *testing.B) {
	// Repeatable scale fixture, not a claim of accuracy against a vendor.
	a, z := sample("before", 1), sample("after", 2)
	ra := collector.Result{Collector: "services", Records: []collector.Record{}}
	rb := collector.Result{Collector: "services", Records: []collector.Record{}}
	for i := 0; i < 10000; i++ {
		name := "service-" + time.Duration(i).String()
		ra.Records = append(ra.Records, service(name, "v1.exe"))
		image := "v1.exe"
		if i%100 == 0 {
			image = "v2.exe"
		}
		rb.Records = append(rb.Records, service(name, image))
	}
	a.Results, z.Results = []collector.Result{ra}, []collector.Result{rb}
	left, right := Source{ID: "before", decoded: a}, Source{ID: "after", decoded: z}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := compare(left, right)
		if err != nil || len(c.Collectors[0].Changes) != 100 || c.Collectors[0].Unchanged != 9900 {
			b.Fatalf("benchmark lost ground truth: %v", err)
		}
	}
}

func FuzzDecodeReport(f *testing.F) {
	data, _ := json.Marshal(sample("seed", 1))
	f.Add(data)
	f.Add([]byte(`{"run_id":"x","RUN_ID":"y"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		_, _ = decodeReport(data)
	})
}
