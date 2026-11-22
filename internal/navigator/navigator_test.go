package navigator

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/attack"
	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

var update = flag.Bool("update", false, "rewrite the golden layers in testdata/")

// A fixed table, so the golden layers don't change when ATT&CK is refreshed.
const testTable = `# attack_version: 20.1
tactic	TA0001	initial-access	Initial Access
tactic	TA0002	execution	Execution
tactic	TA0005	stealth	Stealth
tactic	TA0112	defense-impairment	Defense Impairment
tactic	TA0006	credential-access	Credential Access
tactic	TA0011	command-and-control	Command and Control
tech	T1003	active	-	credential-access	OS Credential Dumping
tech	T1003.001	active	-	credential-access	LSASS Memory
tech	T1003.003	active	-	credential-access	NTDS
tech	T1003.006	active	-	credential-access	DCSync
tech	T1059	active	-	execution	Command and Scripting Interpreter
tech	T1059.001	active	-	execution	PowerShell
tech	T1071	active	-	command-and-control	Application Layer Protocol
tech	T1071.001	active	-	command-and-control	Web Protocols
tech	T1105	active	-	command-and-control	Ingress Tool Transfer
tech	T1219	active	-	command-and-control	Remote Access Tools
tech	T1562	revoked	T1685	-	Impair Defenses
tech	T1562.001	revoked	T1685	-	Disable or Modify Tools
tech	T1685	active	-	defense-impairment	Disable or Modify Tools
tech	T1043	deprecated	-	-	Commonly Used Port
tech	T1036	active	-	stealth	Masquerading
tech	T1566	active	-	initial-access	Phishing
tech	T1566.004	active	-	initial-access	Spearphishing Voice
`

func testOpts(t *testing.T) Options {
	t.Helper()
	tb, err := attack.Parse([]byte(testTable))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Table: tb, ReportSHA256: strings.Repeat("ab", 32)}
}

const secret = `C:\Users\alice\AppData\Local\Temp\payload.exe`

func finding(rule string, sev collector.Severity, tech string, conf int) collector.Finding {
	return collector.Finding{Rule: rule, Severity: sev, Technique: tech, Confidence: conf, Detail: "seen at " + secret}
}

func testReport() output.Report {
	return output.Report{
		Schema: output.SchemaVersion, Tool: "liveresponse-ng", Version: "0.21.0", RunID: "run-1", Host: "lab-dc01",
		OS: "windows", Arch: "amd64", Collected: time.Date(2026, 11, 22, 3, 4, 5, 0, time.UTC),
		Results: []collector.Result{
			{Collector: "defenses", Records: []collector.Record{
				{Fields: map[string]any{"path": secret}, Findings: []collector.Finding{
					finding("defense.amsi_patched", collector.SevCritical, "T1562.001", 95), // revoked: becomes T1685
					finding("defense.defender_exclusion", collector.SevSuspect, "T1685", 70),
				}},
			}},
			{Collector: "memory", Records: []collector.Record{
				{Fields: map[string]any{}, Findings: []collector.Finding{
					finding("cred.ntds_copy", collector.SevSuspect, "T1003.003", 80),
					finding("cred.ntds_copy", collector.SevCritical, "T1003.003", 90),
					finding("network.beacon", collector.SevNotable, "T1071.001", 40),
					finding("inventory.only", collector.SevInfo, "T1036", 10), // below the default minimum
					finding("misc.untagged", collector.SevSuspect, "", 50),    // no technique
					finding("misc.bogus", collector.SevSuspect, "T9999", 50),  // unknown ID
					finding("misc.retired", collector.SevNotable, "T1043", 30),
				}},
			}},
			{Collector: "eventlog",
				Meta: map[string]any{"sigma": map[string]any{"techniques": map[string][]string{"sigma.download_cradle": {"T1059.001", "T1105"}}}},
				Records: []collector.Record{
					{Fields: map[string]any{}, Findings: []collector.Finding{
						finding("sigma.download_cradle", collector.SevSuspect, "T1059.001", 65),
					}},
				}},
		},
	}
}

func encode(t *testing.T, l *Layer) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Encode(&buf, l); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (go test -update to accept):\n%s", name, got)
	}
}

func byID(l *Layer) map[string]Technique {
	m := map[string]Technique{}
	for _, t := range l.Techniques {
		m[t.TechniqueID] = t
	}
	return m
}

func TestBuildFindingsLayer(t *testing.T) {
	l, st, err := Build(testReport(), testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	got := encode(t, l)
	golden(t, "findings_layer.json", got)
	if bytes.Contains(got, []byte("alice")) || bytes.Contains(got, []byte("payload.exe")) {
		t.Fatal("a finding's detail or a record field leaked into the layer")
	}
	if l.Versions.Layer != "4.5" || l.Versions.Attack != "20.1" || l.Domain != "enterprise-attack" || l.Name == "" {
		t.Fatalf("header wrong: %+v", l.Versions)
	}
	techs := byID(l)
	if _, ok := techs["T1562.001"]; ok {
		t.Error("a revoked ID was written as-is")
	}
	t1685 := techs["T1685"]
	if t1685.Score == nil || *t1685.Score != 3 || !strings.Contains(t1685.Comment, "Mapped from T1562.001") ||
		!strings.HasPrefix(t1685.Comment, "defense.amsi_patched (critical), defense.defender_exclusion (suspect)") {
		t.Errorf("T1685 = %+v", t1685)
	}
	if ntds := techs["T1003.003"]; ntds.Score == nil || *ntds.Score != 3 || !strings.Contains(ntds.Comment, "cred.ntds_copy (×2, worst critical)") {
		t.Errorf("T1003.003 should take the worst of its findings: %+v", ntds)
	}
	if _, ok := techs["T1105"]; !ok {
		t.Error("a Sigma rule's second ATT&CK tag (meta.sigma.techniques) wasn't used")
	}
	if _, ok := techs["T1036"]; ok {
		t.Error("an info finding counted at the default minimum")
	}
	if !strings.Contains(techs["T1043"].Comment, "Deprecated") {
		t.Error("a deprecated technique isn't flagged")
	}
	if st.Qualifying != 9 || st.NoTechnique != 1 || st.Unknown["T9999"] != 1 || st.Remapped["T1562.001 -> T1685"] != 1 || st.Techniques != 6 {
		t.Errorf("stats = %+v", st)
	}
}

// -navigator-from reads a saved report: Meta comes back as plain JSON values.
// The layer must be the same as the one built from the live report.
func TestBuildFromSavedReportMatchesLive(t *testing.T) {
	rep := testReport()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var saved output.Report
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	live, _, err := Build(rep, testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	fromFile, _, err := Build(saved, testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encode(t, live), encode(t, fromFile)) {
		t.Fatal("a saved report gives a different layer from the live one")
	}
	again, _, _ := Build(rep, testOpts(t))
	if !bytes.Equal(encode(t, live), encode(t, again)) {
		t.Fatal("the same report gave different bytes")
	}
}

func TestBuildMinSeverity(t *testing.T) {
	opts := testOpts(t)
	opts.MinSeverity = collector.SevCritical
	l, st, err := Build(testReport(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if st.Qualifying != 2 || len(l.Techniques) != 2 || l.Gradient == nil || len(l.Gradient.Colors) < 2 || l.Gradient.MaxValue <= l.Gradient.MinValue {
		t.Errorf("critical-only layer: %d findings, %d techniques, gradient %+v", st.Qualifying, len(l.Techniques), l.Gradient)
	}
	opts.MinSeverity = collector.SevInfo
	l, _, err = Build(testReport(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if s := byID(l)["T1036"].Score; s == nil || *s != 0 || l.Gradient.MinValue != 0 || len(l.Gradient.Colors) != 4 {
		t.Errorf("info minimum: T1036 score %v, gradient %+v", s, l.Gradient)
	}
	opts.MinSeverity = "loud"
	if _, _, err := Build(testReport(), opts); err == nil {
		t.Error("an unknown severity was accepted")
	}
}

const expectedProfile = `# Lab emulation plan
| Tactic | Technique (ID) |
| --- | --- |
| Credential Access | OS Credential Dumping: NTDS (T1003.003) |
| Credential Access | OS Credential Dumping: LSASS (T1003.001) |
| Credential Access | DCSync (T1003.006) |
| Defense Impairment | Impair Defenses (T1562.001) |
| Execution | Command and Scripting Interpreter (T1059) |
| Command and Control | Remote Access Tools (T1219) |
| Bogus | T8888 |
- Out of scope: help desk vishing T1566.004 and impersonation T1036, plus T1071.001
`

func TestCoverageLayer(t *testing.T) {
	exp, err := ParseExpected([]byte(expectedProfile), "profile.md")
	if err != nil {
		t.Fatal(err)
	}
	l, cs, err := Coverage(testReport(), exp, testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	got := encode(t, l)
	golden(t, "coverage_layer.json", got)
	if bytes.Contains(got, []byte("alice")) {
		t.Fatal("detail leaked into the coverage layer")
	}
	states := map[string]string{}
	for _, tc := range l.Techniques {
		states[tc.TechniqueID] = tc.Metadata[0].Value
	}
	want := map[string]string{
		"T1003.003": "detected", // exact
		"T1685":     "detected", // expected as revoked T1562.001, found as revoked T1562.001
		"T1059":     "detected", // parent expected, sub-technique T1059.001 fired
		"T1059.001": "detected", // counts toward its expected parent
		"T1003.001": "missed",
		"T1003.006": "missed",
		"T1219":     "missed",
		"T1105":     "extra",
		"T1043":     "extra",
		"T1071.001": "detected", // marked out of scope, but detected anyway
		"T1036":     "out of scope",
	}
	for id, s := range want {
		if states[id] != s {
			t.Errorf("%s: %q, want %q", id, states[id], s)
		}
	}
	if cs.Expected != 6 || cs.Detected != 3 || cs.Partial != 0 || cs.Missed != 3 || cs.Extra != 2 || cs.OutOfScope != 2 {
		t.Errorf("stats = %+v", cs)
	}
	if cs.Rate() != 50 || !strings.Contains(cs.Line(), "detected 3 (50%)") {
		t.Errorf("rate %.1f, line %q", cs.Rate(), cs.Line())
	}
	if strings.Join(cs.ExpectedUnknown, ",") != "T8888" {
		t.Errorf("unknown expected IDs = %v", cs.ExpectedUnknown)
	}
	for _, tc := range l.Techniques {
		if tc.TechniqueID == "T1036" && (tc.Enabled || tc.Color != "") {
			t.Errorf("an out-of-scope technique should be disabled and uncolored: %+v", tc)
		}
	}
}

func TestCoveragePartial(t *testing.T) {
	exp, err := ParseExpected([]byte("T1071.001 and T1003.001"), "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	rep := testReport()
	rep.Results = append(rep.Results, collector.Result{Collector: "network", Records: []collector.Record{{Fields: map[string]any{},
		Findings: []collector.Finding{finding("network.generic", collector.SevSuspect, "T1003", 50)}}}})
	l, cs, err := Coverage(rep, exp, testOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, tc := range l.Techniques {
		states[tc.TechniqueID] = tc.Metadata[0].Value
	}
	if states["T1003.001"] != "partial" || states["T1003"] != "partial" || states["T1071.001"] != "detected" || cs.Partial != 1 || cs.Detected != 1 {
		t.Errorf("partial matching: states %v, stats %+v", states, cs)
	}
}

func TestParseExpectedLayer(t *testing.T) {
	layer := `{"name":"G1015","domain":"enterprise-attack","versions":{"layer":"4.5"},"techniques":[
	 {"techniqueID":"T1003.003","score":1},{"techniqueID":"T1566.004","enabled":false},{"techniqueID":"T1219","enabled":true}]}`
	e, err := ParseExpected([]byte(layer), "g1015.json")
	if err != nil {
		t.Fatal(err)
	}
	if !e.IDs["T1003.003"] || !e.IDs["T1219"] || !e.OutOfScope["T1566.004"] || len(e.IDs) != 2 {
		t.Errorf("parsed %+v", e)
	}
	for name, body := range map[string]string{
		"mobile layer":   `{"domain":"mobile-attack","techniques":[{"techniqueID":"T1003"}]}`,
		"bad ID":         `{"domain":"enterprise-attack","techniques":[{"techniqueID":"T1003; drop"}]}`,
		"broken JSON":    `{"domain":`,
		"no IDs at all":  "nothing to see here",
		"only out scope": "Out of scope: T1566.004",
		"not UTF-8":      "T1003 \xff",
	} {
		if _, err := ParseExpected([]byte(body), name); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
	if _, err := ParseExpected(bytes.Repeat([]byte("T1003 "), MaxExpectedBytes/6+1), "big"); err == nil {
		t.Error("an oversized file was accepted")
	}
}

// The bundled table, not the test one: a report from v0.20.0 (T1562.001)
// lands on the current ID.
func TestBundledRemap(t *testing.T) {
	rep := testReport()
	l, _, err := Build(rep, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := byID(l)["T1685"]; !ok {
		t.Fatal("T1562.001 didn't map to T1685 with the bundled table")
	}
	tb, _ := attack.Bundled()
	if l.Versions.Attack != tb.Version {
		t.Errorf("layer says ATT&CK %s, table is %s", l.Versions.Attack, tb.Version)
	}
}
