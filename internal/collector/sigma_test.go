package collector

import (
	"strings"
	"testing"
	"time"
)

func mustRuleset(t *testing.T, src string) *SigmaRuleset {
	t.Helper()
	docs, err := parseYAMLDocuments([]byte(src))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	rs := &SigmaRuleset{}
	for _, d := range docs {
		r, reason := compileSigmaRule(d)
		if reason != "" {
			t.Fatalf("rule unexpectedly skipped: %s", reason)
		}
		rs.rules = append(rs.rules, r)
		rs.Loaded++
	}
	return rs
}

func compileReason(t *testing.T, src string) string {
	t.Helper()
	docs, err := parseYAMLDocuments([]byte(src))
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	_, reason := compileSigmaRule(docs[0])
	return reason
}

func ev(eventID int, channel string, kv ...string) winEvent {
	data := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		data[kv[i]] = kv[i+1]
	}
	return winEvent{EventID: eventID, Channel: channel, Data: data, UserData: map[string]string{}}
}

func TestSigmaProcessCreationMatch(t *testing.T) {
	rs := mustRuleset(t, `title: Encoded PowerShell
logsource: {category: process_creation, product: windows}
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
tags: [attack.t1059.001]
level: high
`)
	hit := ev(4688, "Security",
		"NewProcessName", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine", `powershell.exe -nop -w hidden -enc ZQBjAGgAbwA=`)
	f := rs.match(hit)
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %+v", f)
	}
	if f[0].Severity != SevSuspect || f[0].Technique != "T1059.001" {
		t.Errorf("finding = %+v, want suspect/T1059.001", f[0])
	}
	if f[0].Rule != "sigma.encoded_powershell" {
		t.Errorf("rule id = %q", f[0].Rule)
	}

	miss := ev(4688, "Security",
		"NewProcessName", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"CommandLine", `powershell.exe Get-Date`)
	if f := rs.match(miss); len(f) != 0 {
		t.Errorf("non-encoded command should not match: %+v", f)
	}

	// logsource category gate: the same fields in a non-4688 event don't match.
	wrongID := ev(4104, "Security", "CommandLine", "-enc ZZ")
	if f := rs.match(wrongID); len(f) != 0 {
		t.Errorf("logsource gate should exclude non-process-creation: %+v", f)
	}
}

func TestSigmaConditionAndNotFilter(t *testing.T) {
	rs := mustRuleset(t, `title: Suspicious With Filter
detection:
    selection:
        CommandLine|contains: '-enc'
    filter:
        CommandLine|contains: 'KnownGoodTool'
    condition: selection and not filter
level: medium
`)
	if f := rs.match(ev(1, "x", "CommandLine", "foo -enc bar")); len(f) != 1 {
		t.Errorf("selection without filter should match: %+v", f)
	}
	if f := rs.match(ev(1, "x", "CommandLine", "KnownGoodTool -enc bar")); len(f) != 0 {
		t.Errorf("filter should suppress the match: %+v", f)
	}
}

func TestSigmaListOfMaps(t *testing.T) {
	rs := mustRuleset(t, `title: Service Variants
detection:
    selection:
        - EventID: 7045
          ServiceName|contains: 'psexec'
        - EventID: 7045
          ImagePath|contains: '\users\public\'
    condition: selection
level: high
`)
	if f := rs.match(ev(7045, "System", "ImagePath", `C:\Users\Public\x.exe`)); len(f) != 1 {
		t.Errorf("second map should match: %+v", f)
	}
	if f := rs.match(ev(7045, "System", "ImagePath", `C:\Windows\System32\svc.exe`, "ServiceName", "W32Time")); len(f) != 0 {
		t.Errorf("neither map should match: %+v", f)
	}
}

func TestSigmaKeywords(t *testing.T) {
	rs := mustRuleset(t, `title: Cred Tools
detection:
    keywords:
        - 'mimikatz'
        - 'sekurlsa'
    condition: keywords
level: critical
`)
	if f := rs.match(ev(4104, "PS", "ScriptBlockText", "Invoke-Mimikatz -DumpCreds")); len(f) != 1 {
		t.Errorf("keyword should match across fields: %+v", f)
	}
	if f := rs.match(ev(4104, "PS", "ScriptBlockText", "Get-ChildItem")); len(f) != 0 {
		t.Errorf("benign should not match: %+v", f)
	}
}

func TestSigmaQuantifiers(t *testing.T) {
	oneOf := mustRuleset(t, `title: One Of
detection:
    selection_a:
        EventID: 4720
    selection_b:
        EventID: 4726
    condition: 1 of selection_*
level: low
`)
	if f := oneOf.match(ev(4720, "Security")); len(f) != 1 {
		t.Errorf("1 of selection_* should match on 4720: %+v", f)
	}
	if f := oneOf.match(ev(5000, "Security")); len(f) != 0 {
		t.Errorf("neither selection should match: %+v", f)
	}

	allOf := mustRuleset(t, `title: All Of
detection:
    sel_x:
        EventID: 4688
    sel_y:
        CommandLine|contains: 'whoami'
    condition: all of them
level: medium
`)
	if f := allOf.match(ev(4688, "Security", "CommandLine", "cmd /c whoami")); len(f) != 1 {
		t.Errorf("all of them should match when both do: %+v", f)
	}
	if f := allOf.match(ev(4688, "Security", "CommandLine", "cmd /c dir")); len(f) != 0 {
		t.Errorf("all of them should fail when one doesn't: %+v", f)
	}
}

func TestSigmaNumericAndExists(t *testing.T) {
	rs := mustRuleset(t, `title: Numeric Range
detection:
    selection:
        EventID|gte: 4000
        EventID|lt: 5000
    condition: selection
level: low
`)
	if f := rs.match(ev(4688, "Security")); len(f) != 1 {
		t.Errorf("4688 is in [4000,5000): %+v", f)
	}
	if f := rs.match(ev(7045, "System")); len(f) != 0 {
		t.Errorf("7045 is out of range: %+v", f)
	}
}

func TestSigmaUnsupportedModifierSkipped(t *testing.T) {
	// |base64 (the plain, non-offset encoding) and |utf16/|wide remain
	// unsupported, so a rule using one must be skipped rather than mis-scored.
	reason := compileReason(t, `title: Plain Base64 Rule
detection:
    selection:
        CommandLine|base64: 'whoami'
    condition: selection
level: high
`)
	if reason == "" {
		t.Fatal("a rule using |base64 must be skipped, not compiled")
	}
}

func TestSigmaWindash(t *testing.T) {
	rs := mustRuleset(t, `title: Windash Flag
detection:
    selection:
        CommandLine|windash|contains: ' -accepteula'
    condition: selection
level: medium
`)
	for _, cl := range []string{
		`sdelete.exe -accepteula c:\x`,
		`sdelete.exe /accepteula c:\x`,
		"sdelete.exe \u2013accepteula c:\\x", // en dash
		"sdelete.exe \u2014accepteula c:\\x", // em dash
	} {
		if f := rs.match(ev(4688, "Security", "CommandLine", cl)); len(f) != 1 {
			t.Errorf("windash should match %q: %+v", cl, f)
		}
	}
	if f := rs.match(ev(4688, "Security", "CommandLine", `sdelete.exe accepteula`)); len(f) != 0 {
		t.Errorf("windash must still require a dash char: %+v", f)
	}
}

func TestSigmaBase64Offset(t *testing.T) {
	rs := mustRuleset(t, `title: Base64 Encoded Command
detection:
    selection:
        CommandLine|base64offset|contains: 'cmd'
    condition: selection
level: high
`)
	// 'cmd' base64-encoded at each of the three alignments (the canonical
	// SigmaHQ base64offset outputs are Y21k, NtZ, jbW).
	for _, blob := range []string{"Y21k", "NtZ", "jbW"} {
		cl := "powershell -enc AAAA" + blob + "BBBB"
		if f := rs.match(ev(4688, "Security", "CommandLine", cl)); len(f) != 1 {
			t.Errorf("base64offset should match embedded %q: %+v", blob, f)
		}
	}
	if f := rs.match(ev(4688, "Security", "CommandLine", "nothing to see here")); len(f) != 0 {
		t.Errorf("base64offset should not match unrelated text: %+v", f)
	}
}

func TestSigmaKeepsOtherwiseDroppedEvent(t *testing.T) {
	rs := mustRuleset(t, `title: Any Notepad
detection:
    selection:
        Image|endswith: '\notepad.exe'
    condition: selection
level: low
`)
	e := ev(4688, "Security", "Image", `C:\Windows\notepad.exe`)
	_, findings, keep := classifyWinEvent(e, rs)
	if !keep {
		t.Fatal("a Sigma match must keep an otherwise-dropped 4688")
	}
	if hasFinding(findings, "sigma.any_notepad") == nil {
		t.Errorf("want sigma.any_notepad, got %+v", findings)
	}
	// With no ruleset the same high-volume event (no built-in finding) is dropped.
	if _, _, keep := classifyWinEvent(e, nil); keep {
		t.Error("a bare 4688 with no rule should be dropped")
	}
}

// aggFindings runs a ruleset's aggregation over a set of events and returns the
// flushed findings.
func aggFindings(rs *SigmaRuleset, evs ...winEvent) []Finding {
	a := rs.newAggregator()
	for _, e := range evs {
		a.observe(e)
	}
	var out []Finding
	for _, r := range a.flush() {
		out = append(out, r.Findings...)
	}
	return out
}

func TestSigmaAggregationCountBy(t *testing.T) {
	rs := mustRuleset(t, `title: Failed Logon Burst
logsource:
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection | count() by IpAddress > 3
level: high
`)
	burst := make([]winEvent, 0)
	for i := 0; i < 4; i++ { // 4 from the attacker (> 3), 2 from a neighbour
		burst = append(burst, ev(4625, "Security", "IpAddress", "203.0.113.9", "TargetUserName", "u"+itoa(i)))
	}
	burst = append(burst, ev(4625, "Security", "IpAddress", "10.0.0.5"))
	burst = append(burst, ev(4625, "Security", "IpAddress", "10.0.0.5"))

	f := aggFindings(rs, burst...)
	if len(f) != 1 {
		t.Fatalf("expected one aggregation finding (the attacker IP over threshold), got %+v", f)
	}
	if f[0].Rule != "sigma.failed_logon_burst" || f[0].Severity != SevSuspect {
		t.Errorf("finding = %+v", f[0])
	}
	if !strings.Contains(f[0].Detail, "203.0.113.9") {
		t.Errorf("detail should name the over-threshold group: %q", f[0].Detail)
	}
}

func TestSigmaAggregationBelowThreshold(t *testing.T) {
	rs := mustRuleset(t, `title: Many Failures
detection:
    selection:
        EventID: 4625
    condition: selection | count() > 5
level: medium
`)
	var evs []winEvent
	for i := 0; i < 3; i++ {
		evs = append(evs, ev(4625, "Security"))
	}
	if f := aggFindings(rs, evs...); len(f) != 0 {
		t.Errorf("3 events must not cross a > 5 threshold: %+v", f)
	}
}

func TestSigmaAggregationDistinctCount(t *testing.T) {
	// count(TargetUserName) by IpAddress > 2 — password spray: one source
	// hitting many distinct accounts.
	rs := mustRuleset(t, `title: Password Spray
detection:
    selection:
        EventID: 4625
    condition: selection | count(TargetUserName) by IpAddress > 2
level: high
`)
	var evs []winEvent
	for _, u := range []string{"alice", "bob", "carol", "alice"} { // 3 distinct from one IP
		evs = append(evs, ev(4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", u))
	}
	f := aggFindings(rs, evs...)
	if len(f) != 1 {
		t.Fatalf("3 distinct users (> 2) should fire once, got %+v", f)
	}
	if !strings.Contains(f[0].Detail, "distinct TargetUserName") {
		t.Errorf("detail should describe a distinct count: %q", f[0].Detail)
	}
}

func TestSigmaAggregationWindowedCount(t *testing.T) {
	// count() by IpAddress > 3 within a 5m window: a burst of 4 inside 5m fires,
	// but 4 spread across 20m (no 5m window holds > 3) does not — the whole-run
	// count would wrongly fire on the spread-out case.
	rs := mustRuleset(t, `title: Failed Logon Burst
logsource:
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by IpAddress > 3
level: high
`)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	var burst []winEvent
	for i := 0; i < 4; i++ {
		burst = append(burst, evAt(base.Add(time.Duration(i)*time.Minute), 4625, "Security", "IpAddress", "203.0.113.9"))
	}
	f := aggFindings(rs, burst...)
	if len(f) != 1 {
		t.Fatalf("4 failures within 4m should cross a >3/5m window: %+v", f)
	}
	if !strings.Contains(f[0].Detail, "203.0.113.9") || !strings.Contains(f[0].Detail, "within 5m0s") {
		t.Errorf("windowed detail should name the group and the window: %q", f[0].Detail)
	}

	var spread []winEvent
	for i := 0; i < 4; i++ {
		spread = append(spread, evAt(base.Add(time.Duration(i)*7*time.Minute), 4625, "Security", "IpAddress", "203.0.113.9"))
	}
	if f := aggFindings(rs, spread...); len(f) != 0 {
		t.Errorf("4 failures spread over 21m must not cross a 5m window: %+v", f)
	}

	// Events with no timestamp can't be placed in a window, so they never fire.
	var noTime []winEvent
	for i := 0; i < 5; i++ {
		noTime = append(noTime, ev(4625, "Security", "IpAddress", "203.0.113.9"))
	}
	if f := aggFindings(rs, noTime...); len(f) != 0 {
		t.Errorf("timestampless events must not fire a windowed rule: %+v", f)
	}
}

func TestSigmaAggregationWindowedDistinct(t *testing.T) {
	// count(TargetUserName) by IpAddress > 2 within 10m — password spray: one
	// source hitting many distinct accounts in a short window.
	rs := mustRuleset(t, `title: Password Spray
logsource:
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 10m
    condition: selection | count(TargetUserName) by IpAddress > 2
level: high
`)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	within := []winEvent{
		evAt(base, 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "alice"),
		evAt(base.Add(2*time.Minute), 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "bob"),
		evAt(base.Add(4*time.Minute), 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "carol"),
		evAt(base.Add(5*time.Minute), 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "alice"), // repeat, still 3 distinct
	}
	if f := aggFindings(rs, within...); len(f) != 1 {
		t.Fatalf("3 distinct users within 10m should fire: %+v", f)
	}

	spread := []winEvent{
		evAt(base, 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "alice"),
		evAt(base.Add(20*time.Minute), 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "bob"),
		evAt(base.Add(40*time.Minute), 4625, "Security", "IpAddress", "198.51.100.7", "TargetUserName", "carol"),
	}
	if f := aggFindings(rs, spread...); len(f) != 0 {
		t.Errorf("3 distinct users over 40m must not cross a 10m window: %+v", f)
	}
}

func TestSigmaAggregationWindowedSum(t *testing.T) {
	// sum(Size) > 100 within 1m — a volume burst.
	rs := mustRuleset(t, `title: Transfer Volume Burst
detection:
    selection:
        EventID: 3
    timeframe: 1m
    condition: selection | sum(Size) > 100
level: medium
`)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	within := []winEvent{
		evAt(base, 3, "x", "Size", "60"),
		evAt(base.Add(30*time.Second), 3, "x", "Size", "60"),
	}
	if f := aggFindings(rs, within...); len(f) != 1 {
		t.Fatalf("120 within 1m should cross sum > 100: %+v", f)
	}
	spread := []winEvent{
		evAt(base, 3, "x", "Size", "60"),
		evAt(base.Add(5*time.Minute), 3, "x", "Size", "60"),
	}
	if f := aggFindings(rs, spread...); len(f) != 0 {
		t.Errorf("60 + 60 more than 1m apart must not cross sum > 100 in any 1m window: %+v", f)
	}
}

func TestSigmaAggregationTimeframeUnsupportedSkipped(t *testing.T) {
	// A timeframe only has a sound sliding-window meaning for count/sum with
	// >/>=. Other functions or operators must be skipped, not silently counted
	// across the whole run (which would contradict the declared window).
	cases := map[string]string{
		"avg with timeframe": `title: Avg Windowed
detection:
    selection: {EventID: 3}
    timeframe: 5m
    condition: selection | avg(Size) by Host > 10
level: low
`,
		"less-than with timeframe": `title: Count LT Windowed
detection:
    selection: {EventID: 4625}
    timeframe: 5m
    condition: selection | count() < 2
level: low
`,
	}
	for name, src := range cases {
		if reason := compileReason(t, src); reason == "" {
			t.Errorf("%s: expected the rule to be skipped", name)
		}
	}
}

func TestSigmaAggregationNotPerEvent(t *testing.T) {
	// An aggregation rule must not fire from the per-event matcher.
	rs := mustRuleset(t, `title: Burst
detection:
    selection:
        EventID: 4625
    condition: selection | count() > 3
level: high
`)
	if f := rs.match(ev(4625, "Security")); len(f) != 0 {
		t.Errorf("an aggregation rule must not fire per-event: %+v", f)
	}
}

func TestSigmaAggregationNearSkipped(t *testing.T) {
	// A 'near' with no timeframe has no defined window, so it must be skipped
	// (the windowed case is covered by TestSigmaNearTemporal).
	reason := compileReason(t, `title: Temporal
detection:
    a:
        EventID: 4625
    b:
        EventID: 4624
    condition: a | near b
level: high
`)
	if reason == "" {
		t.Fatal("a temporal 'near' with no timeframe must be skipped, not compiled")
	}
}

func TestSigmaUnknownConditionIdentSkipped(t *testing.T) {
	reason := compileReason(t, `title: Typo Rule
detection:
    selection:
        EventID: 1
    condition: selektion
level: low
`)
	if reason == "" {
		t.Fatal("a condition naming an unknown search must be skipped")
	}
}

// evAt is ev with a TimeCreated set, for the temporal 'near' tests.
func evAt(ts time.Time, eventID int, channel string, kv ...string) winEvent {
	e := ev(eventID, channel, kv...)
	e.TimeCreated = ts
	return e
}

func TestSigmaCIDRMatch(t *testing.T) {
	rs := mustRuleset(t, `title: External RDP Logon
logsource:
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
    internal:
        IpAddress|cidr:
            - 10.0.0.0/8
            - 172.16.0.0/12
            - 192.168.0.0/16
            - 127.0.0.0/8
    condition: selection and not internal
level: medium
`)
	if f := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "203.0.113.5")); len(f) != 1 {
		t.Errorf("a public source address should match (not internal): %+v", f)
	}
	if f := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "10.1.2.3")); len(f) != 0 {
		t.Errorf("a 10.0.0.0/8 address is internal and must not match: %+v", f)
	}
	if f := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "192.168.4.4")); len(f) != 0 {
		t.Errorf("a 192.168.0.0/16 address is internal and must not match: %+v", f)
	}
	// An IPv4-mapped IPv6 form of a private address is still internal.
	if f := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "::ffff:10.1.2.3")); len(f) != 0 {
		t.Errorf("an IPv4-mapped private address must be recognised as internal: %+v", f)
	}
	// A non-IP value simply doesn't fall in any range (so 'not internal' holds).
	if f := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "-")); len(f) != 1 {
		t.Errorf("a '-' placeholder address is not in any range: %+v", f)
	}
}

func TestSigmaCIDRInvalidSkipped(t *testing.T) {
	if reason := compileReason(t, `title: Bad CIDR
detection:
    selection:
        IpAddress|cidr: 'not-a-network'
    condition: selection
level: low
`); reason == "" {
		t.Fatal("an unparseable |cidr value must skip the rule")
	}
	if reason := compileReason(t, `title: CIDR Plus Contains
detection:
    selection:
        IpAddress|cidr|contains: '10.0.0.0/8'
    condition: selection
level: low
`); reason == "" {
		t.Fatal("|cidr combined with another value modifier must skip the rule")
	}
}

func TestSigmaFieldRef(t *testing.T) {
	rs := mustRuleset(t, `title: Subject Equals Target
detection:
    selection:
        SubjectUserName|fieldref: TargetUserName
    condition: selection
level: low
`)
	if f := rs.match(ev(4624, "Security", "SubjectUserName", "Admin", "TargetUserName", "admin")); len(f) != 1 {
		t.Errorf("a case-insensitive fieldref should match equal values: %+v", f)
	}
	if f := rs.match(ev(4624, "Security", "SubjectUserName", "alice", "TargetUserName", "bob")); len(f) != 0 {
		t.Errorf("different field values must not match: %+v", f)
	}
	if f := rs.match(ev(4624, "Security", "SubjectUserName", "alice")); len(f) != 0 {
		t.Errorf("an absent referenced field must not match: %+v", f)
	}
}

func TestSigmaFieldRefContainsCased(t *testing.T) {
	rs := mustRuleset(t, `title: Image Contains Service Name
detection:
    selection:
        Image|fieldref|contains|cased: ServiceName
    condition: selection
level: low
`)
	if f := rs.match(ev(7045, "System", "Image", `C:\x\Updater.exe`, "ServiceName", "Updater")); len(f) != 1 {
		t.Errorf("an image containing the exact-case service name should match: %+v", f)
	}
	if f := rs.match(ev(7045, "System", "Image", `C:\x\updater.exe`, "ServiceName", "Updater")); len(f) != 0 {
		t.Errorf("a cased mismatch must not match: %+v", f)
	}
}

func TestSigmaAggregationSum(t *testing.T) {
	rs := mustRuleset(t, `title: Outbound Byte Sum
detection:
    selection:
        EventID: 3
    condition: selection | sum(Bytes) by DestinationIp > 1000
level: medium
`)
	var evs []winEvent
	for i := 0; i < 3; i++ { // 3 × 400 = 1200 > 1000 for the one IP
		evs = append(evs, ev(3, "Sysmon", "DestinationIp", "203.0.113.9", "Bytes", "400"))
	}
	evs = append(evs, ev(3, "Sysmon", "DestinationIp", "10.0.0.1", "Bytes", "100"))
	f := aggFindings(rs, evs...)
	if len(f) != 1 {
		t.Fatalf("a sum over the threshold should fire once, got %+v", f)
	}
	if !strings.Contains(f[0].Detail, "sum(Bytes)=1200") {
		t.Errorf("detail should describe the sum: %q", f[0].Detail)
	}
}

func TestSigmaAggregationAvg(t *testing.T) {
	rs := mustRuleset(t, `title: Average Size
detection:
    selection:
        EventID: 3
    condition: selection | avg(Size) > 10
level: low
`)
	var evs []winEvent
	for _, s := range []string{"5", "15", "25"} { // avg = 15 > 10
		evs = append(evs, ev(3, "Sysmon", "Size", s))
	}
	f := aggFindings(rs, evs...)
	if len(f) != 1 {
		t.Fatalf("avg 15 > 10 should fire, got %+v", f)
	}
	if !strings.Contains(f[0].Detail, "avg(Size)=15") {
		t.Errorf("detail should describe the average: %q", f[0].Detail)
	}
}

func TestSigmaAggregationMinMax(t *testing.T) {
	mkEvs := func() []winEvent {
		var evs []winEvent
		for _, c := range []string{"2", "7", "4"} {
			evs = append(evs, ev(4688, "Security", "Count", c))
		}
		return evs
	}
	maxRule := mustRuleset(t, `title: Max Count
detection:
    selection:
        EventID: 4688
    condition: selection | max(Count) > 5
level: low
`)
	if f := aggFindings(maxRule, mkEvs()...); len(f) != 1 {
		t.Errorf("max 7 > 5 should fire: %+v", f)
	}
	minRule := mustRuleset(t, `title: Min Count
detection:
    selection:
        EventID: 4688
    condition: selection | min(Count) > 5
level: low
`)
	if f := aggFindings(minRule, mkEvs()...); len(f) != 0 {
		t.Errorf("min is 2, not > 5, so it must not fire: %+v", f)
	}
}

func TestSigmaAggregationNonNumericIgnored(t *testing.T) {
	// A group whose field never parses as a number yields no min/max/avg/sum
	// metric, so it must not fire (rather than firing on a zero).
	rs := mustRuleset(t, `title: Sum Of Text
detection:
    selection:
        EventID: 3
    condition: selection | sum(Label) > 0
level: low
`)
	if f := aggFindings(rs, ev(3, "Sysmon", "Label", "alpha"), ev(3, "Sysmon", "Label", "beta")); len(f) != 0 {
		t.Errorf("a non-numeric field must not produce a sum finding: %+v", f)
	}
}

func TestSigmaAggregationFunctionNeedsField(t *testing.T) {
	if reason := compileReason(t, `title: Sum No Field
detection:
    selection:
        EventID: 3
    condition: selection | sum() > 10
level: low
`); reason == "" {
		t.Fatal("sum() with no field must be skipped")
	}
}

func TestSigmaNearTemporal(t *testing.T) {
	rs := mustRuleset(t, `title: Failed Logons Near A Success
logsource:
    service: security
detection:
    fail:
        EventID: 4625
    success:
        EventID: 4624
    timeframe: 1m
    condition: fail | near success
level: high
`)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	within := []winEvent{
		evAt(base, 4625, "Security"),
		evAt(base.Add(30*time.Second), 4624, "Security"),
	}
	f := aggFindings(rs, within...)
	if len(f) != 1 {
		t.Fatalf("a failure and a success 30s apart should fire a 1m near: %+v", f)
	}
	if f[0].Severity != SevSuspect || !strings.Contains(f[0].Detail, "1m0s") {
		t.Errorf("near finding = %+v", f[0])
	}

	outside := []winEvent{
		evAt(base, 4625, "Security"),
		evAt(base.Add(5*time.Minute), 4624, "Security"),
	}
	if f := aggFindings(rs, outside...); len(f) != 0 {
		t.Errorf("events 5m apart must not fire a 1m near: %+v", f)
	}

	// The near condition requires a success; failures alone do not fire.
	onlyFails := []winEvent{
		evAt(base, 4625, "Security"),
		evAt(base.Add(time.Second), 4625, "Security"),
	}
	if f := aggFindings(rs, onlyFails...); len(f) != 0 {
		t.Errorf("failures with no nearby success must not fire: %+v", f)
	}
}

func TestSigmaNearNotSkipped(t *testing.T) {
	// 'not' makes the temporal condition non-monotone, which the window sweep
	// can't evaluate soundly, so the rule must be skipped rather than mis-scored.
	if reason := compileReason(t, `title: Near With Not
detection:
    a:
        EventID: 4625
    b:
        EventID: 4624
    timeframe: 1m
    condition: a | near b and not a
level: low
`); reason == "" {
		t.Fatal("a near expression using 'not' must be skipped")
	}
}

func TestSigmaNearUnknownSelectionSkipped(t *testing.T) {
	if reason := compileReason(t, `title: Near Unknown
detection:
    a:
        EventID: 4625
    timeframe: 1m
    condition: a | near b
level: low
`); reason == "" {
		t.Fatal("a near expression naming an undefined selection must be skipped")
	}
}
