package collector

import (
	"testing"
	"time"
)

// TestBuiltinSigmaPackCompiles guards the shipped starter pack: every rule must
// use only constructs the engine supports, so none are skipped, and none fail
// to parse. A rule that regresses this is a rule that would silently never run.
func TestBuiltinSigmaPackCompiles(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	if rs.Loaded == 0 {
		t.Fatal("the builtin pack loaded no rules")
	}
	if len(rs.Skipped) != 0 {
		t.Errorf("builtin rules must all be supported, but %d were skipped: %v", len(rs.Skipped), rs.Skipped)
	}
	if len(rs.Failed) != 0 {
		t.Errorf("builtin rules must all parse, but %d failed: %v", len(rs.Failed), rs.Failed)
	}
	t.Logf("builtin pack: %d rules", rs.Loaded)
}

// TestBuiltinSigmaPackMatches spot-checks that representative malicious events
// trip the bundled rules, so the pack is wired to the fields lrng produces.
func TestBuiltinSigmaPackMatches(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		ev   winEvent
	}{
		{"encoded powershell", ev(4688, "Security",
			"NewProcessName", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine", `powershell.exe -nop -w hidden -enc ZQBjAGgAbwA=`)},
		{"shadow copy deletion", ev(4688, "Security",
			"CommandLine", `vssadmin.exe delete shadows /all /quiet`)},
		{"psexec service", ev(7045, "System",
			"ServiceName", "PSEXESVC", "ImagePath", `C:\Windows\PSEXESVC.exe`)},
		{"service in public path", ev(7045, "System",
			"ServiceName", "Updater", "ImagePath", `C:\Users\Public\x.exe`)},
		{"lsass dump", ev(4688, "Security",
			"CommandLine", `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 712 C:\temp\l.dmp full`)},
		{"mimikatz script", ev(4104, "Microsoft-Windows-PowerShell/Operational",
			"ScriptBlockText", `IEX (Invoke-Mimikatz -DumpCreds)`)},
		{"hidden account", ev(4720, "Security", "TargetUserName", `svc$`)},
	}
	for _, c := range cases {
		if f := rs.match(c.ev); len(f) == 0 {
			t.Errorf("%s: expected a builtin Sigma match, got none", c.name)
		}
	}
}

// TestBuiltinSigmaExternalRDP checks the |cidr builtin: an interactive RDP logon
// is tripped from a public source address but not from an internal one.
func TestBuiltinSigmaExternalRDP(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	pub := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "198.51.100.23"))
	if hasFinding(pub, "sigma.external_rdp_logon") == nil {
		t.Errorf("RDP from a public source should trip the external-RDP rule: %+v", pub)
	}
	intl := rs.match(ev(4624, "Security", "LogonType", "10", "IpAddress", "10.2.3.4"))
	if hasFinding(intl, "sigma.external_rdp_logon") != nil {
		t.Errorf("RDP from an internal (10/8) source must not trip the rule: %+v", intl)
	}
}

// TestBuiltinSigmaFailedLogonBurstWindowed checks the windowed count() builtin:
// a burst of failed logons from one source inside the 5m window fires, but the
// same number scattered across hours (which the old whole-run count would have
// wrongly flagged) does not.
func TestBuiltinSigmaFailedLogonBurstWindowed(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 4, 1, 3, 0, 0, 0, time.UTC)

	var burst []winEvent
	for i := 0; i < 12; i++ { // > 10, all within ~2m
		burst = append(burst, evAt(base.Add(time.Duration(i)*10*time.Second), 4625, "Security", "IpAddress", "203.0.113.9"))
	}
	if hasFinding(aggFindings(rs, burst...), "sigma.failed_logon_burst_from_single_source") == nil {
		t.Error("12 failed logons within 2m from one source should fire the burst rule")
	}

	var scattered []winEvent
	for i := 0; i < 12; i++ { // > 10, but one every 30m — no 5m window holds > 10
		scattered = append(scattered, evAt(base.Add(time.Duration(i)*30*time.Minute), 4625, "Security", "IpAddress", "203.0.113.9"))
	}
	if hasFinding(aggFindings(rs, scattered...), "sigma.failed_logon_burst_from_single_source") != nil {
		t.Error("12 failures scattered over 6h must not fire a 5m-windowed burst rule")
	}
}

// TestBuiltinSigmaPasswordSpray checks the windowed distinct-count builtin: one
// source failing against many distinct accounts in a short window.
func TestBuiltinSigmaPasswordSpray(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 4, 1, 3, 0, 0, 0, time.UTC)
	var spray []winEvent
	for i := 0; i < 12; i++ { // 12 distinct accounts from one source within ~2m
		spray = append(spray, evAt(base.Add(time.Duration(i)*10*time.Second), 4625, "Security",
			"IpAddress", "198.51.100.7", "TargetUserName", "user"+itoa(i)))
	}
	if hasFinding(aggFindings(rs, spray...), "sigma.password_spray_from_single_source") == nil {
		t.Error("12 distinct accounts from one source within 2m should fire the spray rule")
	}

	// The same source hammering ONE account is a brute force, not a spray: the
	// distinct-account count stays at 1, so the spray rule must stay quiet.
	var oneAccount []winEvent
	for i := 0; i < 12; i++ {
		oneAccount = append(oneAccount, evAt(base.Add(time.Duration(i)*10*time.Second), 4625, "Security",
			"IpAddress", "198.51.100.7", "TargetUserName", "victim"))
	}
	if hasFinding(aggFindings(rs, oneAccount...), "sigma.password_spray_from_single_source") != nil {
		t.Error("many failures against one account must not fire the spray rule")
	}
}

// TestBuiltinSigmaDefenderRTP checks the Defender channel builtin: a real-time
// protection availability event trips it, and an unrelated Defender event does not.
func TestBuiltinSigmaDefenderRTP(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	hit := rs.match(ev(5001, "Microsoft-Windows-Windows Defender/Operational"))
	if hasFinding(hit, "sigma.microsoft_defender_real_time_protection_change") == nil {
		t.Errorf("Defender event 5001 should trip the real-time-protection rule: %+v", hit)
	}
	miss := rs.match(ev(1150, "Microsoft-Windows-Windows Defender/Operational"))
	if hasFinding(miss, "sigma.microsoft_defender_real_time_protection_change") != nil {
		t.Errorf("an unrelated Defender event must not trip the rule: %+v", miss)
	}
}

// TestBuiltinSigmaLogClearedNearInstall checks the temporal 'near' builtin: a log
// clear within the timeframe of a service install correlates; far apart it does not.
func TestBuiltinSigmaLogClearedNearInstall(t *testing.T) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)
	near := []winEvent{
		evAt(base, 7045, "System", "ServiceName", "x", "ImagePath", `C:\Windows\x.exe`),
		evAt(base.Add(2*time.Minute), 1102, "Security"),
	}
	if hasFinding(aggFindings(rs, near...), "sigma.event_log_cleared_near_a_service_install") == nil {
		t.Error("a log clear 2m after a service install should fire the near builtin")
	}
	far := []winEvent{
		evAt(base, 7045, "System", "ServiceName", "x", "ImagePath", `C:\Windows\x.exe`),
		evAt(base.Add(30*time.Minute), 1102, "Security"),
	}
	if hasFinding(aggFindings(rs, far...), "sigma.event_log_cleared_near_a_service_install") != nil {
		t.Error("a log clear 30m after an install must not fire a 5m near")
	}
}
