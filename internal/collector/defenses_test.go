package collector

import (
	"strings"
	"testing"
	"time"
)

func TestJudgeExclusion(t *testing.T) {
	cases := []struct {
		e    exclusion
		sev  Severity
		want string
	}{
		{exclusion{Kind: "path", Value: `C:\Users\Public`}, SevSuspect, "the Public profile"},
		{exclusion{Kind: "path", Value: `C:\Users\bob\AppData\Local\Temp\`}, SevSuspect, "where payloads are dropped"},
		{exclusion{Kind: "path", Value: `C:\`}, SevSuspect, "a whole drive"},
		{exclusion{Kind: "path", Value: `D:`}, SevSuspect, "a whole drive"},
		{exclusion{Kind: "path", Value: `C:\ProgramData`, Policy: true}, SevSuspect, "set by group policy"},
		{exclusion{Kind: "path", Value: `C:\Program Files\Microsoft SQL Server\MSSQL\Data`}, SevNotable, "software vendors"},
		{exclusion{Kind: "extension", Value: ".ps1"}, SevSuspect, "run code"},
		{exclusion{Kind: "extension", Value: "exe"}, SevSuspect, "run code"},
		{exclusion{Kind: "extension", Value: ".mdf"}, SevNotable, "software vendors"},
		{exclusion{Kind: "process", Value: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}, SevSuspect, "runs whatever it is given"},
		{exclusion{Kind: "process", Value: "rundll32.exe"}, SevSuspect, "runs whatever it is given"},
		{exclusion{Kind: "process", Value: `C:\Program Files\Veeam\agent.exe`}, SevNotable, "software vendors"},
		{exclusion{Kind: "ip", Value: "203.0.113.9"}, SevNotable, "network protection"},
	}
	for _, c := range cases {
		f := judgeExclusion(c.e)
		if f.Rule != "defense.defender_exclusion" || f.Severity != c.sev || f.Technique != "T1562.001" || !strings.Contains(f.Detail, c.want) {
			t.Errorf("%+v: got [%s] %s", c.e, f.Severity, f.Detail)
		}
	}
}

func TestDefensesReport(t *testing.T) {
	on, off, four := uint32(1), uint32(0), uint32(4)
	res := NewResult("defenses")
	defensesReport(res, defenderState{
		Exclusions: []exclusion{{Kind: "path", Value: `C:\Windows\Temp`}, {Kind: "extension", Value: ".exe", Policy: true}},
		Settings: []setting{
			{Path: defenderKeyForTest + `\Real-Time Protection`, Name: "DisableRealtimeMonitoring", Value: 1},
			{Path: defenderKeyForTest, Name: "DisableAntiSpyware", Value: 0},
			{Path: `SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`, Name: "SpynetReporting", Value: 0, Policy: true},
		},
		Tamper: &four,
	}, credentialState{WDigest: &on, RunAsPPL: &off, RestrictedAdmin: &off, LmCompat: ptrU32(1)})
	got := res.Finish()
	if len(got.Records) != 2 {
		t.Fatalf("want a Defender and a credentials record: %+v", got.Records)
	}
	def := got.Records[0]
	rules := map[string]int{}
	for _, f := range def.Findings {
		rules[f.Rule+"/"+string(f.Severity)]++
	}
	if rules["defense.defender_exclusion/suspect"] != 2 || rules["defense.defender_protection_off/suspect"] != 1 ||
		rules["defense.defender_protection_off/notable"] != 2 {
		t.Errorf("Defender findings: %v", rules)
	}
	if def.Fields["exclusions_extension"].([]string)[0] != ".exe (policy)" || def.Fields["tamper_protection"] != four ||
		def.Fields["settings"].(map[string]uint32)["DisableAntiSpyware"] != 0 {
		t.Errorf("Defender record: %+v", def.Fields)
	}
	cred := got.Records[1]
	var names []string
	for _, f := range cred.Findings {
		names = append(names, f.Rule)
	}
	if strings.Join(names, ",") != "cred.wdigest_enabled,cred.lsa_protection_off,cred.restricted_admin_enabled,cred.ntlmv1_allowed" {
		t.Errorf("credential findings: %v", names)
	}
	if cred.Fields["wdigest_use_logon_credential"] != on || cred.Fields["lsa_cfg_flags"] != nil {
		t.Errorf("credentials record: %+v", cred.Fields)
	}

	// Windows' defaults read as nothing to report.
	res = NewResult("defenses")
	defensesReport(res, defenderState{Tamper: ptrU32(5)}, credentialState{WDigest: &off, LmCompat: ptrU32(3)})
	for _, r := range res.Finish().Records {
		if len(r.Findings) != 0 {
			t.Errorf("defaults: %+v", r.Findings)
		}
	}
	res = NewResult("defenses")
	defensesReport(res, defenderState{NotInstalled: true}, credentialState{})
	if r := res.Finish().Records[0]; r.Fields["installed"] != false || len(r.Findings) != 0 {
		t.Errorf("no Defender: %+v", r)
	}
}

const defenderKeyForTest = `SOFTWARE\Microsoft\Windows Defender`

func ptrU32(v uint32) *uint32 { return &v }

func TestDefenderEvents(t *testing.T) {
	ev := func(id int, data map[string]string) winEvent {
		return winEvent{EventID: id, Provider: "Microsoft-Windows-Windows Defender", Channel: "Microsoft-Windows-Windows Defender/Operational",
			TimeCreated: time.Date(2026, 10, 31, 7, 8, 9, 0, time.UTC), UserData: map[string]string{}, Data: data}
	}
	fs := eventFindings(ev(5007, map[string]string{
		"Old Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = `,
		"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0`}))
	if len(fs) != 1 || fs[0].Rule != "defense.defender_exclusion" || !strings.Contains(fs[0].Detail, "2026-10-31T07:08:09Z") ||
		!strings.Contains(fs[0].Detail, `Paths\C:\Users\Public`) {
		t.Errorf("exclusion added: %+v", fs)
	}
	fs = eventFindings(ev(5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1`}))
	if len(fs) != 1 || fs[0].Rule != "defense.defender_protection_off" {
		t.Errorf("real-time monitoring switched off: %+v", fs)
	}
	if fs := eventFindings(ev(5007, map[string]string{"New Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureUpdateCatchupInterval = 0x1`})); len(fs) != 0 {
		t.Errorf("an ordinary configuration change: %+v", fs)
	}
	for id, rule := range map[int]string{5001: "defense.defender_protection_off", 5010: "defense.defender_protection_off",
		5012: "defense.defender_protection_off", 5013: "defense.defender_tamper_blocked"} {
		if fs := eventFindings(ev(id, map[string]string{"Value": `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x`})); len(fs) != 1 || fs[0].Rule != rule {
			t.Errorf("event %d: %+v", id, fs)
		}
	}
	other := ev(5001, nil)
	other.Provider, other.Channel = "Microsoft-Windows-Something", "System"
	if fs := eventFindings(other); len(fs) != 0 {
		t.Errorf("event 5001 from another provider: %+v", fs)
	}
}
