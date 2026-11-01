package collector

import (
	"strings"
	"testing"
	"time"
)

func TestCodeIntegrityEvents(t *testing.T) {
	ev := func(id int, data map[string]string) winEvent {
		return winEvent{EventID: id, Provider: "Microsoft-Windows-CodeIntegrity", Channel: "Microsoft-Windows-CodeIntegrity/Operational",
			TimeCreated: time.Date(2026, 10, 31, 9, 8, 7, 0, time.UTC), UserData: map[string]string{}, Data: data}
	}
	// szkg64.sys (a listed vulnerable driver) by its Authenticode SHA-256,
	// as Code Integrity writes it (upper case), and nothing else.
	szkg := map[string]string{
		"File Name":           `\Device\HarddiskVolume3\Users\Public\szkg64.sys`,
		"Process Name":        `\Device\HarddiskVolume3\Windows\System32\services.exe`,
		"SHA256 Hash":         "95CA14E045618FB38834D17C5CC176162A29D846C1463B840C9129FB9AF47C68",
		"SI Signing Scenario": "0",
		"PolicyName":          "Microsoft Windows Driver Policy",
	}
	fs := eventFindings(ev(3077, szkg))
	if len(fs) != 1 || fs[0].Rule != "privesc.vulnerable_driver_blocked" || fs[0].Severity != SevSuspect ||
		!strings.Contains(fs[0].Detail, "Authenticode SHA-256") || !strings.Contains(fs[0].Detail, "policy Microsoft Windows Driver Policy") ||
		!strings.Contains(fs[0].Detail, "2026-10-31T09:08:07Z") {
		t.Errorf("listed driver blocked: %+v", fs)
	}
	// The same driver under a policy that only audits: it was loaded.
	fs = eventFindings(ev(3076, szkg))
	if len(fs) != 1 || fs[0].Rule != "privesc.vulnerable_driver_loaded" || !strings.Contains(fs[0].Detail, "only auditing") {
		t.Errorf("listed driver audited: %+v", fs)
	}
	// A listed malicious driver, by its flat SHA-256: critical even though blocked.
	fs = eventFindings(ev(3033, map[string]string{
		"File Name":        `System32\drivers\driver_090d409f.sys`,
		"SHA256 Flat Hash": "090d409f86430e078694e621ad0bd5e458d32aa727f0eb99bda3961577df8d49",
	}))
	if len(fs) != 1 || fs[0].Rule != "persistence.malicious_driver" || fs[0].Severity != SevCritical ||
		!strings.Contains(fs[0].Detail, "was blocked from loading") {
		t.Errorf("malicious driver blocked: %+v", fs)
	}
	// An unlisted driver refused.
	fs = eventFindings(ev(3077, map[string]string{"File Name": `\Device\HarddiskVolume3\Temp\rk.sys`, "SHA256 Flat Hash": strings.Repeat("ab", 32)}))
	if len(fs) != 1 || fs[0].Rule != "defense.driver_load_blocked" || fs[0].Severity != SevNotable {
		t.Errorf("unlisted driver blocked: %+v", fs)
	}
	// A DLL kept out of LSASS by LSA protection.
	fs = eventFindings(ev(3033, map[string]string{"File Name": `\Device\HarddiskVolume3\Windows\System32\mimilib.dll`,
		"Process Name": `\Device\HarddiskVolume3\Windows\System32\lsass.exe`, "SI Signing Scenario": "1"}))
	if len(fs) != 1 || fs[0].Rule != "cred.lsa_plugin_blocked" || !strings.Contains(fs[0].Detail, "mimilib.dll") {
		t.Errorf("plugin kept out of LSASS: %+v", fs)
	}
	// Quiet: an App Control block of an ordinary DLL, an audited unlisted
	// driver, the signature-information event, another provider's 3077.
	quiet := []winEvent{
		ev(3077, map[string]string{"File Name": `C:\Users\bob\AppData\Local\app\x.dll`, "Process Name": `C:\Program Files\App\app.exe`, "SI Signing Scenario": "1"}),
		ev(3076, map[string]string{"File Name": `\Device\HarddiskVolume3\Windows\System32\drivers\vendor.sys`}),
		ev(3089, map[string]string{"File Name": `x.sys`}),
	}
	other := ev(3077, szkg)
	other.Provider, other.Channel = "Microsoft-Windows-Something", "Application"
	quiet = append(quiet, other)
	for _, q := range quiet {
		if fs := eventFindings(q); len(fs) != 0 {
			t.Errorf("event %d (%s): %+v", q.EventID, q.Data["File Name"], fs)
		}
	}
}
