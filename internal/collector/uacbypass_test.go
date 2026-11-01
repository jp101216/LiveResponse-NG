package collector

import (
	"strings"
	"testing"
	"time"
)

func TestMatchUACBypassPath(t *testing.T) {
	for _, c := range []struct {
		path, key, value string
		ok               bool
	}{
		{`HKU\S-1-5-21-1-2-3-1001_Classes\ms-settings\Shell\Open\command\(Default)`, `ms-settings\shell\open\command`, "", true},
		{`HKU\S-1-5-21-1-2-3-1001\Software\Classes\ms-settings\shell\open\command\DelegateExecute`, `ms-settings\shell\open\command`, "delegateexecute", true},
		{`HKCU\Software\Classes\mscfile\shell\open\command`, `mscfile\shell\open\command`, "", true},
		{`HKU\S-1-5-21-1-2-3-1001_Classes\exefile\shell\runas\command\IsolatedCommand`, `exefile\shell\runas\command`, "isolatedcommand", true},
		{`HKU\S-1-5-21-1-2-3-1001\Environment\windir`, `environment`, "windir", true},
		{`\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe\(Default)`,
			`software\microsoft\windows\currentversion\app paths\control.exe`, "", true},
		// Machine-wide keys are Windows' own; deeper keys aren't the command key.
		{`HKLM\SOFTWARE\Classes\ms-settings\shell\open\command\(Default)`, "", "", false},
		{`HKU\S-1-5-21-1-2-3-1001_Classes\ms-settings\shell\open\command\x\y`, "", "", false},
		{`HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run\x`, "", "", false},
		// Environment lives in the user's hive, not Classes.
		{`HKU\S-1-5-21-1-2-3-1001_Classes\Environment\windir`, "", "", false},
	} {
		k, v, ok := matchUACBypassPath(c.path)
		if ok != c.ok || (ok && (k.key != c.key || v != c.value)) {
			t.Errorf("%s: %q %q %v, want %q %q %v", c.path, k.key, v, ok, c.key, c.value, c.ok)
		}
	}
}

func TestRegistryEventFindings(t *testing.T) {
	sysmon := func(id int, data map[string]string) winEvent {
		return winEvent{EventID: id, Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational",
			Data: data, UserData: map[string]string{}, TimeCreated: time.Date(2026, 10, 29, 14, 2, 3, 0, time.UTC)}
	}
	// NIK C2's fodhelper bypass, as Sysmon records it.
	key := `HKU\S-1-5-21-1-2-3-1001_Classes\ms-settings\shell\open\command`
	img := `C:\Users\bob\AppData\Roaming\Microsoft\Network\svchost.exe`
	created := sysmon(12, map[string]string{"EventType": "CreateKey", "TargetObject": key, "Image": img})
	only(t, "key created", eventFindings(created), "privesc.uac_bypass_key", SevSuspect)
	set := sysmon(13, map[string]string{"EventType": "SetValue", "TargetObject": key + `\(Default)`, "Image": img,
		"Details": `C:\Users\bob\AppData\Roaming\Microsoft\Network\svchost.exe elevated`})
	f := only(t, "command set", eventFindings(set), "privesc.uac_bypass_key", SevCritical)
	if !strings.Contains(f.Detail, "fodhelper.exe") || !strings.Contains(f.Detail, "svchost.exe elevated") ||
		!strings.Contains(f.Detail, "2026-10-29T14:02:03Z") {
		t.Errorf("detail: %s", f.Detail)
	}
	delegate := sysmon(13, map[string]string{"EventType": "SetValue", "TargetObject": key + `\DelegateExecute`, "Image": img, "Details": "(Empty)"})
	none(t, "DelegateExecute beside the command", eventFindings(delegate))
	deleted := sysmon(12, map[string]string{"EventType": "DeleteKey", "TargetObject": key, "Image": img})
	none(t, "key deleted", eventFindings(deleted))

	// sdclt's Folder variant counts only with its empty DelegateExecute.
	folder := `HKU\S-1-5-21-1-2-3-1001_Classes\Folder\shell\open\command`
	none(t, "Folder command alone", eventFindings(sysmon(13, map[string]string{"TargetObject": folder + `\(Default)`, "Details": `C:\Tools\dopus.exe "%1"`})))
	only(t, "Folder DelegateExecute", eventFindings(sysmon(13, map[string]string{"TargetObject": folder + `\DelegateExecute`, "Details": "(Empty)"})),
		"privesc.uac_bypass_key", SevCritical)
	// SilentCleanup: the user's own %windir%.
	only(t, "windir", eventFindings(sysmon(13, map[string]string{"TargetObject": `HKU\S-1-5-21-1-2-3-1001\Environment\windir`,
		"Details": `cmd /c start C:\Users\Public\p.exe &&`})), "privesc.uac_bypass_key", SevCritical)
	none(t, "another environment variable", eventFindings(sysmon(13, map[string]string{"TargetObject": `HKU\S-1-5-21-1-2-3-1001\Environment\TEMP`, "Details": `C:\t`})))

	// The System log's 12 and 13 are boot and shutdown.
	boot := sysmon(13, map[string]string{"TargetObject": key + `\(Default)`, "Details": "x"})
	boot.Provider, boot.Channel = "Microsoft-Windows-Kernel-General", "System"
	none(t, "System log 13", eventFindings(boot))

	// The registry walk's judgement: a key with a command, and one without.
	k, _, _ := matchUACBypassPath(key)
	if f := uacBypassFinding(k, `HKU\x`, "", ""); f.Severity != SevSuspect {
		t.Errorf("empty key: %+v", f)
	}
	if f := uacBypassFinding(k, `HKU\x`, `C:\p.exe`, ""); f.Severity != SevCritical {
		t.Errorf("planted key: %+v", f)
	}
}
