package collector

import "testing"

func TestJudgeTypeLibQuietOnNormal(t *testing.T) {
	normal := []typeLibEntry{
		// A machine type library in System32 raises nothing.
		{LibID: "{00020430-0000-0000-c000-000000000046}", Version: "2.0", LCID: "0", Platform: "win64",
			Hive: "HKLM", View: "native", Name: "OLE Automation",
			Path: `C:\Windows\System32\stdole2.tlb`, PathRaw: `C:\Windows\System32\stdole2.tlb`},
		// A per-user type library that does NOT shadow a machine LibID is an
		// ordinary per-app registration.
		{LibID: "{abcd1234-0000-0000-0000-000000000001}", Version: "1.0", LCID: "0", Platform: "win64",
			Hive: `HKU\S-1-5-21-5`, User: true,
			Path: `C:\Program Files\App\app.tlb`, PathRaw: `C:\Program Files\App\app.tlb`},
		// No value at all: nothing to judge.
		{LibID: "{00000000-0000-0000-0000-000000000000}", Hive: "HKLM"},
	}
	for _, e := range normal {
		if got := judgeTypeLib(e); len(got) != 0 {
			t.Errorf("%s: unexpected findings %v", e.LibID, keys(rulesOf(got)))
		}
	}
}

func TestJudgeTypeLibFindsHijacks(t *testing.T) {
	cases := []struct {
		name string
		e    typeLibEntry
		want []string
	}{
		{"script moniker to a scriptlet in Public",
			typeLibEntry{LibID: "{11111111-0000-0000-0000-000000000001}", Version: "1.0", LCID: "0", Platform: "win32",
				Hive: "HKLM", View: "native",
				PathRaw: `script:C:\Users\Public\evil.sct`, Path: `script:C:\Users\Public\evil.sct`},
			[]string{"persistence.typelib_script_moniker", "persistence.typelib_unusual_path"}},
		{"url scriptlet moniker",
			typeLibEntry{LibID: "{22222222-0000-0000-0000-000000000002}", Version: "1.0", LCID: "0", Platform: "win32",
				Hive: "HKLM", View: "native",
				PathRaw: `scriptlet:https://example.test/a`, Path: `scriptlet:https://example.test/a`},
			[]string{"persistence.typelib_script_moniker"}},
		{"library in a user temp path",
			typeLibEntry{LibID: "{33333333-0000-0000-0000-000000000003}", Version: "1.0", LCID: "0", Platform: "win64",
				Hive: "HKLM", View: "native",
				PathRaw: `C:\Users\bob\AppData\Local\Temp\x.tlb`, Path: `C:\Users\bob\AppData\Local\Temp\x.tlb`},
			[]string{"persistence.typelib_unusual_path"}},
		{"per-user shadow with an ordinary path",
			typeLibEntry{LibID: "{44444444-0000-0000-0000-000000000004}", Version: "1.0", LCID: "0", Platform: "win64",
				Hive: `HKU\S-1-5-21-7`, User: true, Shadows: true,
				Path: `C:\Program Files\App\app.tlb`, PathRaw: `C:\Program Files\App\app.tlb`},
			[]string{"persistence.typelib_user_shadow"}},
	}
	for _, c := range cases {
		got := rulesOf(judgeTypeLib(c.e))
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("%s: %s missing (got %v)", c.name, w, keys(got))
			}
		}
	}
}

func TestJudgeTypeLibUserShadowCritical(t *testing.T) {
	// A per-user TypeLib that shadows a machine one and points at a script
	// moniker is the full hijack — critical.
	e := typeLibEntry{LibID: "{44444444-0000-0000-0000-000000000004}", Version: "1.0", LCID: "0", Platform: "win32",
		Hive: `HKU\S-1-5-21-7`, User: true, Shadows: true,
		PathRaw: `script:C:\Users\bob\AppData\Local\Temp\e.sct`, Path: `script:C:\Users\bob\AppData\Local\Temp\e.sct`}
	got := rulesOf(judgeTypeLib(e))
	f, ok := got["persistence.typelib_user_shadow"]
	if !ok {
		t.Fatal("user-shadow finding missing")
	}
	if f.Severity != SevCritical {
		t.Errorf("user shadow with a script moniker should be critical, got %s", f.Severity)
	}
}

func TestTypeLibScriptMoniker(t *testing.T) {
	hits := []string{`script:C:\x\a.sct`, `Scriptlet:https://h/a`, `C:\x\b.sct`, `C:\Windows\System32\scrobj.dll`}
	for _, s := range hits {
		if typeLibScriptMoniker(s) == "" {
			t.Errorf("%q should be flagged as a script moniker/scriptlet", s)
		}
	}
	misses := []string{`C:\Windows\System32\stdole2.tlb`, `C:\Program Files\App\app.dll`, ``}
	for _, s := range misses {
		if d := typeLibScriptMoniker(s); d != "" {
			t.Errorf("%q should not be flagged, got %q", s, d)
		}
	}
}
