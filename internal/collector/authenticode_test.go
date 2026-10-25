package collector

import (
	"fmt"
	"strings"
	"testing"
)

func TestSigStateString(t *testing.T) {
	cases := map[SigState]string{
		SigTrusted: "trusted", SigUntrusted: "untrusted", SigUnsigned: "unsigned",
		SigError: "error", SigUnknown: "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", s, got, want)
		}
	}
}

func TestApplySignatureFields(t *testing.T) {
	f := map[string]any{}
	applySignatureFields(f, SignatureResult{State: SigTrusted, Signer: "Acme Corp", Catalog: true})
	if f["signature_state"] != "trusted" || f["signer"] != "Acme Corp" || f["signature_catalog"] != true {
		t.Fatalf("trusted fields = %+v", f)
	}

	f = map[string]any{}
	applySignatureFields(f, SignatureResult{State: SigError, Detail: "catalog info unavailable"})
	if f["signature_state"] != "error" || f["signature_error"] != "catalog info unavailable" {
		t.Fatalf("error fields = %+v", f)
	}

	f = map[string]any{}
	applySignatureFields(f, SignatureResult{State: SigUnknown})
	if len(f) != 0 {
		t.Fatalf("unknown should add nothing, got %+v", f)
	}
}

func TestSignatureFindings(t *testing.T) {
	const root = `C:\Windows`

	f := signatureFindings(`C:\Windows\System32\evil.exe`, SignatureResult{State: SigUnsigned}, root)
	if len(f) != 1 || f[0].Rule != "integrity.unsigned_system_binary" || f[0].Severity != SevNotable {
		t.Fatalf("unsigned system binary findings = %+v", f)
	}

	f = signatureFindings(`C:\Windows\SysWOW64\x.exe`, SignatureResult{State: SigUntrusted, Detail: "untrusted root"}, root)
	if len(f) != 1 || f[0].Severity != SevSuspect {
		t.Fatalf("untrusted system binary should be suspect: %+v", f)
	}
	if strings.Contains(f[0].Detail, "from \"") {
		t.Errorf("no signer known, but the detail names one: %q", f[0].Detail)
	}

	// An untrusted signature names who it claims to be from.
	f = signatureFindings(`C:\Windows\System32\svchost.exe`,
		SignatureResult{State: SigUntrusted, Signer: "Microsoft Windows", Detail: "signature chains to an untrusted root"}, root)
	if len(f) != 1 || !strings.Contains(f[0].Detail, `untrusted signature from "Microsoft Windows"`) {
		t.Fatalf("untrusted finding should name the signer: %+v", f)
	}

	none := []struct {
		path string
		res  SignatureResult
	}{
		{`C:\Windows\System32\cmd.exe`, SignatureResult{State: SigTrusted}},
		{`C:\Windows\System32\cmd.exe`, SignatureResult{State: SigError, Detail: "x"}},
		{`C:\Users\u\AppData\Local\Temp\x.exe`, SignatureResult{State: SigUnsigned}}, // not a system dir
		{`C:\Program Files\App\app.exe`, SignatureResult{State: SigUnsigned}},
		{"", SignatureResult{State: SigUnsigned}},
	}
	for _, c := range none {
		if f := signatureFindings(c.path, c.res, root); len(f) != 0 {
			t.Errorf("signatureFindings(%q, %v) = %+v, want none", c.path, c.res.State, f)
		}
	}
}

func TestCleanSignerName(t *testing.T) {
	long := strings.Repeat("x", maxSignerRunes+40)
	// esc spells a rune the way cleanSignerName escapes it; built here so the
	// test source itself holds no invisible characters.
	esc := func(r rune) string { return fmt.Sprintf("%cu%04X", 0x5C, r) }
	cases := []struct{ in, want string }{
		{"Microsoft Windows", "Microsoft Windows"},
		{"  Acme Corp\t", "Acme Corp"},
		{"Acme 🚀 Studio", "Acme 🚀 Studio"}, // printable non-ASCII stays as is
		// A bidi override can't reorder the name; a look-alike space is made visible.
		{"Micro" + string(rune(0x202E)) + "tfos Corporation", "Micro" + esc(0x202E) + "tfos Corporation"},
		{"Acme" + string(rune(0xA0)) + "Corp", "Acme" + esc(0xA0) + "Corp"},
		{"a\x00b\nc\x1b[31m", `a\u0000b\u000Ac\u001B[31m`},
		{"tag\U000E0041", `tag\U000E0041`}, // non-BMP format character
		{"", ""},
		{long, strings.Repeat("x", maxSignerRunes) + "…"},
	}
	for _, c := range cases {
		if got := cleanSignerName(c.in); got != c.want {
			t.Errorf("cleanSignerName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnderSystemDir(t *testing.T) {
	const root = `C:\Windows`
	in := []string{
		`C:\Windows\System32\svchost.exe`,
		`c:\windows\system32\svchost.exe`,
		`C:\Windows\SysWOW64\x.dll`,
	}
	out := []string{
		`C:\Windows\explorer.exe`, // Windows dir, but not System32/SysWOW64
		`C:\Program Files\x\y.exe`,
		`C:\Users\u\Downloads\a.exe`,
		`D:\System32\x.exe`, // different drive/root
	}
	for _, p := range in {
		if !underSystemDir(p, root) {
			t.Errorf("underSystemDir(%q) = false, want true", p)
		}
	}
	for _, p := range out {
		if underSystemDir(p, root) {
			t.Errorf("underSystemDir(%q) = true, want false", p)
		}
	}
}
