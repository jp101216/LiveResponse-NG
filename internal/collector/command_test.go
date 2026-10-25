package collector

import "testing"

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		cmd, image, args string
		quoted           bool
	}{
		{`"C:\Program Files\x\svc.exe" -k net`, `C:\Program Files\x\svc.exe`, `-k net`, true},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, `C:\Windows\system32\svchost.exe`, `-k netsvcs -p`, false},
		{`C:\Program Files\Acme App\svc.exe -k net`, `C:\Program Files\Acme App\svc.exe`, `-k net`, false},
		{`C:\Users\Public\My Folder\evil.exe`, `C:\Users\Public\My Folder\evil.exe`, ``, false},
		{`%ProgramFiles%\My App\x.exe /run`, `%ProgramFiles%\My App\x.exe`, `/run`, false},
		{`\??\C:\Windows\system32\drivers\x.sys`, `C:\Windows\system32\drivers\x.sys`, ``, false},
		// A program without an extension followed by real arguments.
		{`C:\Tools\mytool --load x.dll`, `C:\Tools\mytool`, `--load x.dll`, false},
		{`cmd /c start x.exe`, `cmd`, `/c start x.exe`, false},
		{`rundll32 C:\x\a.dll,Run`, `rundll32`, `C:\x\a.dll,Run`, false},
		{`ping example.com`, `ping`, `example.com`, false},
		{`"C:\unterminated\x.exe -a`, `C:\unterminated\x.exe -a`, ``, true},
		{`notepad.exe`, `notepad.exe`, ``, false},
		{`C:\Windows\system32\userinit.exe, C:\x\y.exe`, `C:\Windows\system32\userinit.exe`, `, C:\x\y.exe`, false},
		{`userinit.exe,`, `userinit.exe`, `,`, false},
		{`noext`, `noext`, ``, false},
		{`  `, ``, ``, false},
	}
	for _, c := range cases {
		img, args, q := splitCommand(c.cmd)
		if img != c.image || args != c.args || q != c.quoted {
			t.Errorf("splitCommand(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.cmd, img, args, q, c.image, c.args, c.quoted)
		}
	}
}

func TestUnquotedSpacePath(t *testing.T) {
	yes := []string{
		`C:\Program Files\Acme App\svc.exe`,
		`C:\Program Files\Acme\svc.exe -k x`,
	}
	no := []string{
		`"C:\Program Files\Acme\svc.exe" -k x`,
		`C:\Windows\system32\svchost.exe -k netsvcs`,
		`system32\drivers\x.sys`,
		`C:\Tools\mytool --flag x.dll`,
	}
	for _, c := range yes {
		if !unquotedSpacePath(c) {
			t.Errorf("unquotedSpacePath(%q) = false", c)
		}
	}
	for _, c := range no {
		if unquotedSpacePath(c) {
			t.Errorf("unquotedSpacePath(%q) = true", c)
		}
	}
}

func TestImageFromCommand(t *testing.T) {
	if got := imageFromCommand(`"C:\a b\c.exe" x`); got != `C:\a b\c.exe` {
		t.Fatal(got)
	}
}
