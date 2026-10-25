package collector

import "testing"

func TestExpansionNeverUsesTheAgentsUserEnvironment(t *testing.T) {
	agentEnv := map[string]string{
		"systemroot": `C:\Windows`, "programfiles": `C:\Program Files`,
		"temp": `C:\Windows\TEMP`, "appdata": `C:\Windows\system32\config\systemprofile\AppData\Roaming`,
	}
	machine := machineLookupFrom(func(n string) string { return agentEnv[n] })

	// Machine variables expand; the agent's own %TEMP%/%APPDATA% never leak in.
	if got := expandEnvRefs(`%SystemRoot%\x.exe %TEMP%\y.exe %AppData%\z.exe`, machine); got != `C:\Windows\x.exe %TEMP%\y.exe %AppData%\z.exe` {
		t.Fatalf("machine-only expansion: %q", got)
	}
	// With a profile, per-user variables resolve under that user.
	alice := chain(userLookup(`C:\Users\alice\`), machine)
	cases := map[string]string{
		`%APPDATA%\evil\x.exe`:             `C:\Users\alice\AppData\Roaming\evil\x.exe`,
		`%LocalAppData%\Temp\a.exe`:        `C:\Users\alice\AppData\Local\Temp\a.exe`,
		`%TEMP%\b.exe`:                     `C:\Users\alice\AppData\Local\Temp\b.exe`,
		`%USERPROFILE%\c.exe`:              `C:\Users\alice\c.exe`,
		`%HOMEDRIVE%%HOMEPATH%\d.exe`:      `C:\Users\alice\d.exe`,
		`%USERNAME%`:                       `alice`,
		`%ProgramFiles%\App\app.exe`:       `C:\Program Files\App\app.exe`,
		`%OneDrive%\unknown-stays-raw.exe`: `%OneDrive%\unknown-stays-raw.exe`,
	}
	for in, want := range cases {
		if got := expandEnvRefs(in, alice); got != want {
			t.Errorf("expand(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := userLookup("")("temp"); ok {
		t.Fatal("empty profile must resolve nothing")
	}
}

func TestNormalizeImageWith(t *testing.T) {
	machine := machineLookupFrom(func(n string) string {
		return map[string]string{"systemroot": `D:\Win`, "programfiles": `D:\PF`}[n]
	})
	cases := map[string]string{
		`\SystemRoot\System32\drivers\tcpip.sys`: `D:\Win\System32\drivers\tcpip.sys`,
		`System32\drivers\x.sys`:                 `D:\Win\System32\drivers\x.sys`,
		`\??\C:\Windows\system32\drivers\y.sys`:  `C:\Windows\system32\drivers\y.sys`,
		`\\?\C:\long\path.exe`:                   `C:\long\path.exe`,
		`\\?\UNC\server\share\a.exe`:             `\\?\UNC\server\share\a.exe`,
		`%SystemRoot%\system32\svchost.exe`:      `D:\Win\system32\svchost.exe`,
		`"%ProgramFiles%\Acme\agent.exe"`:        `D:\PF\Acme\agent.exe`,
		`C:\Program Files\x.exe`:                 `C:\Program Files\x.exe`,
		``:                                       ``,
	}
	for in, want := range cases {
		if got := normalizeImageWith(in, `D:\Win`, machine); got != want {
			t.Errorf("normalizeImageWith(%q) = %q, want %q", in, got, want)
		}
	}
}
