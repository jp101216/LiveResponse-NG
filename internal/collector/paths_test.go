package collector

import (
	"reflect"
	"testing"
)

func TestPathRisk(t *testing.T) {
	cases := []struct {
		path string
		want riskLevel
	}{
		{`C:\Users\a\AppData\Local\Temp\x.exe`, riskHigh},
		{`C:\Users\Public\update.exe`, riskHigh},
		{`C:\Windows\Temp\svc.exe`, riskHigh},
		{`c:/users/a/downloads/setup.exe`, riskHigh},
		{`C:\$Recycle.Bin\S-1-5-21-1\x.exe`, riskHigh},
		{`C:\Windows\System32\spool\drivers\color\x.exe`, riskHigh},
		{`C:\PerfLogs\x.exe`, riskHigh},
		// Environment references must not hide the location.
		{`%TEMP%\x.exe`, riskHigh},
		{`%tmp%\x.exe`, riskHigh},
		{`%Public%\x.dll`, riskHigh},
		{`%LOCALAPPDATA%\Temp\x.exe`, riskHigh},
		{`%ProgramData%\x\y.exe`, riskLow},
		{`\\?\C:\Users\Public\x.exe`, riskHigh},
		{`\??\C:\Windows\Temp\drv.sys`, riskHigh},
		// ProgramData is lower risk; Defender's own home is trusted.
		{`C:\ProgramData\updater\upd.exe`, riskLow},
		{`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`, riskNone},
		{`C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{X}\mpengine.dll`, riskNone},
		{`C:\update.exe`, riskLow},
		{`C:\pagefile.sys`, riskLow},
		{`C:\Program Files\Google\Chrome\Application\chrome.exe`, riskNone},
		{`C:\Users\a\AppData\Local\Programs\Microsoft VS Code\Code.exe`, riskNone},
		{`%SystemRoot%\System32\svchost.exe`, riskNone},
		{`\SystemRoot\System32\drivers\tcpip.sys`, riskNone},
		{`System32\drivers\x.sys`, riskNone},
		{`C:\Windows\explorer.exe`, riskNone},
		{``, riskNone},
	}
	for _, c := range cases {
		if got, why := pathRisk(c.path); got != c.want {
			t.Errorf("pathRisk(%q) = %v (%s), want %v", c.path, got, why, c.want)
		}
	}
}

func TestSuspiciousPath(t *testing.T) {
	if !suspiciousPath(`C:\Users\a\AppData\Local\Temp\x.exe`) || suspiciousPath(`C:\Windows\System32\cmd.exe`) {
		t.Fatal("suspiciousPath disagrees with pathRisk")
	}
}

func TestExpandEnvRefs(t *testing.T) {
	env := map[string]string{"windir": `C:\Windows`, "temp": `C:\T`}
	look := func(n string) (string, bool) { v, ok := env[n]; return v, ok }
	cases := map[string]string{
		`%WINDIR%\x.exe`:            `C:\Windows\x.exe`,
		`%Unknown%\x`:               `%Unknown%\x`,
		`%UNKNOWN%%windir%\a`:       `%UNKNOWN%C:\Windows\a`,
		`no refs`:                   `no refs`,
		`50% off %temp%`:            `50% off C:\T`,
		`%temp%%temp%`:              `C:\TC:\T`,
		`trailing %`:                `trailing %`,
		`%%`:                        `%%`,
		`%windir%\%unknown%\%temp%`: `C:\Windows\%unknown%\C:\T`,
	}
	for in, want := range cases {
		if got := expandEnvRefs(in, look); got != want {
			t.Errorf("expandEnvRefs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommandPathRisk(t *testing.T) {
	cases := []struct {
		cmd     string
		want    riskLevel
		culprit string
	}{
		// A temp path in an ordinary program's arguments is just a log file.
		{`"C:\Program Files\Acme\agent.exe" --log C:\Windows\Temp\agent.log`, riskNone, ""},
		// ...but in a proxy host's arguments it's the payload.
		{`rundll32.exe C:\Users\Public\x.dll,Start`, riskHigh, `C:\Users\Public\x.dll`},
		{`C:\Windows\System32\wscript.exe "%APPDATA%\..\Local\Temp\a.vbs"`, riskHigh, `%APPDATA%\..\Local\Temp\a.vbs`},
		{`regsvr32 /s /i:C:\Users\Public\x.sct scrobj.dll`, riskHigh, `C:\Users\Public\x.sct`},
		{`powershell.exe -File %TEMP%\a.ps1`, riskHigh, `%TEMP%\a.ps1`},
		{`C:\Users\a\Downloads\tool.exe /quiet`, riskHigh, `C:\Users\a\Downloads\tool.exe`},
		{`C:\Windows\system32\svchost.exe -k netsvcs -p`, riskNone, ""},
	}
	for _, c := range cases {
		lvl, _, culprit := commandPathRisk(c.cmd)
		if lvl != c.want || (c.want != riskNone && culprit != c.culprit) {
			t.Errorf("commandPathRisk(%q) = %v %q, want %v %q", c.cmd, lvl, culprit, c.want, c.culprit)
		}
	}
}

func TestPathTokens(t *testing.T) {
	got := pathTokens(`/s /i:C:\x\a.sct "C:\My Dir\b.dll",Entry -f=%TEMP%\c.ps1 http://x/y.exe plain`)
	want := []string{`C:\x\a.sct`, `C:\My Dir\b.dll`, `%TEMP%\c.ps1`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBaseAndDirName(t *testing.T) {
	if baseName(`"C:\Windows\System32\CMD.EXE"`) != "cmd.exe" || baseName("cmd.exe") != "cmd.exe" ||
		baseName("/usr/bin/sleep") != "sleep" {
		t.Fatal("baseName")
	}
	if dirName(`C:\Windows\System32\cmd.exe`) != `c:\windows\system32` || dirName("cmd.exe") != "" {
		t.Fatal("dirName")
	}
}

func TestProxyPayload(t *testing.T) {
	cases := map[string]string{
		`rundll32.exe C:\Users\Public\x.dll,Start`:                     `C:\Users\Public\x.dll`,
		`regsvr32 /s /i:C:\x\a.sct scrobj.dll`:                         `C:\x\a.sct`,
		`wscript.exe "%APPDATA%\a.vbs"`:                                `%APPDATA%\a.vbs`,
		`powershell -ep bypass -File C:\s\run.ps1`:                     `C:\s\run.ps1`,
		`"C:\Program Files\App\app.exe" C:\data\x.dll`:                 ``,
		`rundll32.exe shell32.dll,Control_RunDLL`:                      ``,
		`C:\Windows\system32\rundll32.exe C:\Windows\system32\a.dll,X`: `C:\Windows\system32\a.dll`,
	}
	for in, want := range cases {
		if got := proxyPayload(in); got != want {
			t.Errorf("proxyPayload(%q) = %q, want %q", in, got, want)
		}
	}
}
