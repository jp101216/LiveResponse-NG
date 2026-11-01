package collector

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// envBlock encodes NAME=value strings as a process's UTF-16 environment block.
func envBlock(vars ...string) []byte {
	var b []byte
	for _, v := range append(vars, "") {
		for _, c := range utf16.Encode([]rune(v)) {
			b = binary.LittleEndian.AppendUint16(b, c)
		}
		b = append(b, 0, 0)
	}
	return b
}

func TestEnvironmentBlock(t *testing.T) {
	block := envBlock("=C:=C:\\Users\\x", "Path=C:\\Windows", "COMPlus_ETWEnabled=0", "SECRET_TOKEN=hunter2", "cor_enable_profiling=1",
		"COR_PROFILER={11111111-2222-3333-4444-555555555555}")
	if !envBlockEnds(block) || envBlockEnds(block[:len(block)-4]) {
		t.Error("block end")
	}
	strs := envStrings(append(block, 0x41, 0, 0, 0)) // bytes after the end are ignored
	if len(strs) != 6 || strs[3] != "SECRET_TOKEN=hunter2" {
		t.Fatalf("strings: %q", strs)
	}
	env := parseEnvBlock(strs)
	if len(env) != 3 || env["COMPLUS_ETWENABLED"] != "0" || env["COR_ENABLE_PROFILING"] != "1" || env["SECRET_TOKEN"] != "" {
		t.Errorf("only the runtime variables are kept: %v", env)
	}
	// A block cut off mid-string loses only that string.
	if got := envStrings(block[:20]); len(got) != 0 && !strings.HasPrefix(got[0], "=C:") {
		t.Errorf("truncated: %q", got)
	}
}

func TestRuntimeEnvFindings(t *testing.T) {
	fs := runtimeEnvFindings("process x.exe (pid 4242)'s environment", map[string]string{"COMPLUS_ETWENABLED": "0"}, nil)
	f := only(t, "etw", fs, "defense.dotnet_etw_disabled", SevSuspect)
	if !strings.Contains(f.Detail, "pid 4242") || !strings.Contains(f.Detail, "COMPLUS_ETWENABLED=0") {
		t.Errorf("detail: %s", f.Detail)
	}
	none(t, "etw on", runtimeEnvFindings("x", map[string]string{"COMPLUS_ETWENABLED": "1", "DOTNET_ETWENABLED": ""}, nil))

	resolve := func(clsid string) string {
		if clsid == "{AAAA}" {
			return `C:\Users\Public\prof.dll`
		}
		return ""
	}
	f = only(t, "planted profiler", runtimeEnvFindings("user S-1-5-21-1's environment",
		map[string]string{"COR_ENABLE_PROFILING": "1", "COR_PROFILER": "{AAAA}"}, resolve), "persistence.clr_profiler", SevSuspect)
	if !strings.Contains(f.Detail, `C:\Users\Public\prof.dll`) || !strings.Contains(f.Detail, ".NET Framework") {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "apm agent", runtimeEnvFindings("service W3SVC's environment", map[string]string{"CORECLR_ENABLE_PROFILING": "1",
		"CORECLR_PROFILER": "{BBBB}", "CORECLR_PROFILER_PATH_64": `C:\Program Files\Vendor\Agent\profiler.dll`}, resolve),
		"persistence.clr_profiler", SevNotable)
	none(t, "profiling off", runtimeEnvFindings("x", map[string]string{"COR_ENABLE_PROFILING": "0", "COR_PROFILER": "{AAAA}"}, resolve))

	res := NewResult("defenses")
	runtimeEnvReport(res, []envSource{{Where: "the system environment", Env: map[string]string{"DOTNET_ETWENABLED": "0"}}})
	got := res.Finish()
	if len(got.Records) != 1 || got.Records[0].Fields["area"] != "environment" || got.Records[0].Findings[0].Rule != "defense.dotnet_etw_disabled" {
		t.Errorf("report: %+v", got.Records)
	}
}

func TestAMSIProviders(t *testing.T) {
	mpoav := `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MpOav.dll"`
	if f, ok := judgeAMSIProvider("{2781761E-28E0-4109-99FE-B9D127C57AFE}", mpoav); ok {
		t.Errorf("Defender's own provider: %+v", f)
	}
	f, ok := judgeAMSIProvider("{2781761e-28e0-4109-99fe-b9d127c57afe}", `C:\Users\Public\amsi.dll`)
	if !ok || f.Rule != "defense.amsi_provider_hijacked" || f.Severity != SevSuspect {
		t.Errorf("hijacked: %+v", f)
	}
	if f, _ := judgeAMSIProvider("{1}", `C:\Program Files\Vendor\amsiprov.dll`); f.Rule != "persistence.amsi_provider" || f.Severity != SevNotable {
		t.Errorf("vendor: %+v", f)
	}
	if f, _ := judgeAMSIProvider("{2}", `C:\Users\bob\AppData\Roaming\x.dll`); f.Severity != SevSuspect {
		t.Errorf("planted: %+v", f)
	}

	res := NewResult("defenses")
	amsiReport(res, amsiState{Present: true, Providers: []amsiProvider{{CLSID: "{2781761E-28E0-4109-99FE-B9D127C57AFE}", DLL: mpoav}}}, true)
	amsiReport(res, amsiState{Present: true}, true)
	amsiReport(res, amsiState{Present: true}, false)
	amsiReport(res, amsiState{}, true) // no AMSI (before Windows 10): no record
	got := res.Finish()
	if len(got.Records) != 3 || len(got.Records[0].Findings) != 0 || got.Records[0].Fields["area"] != "amsi" {
		t.Fatalf("records: %+v", got.Records)
	}
	if fs := got.Records[1].Findings; len(fs) != 1 || fs[0].Rule != "defense.amsi_provider_missing" {
		t.Errorf("missing: %+v", fs)
	}
	if len(got.Records[2].Findings) != 0 {
		t.Errorf("no Defender, no providers: %+v", got.Records[2])
	}
}

func TestAccessibilityFinding(t *testing.T) {
	p := `C:\Windows\System32\sethc.exe`
	if f, ok := accessibilityFinding(p, "sethc.exe.mui", ""); ok {
		t.Errorf("genuine: %+v", f)
	}
	for file, orig := range map[string]string{"Utilman.exe": "utilman2.exe", "Magnify.exe": "ScreenMagnifier.exe", "Narrator.exe": "SR.exe",
		"AtBroker.exe": "ATBroker.exe"} {
		if f, ok := accessibilityFinding(`C:\Windows\System32\`+file, orig, ""); ok {
			t.Errorf("Windows' own %s: %+v", file, f)
		}
	}
	if f, ok := accessibilityFinding(p, "", ""); ok {
		t.Errorf("unreadable resource alone: %+v", f)
	}
	f, ok := accessibilityFinding(p, "sethc.exe", "cmd.exe")
	if !ok || f.Severity != SevCritical || !strings.Contains(f.Detail, "copy of cmd.exe") {
		t.Errorf("copy: %+v", f)
	}
	f, _ = accessibilityFinding(p, "Cmd.Exe.MUI", "")
	if f.Severity != SevCritical || !strings.Contains(f.Detail, "really cmd.exe") {
		t.Errorf("renamed shell: %+v", f)
	}
	f, _ = accessibilityFinding(p, "backdoor.exe", "")
	if f.Rule != "persistence.accessibility_backdoor" || f.Severity != SevSuspect {
		t.Errorf("other program: %+v", f)
	}
}

func TestPowerShellEngineEvent(t *testing.T) {
	text := "\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n" +
		"\tHostVersion=2.0\r\n\tHostId=1\r\n\tHostApplication=powershell.exe -version 2 -nop -c whoami\r\n\tEngineVersion=2.0\r\n\tRunspaceId=x"
	ev := winEvent{EventID: 400, Provider: "PowerShell", Channel: "Windows PowerShell", Data: map[string]string{},
		UserData: map[string]string{}, DataList: []string{"Available", "None", text}, TimeCreated: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	f := only(t, "downgrade", eventFindings(ev), "defense.powershell_downgrade", SevSuspect)
	if !strings.Contains(f.Detail, "powershell.exe -version 2 -nop -c whoami") || !strings.Contains(f.Detail, "2026-10-30T01:00:00Z") {
		t.Errorf("detail: %s", f.Detail)
	}
	ev.DataList[2] = strings.Replace(text, "EngineVersion=2.0", "EngineVersion=5.1.19041.4648", 1)
	none(t, "5.1", eventFindings(ev))
	other := ev
	other.DataList = []string{text}
	other.Provider, other.Channel = "Some-App", "Application"
	none(t, "another provider's 400", eventFindings(other))
}

func TestSysmonInjectionEvents(t *testing.T) {
	sysmon := func(id int, kv ...string) winEvent {
		ev := dcEvent(id, kv...)
		ev.Provider, ev.Channel = "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"
		return ev
	}
	f := only(t, "unbacked", eventFindings(sysmon(8, "SourceImage", `C:\Users\bob\Downloads\loader.exe`,
		"TargetImage", `C:\Windows\System32\notepad.exe`, "StartAddress", "0x000001F2A3B40000", "StartModule", "", "StartFunction", "")),
		"memory.remote_thread_unbacked", SevSuspect)
	if !strings.Contains(f.Detail, "0x000001F2A3B40000") || !strings.Contains(f.Detail, "loader.exe") {
		t.Errorf("detail: %s", f.Detail)
	}
	f = only(t, "into lsass", eventFindings(sysmon(8, "SourceImage", `C:\Program Files\Tool\x.exe`,
		"TargetImage", `C:\Windows\System32\lsass.exe`, "StartAddress", "0x1000", "StartModule", "-")), "memory.remote_thread_unbacked", SevSuspect)
	if f.Technique != "T1003.001" {
		t.Errorf("lsass: %+v", f)
	}
	only(t, "security product", eventFindings(sysmon(8, "SourceImage", `C:\Program Files\EDR\agent.exe`,
		"TargetImage", `C:\Windows\explorer.exe`, "StartAddress", "0x1000", "StartModule", "")), "memory.remote_thread_unbacked", SevNotable)
	only(t, "loadlibrary", eventFindings(sysmon(8, "SourceImage", `C:\Temp\inj.exe`, "TargetImage", `C:\Windows\explorer.exe`,
		"StartAddress", "0x7FFB1E2A0000", "StartModule", `C:\Windows\System32\KERNELBASE.dll`, "StartFunction", "LoadLibraryW")),
		"memory.remote_thread_loadlibrary", SevSuspect)
	none(t, "csrss ctrl handler", eventFindings(sysmon(8, "SourceImage", `C:\Windows\System32\csrss.exe`, "TargetImage", `C:\x\app.exe`,
		"StartModule", `C:\Windows\System32\KERNELBASE.dll`, "StartFunction", "CtrlRoutine")))
	notSysmon := dcEvent(8, "StartModule", "")
	none(t, "another provider's 8", eventFindings(notSysmon))

	only(t, "hollowing", eventFindings(sysmon(25, "Image", `C:\Users\bob\AppData\Local\Temp\svchost.exe`, "Type", "Image is replaced")),
		"memory.process_tampering", SevSuspect)
	only(t, "herpaderping", eventFindings(sysmon(25, "Image", `C:\Temp\x.exe`, "Type", "Image is locked for access")),
		"memory.process_tampering", SevSuspect)
	none(t, "updater", eventFindings(sysmon(25, "Image", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "Type", "Image is replaced")))
	none(t, "wmiadap", eventFindings(sysmon(25, "Image", `C:\Windows\System32\wbem\WMIADAP.exe`, "Type", "Image is replaced")))
}

func TestEvasionCommandLines(t *testing.T) {
	cases := []struct {
		image, cmd, rule string
	}{
		{"", `powershell.exe -version 2 -nop -c "iex $x"`, "defense.powershell_downgrade"},
		{"", `powershell -NoP -W Hidden -v 2.0 -enc AAAA`, "defense.powershell_downgrade"},
		{"", `cmd /c "powershell.exe -ve 2 -file x.ps1"`, "defense.powershell_downgrade"},
		{"", `"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --headless --restore-last-session`, "cred.browser_remote_debugging"},
		{"", `msedge.exe --remote-debugging-port=9222 --user-data-dir="C:\Users\bob\AppData\Local\Microsoft\Edge\User Data"`, "cred.browser_remote_debugging"},
		{`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`, `brave.exe --remote-debugging-pipe`, "cred.browser_remote_debugging"},
		{"", `netsh interface portproxy add v4tov4 listenport=4444 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.0.0.5`, "network.portproxy_rule"},
	}
	for _, c := range cases {
		if hasFinding(analyzeCommandLine("process", c.image, c.cmd), c.rule) == nil {
			t.Errorf("%s: want %s, got %+v", c.cmd, c.rule, analyzeCommandLine("process", c.image, c.cmd))
		}
	}
	for _, c := range []struct{ image, cmd string }{
		{"", `powershell.exe -nop -c "tool.exe -v 2"`},
		{"", `pwsh -v`},
		{"", `powershell -version 5.1 -c x`},
		{"", `chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\Users\bob\AppData\Local\Temp\scoped_dir4242_1`},
		{"", `chrome.exe --type=renderer --remote-debugging-port=9222`},
		{"", `Code.exe --remote-debugging-port=9229`},
		{"", `netsh interface portproxy show all`},
	} {
		for _, f := range analyzeCommandLine("process", c.image, c.cmd) {
			switch f.Rule {
			case "defense.powershell_downgrade", "cred.browser_remote_debugging", "network.portproxy_rule":
				t.Errorf("%s flagged: %+v", c.cmd, f)
			}
		}
	}
}
