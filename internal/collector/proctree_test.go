package collector

import "testing"

const sysRoot = `C:\Windows`

func treeRules(t *testing.T, procs []procView) map[uint32]map[string]Finding {
	t.Helper()
	out := map[uint32]map[string]Finding{}
	for pid, fs := range analyzeProcessTree(procs, sysRoot) {
		out[pid] = rulesOf(fs)
	}
	return out
}

// A healthy Windows 11 process tree must produce no findings at all.
func TestProcessTreeHealthyHostIsQuiet(t *testing.T) {
	procs := []procView{
		{PID: 4, Name: "System"},
		{PID: 140, PPID: 4, Name: "smss.exe", ImagePath: `C:\Windows\System32\smss.exe`, ParentName: "System", ParentVerified: true},
		{PID: 600, PPID: 590, Name: "csrss.exe", ImagePath: `C:\Windows\System32\csrss.exe`},
		{PID: 680, PPID: 590, Name: "wininit.exe", ImagePath: `C:\Windows\System32\wininit.exe`},
		{PID: 760, PPID: 680, Name: "services.exe", ImagePath: `C:\Windows\System32\services.exe`, ParentName: "wininit.exe", ParentVerified: true},
		{PID: 780, PPID: 680, Name: "lsass.exe", ImagePath: `C:\Windows\System32\lsass.exe`, ParentName: "wininit.exe", ParentVerified: true},
		{PID: 900, PPID: 760, Name: "svchost.exe", ImagePath: `C:\Windows\System32\svchost.exe`, ParentName: "services.exe", ParentVerified: true},
		{PID: 1900, PPID: 900, Name: "WmiPrvSE.exe", ImagePath: `C:\Windows\System32\wbem\WmiPrvSE.exe`, ParentName: "svchost.exe", ParentVerified: true},
		{PID: 2200, PPID: 760, Name: "MsMpEng.exe", ImagePath: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`, ParentName: "services.exe", ParentVerified: true},
		{PID: 3000, PPID: 2990, Name: "explorer.exe", ImagePath: `C:\Windows\explorer.exe`},
		{PID: 3100, PPID: 3000, Name: "WINWORD.EXE", ImagePath: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`, ParentName: "explorer.exe", ParentVerified: true},
		{PID: 3200, PPID: 3000, Name: "cmd.exe", ImagePath: `C:\Windows\System32\cmd.exe`, ParentName: "explorer.exe", ParentVerified: true},
		{PID: 3300, PPID: 3200, Name: "conhost.exe", ImagePath: `C:\Windows\System32\conhost.exe`, ParentName: "cmd.exe", ParentVerified: true},
		{PID: 3400, PPID: 3000, Name: "Ssms.exe", ImagePath: `C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe`, ParentName: "explorer.exe", ParentVerified: true},
		{PID: 3500, PPID: 900, Name: "taskhostw.exe", ImagePath: `C:\Windows\System32\taskhostw.exe`, ParentName: "svchost.exe", ParentVerified: true},
		{PID: 3600, PPID: 3000, Name: "powershell.exe", ImagePath: `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`, ParentName: "explorer.exe", ParentVerified: true},
		// lrng itself, run from a Downloads folder, is never judged.
		{PID: 4000, PPID: 3200, Name: "lrng.exe", ImagePath: `C:\Users\a\Downloads\lrng.exe`, ParentName: "cmd.exe", ParentVerified: true, Self: true},
	}
	if got := treeRules(t, procs); len(got) != 0 {
		t.Fatalf("healthy tree produced findings: %+v", got)
	}
}

func TestProcessTreeFindsEvil(t *testing.T) {
	procs := []procView{
		{PID: 10, Name: "svchost.exe", ImagePath: `C:\Users\Public\svchost.exe`, ParentName: "explorer.exe", PPID: 3, ParentVerified: true},
		{PID: 11, Name: "lsass.exe", ImagePath: `C:\Windows\System32\lsass.exe`, ParentName: "cmd.exe", PPID: 4, ParentVerified: true},
		{PID: 12, Name: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentName: "WINWORD.EXE", PPID: 5, ParentVerified: true},
		{PID: 13, Name: "cmd.exe", ImagePath: `C:\Windows\System32\cmd.exe`, ParentName: "w3wp.exe", PPID: 6, ParentVerified: true},
		{PID: 14, Name: "powershell.exe", ImagePath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, ParentName: "WmiPrvSE.exe", PPID: 7, ParentVerified: true},
		{PID: 15, Name: "cmd.exe", ImagePath: `C:\Windows\System32\cmd.exe`, ParentName: "services.exe", PPID: 8, ParentVerified: true},
		{PID: 16, Name: "scvhost.exe", ImagePath: `C:\Windows\scvhost.exe`},
		{PID: 17, Name: "Isass.exe", ImagePath: `C:\Windows\System32\Isass.exe`},
		{PID: 18, Name: "updater.exe", ImagePath: `C:\Users\a\AppData\Local\Temp\updater.exe`},
		{PID: 19, Name: "agent.exe", ImagePath: `C:\ProgramData\agent\agent.exe`},
		{PID: 20, Name: "explorer.exe", ImagePath: `C:\Windows\Temp\explorer.exe`},
	}
	got := treeRules(t, procs)
	want := map[uint32]struct {
		rule string
		sev  Severity
	}{
		10: {"process.masquerade_path", SevCritical},
		11: {"process.unexpected_parent", SevCritical},
		12: {"process.document_app_child", SevSuspect},
		13: {"process.server_app_child", SevCritical},
		14: {"process.wmi_child", SevSuspect},
		15: {"process.service_shell", SevSuspect},
		16: {"process.name_typosquat", SevSuspect},
		17: {"process.name_typosquat", SevSuspect},
		18: {"process.unusual_path", SevSuspect},
		19: {"process.unusual_path", SevNotable},
		20: {"process.masquerade_path", SevCritical},
	}
	for pid, w := range want {
		f, ok := got[pid][w.rule]
		if !ok {
			t.Errorf("pid %d: %s missing (got %v)", pid, w.rule, keys(got[pid]))
			continue
		}
		if f.Severity != w.sev {
			t.Errorf("pid %d: %s severity %s, want %s", pid, w.rule, f.Severity, w.sev)
		}
	}
	// A masquerading binary isn't additionally reported as merely "unusual".
	if _, dup := got[10]["process.unusual_path"]; dup {
		t.Error("masquerade also reported as unusual_path")
	}
}

func TestInSystemDirsArm64(t *testing.T) {
	if !inSystemDirs(`c:\windows\sysarm32`, `c:\windows`, []string{`syswow64`}) {
		t.Fatal("SysArm32 copy not accepted where SysWOW64 is")
	}
	if inSystemDirs(`c:\windows\system32\drivers`, `c:\windows`, []string{`system32`}) {
		t.Fatal("subdirectory accepted")
	}
}

func TestEditDistanceAtMostOne(t *testing.T) {
	yes := [][2]string{{"svch0st", "svchost"}, {"scvhost", "svchost"}, {"svhost", "svchost"},
		{"svchosts", "svchost"}, {"isass", "lsass"}, {"lsasss", "lsass"}}
	no := [][2]string{{"svchost", "svchost"}, {"sihost", "svchost"}, {"dashost", "dllhost"},
		{"iexplore", "explorer"}, {"lsaiso", "lsass"}, {"abc", "xyz"}}
	for _, p := range yes {
		if !editDistanceAtMostOne(p[0], p[1]) {
			t.Errorf("%q vs %q should be one edit", p[0], p[1])
		}
	}
	for _, p := range no {
		if editDistanceAtMostOne(p[0], p[1]) {
			t.Errorf("%q vs %q should not be one edit", p[0], p[1])
		}
	}
	if _, ok := typosquatOf("ssms.exe"); ok {
		t.Error("SQL Server Management Studio flagged as an smss typosquat")
	}
	if _, ok := typosquatOf("taskhost.exe"); ok {
		t.Error("taskhost.exe flagged")
	}
}

// A parent whose creation time couldn't be read may be a recycled PID: the
// parent-based rules must not fire on it.
func TestProcessTreeIgnoresUnverifiedParents(t *testing.T) {
	procs := []procView{
		{PID: 11, Name: "lsass.exe", ImagePath: `C:\Windows\System32\lsass.exe`, ParentName: "cmd.exe", PPID: 4},
		{PID: 13, Name: "cmd.exe", ImagePath: `C:\Windows\System32\cmd.exe`, ParentName: "w3wp.exe", PPID: 6},
	}
	if got := treeRules(t, procs); len(got) != 0 {
		t.Fatalf("unverified parents produced findings: %v", got)
	}
}
