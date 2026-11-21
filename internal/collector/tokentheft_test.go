package collector

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the detections that close the remaining C2 roadmap gaps
// (docs/lattice-coverage.md): token theft, the .NET runtime in a native
// process, and directory enumeration over LDAP.

const (
	sidAlice = "S-1-5-21-1004336348-1177238915-682003330-1104"
	sidAdmin = "S-1-5-21-1004336348-1177238915-682003330-500"
	sysRootC = `C:\Windows`
)

func TestStolenTokenFinding(t *testing.T) {
	sys := tokenView{SID: "S-1-5-18", User: `NT AUTHORITY\SYSTEM`}
	alice := tokenView{SID: sidAlice, User: `CORP\alice`}
	admin := tokenView{SID: sidAdmin, User: `CORP\Administrator`}
	as := func(base tokenView, name, img string) tokenView {
		base.Name, base.ImagePath = name, img
		return base
	}
	for _, c := range []struct {
		name          string
		child, parent tokenView
		want          Severity
	}{
		{"user's shell starts a SYSTEM process", as(sys, "cmd.exe", `C:\Windows\System32\cmd.exe`),
			as(alice, "cmd.exe", `C:\Windows\System32\cmd.exe`), SevSuspect},
		{"sacrificial SYSTEM process starts one as a domain admin", as(admin, "cmd.exe", `C:\Windows\System32\cmd.exe`),
			as(sys, "rundll32.exe", `C:\Windows\System32\rundll32.exe`), SevSuspect},
		{"agent in Temp starts one as another user", as(admin, "whoami.exe", `C:\Windows\System32\whoami.exe`),
			as(alice, "wraith.exe", `C:\Users\alice\AppData\Local\Temp\wraith.exe`), SevSuspect},
		{"svchost impostor in Temp", as(alice, "cmd.exe", `C:\Windows\System32\cmd.exe`),
			as(sys, "svchost.exe", `C:\Users\Public\svchost.exe`), SevSuspect},
		{"PowerShell Start-Process -Credential", as(admin, "mmc.exe", `C:\Windows\System32\mmc.exe`),
			as(alice, "powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`), SevNotable},
		{"agent in ProgramData running as SYSTEM", as(alice, "agentui.exe", `C:\ProgramData\Agent\agentui.exe`),
			as(sys, "agent.exe", `C:\ProgramData\Agent\agent.exe`), SevNotable},
		{"Explorer's run as different user", as(admin, "mmc.exe", `C:\Windows\System32\mmc.exe`),
			as(alice, "explorer.exe", `C:\Windows\explorer.exe`), ""},
		{"Task Scheduler", as(alice, "onedrive.exe", `C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe`),
			as(sys, "svchost.exe", `C:\Windows\System32\svchost.exe`), ""},
		{"protected broker with an unreadable image", as(tokenView{SID: "S-1-5-20"}, "svchost.exe", ""),
			as(sys, "services.exe", ""), ""},
		{"installed service starting its tray app", as(alice, "vmtoolsd.exe", `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`),
			as(sys, "vmtoolsd.exe", `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`), ""},
		{"management agent in the Windows folder", as(alice, "scclient.exe", `C:\Windows\CCM\SCClient.exe`),
			as(sys, "ccmexec.exe", `C:\Windows\CCM\CcmExec.exe`), ""},
		{"same account", as(alice, "notepad.exe", `C:\Windows\System32\notepad.exe`),
			as(alice, "rundll32.exe", `C:\Windows\System32\rundll32.exe`), ""},
		{"owner unreadable", as(tokenView{}, "x.exe", `C:\Users\Public\x.exe`), as(alice, "rundll32.exe", `C:\Windows\System32\rundll32.exe`), ""},
	} {
		f, ok := stolenTokenFinding("process "+c.child.Name+" (pid 7)", c.child, c.parent, sysRootC)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected %+v", c.name, f)
		case c.want != "" && (!ok || f.Rule != "privesc.stolen_token_process" || f.Severity != c.want):
			t.Errorf("%s: got %+v (ok %v), want %s", c.name, f, ok, c.want)
		case ok && !strings.Contains(f.Detail, c.parent.who()):
			t.Errorf("%s: detail doesn't name the parent's account: %s", c.name, f.Detail)
		}
	}
}

func TestImpersonationFinding(t *testing.T) {
	sys := tokenView{SID: "S-1-5-18", User: `NT AUTHORITY\SYSTEM`}
	alice := tokenView{SID: sidAlice, User: `CORP\alice`}
	as := func(base tokenView, name, img string) tokenView {
		base.Name, base.ImagePath = name, img
		return base
	}
	adminImp := []threadToken{{TID: 4410, SID: sidAdmin, User: `CORP\Administrator`, Level: "impersonation"}}
	sysImp := []threadToken{{TID: 912, SID: "S-1-5-18", User: `NT AUTHORITY\SYSTEM`, Level: "impersonation"}}
	for _, c := range []struct {
		name    string
		proc    tokenView
		threads []threadToken
		want    Severity
		has     string
	}{
		{"steal_token in a sacrificial rundll32", as(sys, "rundll32.exe", `C:\Windows\System32\rundll32.exe`), adminImp, SevSuspect, `CORP\Administrator`},
		{"agent in Temp", as(sys, "wraith.exe", `C:\Windows\Temp\wraith.exe`), adminImp, SevSuspect, "temporary"},
		{"user's PowerShell wearing SYSTEM", as(alice, "powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`),
			sysImp, SevSuspect, "getsystem"},
		{"delegation level", as(sys, "notepad.exe", `C:\Windows\System32\notepad.exe`),
			[]threadToken{{TID: 1, SID: sidAdmin, Level: "delegation"}}, SevSuspect, "across the network"},
		{"program in AppData", as(alice, "tool.exe", `C:\Users\alice\AppData\Local\Tool\tool.exe`), sysImp, SevNotable, ""},
		{"several threads", as(sys, "rundll32.exe", `C:\Windows\System32\rundll32.exe`),
			append(append([]threadToken{}, adminImp...), threadToken{TID: 4411, SID: sidAdmin, Level: "impersonation"}), SevSuspect, "2 threads"},
		{"RPC server in svchost", as(sys, "svchost.exe", `C:\Windows\System32\svchost.exe`), adminImp, "", ""},
		{"IIS worker", as(tokenView{SID: "S-1-5-82-1"}, "w3wp.exe", `C:\Windows\System32\inetsrv\w3wp.exe`), adminImp, "", ""},
		{"SQL Server", as(tokenView{SID: "S-1-5-80-1"}, "sqlservr.exe", `C:\Program Files\Microsoft SQL Server\MSSQL\Binn\sqlservr.exe`),
			adminImp, "", ""},
		{"identification level only", as(sys, "rundll32.exe", `C:\Windows\System32\rundll32.exe`),
			[]threadToken{{TID: 1, SID: sidAdmin, Level: "identification"}}, "", ""},
		{"anonymous token", as(sys, "rundll32.exe", `C:\Windows\System32\rundll32.exe`),
			[]threadToken{{TID: 1, SID: "S-1-5-7", Level: "impersonation"}}, "", ""},
		{"its own account", as(alice, "rundll32.exe", `C:\Windows\System32\rundll32.exe`),
			[]threadToken{{TID: 1, SID: sidAlice, Level: "impersonation"}}, "", ""},
		{"process owner unread", as(tokenView{}, "rundll32.exe", `C:\Windows\System32\rundll32.exe`), adminImp, "", ""},
	} {
		f, ok := impersonationFinding("process "+c.proc.Name+" (pid 9)", c.proc, c.threads)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected %+v", c.name, f)
		case c.want != "" && (!ok || f.Rule != "privesc.thread_impersonation" || f.Severity != c.want):
			t.Errorf("%s: got %+v (ok %v), want %s", c.name, f, ok, c.want)
		case ok && !strings.Contains(f.Detail, c.has):
			t.Errorf("%s: detail lacks %q: %s", c.name, c.has, f.Detail)
		}
	}

	var many []threadToken
	for i := 0; i < 20; i++ {
		many = append(many, threadToken{TID: uint32(i), SID: sidAdmin, Level: "impersonation"})
	}
	many = append(many, threadToken{TID: 99, SID: sidAlice, Level: "impersonation"})
	if got := impersonationFields(many, sidAlice); len(got) != 16 || got[0]["user_sid"] != sidAdmin {
		t.Errorf("impersonationFields: got %d entries, want 16 of the other account's", len(got))
	}
	if got := impersonationFields(many[20:], sidAlice); len(got) != 0 {
		t.Errorf("impersonationFields recorded the process's own account: %v", got)
	}
}

// writePE writes a minimal PE image: a DOS header, the PE signature, a COFF
// header with no sections and an optional header whose COM descriptor
// directory is set when managed.
func writePE(t *testing.T, dir, name string, pe32plus, managed bool) string {
	t.Helper()
	var b bytes.Buffer
	dos := make([]byte, 64)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[60:], 64)
	b.Write(dos)
	b.WriteString("PE\x00\x00")
	machine, ohSize, magic := uint16(0x14c), uint16(224), uint16(0x10b)
	if pe32plus {
		machine, ohSize, magic = 0x8664, 240, 0x20b
	}
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], machine)
	binary.LittleEndian.PutUint16(coff[16:], ohSize)
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)
	b.Write(coff)
	oh := make([]byte, ohSize)
	binary.LittleEndian.PutUint16(oh[0:], magic)
	dirs := 92 // offset of NumberOfRvaAndSizes in PE32
	if pe32plus {
		dirs = 108
	}
	binary.LittleEndian.PutUint32(oh[dirs:], 16)
	if managed {
		entry := dirs + 4 + 14*8
		binary.LittleEndian.PutUint32(oh[entry:], 0x2008)
		binary.LittleEndian.PutUint32(oh[entry+4:], 0x48)
	}
	b.Write(oh)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagedPE(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		name              string
		pe32plus, managed bool
		want              peKind
	}{
		{"native64.exe", true, false, peNative},
		{"managed64.exe", true, true, peManaged},
		{"native32.exe", false, false, peNative},
		{"managed32.exe", false, true, peManaged},
	} {
		if got := managedPE(writePE(t, dir, c.name, c.pe32plus, c.managed)); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	junk := filepath.Join(dir, "junk.exe")
	if err := os.WriteFile(junk, []byte("not a PE file"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{junk, filepath.Join(dir, "missing.exe"), dir} {
		if got := managedPE(p); got != peUnknown {
			t.Errorf("%s: got %s, want unknown", p, got)
		}
	}
}

func TestCLRInNativeFinding(t *testing.T) {
	clr := `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll`
	for _, c := range []struct {
		name, image, cmdline string
		kind                 peKind
		want                 Severity
	}{
		{"execute-assembly in rundll32", `C:\Windows\System32\rundll32.exe`, "rundll32.exe", peUnknown, SevSuspect},
		{"spawnto notepad", `C:\Windows\SysWOW64\notepad.exe`, "", peNative, SevSuspect},
		{"DotNetToJScript in wscript (or an admin script's .NET COM objects)", `C:\Windows\System32\wscript.exe`, "", peNative, SevNotable},
		{"spawnto mshta", `C:\Windows\System32\mshta.exe`, "", peNative, SevSuspect},
		{"implant in Temp hosting the CLR", `C:\Users\bob\AppData\Local\Temp\wraith.exe`, "", peNative, SevSuspect},
		{"native program in AppData", `C:\Users\bob\AppData\Local\App\app.exe`, "", peNative, SevNotable},
		{"Windows Installer managed custom action", `C:\Windows\System32\rundll32.exe`,
			`rundll32.exe "C:\Windows\Installer\MSI8A2.tmp",zzzzInvokeManagedCustomActionOutOfProc SfxCA_1 2 Ca!Ca.Run`, peNative, ""},
		{"ClickOnce launch", `C:\Windows\System32\rundll32.exe`,
			`rundll32.exe dfshim.dll,ShOpenVerbApplication https://apps.example.com/tool.application`, peNative, ""},
		{".NET program in Temp", `C:\Users\bob\AppData\Local\Temp\setup.exe`, "", peManaged, ""},
		{"unreadable image in Temp", `C:\Users\bob\AppData\Local\Temp\setup.exe`, "", peUnknown, ""},
		{"MSBuild", `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`, "", peUnknown, ""},
		{"MMC snap-ins", `C:\Windows\System32\mmc.exe`, "", peNative, ""},
		{"Windows PowerShell", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "", peNative, ""},
		{"Office add-in", `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, "", peNative, ""},
	} {
		f, ok := clrInNativeFinding("x (pid 3)", c.image, clr, c.cmdline, c.kind)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected %+v", c.name, f)
		case c.want != "" && (!ok || f.Rule != "modules.clr_in_native_process" || f.Severity != c.want || f.Technique != "T1620"):
			t.Errorf("%s: got %+v (ok %v), want %s", c.name, f, ok, c.want)
		}
	}
	for _, p := range []string{clr, `C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorwks.dll`} {
		if !clrModule(p) {
			t.Errorf("clrModule(%s) = false", p)
		}
	}
	if clrModule(`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\coreclr.dll`) {
		t.Error("clrModule matched .NET's coreclr.dll")
	}

	// Sysmon's image-load event, through the event dispatch.
	load := func(img, dll string) winEvent {
		return sysmonEvent(7, map[string]string{"Image": img, "ImageLoaded": dll, "ProcessId": "5120"})
	}
	if got := ruleSeverities(eventFindings(load(`C:\Windows\System32\rundll32.exe`, clr)), "modules.clr_in_native_process"); len(got) != 1 || got[0] != SevSuspect {
		t.Errorf("Sysmon 7 into rundll32: got %v", got)
	}
	for _, ev := range []winEvent{
		load(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, clr),
		load(`C:\Windows\System32\rundll32.exe`, `C:\Windows\System32\shell32.dll`),
		load(`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`, clr),
		{EventID: 7, Provider: "Microsoft-Windows-Kernel-General", Data: map[string]string{
			"Image": `C:\Windows\System32\rundll32.exe`, "ImageLoaded": clr}},
	} {
		if got := ruleSeverities(eventFindings(ev), "modules.clr_in_native_process"); len(got) != 0 {
			t.Errorf("unexpected finding for %v", ev.Data)
		}
	}
}

func TestLDAPDiscoveryFinding(t *testing.T) {
	ap := netip.MustParseAddrPort
	for _, c := range []struct {
		name, image, cmdline string
		peer                 netip.AddrPort
		want                 Severity
	}{
		{"net-enum from a sacrificial rundll32", `C:\Windows\System32\rundll32.exe`, "rundll32.exe", ap("10.0.0.5:389"), SevSuspect},
		{"image path unread, judged by name", "rundll32.exe", "", ap("10.0.0.5:389"), SevSuspect},
		{"Find Users dialog", `C:\Windows\System32\rundll32.exe`, `rundll32.exe dsquery.dll,OpenQueryWindow`, ap("10.0.0.5:389"), SevNotable},
		{"SharpHound from Temp over LDAPS", `C:\Users\bob\AppData\Local\Temp\sh.exe`, "", ap("10.0.0.5:636"), SevSuspect},
		{"global catalog from the Public profile", `C:\Users\Public\a.exe`, "", ap("[fd00::5]:3268"), SevSuspect},
		{"PowerShell", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "", ap("10.0.0.5:3268"), SevNotable},
		{"program in AppData", `C:\Users\bob\AppData\Local\Tool\tool.exe`, "", ap("10.0.0.5:389"), SevNotable},
		{"Linux agent in /dev/shm", "/dev/shm/.x/agent", "", ap("10.0.0.5:389"), SevSuspect},
		{"BloodHound.py", "/usr/bin/python3.12", "", ap("10.0.0.5:389"), SevNotable},
		{"Linux program in a home folder", "/home/bob/tools/enum", "", ap("10.0.0.5:636"), SevNotable},
		{"LSASS", `C:\Windows\System32\lsass.exe`, "", ap("10.0.0.5:389"), ""},
		{"Group Policy in svchost", `C:\Windows\System32\svchost.exe`, "", ap("10.0.0.5:389"), ""},
		{"installed program", `C:\Program Files\Vendor\agent.exe`, "", ap("10.0.0.5:636"), ""},
		{"SSSD", "/usr/libexec/sssd/sssd_be", "", ap("10.0.0.5:389"), ""},
		{"cmd.exe", `C:\Windows\System32\cmd.exe`, "", ap("10.0.0.5:389"), ""},
		{"loopback", `C:\Users\Public\a.exe`, "", ap("127.0.0.1:389"), ""},
		{"not LDAP", `C:\Users\Public\a.exe`, "", ap("10.0.0.5:445"), ""},
		{"no image", "", "", ap("10.0.0.5:389"), ""},
		{"bare name of an ordinary program", "agent.exe", "", ap("10.0.0.5:389"), ""},
		{"bare name of LSASS", "lsass.exe", "", ap("10.0.0.5:389"), ""},
	} {
		f, ok := ldapDiscoveryFinding("x (pid 2)", c.image, c.cmdline, c.peer, "")
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected %+v", c.name, f)
		case c.want != "" && (!ok || f.Rule != "discovery.ldap_unusual_process" || f.Severity != c.want):
			t.Errorf("%s: got %+v (ok %v), want %s", c.name, f, ok, c.want)
		}
	}

	// The live Windows and Linux paths, and Sysmon's network event.
	conn := connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("10.0.0.5"), RemotePort: 389, PID: 812,
		Process: "rundll32.exe", ImagePath: `C:\Windows\System32\rundll32.exe`}
	if got := ruleSeverities(analyzeConnection(conn), "discovery.ldap_unusual_process"); len(got) != 1 {
		t.Errorf("analyzeConnection: got %v", got)
	}
	conn.State = "TIME_WAIT"
	if got := ruleSeverities(analyzeConnection(conn), "discovery.ldap_unusual_process"); len(got) != 0 {
		t.Errorf("analyzeConnection judged a closing socket: %v", got)
	}
	lin := connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("10.0.0.5"), RemotePort: 636, PID: 77,
		Process: "agent", ImagePath: "/tmp/agent"}
	if got := ruleSeverities(linuxConnFindings(lin), "discovery.ldap_unusual_process"); len(got) != 1 {
		t.Errorf("linuxConnFindings: got %v", got)
	}
	lin.Inbound = true
	if got := ruleSeverities(linuxConnFindings(lin), "discovery.ldap_unusual_process"); len(got) != 0 {
		t.Errorf("linuxConnFindings judged an accepted connection: %v", got)
	}
	ev := sysmonEvent(3, map[string]string{"Initiated": "true", "Image": `C:\Windows\System32\rundll32.exe`, "ProcessId": "812",
		"DestinationIp": "10.0.0.5", "DestinationPort": "389", "Protocol": "tcp"})
	if got := ruleSeverities(eventFindings(ev), "discovery.ldap_unusual_process"); len(got) != 1 {
		t.Errorf("Sysmon 3: got %v", got)
	}
	ev.Data["Initiated"] = "false"
	if got := ruleSeverities(eventFindings(ev), "discovery.ldap_unusual_process"); len(got) != 0 {
		t.Errorf("Sysmon 3 judged an inbound connection: %v", got)
	}
}
