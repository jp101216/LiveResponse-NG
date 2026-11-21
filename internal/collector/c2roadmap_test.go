package collector

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Tests for the detections added to cover the remaining features on a C2
// framework's roadmap (docs/lattice-coverage.md): encrypted DNS, Mojo pipe
// impostors, Linux shell recon chains, listeners from dropped programs,
// self-deleting images and stripped process protection.

func sysmonEvent(id int, data map[string]string) winEvent {
	return winEvent{EventID: id, Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational",
		TimeCreated: time.Date(2026, 11, 21, 7, 0, 0, 0, time.UTC), Data: data}
}

func ruleSeverities(fs []Finding, rule string) []Severity {
	var out []Severity
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f.Severity)
		}
	}
	return out
}

func TestDoHFinding(t *testing.T) {
	ap := func(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
	for _, c := range []struct {
		name, image string
		peer        netip.AddrPort
		want        Severity
	}{
		{"dropped program to Cloudflare DoH", `C:\Users\bob\AppData\Local\Temp\upd.exe`, ap("1.1.1.1:443"), SevSuspect},
		{"Quad9 over IPv6", `C:\Users\bob\Downloads\tool.exe`, ap("[2620:fe::fe]:443"), SevSuspect},
		{"IPv4-mapped Google", `C:\Users\bob\Downloads\tool.exe`, ap("[::ffff:8.8.8.8]:443"), SevSuspect},
		{"DoT anywhere", `C:\ProgramData\svc\agent.exe`, ap("203.0.113.7:853"), SevSuspect},
		{"Linux agent in /tmp", "/tmp/.cache/agent", ap("9.9.9.9:443"), SevSuspect},
		{"installed program", `C:\Program Files\Vendor\vpn.exe`, ap("1.0.0.1:443"), SevNotable},
		{"packaged Linux tool", "/usr/bin/curl", ap("1.1.1.1:443"), SevNotable},
		{"browser", `C:\Program Files\Google\Chrome\Application\chrome.exe`, ap("1.1.1.1:443"), ""},
		{"DNS client", `C:\Windows\System32\svchost.exe`, ap("1.1.1.1:443"), ""},
		{"systemd-resolved DoT", "/usr/lib/systemd/systemd-resolved", ap("1.1.1.1:853"), ""},
		{"WARP", `C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe`, ap("1.1.1.1:443"), ""},
		{"HTTPS elsewhere", `C:\Users\bob\AppData\Local\Temp\upd.exe`, ap("93.184.216.34:443"), ""},
	} {
		f, ok := dohFinding("x (pid 1)", c.image, c.peer, "")
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected %+v", c.name, f)
		case c.want != "" && (!ok || f.Rule != "network.doh_outbound" || f.Severity != c.want):
			t.Errorf("%s: got %+v (ok %v), want %s", c.name, f, ok, c.want)
		}
	}

	// Through Sysmon's network event and both live connection paths.
	ev := sysmonEvent(3, map[string]string{"Initiated": "true", "Image": `C:\Users\bob\AppData\Local\Temp\upd.exe`,
		"ProcessId": "4242", "DestinationIp": "1.1.1.1", "DestinationPort": "443", "Protocol": "tcp"})
	if got := ruleSeverities(eventFindings(ev), "network.doh_outbound"); len(got) != 1 {
		t.Errorf("Sysmon 3: %v", got)
	}
	cv := connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("8.8.4.4"), RemotePort: 443, PID: 900,
		Process: "upd.exe", ImagePath: `C:\Users\Public\upd.exe`}
	if got := ruleSeverities(analyzeConnection(cv), "network.doh_outbound"); len(got) != 1 {
		t.Errorf("Windows live: %v", got)
	}
	cv = connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("94.140.14.14"), RemotePort: 853, PID: 900,
		Process: "agent", ImagePath: "/dev/shm/agent"}
	if got := ruleSeverities(linuxConnFindings(cv), "network.doh_outbound"); len(got) != 1 {
		t.Errorf("Linux live: %v", got)
	}
}

func TestUnusualPathListener(t *testing.T) {
	any4 := netip.MustParseAddr("0.0.0.0")
	lo := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		name  string
		c     connView
		linux bool
		want  Severity
	}{
		{"SOCKS from Temp", connView{State: "LISTEN", Local: any4, LocalPort: 1080, PID: 7, Process: "svc.exe",
			ImagePath: `C:\Users\bob\AppData\Local\Temp\svc.exe`}, false, SevSuspect},
		{"loopback SOCKS from Public", connView{State: "LISTEN", Local: lo, LocalPort: 1080, PID: 7, Process: "svc.exe",
			ImagePath: `C:\Users\Public\svc.exe`}, false, SevNotable},
		{"installed server", connView{State: "LISTEN", Local: any4, LocalPort: 8080, PID: 7, Process: "srv.exe",
			ImagePath: `C:\Program Files\Srv\srv.exe`}, false, ""},
		{"Linux relay in /tmp", connView{State: "LISTEN", Local: any4, LocalPort: 4445, PID: 7, Process: "relay",
			ImagePath: "/tmp/relay"}, true, SevSuspect},
		{"Linux daemon", connView{State: "LISTEN", Local: any4, LocalPort: 22, PID: 7, Process: "sshd",
			ImagePath: "/usr/sbin/sshd"}, true, ""},
		{"outbound only", connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("10.0.0.5"), RemotePort: 443, PID: 7,
			Process: "svc.exe", ImagePath: `C:\Users\Public\svc.exe`}, false, ""},
	} {
		fs := analyzeConnection(c.c)
		if c.linux {
			fs = linuxConnFindings(c.c)
		}
		got := ruleSeverities(fs, "network.unusual_path_listener")
		if (c.want == "" && len(got) != 0) || (c.want != "" && (len(got) != 1 || got[0] != c.want)) {
			t.Errorf("%s: %v, want %q", c.name, got, c.want)
		}
	}
}

func TestMojoPipeImpostor(t *testing.T) {
	for _, c := range []struct {
		name, pipe, image string
		want              Severity
	}{
		{"non-Chromium creator", "mojo.5688.8052.1234", `C:\Users\bob\AppData\Local\Temp\a.exe`, SevSuspect},
		{"installed non-Chromium creator", "mojo.1.2.3", `C:\Program Files\Vendor\app.exe`, SevNotable},
		{"Chrome", "mojo.6024.7612.18446744073709551", `C:\Program Files\Google\Chrome\Application\chrome.exe`, ""},
		{"Electron app", "mojo.1.2.3", `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`, ""},
		{"live, wrong shape", "mojo.5688", "", SevSuspect},
		{"live, Chromium shape", "mojo.6024.7612.1844674407370955161", "", ""},
		{"not mojo", "status_1a", "", ""},
	} {
		f, ok := mojoImpostorFinding(c.pipe, c.image)
		if (c.want == "" && ok) || (c.want != "" && (!ok || f.Severity != c.want || f.Rule != "network.mojo_pipe_impostor")) {
			t.Errorf("%s: %+v (ok %v), want %q", c.name, f, ok, c.want)
		}
	}

	// Sysmon 17: an impostor is reported, Cobalt Strike's own default still
	// by its name, and a connection (18) to a mojo pipe isn't judged.
	mk := func(id int, pipe, image string) winEvent {
		return sysmonEvent(id, map[string]string{"PipeName": `\` + pipe, "Image": image})
	}
	if got := ruleSeverities(eventFindings(mk(17, "mojo.5688", `C:\Users\Public\a.exe`)), "network.mojo_pipe_impostor"); len(got) != 1 {
		t.Errorf("Sysmon 17 impostor: %v", got)
	}
	if got := ruleSeverities(eventFindings(mk(17, "mojo.5688.8052.18389493978708887731", `C:\Users\Public\a.exe`)),
		"network.c2_named_pipe"); len(got) != 1 {
		t.Errorf("Cobalt Strike default: %v", got)
	}
	if fs := eventFindings(mk(18, "mojo.5688", `C:\Users\Public\a.exe`)); len(fs) != 0 {
		t.Errorf("Sysmon 18: %+v", fs)
	}

	res := NewResult("lateral")
	lateralReport(res, []string{"mojo.5688", "mojo.1.2.3", "lsass"}, nil, nil)
	n := 0
	for _, r := range res.Records {
		n += len(ruleSeverities(r.Findings, "network.mojo_pipe_impostor"))
	}
	if n != 1 {
		t.Errorf("live pipe list: %d impostor findings, want 1", n)
	}
}

func TestUnixShellRecon(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want Severity
		conf int
	}{
		// Project Lattice's agent, as /proc/<pid>/cmdline joins it.
		{"sh -c hostname 2>/dev/null || uname -n", SevNotable, 45},
		{"sh -c whoami 2>/dev/null || id -un", SevNotable, 45},
		{"sh -c ip -o addr show 2>/dev/null || ifconfig 2>/dev/null", SevNotable, 45},
		{"sh -c ss -tulnp 2>/dev/null || netstat -tuln 2>/dev/null | head -n 20", SevNotable, 45},
		{"/bin/sh -c id && uname -a && ps -ef | head -n 10", SevNotable, 35},
		{"bash -c cat /etc/passwd; w; last -n 5", SevNotable, 35},
		// Not recon chains.
		{"sh -c make install", "", 0},
		{"bash -c ps -ef | grep nginx", "", 0},
		{"sh -c command -v systemctl 2>/dev/null || echo none", "", 0},
		{"python3 -c whoami; id; uname", "", 0},
		{"whoami", "", 0},
	} {
		sev, conf, what, ok := unixShellRecon(strings.ToLower(c.cmd))
		if (c.want == "" && ok) || (c.want != "" && (!ok || sev != c.want || conf != c.conf)) {
			t.Errorf("%q: %s %d %q (ok %v), want %s %d", c.cmd, sev, conf, what, ok, c.want, c.conf)
		}
	}
	fs := analyzeUnixCommandLine("process sh (pid 5) command line", "/usr/bin/dash", "sh -c whoami 2>/dev/null || id -un")
	if got := ruleSeverities(fs, "exec.c2_shell_recon"); len(got) != 1 {
		t.Errorf("through analyzeUnixCommandLine: %+v", fs)
	}
}

func TestSelfDeleteAndDeletedImage(t *testing.T) {
	f := deletedImageFinding("process upd.exe (pid 9)", `C:\Users\bob\AppData\Local\Temp\upd.exe`)
	if f.Rule != "process.deleted_binary" || f.Severity != SevSuspect || !strings.Contains(f.Detail, "alternate stream") {
		t.Errorf("deleted image: %+v", f)
	}
	mk := func(id int, image, target string) winEvent {
		return sysmonEvent(id, map[string]string{"Image": image, "TargetFilename": target, "ProcessId": "77"})
	}
	img := `C:\Users\bob\AppData\Local\Temp\upd.exe`
	for _, c := range []struct {
		ev   winEvent
		want Severity
	}{
		{mk(26, img, img), SevSuspect},
		{mk(23, img, strings.ToUpper(img)), SevSuspect},
		{mk(26, `C:\Program Files\App\unins000.exe`, `C:\Program Files\App\unins000.exe`), SevNotable},
		{mk(26, img, `C:\Users\bob\AppData\Local\Temp\other.tmp`), ""},
	} {
		got := ruleSeverities(eventFindings(c.ev), "defense.self_delete")
		if (c.want == "" && len(got) != 0) || (c.want != "" && (len(got) != 1 || got[0] != c.want)) {
			t.Errorf("%+v: %v, want %q", c.ev.Data, got, c.want)
		}
	}
	// Event 26 from another provider isn't Sysmon's.
	other := mk(26, img, img)
	other.Provider, other.Channel = "Application Popup", "System"
	if fs := eventFindings(other); len(fs) != 0 {
		t.Errorf("non-Sysmon 26: %+v", fs)
	}
}

func TestPPLFindings(t *testing.T) {
	one, zero := uint32(1), uint32(0)
	const wintcbLight, lsaLight, amLight = 0x61, 0x41, 0x31
	for _, c := range []struct {
		name     string
		p        protectedProcess
		runAsPPL *uint32
		want     Severity
	}{
		{"csrss stripped", protectedProcess{"csrss.exe", 600, 0}, nil, SevCritical},
		{"services stripped", protectedProcess{"services.exe", 700, 0}, nil, SevCritical},
		{"csrss protected", protectedProcess{"csrss.exe", 600, wintcbLight}, nil, ""},
		{"lsass stripped with RunAsPPL", protectedProcess{"lsass.exe", 780, 0}, &one, SevSuspect},
		{"lsass PPL", protectedProcess{"lsass.exe", 780, lsaLight}, &one, ""},
		{"lsass unprotected, not configured", protectedProcess{"lsass.exe", 780, 0}, nil, ""},
		{"lsass unprotected, switched off", protectedProcess{"lsass.exe", 780, 0}, &zero, ""},
		{"Defender stripped", protectedProcess{"msmpeng.exe", 3000, 0}, nil, SevSuspect},
		{"Defender PPL", protectedProcess{"msmpeng.exe", 3000, amLight}, nil, ""},
	} {
		got := ruleSeverities(pplFindings([]protectedProcess{c.p}, c.runAsPPL), "defense.ppl_stripped")
		if (c.want == "" && len(got) != 0) || (c.want != "" && (len(got) != 1 || got[0] != c.want)) {
			t.Errorf("%s: %v, want %q", c.name, got, c.want)
		}
	}
	for level, want := range map[byte]string{0: "unprotected", lsaLight: "PPL (Lsa)", 0x72: "PP (WinSystem)", amLight: "PPL (Antimalware)"} {
		if got := pplLevelName(level); got != want {
			t.Errorf("pplLevelName(%#x) = %q, want %q", level, got, want)
		}
	}
	res := NewResult("defenses")
	pplReport(res, []protectedProcess{{"csrss.exe", 600, 0}, {"lsass.exe", 780, lsaLight}}, 1, &one)
	if len(res.Records) != 1 || len(res.Records[0].Findings) != 1 || res.Records[0].Fields["unread"] != 1 {
		t.Errorf("report: %+v", res.Records)
	}
}

func TestLSASSIndirectSyscall(t *testing.T) {
	mk := func(target, trace string) winEvent {
		return sysmonEvent(10, map[string]string{"SourceImage": `C:\Users\Public\w.exe`, "TargetImage": target,
			"GrantedAccess": "0x1fffff", "CallTrace": trace})
	}
	lsass := `C:\Windows\system32\lsass.exe`
	for _, c := range []struct {
		name, target, trace, rule string
	}{
		{"indirect into LSASS", lsass, `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(000001A2B3C40123)`, "defense.indirect_syscall"},
		{"direct into LSASS", lsass, `UNKNOWN(000001A2B3C40123)|C:\x.exe+10`, "defense.direct_syscall"},
		{"ordinary LSASS access", lsass, `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e`, ""},
		{"JIT caller further up", lsass, `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|UNKNOWN(1)`, ""},
		{"no ntdll frame first", lsass, `C:\x.exe+10|UNKNOWN(000001A2B3C40123)`, ""},
		{"JIT frames elsewhere", `C:\x\notepad.exe`, `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(000001A2B3C40123)`, ""},
	} {
		fs := eventFindings(mk(c.target, c.trace))
		switch {
		case c.rule == "" && len(fs) != 0:
			t.Errorf("%s: %+v", c.name, fs)
		case c.rule != "" && (len(fs) != 1 || fs[0].Rule != c.rule || fs[0].Severity != SevCritical):
			t.Errorf("%s: %+v, want %s", c.name, fs, c.rule)
		}
	}
}
