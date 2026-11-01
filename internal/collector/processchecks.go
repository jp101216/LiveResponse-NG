package collector

import (
	"fmt"
	"strings"
	"time"
)

// processchecks.go — judges the process collectors share. Each catches a trick
// NIK C2 (Cisco Talos, October 2026) plays, and other implants with it:
//
//   - a process marked critical, so that ending it crashes Windows (RATs call
//     it "BSOD protection");
//   - a process started on a desktop of its own, where the signed-in user never
//     sees it (hidden VNC);
//   - an executable whose file times were set by hand (timestomping).
//
// Portable: the Windows and Linux collectors read the facts, these judge them.

// windowsCriticalProcesses are the processes Windows itself marks critical
// (ProcessBreakOnTermination), each expected under System32; the kernel's
// minimal processes have no image file at all.
var (
	windowsCriticalProcesses = set("smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
		"lsass.exe", "lsaiso.exe", "svchost.exe")
	minimalProcesses = set("system", "registry", "memory compression", "memcompression", "secure system")
)

// underSystem32 reports whether an image lives directly in the Windows
// directory's System32 (or SysWOW64) folder.
func underSystem32(imagePath, sysRoot string) bool {
	root := strings.TrimRight(strings.ToLower(strings.ReplaceAll(sysRoot, "/", `\`)), `\`)
	if root == "" {
		return false
	}
	return inSystemDirs(dirName(imagePath), root, []string{`system32`, `syswow64`})
}

// criticalProcessFinding judges a process marked critical. Windows marks only
// its own core processes; anything else has made itself unkillable, and ending
// it crashes the host — so the finding also tells the responder not to.
func criticalProcessFinding(label, name, imagePath, sysRoot string) (Finding, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	inSys := imagePath != "" && underSystem32(imagePath, sysRoot)
	switch {
	case minimalProcesses[n] && !strings.ContainsAny(imagePath, `\/`):
		// The kernel's minimal processes have no image file (Windows names
		// them, at most, by themselves).
		return Finding{}, false
	case windowsCriticalProcesses[n] && (inSys || imagePath == ""):
		// Where its image couldn't be read, the name is all there is to go on.
		return Finding{}, false
	}
	const warn = " Don't end it while responding: Windows stops with a blue screen (CRITICAL_PROCESS_DIED) the moment it " +
		"exits. Suspend it, or clear the flag with a tool that can (System Informer), and take its memory first"
	if inSys {
		return Finding{Rule: "defense.critical_process", Severity: SevNotable, Technique: "T1562", Confidence: 35,
			Detail: fmt.Sprintf("%s, a Windows program (%s), is marked critical, which Windows doesn't do for it: a "+
				"process made unkillable, by malware running in it or a tool that set the flag.%s", label, imagePath, warn)}, true
	}
	where := imagePath
	if where == "" {
		where = "its image path unreadable"
	}
	return Finding{Rule: "defense.critical_process", Severity: SevCritical, Technique: "T1562", Confidence: 90,
		Detail: fmt.Sprintf("%s (%s) is marked critical (ProcessBreakOnTermination). Windows marks only its own core "+
			"processes this way; malware marks itself so that it can't be killed (NIK C2 does, and njRAT- and "+
			"AsyncRAT-style \"BSOD protection\" works the same way).%s", label, where, warn)}, true
}

// standardDesktops are the desktops Windows runs programs on: the user's
// (Default), the secure desktop (Winlogon: the sign-in screen, UAC prompts),
// the screen saver's, and the one a disconnected session switches to.
var standardDesktops = set("default", "winlogon", "screen-saver", "disconnect")

// hvncHosts are the programs a hidden VNC starts on its desktop for the
// operator: the shell, and browsers (with a copy of the user's profile).
var (
	hvncShell    = set("explorer.exe")
	hvncBrowsers = set("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
		"iexplore.exe", "chromium.exe")
	hvncTools = set("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
		"rundll32.exe", "regsvr32.exe")
)

// splitDesktop splits DesktopInfo ("WinSta0\Default") into its window station
// and desktop; a bare name is a desktop in the inherited window station.
func splitDesktop(s string) (winsta, desktop string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

// desktopFinding judges the desktop a process started on (DesktopInfo in its
// process parameters). A hidden VNC (HVNC) creates a desktop of its own and
// starts explorer and browsers on it: the operator works in the user's
// session, with the user's cookies and sign-ins, and the user sees nothing.
// Browser sandboxes start their child processes on alternate desktops, and
// Windows Search runs its filters on one; both are left alone.
func desktopFinding(label, name, commandLine, desktopInfo string) (Finding, bool) {
	winsta, desk := splitDesktop(desktopInfo)
	ld, lw := strings.ToLower(desk), strings.ToLower(winsta)
	if ld == "" || standardDesktops[ld] {
		return Finding{}, false
	}
	if lw == "msswindowstation" && ld == "mssrestricteddesk" {
		return Finding{}, false // Windows Search's filter hosts
	}
	cl := strings.ToLower(commandLine)
	if strings.HasPrefix(ld, "sbox_alternate_desktop") &&
		(strings.Contains(cl, "--type=") || strings.Contains(cl, "-contentproc")) {
		return Finding{}, false // a Chromium or Firefox sandboxed child
	}
	n := strings.ToLower(name)
	shown := desktopInfo
	f := Finding{Rule: "defense.hidden_desktop", Technique: "T1564.003"}
	switch {
	case hvncShell[n]:
		f.Severity, f.Confidence = SevCritical, 85
		f.Detail = fmt.Sprintf("%s started on desktop %s, not the user's: a hidden VNC (HVNC) creates a desktop of its "+
			"own and starts explorer and browsers there, so the operator works in the user's session, signed in as "+
			"them, while the user sees nothing (banking trojans, NIK C2). Sysinternals Desktops also starts explorer "+
			"on extra desktops", label, shown)
	case hvncBrowsers[n] || hvncTools[n]:
		f.Severity, f.Confidence = SevSuspect, 70
		f.Detail = fmt.Sprintf("%s started on desktop %s, not the user's: a program on a desktop nobody is looking "+
			"at, where a hidden VNC (HVNC) runs browsers and shells for its operator", label, shown)
	default:
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail = fmt.Sprintf("%s started on desktop %s rather than the user's: hidden VNC (HVNC) works on a desktop "+
			"of its own; some tools legitimately use extra desktops too", label, shown)
	}
	return f, true
}

// timestompFloor is the earliest honest time an executable can carry: no
// file system or archive a program reaches Windows through records anything
// before 1980 (FAT and ZIP can't). The first day of 1970 is left alone: it is
// Unix's time zero, which reproducible builds and some packagers write.
var timestompFloor = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// implausibleTime says what is wrong with a file time, if anything.
func implausibleTime(t, now time.Time) string {
	switch {
	case t.IsZero():
		return ""
	case t.Before(timestompFloor) && !(t.UTC().Year() == 1970 && t.UTC().YearDay() == 1):
		return "before 1980"
	case t.After(now.Add(48 * time.Hour)):
		return "in the future"
	}
	return ""
}

// timestompFinding judges an executable's file times (created may be zero
// where the file system doesn't record it).
func timestompFinding(what, path string, created, modified, now time.Time) (Finding, bool) {
	var bad []string
	early := false
	for _, t := range []struct {
		name string
		at   time.Time
	}{{"created", created}, {"modified", modified}} {
		if why := implausibleTime(t.at, now); why != "" {
			bad = append(bad, fmt.Sprintf("%s %s (%s)", t.name, t.at.UTC().Format("2006-01-02 15:04:05"), why))
			early = early || why == "before 1980"
		}
	}
	if len(bad) == 0 {
		return Finding{}, false
	}
	if early {
		return Finding{Rule: "defense.timestomp", Severity: SevSuspect, Technique: "T1070.006", Confidence: 70,
			Detail: fmt.Sprintf("%s %s is dated %s: no file system or archive an executable arrives through records "+
				"a time before 1980, so its times were set by hand (timestomping) to make it look old and blend in. "+
				"NIK C2 dates its copies 1979", what, path, strings.Join(bad, ", "))}, true
	}
	return Finding{Rule: "defense.timestomp", Severity: SevNotable, Technique: "T1070.006", Confidence: 35,
		Detail: fmt.Sprintf("%s %s is dated %s: a clock that was wrong when it was written, or times set by hand",
			what, path, strings.Join(bad, ", "))}, true
}
