package collector

import (
	"fmt"
	"strings"
)

// Token theft (T1134): a token duplicated from another process and either
// worn by one of the thief's threads (ImpersonateLoggedOnUser, Cobalt Strike's
// steal_token) or used to start a process (CreateProcessWithTokenW, the
// potato exploits). No build tag: the judges are pure logic over what the
// Windows process collector reads, unit-tested on any OS.

// spawnToHosts are signed Windows programs that C2 frameworks start as
// sacrificial processes or inject into (Cobalt Strike's spawnto default is
// rundll32), and the script and build hosts used to run payloads in memory.
// None of them has a reason to wear another account's token, start a process
// as another account, or query a directory.
var spawnToHosts = set("rundll32.exe", "regsvr32.exe", "notepad.exe", "mshta.exe", "gpupdate.exe", "cmstp.exe", "odbcconf.exe",
	"hh.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe")

// tokenScriptHosts are shells that run whatever an operator types; a thread
// of one wearing another account's token is rarer than in a server, but
// scripts do impersonate on purpose now and then.
var tokenScriptHosts = set("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe")

// tokenBrokers are the Windows programs whose job includes starting
// processes as other accounts: session and service managers, the scheduler
// and COM launchers in svchost, WMI's provider host (Win32_Process.Create runs
// as the caller), Explorer's and runas's "run as different user", and
// Windows Installer. They count only when their image is in the Windows
// folder, so a copy named svchost.exe in Temp is judged like anything else.
var tokenBrokers = set("smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
	"userinit.exe", "explorer.exe", "runas.exe", "wmiprvse.exe", "msiexec.exe", "consent.exe", "taskhostw.exe", "taskeng.exe",
	"wsmprovhost.exe", "logonui.exe", "dllhost.exe")

// tokenView is one process as the token judges see it.
type tokenView struct {
	Name      string // image name from the process table
	ImagePath string // "" when unreadable
	SID       string // the primary token's user
	User      string // DOMAIN\user, "" when unresolved
}

func (v tokenView) who() string {
	if v.User != "" {
		return v.User
	}
	return v.SID
}

// threadToken is an impersonation token one thread was found wearing.
type threadToken struct {
	TID   uint32
	SID   string
	User  string
	Level string // anonymous, identification, impersonation, delegation
}

// serviceAccountSID reports SYSTEM, LOCAL SERVICE and NETWORK SERVICE.
func serviceAccountSID(sid string) bool {
	switch strings.ToUpper(strings.TrimSpace(sid)) {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	return false
}

// personSID reports a local, domain or Entra ID account: someone who logs on,
// as opposed to the operating system's own accounts.
func personSID(sid string) bool {
	s := strings.ToUpper(strings.TrimSpace(sid))
	return strings.HasPrefix(s, "S-1-5-21-") || strings.HasPrefix(s, "S-1-12-1-")
}

// inWindowsDirs reports an image directly in the Windows folder, System32 or
// SysWOW64 (Explorer lives in the first).
func inWindowsDirs(img, sysRoot string) bool {
	root := strings.TrimRight(strings.ToLower(strings.ReplaceAll(sysRoot, "/", `\`)), `\`)
	return root != "" && img != "" && inSystemDirs(dirName(img), root, []string{"", `system32`, `syswow64`})
}

// tokenBroker reports a process whose job includes switching accounts. An
// unreadable image path (a protected process) is taken at its name.
func tokenBroker(v tokenView, sysRoot string) bool {
	return tokenBrokers[strings.ToLower(v.Name)] && (v.ImagePath == "" || inWindowsDirs(v.ImagePath, sysRoot))
}

// stolenTokenFinding judges a process that runs as a different account from
// the parent that started it. Windows' brokers do that all day; anything
// else needed a token from somewhere: CreateProcessWithTokenW on a token
// duplicated from another process (how C2 frameworks run commands as a
// stolen identity), a potato exploit's SYSTEM token, or, less often, an
// administrator's Start-Process -Credential. The caller checks that the
// parent really is the parent (it was created before the child).
func stolenTokenFinding(label string, child, parent tokenView, sysRoot string) (Finding, bool) {
	if child.SID == "" || parent.SID == "" || strings.EqualFold(child.SID, parent.SID) || tokenBroker(parent, sysRoot) {
		return Finding{}, false
	}
	pname := strings.ToLower(parent.Name)
	plevel, pwhy := pathRisk(parent.ImagePath)
	risky := spawnToHosts[pname] || plevel == riskHigh
	where := ""
	if parent.ImagePath != "" {
		where = " (" + parent.ImagePath + ")"
	}
	base := fmt.Sprintf("%s runs as %s, but its parent %s%s runs as %s", label, child.who(), parent.Name, where, parent.who())
	f := Finding{Rule: "privesc.stolen_token_process", Severity: SevSuspect, Technique: "T1134.002"}
	switch {
	case serviceAccountSID(child.SID) && personSID(parent.SID):
		f.Confidence = 75
		f.Detail = base + ": a user's process started one that runs as a service account, which takes a token duplicated " +
			"from a SYSTEM process (token theft, or a potato exploit's coerced token) passed to CreateProcessWithTokenW"
	case risky:
		f.Confidence = 65
		why := "a program C2 frameworks use as a sacrificial process"
		if plevel == riskHigh {
			why = "a program running from " + pwhy
		}
		f.Detail = base + ". The parent is " + why + ", and starting a process as another account takes that account's " +
			"token: the shape of a stolen token (steal_token, then a command run with CreateProcessWithTokenW)"
	case serviceAccountSID(parent.SID) && installedProgram(parent.ImagePath):
		// An installed service starting a program in a user's session
		// (management agents, VM tools, updaters).
		return Finding{}, false
	default:
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail = base + ". Starting a process as another account takes that account's token or password: a stolen token " +
			"(CreateProcessWithTokenW), or an administrator's Start-Process -Credential or over-the-shoulder elevation"
	}
	return f, true
}

// impersonationFinding judges the threads of one process found wearing
// another account's impersonation token. Servers impersonate their clients
// constantly (svchost, LSASS, the spooler, SQL Server, IIS), so only programs
// that aren't installed servers are judged: the sacrificial and script hosts
// C2 frameworks run in, and programs outside Program Files and the Windows
// folder. Identification and anonymous tokens can't act as their account and
// pass.
func impersonationFinding(label string, proc tokenView, threads []threadToken) (Finding, bool) {
	var worn []threadToken
	for _, t := range threads {
		lvl := strings.ToLower(t.Level)
		if t.SID == "" || strings.EqualFold(t.SID, proc.SID) || strings.EqualFold(t.SID, "S-1-5-7") ||
			(lvl != "impersonation" && lvl != "delegation") {
			continue
		}
		worn = append(worn, t)
	}
	if len(worn) == 0 || proc.SID == "" {
		return Finding{}, false
	}
	name := strings.ToLower(proc.Name)
	lvl, why := pathRisk(proc.ImagePath)
	f := Finding{Rule: "privesc.thread_impersonation", Severity: SevSuspect, Technique: "T1134.001"}
	switch {
	case spawnToHosts[name]:
		f.Confidence, why = 70, "a program C2 frameworks use as a sacrificial process"
	case lvl == riskHigh:
		f.Confidence, why = 70, "a program running from "+why
	case tokenScriptHosts[name]:
		f.Confidence, why = 60, "a shell"
	case proc.ImagePath == "" || installedProgram(proc.ImagePath):
		return Finding{}, false
	default:
		f.Severity, f.Confidence, why = SevNotable, 45, "not an installed server"
	}
	t := worn[0]
	who := firstNonEmpty(t.User, t.SID)
	f.Detail = fmt.Sprintf("thread %d of %s is impersonating %s (%s level) while the process runs as %s. The process is %s, "+
		"and wearing another account's token is the shape of a stolen one (steal_token, or ImpersonateLoggedOnUser on a "+
		"duplicated token): the thread acts as that account on this host and, at delegation level, across the network",
		t.TID, label, who, strings.ToLower(t.Level), proc.who(), why)
	if serviceAccountSID(t.SID) && personSID(proc.SID) {
		f.Detail += ". A user's process wearing a service account's token is how getsystem-style escalations end"
	}
	if len(worn) > 1 {
		f.Detail += fmt.Sprintf(" (%d threads in all)", len(worn))
	}
	return f, true
}

// impersonationFields records the threads wearing a token of an account other
// than their process's (up to 16), for the process's record.
func impersonationFields(threads []threadToken, procSID string) []map[string]any {
	var out []map[string]any
	for _, t := range threads {
		if t.SID == "" || strings.EqualFold(t.SID, procSID) {
			continue
		}
		if len(out) == 16 {
			break
		}
		m := map[string]any{"tid": t.TID, "user_sid": t.SID, "level": t.Level}
		if t.User != "" {
			m["user"] = t.User
		}
		out = append(out, m)
	}
	return out
}
