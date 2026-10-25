package collector

import (
	"fmt"
	"strings"
)

// Process-tree heuristics: the "know normal, find evil" checks a responder
// runs by eye over a process list — a system binary in the wrong directory,
// with the wrong parent, a document reader spawning a shell, a web server
// spawning a shell, or a name one typo away from a system process.
//
// No build tag: pure logic over plain values, unit-tested on any OS.

// procView is what the tree heuristics need to know about one process.
type procView struct {
	PID, PPID  uint32
	Name       string // as reported by the process snapshot
	ImagePath  string // full path, "" when it couldn't be read
	ParentName string // "" when the parent is gone, unknown, or its PID was reused
	// ParentVerified is true only when both creation times are known and the
	// parent predates the child. Without that, the "parent" could be an
	// unrelated process that was handed a recycled PID, so the parent-based
	// rules (some of them critical) stay silent.
	ParentVerified bool
	Self           bool // lrng or one of its components: never judged
}

// systemBinaryDirs lists where core Windows binaries live, relative to
// %SystemRoot% ("" is %SystemRoot% itself). A copy running from anywhere else
// is masquerading (T1036.005). Store-delivered apps (notepad, paint on
// Windows 11) are deliberately absent.
var systemBinaryDirs = map[string][]string{
	"svchost.exe":       {`system32`, `syswow64`},
	"lsass.exe":         {`system32`},
	"lsaiso.exe":        {`system32`},
	"services.exe":      {`system32`},
	"csrss.exe":         {`system32`},
	"smss.exe":          {`system32`},
	"wininit.exe":       {`system32`},
	"winlogon.exe":      {`system32`},
	"taskhostw.exe":     {`system32`},
	"spoolsv.exe":       {`system32`},
	"explorer.exe":      {``, `syswow64`},
	"conhost.exe":       {`system32`},
	"dllhost.exe":       {`system32`, `syswow64`},
	"rundll32.exe":      {`system32`, `syswow64`},
	"regsvr32.exe":      {`system32`, `syswow64`},
	"cmd.exe":           {`system32`, `syswow64`},
	"powershell.exe":    {`system32\windowspowershell\v1.0`, `syswow64\windowspowershell\v1.0`},
	"wmiprvse.exe":      {`system32\wbem`, `syswow64\wbem`},
	"mshta.exe":         {`system32`, `syswow64`},
	"wscript.exe":       {`system32`, `syswow64`},
	"cscript.exe":       {`system32`, `syswow64`},
	"sihost.exe":        {`system32`},
	"dwm.exe":           {`system32`},
	"fontdrvhost.exe":   {`system32`},
	"runtimebroker.exe": {`system32`},
	"userinit.exe":      {`system32`},
	"logonui.exe":       {`system32`},
	"searchindexer.exe": {`system32`},
	"audiodg.exe":       {`system32`},
	"ctfmon.exe":        {`system32`, `syswow64`},
	"msiexec.exe":       {`system32`, `syswow64`},
	"certutil.exe":      {`system32`, `syswow64`},
	"werfault.exe":      {`system32`, `syswow64`},
}

// expectedParents lists the only parents some processes ever have. A
// different (living, non-reused) parent means injection-launched lookalikes or
// PPID spoofing. The "smss.exe" parents exit after start-up, so for those the
// check only fires when a different process is found in the parent slot.
var expectedParents = map[string]struct {
	parents []string
	sev     Severity
}{
	"lsass.exe":         {[]string{"wininit.exe"}, SevCritical},
	"lsaiso.exe":        {[]string{"wininit.exe"}, SevCritical},
	"services.exe":      {[]string{"wininit.exe"}, SevCritical},
	"wininit.exe":       {[]string{"smss.exe"}, SevCritical},
	"csrss.exe":         {[]string{"smss.exe"}, SevCritical},
	"winlogon.exe":      {[]string{"smss.exe"}, SevCritical},
	"smss.exe":          {[]string{"system", "smss.exe"}, SevCritical},
	"svchost.exe":       {[]string{"services.exe"}, SevSuspect},
	"spoolsv.exe":       {[]string{"services.exe"}, SevSuspect},
	"searchindexer.exe": {[]string{"services.exe"}, SevSuspect},
	"taskhostw.exe":     {[]string{"svchost.exe"}, SevSuspect},
	"runtimebroker.exe": {[]string{"svchost.exe"}, SevSuspect},
	"wmiprvse.exe":      {[]string{"svchost.exe"}, SevSuspect},
	"sihost.exe":        {[]string{"svchost.exe"}, SevSuspect},
	"dwm.exe":           {[]string{"winlogon.exe"}, SevSuspect},
	"logonui.exe":       {[]string{"winlogon.exe", "wininit.exe"}, SevSuspect},
	"fontdrvhost.exe":   {[]string{"wininit.exe", "winlogon.exe"}, SevSuspect},
	"userinit.exe":      {[]string{"winlogon.exe"}, SevSuspect},
}

// shellLike are interpreters and LOLBins an exploited application spawns.
var shellLike = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "wscript.exe": true,
	"cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"certutil.exe": true, "bitsadmin.exe": true, "msbuild.exe": true, "installutil.exe": true,
	"regasm.exe": true, "regsvcs.exe": true, "schtasks.exe": true, "wmic.exe": true,
	"curl.exe": true, "cmstp.exe": true, "hh.exe": true, "forfiles.exe": true,
}

// documentApps open untrusted documents; one spawning a shell is the classic
// malicious-macro / exploit chain (T1204.002 via T1566.001).
var documentApps = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true,
	"msaccess.exe": true, "mspub.exe": true, "onenote.exe": true, "onenotem.exe": true,
	"visio.exe": true, "winproj.exe": true, "acrord32.exe": true, "acrobat.exe": true,
	"foxitreader.exe": true, "foxitpdfreader.exe": true, "wordpad.exe": true, "hwp.exe": true,
}

// serverApps are internet-facing servers; one spawning a shell is the shape
// of a web shell or exploited service (T1505.003, T1190).
var serverApps = map[string]bool{
	"w3wp.exe": true, "httpd.exe": true, "nginx.exe": true, "php-cgi.exe": true,
	"tomcat.exe": true, "tomcat7.exe": true, "tomcat8.exe": true, "tomcat9.exe": true,
	"tomcat10.exe": true, "sqlservr.exe": true, "umworkerprocess.exe": true,
	"umservice.exe": true, "jboss.exe": true, "weblogic.exe": true,
}

// squatTargets are process names malware imitates with a one-character
// change (svch0st, scvhost, lsasss, Isass, ...).
var squatTargets = []string{
	"svchost", "lsass", "csrss", "services", "winlogon", "wininit", "explorer",
	"spoolsv", "taskhostw", "conhost", "dllhost", "rundll32", "smss",
}

// knownGoodNames are legitimate programs one edit away from a squat target:
// taskhost.exe (Windows 7/8), SQL Server Management Studio (ssms.exe, an
// adjacent swap of smss) and the generic service.exe some vendors ship.
var knownGoodNames = map[string]bool{
	"taskhost": true, "ssms": true, "service": true,
}

// analyzeProcessTree returns findings per PID. systemRoot is the host's
// Windows directory (e.g. C:\Windows), used to check where system binaries
// run from.
func analyzeProcessTree(procs []procView, systemRoot string) map[uint32][]Finding {
	out := map[uint32][]Finding{}
	add := func(pid uint32, f Finding) { out[pid] = mergeFindings(out[pid], f) }
	sysRoot := strings.TrimRight(strings.ToLower(strings.ReplaceAll(systemRoot, "/", `\`)), `\`)

	for _, p := range procs {
		if p.Self || p.PID == 0 || p.PID == 4 {
			continue
		}
		name := strings.ToLower(p.Name)
		parent := ""
		if p.ParentVerified {
			parent = strings.ToLower(p.ParentName)
		}
		label := fmt.Sprintf("%s (pid %d)", p.Name, p.PID)

		masquerade := false
		if dirs, ok := systemBinaryDirs[name]; ok && p.ImagePath != "" && sysRoot != "" {
			if !inSystemDirs(dirName(p.ImagePath), sysRoot, dirs) {
				masquerade = true
				add(p.PID, Finding{
					Rule: "process.masquerade_path", Severity: SevCritical, Technique: "T1036.005", Confidence: 85,
					Detail: fmt.Sprintf("%s has the name of a Windows system binary but runs from %s (expected under %s)",
						label, p.ImagePath, describeDirs(sysRoot, dirs)),
				})
			}
		}

		if exp, ok := expectedParents[name]; ok && parent != "" && !contains(exp.parents, parent) {
			add(p.PID, Finding{
				Rule: "process.unexpected_parent", Severity: exp.sev, Technique: "T1036.005", Confidence: 75,
				Detail: fmt.Sprintf("%s was started by %s (pid %d); %s is only ever started by %s — a lookalike, or a spoofed parent (T1134.004)",
					label, p.ParentName, p.PPID, p.Name, strings.Join(exp.parents, " or ")),
			})
		}

		if shellLike[name] && parent != "" {
			switch {
			case documentApps[parent]:
				add(p.PID, Finding{
					Rule: "process.document_app_child", Severity: SevSuspect, Technique: "T1204.002", Confidence: 75,
					Detail: fmt.Sprintf("%s was started by document application %s (pid %d) — the shape of a malicious document",
						label, p.ParentName, p.PPID),
				})
			case serverApps[parent]:
				add(p.PID, Finding{
					Rule: "process.server_app_child", Severity: SevCritical, Technique: "T1505.003", Confidence: 80,
					Detail: fmt.Sprintf("%s was started by server process %s (pid %d) — the shape of a web shell or exploited service",
						label, p.ParentName, p.PPID),
				})
			case parent == "wmiprvse.exe" && name != "wmic.exe":
				add(p.PID, Finding{
					Rule: "process.wmi_child", Severity: SevSuspect, Technique: "T1047", Confidence: 65,
					Detail: fmt.Sprintf("%s was started through WMI (parent wmiprvse.exe, pid %d) — remote WMI execution looks like this",
						label, p.PPID),
				})
			case parent == "services.exe" && (name == "cmd.exe" || name == "powershell.exe" || name == "pwsh.exe"):
				add(p.PID, Finding{
					Rule: "process.service_shell", Severity: SevSuspect, Technique: "T1569.002", Confidence: 65,
					Detail: fmt.Sprintf("%s runs directly as a service (parent services.exe) — PsExec/smbexec-style remote execution looks like this",
						label),
				})
			}
		}

		if target, ok := typosquatOf(name); ok {
			add(p.PID, Finding{
				Rule: "process.name_typosquat", Severity: SevSuspect, Technique: "T1036.005", Confidence: 65,
				Detail: fmt.Sprintf("%s is one character away from the system process %s.exe", label, target),
			})
		}

		if !masquerade {
			if lvl, why := pathRisk(p.ImagePath); lvl != riskNone {
				sev, conf := SevSuspect, 50
				if lvl == riskLow {
					sev, conf = SevNotable, 30
				}
				add(p.PID, Finding{
					Rule: "process.unusual_path", Severity: sev, Technique: "T1204.002", Confidence: conf,
					Detail: fmt.Sprintf("%s runs from %s: %s", label, why, p.ImagePath),
				})
			}
		}
	}
	return out
}

func inSystemDirs(dir, sysRoot string, rels []string) bool {
	for _, rel := range rels {
		want := sysRoot
		if rel != "" {
			want += `\` + rel
		}
		if dir == want {
			return true
		}
		// Windows on ARM keeps x86/ARM32 copies alongside SysWOW64.
		if strings.HasPrefix(rel, "syswow64") {
			for _, alt := range []string{"sysarm32", "sychpe32"} {
				if dir == sysRoot+`\`+alt+strings.TrimPrefix(rel, "syswow64") {
					return true
				}
			}
		}
	}
	return false
}

func describeDirs(sysRoot string, rels []string) string {
	var out []string
	for _, rel := range rels {
		d := sysRoot
		if rel != "" {
			d += `\` + rel
		}
		out = append(out, d)
	}
	return strings.Join(out, " or ")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// typosquatOf reports whether name (lower-case, with .exe) is exactly one
// edit — an insertion, deletion, substitution or adjacent swap — away from a
// core system process name, and isn't itself a known legitimate name.
func typosquatOf(name string) (string, bool) {
	stem, ok := strings.CutSuffix(name, ".exe")
	if !ok || len(stem) < 4 || knownGoodNames[stem] {
		return "", false
	}
	for _, t := range squatTargets {
		if stem == t {
			return "", false
		}
	}
	for _, t := range squatTargets {
		if editDistanceAtMostOne(stem, t) {
			return t, true
		}
	}
	return "", false
}

// editDistanceAtMostOne reports whether a and b differ by at most one
// insertion, deletion, substitution or transposition of adjacent characters
// (restricted Damerau-Levenshtein distance <= 1). a != b is assumed.
func editDistanceAtMostOne(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	switch {
	case la == lb:
		i := 0
		for i < la && a[i] == b[i] {
			i++
		}
		if a[i+1:] == b[i+1:] {
			return true // one substitution
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:] // adjacent swap
	case la == lb+1:
		return oneDeletion(a, b)
	case lb == la+1:
		return oneDeletion(b, a)
	}
	return false
}

// oneDeletion reports whether deleting one character from long yields short.
func oneDeletion(long, short string) bool {
	i := 0
	for i < len(short) && long[i] == short[i] {
		i++
	}
	return long[i+1:] == short[i:]
}
