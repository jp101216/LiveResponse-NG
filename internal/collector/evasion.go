package collector

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// evasion.go — smaller defence-evasion and persistence checks that share no
// home elsewhere: the .NET runtime's environment variables (ETW switched off,
// profiler DLLs), AMSI providers, accessibility programs replaced at the
// logon screen, PowerShell 2.0 started on purpose, and Sysmon's remote-thread
// (8) and process-tampering (25) events. Portable: the Windows readers live
// with the collectors that call them.

// eventTime renders when an event happened for a detail line.
func eventTime(ev winEvent) string {
	if ev.TimeCreated.IsZero() {
		return ""
	}
	return " at " + ev.TimeCreated.UTC().Format(time.RFC3339)
}

// runtimeEnvNames are the only environment variables read out of a process
// or the registry for these checks, upper-cased. An environment block also
// holds secrets, so nothing else is ever recorded.
var runtimeEnvNames = []string{
	"COMPLUS_ETWENABLED", "DOTNET_ETWENABLED",
	"COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH", "COR_PROFILER_PATH_64", "COR_PROFILER_PATH_32",
	"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH", "CORECLR_PROFILER_PATH_64", "CORECLR_PROFILER_PATH_32",
}

var runtimeEnvSet = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range runtimeEnvNames {
		m[n] = true
	}
	return m
}()

// runtimeEnvVar reports whether an environment variable is one of
// runtimeEnvNames (names are case-insensitive on Windows).
func runtimeEnvVar(name string) bool { return runtimeEnvSet[strings.ToUpper(strings.TrimSpace(name))] }

// parseEnvBlock picks runtimeEnvNames out of "NAME=value" strings (an
// environment block, or a service's Environment multi-string), keyed
// upper-case.
func parseEnvBlock(lines []string) map[string]string {
	out := map[string]string{}
	for _, l := range lines {
		name, value, ok := strings.Cut(l, "=")
		if !ok || name == "" { // "=C:=C:\…" drive entries start with '='
			continue
		}
		if runtimeEnvVar(name) {
			out[strings.ToUpper(strings.TrimSpace(name))] = value
		}
	}
	return out
}

// envBlockEnds reports whether a UTF-16 environment block holds its
// terminating empty string.
func envBlockEnds(b []byte) bool {
	for i := 0; i+3 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 0 && b[i+3] == 0 {
			return true
		}
	}
	return false
}

// envStrings splits a UTF-16 environment block into its NAME=value strings.
func envStrings(b []byte) []string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	var out []string
	start := 0
	for i, c := range u {
		if c != 0 {
			continue
		}
		if i == start {
			break // the empty string that ends the block
		}
		out = append(out, string(utf16.Decode(u[start:i])))
		start = i + 1
	}
	return out
}

// runtimeEnvFindings judges the .NET runtime's environment variables, read
// from a process or from the registry (the system's, a user's or a service's
// environment). resolve maps a profiler's CLSID to its registered DLL ("" if
// it isn't registered); it may be nil.
func runtimeEnvFindings(where string, env map[string]string, resolve func(clsid string) string) []Finding {
	var out []Finding
	for _, name := range []string{"COMPLUS_ETWENABLED", "DOTNET_ETWENABLED"} {
		if v, ok := env[name]; ok && strings.TrimSpace(v) == "0" {
			out = append(out, Finding{Rule: "defense.dotnet_etw_disabled", Severity: SevSuspect, Technique: "T1562.006", Confidence: 75,
				Detail: fmt.Sprintf("%s sets %s=0: the .NET runtime stops writing its ETW events, so EDR no longer sees which "+
					"assemblies a process loads. It is set before running offensive .NET tools in memory", where, name)})
			break
		}
	}
	for _, rt := range []struct{ prefix, name string }{{"COR_", ".NET Framework"}, {"CORECLR_", ".NET"}} {
		if strings.TrimSpace(env[rt.prefix+"ENABLE_PROFILING"]) != "1" {
			continue
		}
		clsid := strings.TrimSpace(env[rt.prefix+"PROFILER"])
		dll := strings.Trim(strings.TrimSpace(firstNonEmpty(env[rt.prefix+"PROFILER_PATH_64"], env[rt.prefix+"PROFILER_PATH"],
			env[rt.prefix+"PROFILER_PATH_32"])), `"`)
		if dll == "" && clsid != "" && resolve != nil {
			dll = strings.Trim(strings.TrimSpace(resolve(clsid)), `"`)
		}
		if clsid == "" && dll == "" {
			continue
		}
		loads := "a DLL the CLSID doesn't register here"
		if dll != "" {
			loads = dll
		}
		f := Finding{Rule: "persistence.clr_profiler", Severity: SevNotable, Technique: "T1574.012", Confidence: 40,
			Detail: fmt.Sprintf("%s switches on a %s profiler (%sPROFILER=%s): every %s process it reaches loads %s at start-up. "+
				"Application-monitoring agents work this way; so does a DLL planted to run inside other programs, or to bypass UAC "+
				"through an auto-elevating .NET program", where, rt.name, rt.prefix, firstNonEmpty(clsid, "(none)"), rt.name, loads)}
		if why := plantedDLL(dll); why != "" {
			f.Severity, f.Confidence = SevSuspect, 75
			f.Detail += "; the DLL is in " + why
		}
		out = append(out, f)
	}
	return out
}

// defenderAMSICLSID is Microsoft Defender's AMSI provider (MpOav.dll).
const defenderAMSICLSID = "2781761E-28E0-4109-99FE-B9D127C57AFE"

// judgeAMSIProvider judges one registered AMSI provider: Defender's CLSID
// pointing anywhere but Defender's MpOav.dll is a hijack; any other provider
// is a DLL loaded into every PowerShell, script host and Office process,
// which sees every script they run (normal for antivirus products).
func judgeAMSIProvider(clsid, dll string) (Finding, bool) {
	id := strings.ToUpper(strings.Trim(strings.TrimSpace(clsid), "{}"))
	path := strings.ToLower(strings.Trim(strings.TrimSpace(dll), `"`))
	if id == defenderAMSICLSID {
		if baseName(path) == "mpoav.dll" && strings.Contains(path, `\windows defender`) {
			return Finding{}, false
		}
		return Finding{Rule: "defense.amsi_provider_hijacked", Severity: SevSuspect, Technique: "T1562.001", Confidence: 75,
			Detail: fmt.Sprintf("Microsoft Defender's AMSI provider {%s} is registered to %s rather than Defender's MpOav.dll: the "+
				"scripts AMSI hands to Defender go to that DLL instead", id, firstNonEmpty(dll, "no DLL at all"))}, true
	}
	f := Finding{Rule: "persistence.amsi_provider", Severity: SevNotable, Technique: "T1546", Confidence: 35,
		Detail: fmt.Sprintf("AMSI provider {%s} (%s) is loaded into every PowerShell, script host and Office process and sees every "+
			"script they run: normal for an antivirus product, and a quiet way to run code and read scripts otherwise", id,
			firstNonEmpty(dll, "its CLSID registers no DLL"))}
	if why := plantedDLL(path); why != "" {
		f.Severity, f.Confidence = SevSuspect, 75
		f.Detail += "; the DLL is in " + why
	}
	return f, true
}

// plantedDLL says why a DLL that a machine-wide mechanism loads (an AMSI
// provider, a .NET profiler) sits somewhere an installer wouldn't put it: a
// high-risk location, or any user's profile. "" when it doesn't.
func plantedDLL(path string) string {
	if lvl, why := pathRisk(path); lvl == riskHigh {
		return why
	}
	if strings.Contains(strings.ToLower(strings.ReplaceAll(path, "/", `\`)), `:\users\`) {
		return "a user's profile"
	}
	return ""
}

// accessibilityBinaries are the programs the logon screen starts before
// anyone logs on (Ease of Access, Shift five times, Win+U, Win+P…). Replacing
// one with cmd.exe gives a SYSTEM shell at the logon screen.
var accessibilityBinaries = []string{"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"}

// accessibilityShells are programs whose name in an accessibility program's
// version resource means it was replaced with a shell or a tool.
var accessibilityShells = set("cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe", "taskmgr.exe", "regedit.exe",
	"mmc.exe", "rundll32.exe", "conhost.exe", "wscript.exe", "cscript.exe", "mshta.exe", "notepad.exe", "powershell_ise.exe")

// accessibilityAliases are original file names Windows itself gives
// accessibility programs that differ from the file's name.
var accessibilityAliases = map[string]map[string]bool{
	"utilman.exe": set("utilman2.exe"),
}

// accessibilityFinding judges one accessibility program by its version
// resource's original file name and by whether it is a byte-for-byte copy of
// another program (sameAs names it).
func accessibilityFinding(path, original, sameAs string) (Finding, bool) {
	base := baseName(path)
	orig := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(original)), ".mui")
	backdoor := "pressing Shift five times or the Ease of Access button at the logon screen runs it as SYSTEM, a backdoor that needs no password"
	switch {
	case sameAs != "":
		return Finding{Rule: "persistence.accessibility_backdoor", Severity: SevCritical, Technique: "T1546.008", Confidence: 90,
			Detail: fmt.Sprintf("%s is a copy of %s: %s", path, sameAs, backdoor)}, true
	case orig == "" || orig == base || accessibilityAliases[base][orig]:
		return Finding{}, false
	case accessibilityShells[orig]:
		return Finding{Rule: "persistence.accessibility_backdoor", Severity: SevCritical, Technique: "T1546.008", Confidence: 85,
			Detail: fmt.Sprintf("%s is really %s (its version resource's original file name): %s", path, orig, backdoor)}, true
	}
	return Finding{Rule: "persistence.accessibility_backdoor", Severity: SevSuspect, Technique: "T1546.008", Confidence: 65,
		Detail: fmt.Sprintf("%s calls itself %s in its version resource, not %s: an accessibility program replaced with another "+
			"program runs as SYSTEM from the logon screen", path, orig, base)}, true
}

// psEngineField reads "Name=value" out of Windows PowerShell's engine
// lifecycle text.
func psEngineField(text, name string) string {
	i := strings.Index(text, name+"=")
	if i < 0 {
		return ""
	}
	v := text[i+len(name)+1:]
	if j := strings.IndexAny(v, "\r\n\t"); j >= 0 {
		v = v[:j]
	}
	return strings.TrimSpace(v)
}

// psEngineFindings judges Windows PowerShell's event 400 (an engine started)
// by its EngineVersion: 2.0 has no script-block logging, no AMSI and no
// Constrained Language enforcement, which is why intruders ask for it.
func psEngineFindings(ev winEvent) []Finding {
	if !strings.EqualFold(ev.Channel, "Windows PowerShell") && !strings.EqualFold(ev.Provider, "PowerShell") {
		return nil
	}
	parts := append([]string(nil), ev.DataList...)
	keys := make([]string, 0, len(ev.Data))
	for k := range ev.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, ev.Data[k])
	}
	text := strings.Join(parts, "\n")
	if !strings.HasPrefix(psEngineField(text, "EngineVersion"), "2.") {
		return nil
	}
	host := firstNonEmpty(psEngineField(text, "HostApplication"), psEngineField(text, "HostName"), "unrecorded")
	return []Finding{{Rule: "defense.powershell_downgrade", Severity: SevSuspect, Technique: "T1562.010", Confidence: 65,
		Detail: fmt.Sprintf("PowerShell's 2.0 engine started%s (host: %s). Version 2 has no script-block logging, no AMSI and no "+
			"Constrained Language enforcement, which is why intruders ask for it (powershell -version 2); it is native only on "+
			"Windows 7 without later Windows Management Framework updates", eventTime(ev), excerpt(host, 200))}}
}

// installedProgram reports whether an image lives under Program Files or the
// Windows directory, where an intruder's own tools rarely are.
func installedProgram(img string) bool {
	low := strings.ToLower(img)
	return strings.Contains(low, `:\program files`) || strings.Contains(low, `:\windows\`)
}

// remoteThreadFindings judges Sysmon's event 8 (a thread created in another
// process): one starting in memory no module backs is code written into the
// process and run there; one starting at LoadLibrary is DLL injection.
// csrss.exe's Ctrl+C handler threads start in kernelbase and pass.
func remoteThreadFindings(ev winEvent) []Finding {
	src := firstNonEmpty(evData(ev, "SourceImage"), "a process")
	dst := firstNonEmpty(evData(ev, "TargetImage"), "another process")
	module := strings.TrimSpace(evData(ev, "StartModule"))
	fn := strings.TrimSpace(evData(ev, "StartFunction"))
	addr := firstNonEmpty(evData(ev, "StartAddress"), "an unrecorded address")
	lsass := baseName(dst) == "lsass.exe"
	switch {
	case module == "" || module == "-":
		f := Finding{Rule: "memory.remote_thread_unbacked", Severity: SevSuspect, Technique: "T1055", Confidence: 70,
			Detail: fmt.Sprintf("%s started a thread in %s%s at %s, in memory no module backs: code written into that process "+
				"and run there (process injection)", src, dst, eventTime(ev), addr)}
		switch {
		case lsass:
			f.Technique, f.Confidence = "T1003.001", 80
			f.Detail += ". The target is LSASS, which credential dumpers inject into"
		case installedProgram(src):
			f.Severity, f.Confidence = SevNotable, 45
			f.Detail += ". The source is an installed program; security and monitoring products do this too"
		}
		return []Finding{f}
	case strings.HasPrefix(strings.ToLower(fn), "loadlibrary"):
		f := Finding{Rule: "memory.remote_thread_loadlibrary", Severity: SevSuspect, Technique: "T1055.001", Confidence: 65,
			Detail: fmt.Sprintf("%s started a thread in %s%s at %s!%s, which loads a DLL into it: classic DLL injection",
				src, dst, eventTime(ev), firstNonEmpty(baseName(module), module), fn)}
		if installedProgram(src) && !lsass {
			f.Severity, f.Confidence = SevNotable, 40
			f.Detail += ". The source is an installed program; some legitimate software injects this way"
		}
		return []Finding{f}
	}
	return nil
}

// tamperingFindings judges Sysmon's event 25 (process tampering): the image
// of a running process replaced in memory (hollowing), or the file behind it
// changed while it was mapped (herpaderping, ghosting). Browsers' updaters
// and WMIADAP trip it legitimately, as Sigma's rule notes.
func tamperingFindings(ev winEvent) []Finding {
	img := firstNonEmpty(evData(ev, "Image"), "a process")
	low := strings.ToLower(img)
	if strings.Contains(low, `:\program files`) || strings.HasSuffix(low, `\wbem\wmiadap.exe`) ||
		(strings.Contains(low, `\appdata\local\programs\opera\`) && strings.HasSuffix(low, `\opera.exe`)) ||
		strings.HasSuffix(low, `\windowsapps\microsoftedge.exe`) {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(evData(ev, "Type"))) {
	case "image is replaced":
		return []Finding{{Rule: "memory.process_tampering", Severity: SevSuspect, Technique: "T1055.012", Confidence: 70,
			Detail: fmt.Sprintf("Sysmon saw the image of %s replaced in memory%s: the process runs code other than its file "+
				"(process hollowing)", img, eventTime(ev))}}
	case "image is locked for access":
		return []Finding{{Rule: "memory.process_tampering", Severity: SevSuspect, Technique: "T1055", Confidence: 65,
			Detail: fmt.Sprintf("Sysmon saw the file behind %s changed while it was mapped%s: the process runs code its file on "+
				"disk no longer shows (process herpaderping or ghosting)", img, eventTime(ev))}}
	}
	return nil
}
