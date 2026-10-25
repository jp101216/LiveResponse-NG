package collector

import (
	"fmt"
	"strings"
)

// Autostart (ASEP) heuristics: where an entry runs from, what its command
// does, and — for locations that have a known Windows default — whether it
// departs from that default. No build tag: pure logic, unit-tested on any OS.

// autorunEntry is one autostart entry as the heuristics see it.
type autorunEntry struct {
	Kind     string // see autorunKinds
	Location string // registry key or folder
	Name     string // value name, subkey or file name
	Command  string // what runs, expanded where possible
	// Enabled is false when the mechanism is configured but switched off
	// (AppInit_DLLs with LoadAppInit_DLLs=0, SilentProcessExit without the
	// IFEO GlobalFlag): still reported, at a lower severity.
	Enabled bool
	// Direct marks a program or script dropped straight into a Startup
	// folder, rather than a shortcut to one.
	Direct bool
}

// autorunKind describes how one kind of autostart point is judged.
type autorunKind struct {
	technique string
	// always: any entry here is itself notable (the location is rare and
	// abused); sev/conf are used for that baseline finding.
	always bool
	sev    Severity
	conf   int
	what   string
}

var autorunKinds = map[string]autorunKind{
	"run":                         {technique: "T1547.001"},
	"runonce":                     {technique: "T1547.001"},
	"runservices":                 {technique: "T1547.001"},
	"runservicesonce":             {technique: "T1547.001"},
	"policies_run":                {technique: "T1547.001", always: true, sev: SevNotable, conf: 35, what: "a policy-defined Run entry (rarely used outside GPO)"},
	"run_wow64":                   {technique: "T1547.001"},
	"runonce_wow64":               {technique: "T1547.001"},
	"windows_load":                {technique: "T1547.001", always: true, sev: SevSuspect, conf: 60, what: "a legacy Windows\\Load/Run entry (obsolete, abused for persistence)"},
	"startup_folder":              {technique: "T1547.001"},
	"winlogon":                    {technique: "T1547.004"},
	"winlogon_extra":              {technique: "T1547.004", always: true, sev: SevSuspect, conf: 65, what: "a Winlogon Taskman/AppSetup entry (absent on a normal install)"},
	"appinit_dlls":                {technique: "T1546.010", always: true, sev: SevNotable, conf: 70, what: "AppInit_DLLs (loads a DLL into most user processes)"},
	"appcert_dlls":                {technique: "T1546.009", always: true, sev: SevSuspect, conf: 65, what: "an AppCertDLLs entry (loads a DLL into every process that calls CreateProcess)"},
	"ifeo_debugger":               {technique: "T1546.012", always: true, sev: SevSuspect, conf: 75, what: "an Image File Execution Options Debugger (launches in place of the program)"},
	"silent_process_exit":         {technique: "T1546.012", always: true, sev: SevSuspect, conf: 75, what: "a SilentProcessExit MonitorProcess (launches when the program exits)"},
	"cmd_autorun":                 {technique: "T1546", always: true, sev: SevNotable, conf: 45, what: "a Command Processor AutoRun command (runs every time cmd.exe starts)"},
	"boot_execute":                {technique: "T1547"},
	"lsa_authentication_packages": {technique: "T1547.002"},
	"lsa_security_packages":       {technique: "T1547.005"},
	"lsa_notification_packages":   {technique: "T1556.002"},
	"print_monitor":               {technique: "T1547.010"},
	"netsh_helper":                {technique: "T1546.007"},
	"screensaver":                 {technique: "T1546.002"},
}

// Known Windows defaults for locations where only deviations matter. Names
// are lower-case file names (DLLs without a path load from System32).
var (
	defaultLSAAuthPackages = set("msv1_0")
	defaultLSASecPackages  = set("", `""`, "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u",
		"cloudap", "negoexts", "livessp", "wsauth")
	defaultLSANotifyPkgs = set("scecli", "rassfm")
	defaultPrintMonitors = set("localspl.dll", "tcpmon.dll", "usbmon.dll", "wsdmon.dll", "appmon.dll",
		"fxsmon.dll", "pjlmon.dll", "apmon.dll", "mspmon.dll")
	defaultNetshHelpers = set("ifmon.dll", "rasmontr.dll", "authfwcfg.dll", "dhcpcmonitor.dll", "dot3cfg.dll",
		"fwcfg.dll", "hnetmon.dll", "netiohlp.dll", "nettrace.dll", "nshhttp.dll", "nshipsec.dll",
		"nshwfp.dll", "p2pnetsh.dll", "rpcnsh.dll", "wcnnetsh.dll", "whhelper.dll", "wlancfg.dll",
		"wshelper.dll", "wwancfg.dll", "peerdistsh.dll", "napmontr.dll")
)

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// judgeAutorun returns the findings for one autostart entry. sysRoot is the
// host's Windows directory.
func judgeAutorun(e autorunEntry, sysRoot string) []Finding {
	k, ok := autorunKinds[e.Kind]
	if !ok {
		k = autorunKind{technique: "T1547"}
	}
	where := e.Location
	if e.Name != "" {
		where += ` \ ` + e.Name
	}
	var out []Finding

	if k.always {
		sev, conf := k.sev, k.conf
		if !e.Enabled {
			sev, conf = SevNotable, conf/2 // configured but switched off
		}
		state := ""
		if !e.Enabled {
			state = " (configured but not active)"
		}
		out = append(out, Finding{
			Rule: "persistence." + e.Kind, Severity: sev, Technique: k.technique, Confidence: conf,
			Detail: fmt.Sprintf("%s%s at %s: %s", k.what, state, where, excerpt(e.Command, 240)),
		})
	}
	if f, ok := judgeDefault(e, k, sysRoot, where); ok {
		out = append(out, f)
	}

	if e.Direct {
		out = append(out, Finding{
			Rule: "persistence.startup_folder_program", Severity: SevSuspect, Technique: "T1547.001", Confidence: 60,
			Detail: fmt.Sprintf("a program or script was dropped directly into a Startup folder: %s", e.Command),
		})
	}

	if lvl, why, culprit := commandPathRisk(e.Command); lvl != riskNone {
		sev, conf := SevSuspect, 60
		if lvl == riskLow {
			sev, conf = SevNotable, 35
		}
		out = append(out, Finding{
			Rule: "persistence.autorun_unusual_path", Severity: sev, Technique: k.technique, Confidence: conf,
			Detail: fmt.Sprintf("autostart entry %s runs code from %s: %s", where, why, culprit),
		})
	}
	return mergeFindings(out, analyzeCommandLine("autostart entry "+where, "", e.Command)...)
}

// judgeDefault compares an entry against the location's Windows default.
func judgeDefault(e autorunEntry, k autorunKind, sysRoot, where string) (Finding, bool) {
	dev := func(rule string, sev Severity, conf int, msg string) (Finding, bool) {
		return Finding{Rule: rule, Severity: sev, Technique: k.technique, Confidence: conf,
			Detail: fmt.Sprintf("%s at %s: %s", msg, where, excerpt(e.Command, 240))}, true
	}
	name := strings.ToLower(e.Name)
	switch e.Kind {
	case "winlogon":
		var want, wantDir string
		switch name {
		case "shell":
			want, wantDir = "explorer.exe", ""
		case "userinit":
			want, wantDir = "userinit.exe", "system32"
		default:
			return Finding{}, false
		}
		if unexpectedWinlogon(e.Command, want, wantDir, sysRoot) {
			return dev("persistence.winlogon_hijack", SevSuspect, 75,
				fmt.Sprintf("Winlogon %s runs something other than %s (logon hijack)", e.Name, want))
		}
	case "boot_execute":
		f := strings.Fields(strings.ToLower(e.Command))
		if len(f) < 2 || f[0] != "autocheck" || f[1] != "autochk" {
			return dev("persistence.boot_execute", SevSuspect, 65,
				"BootExecute runs something other than autochk before Windows starts")
		}
	case "lsa_authentication_packages":
		if !defaultLSAAuthPackages[strings.ToLower(e.Command)] {
			return dev("persistence.lsa_authentication_package", SevSuspect, 60,
				"a non-default LSA authentication package is loaded into LSASS (verify the vendor)")
		}
	case "lsa_security_packages":
		if !defaultLSASecPackages[strings.ToLower(e.Command)] {
			return dev("persistence.lsa_security_package", SevSuspect, 65,
				"a non-default security support provider is loaded into LSASS (mimilib/memssp-style credential capture; verify the vendor)")
		}
	case "lsa_notification_packages":
		if !defaultLSANotifyPkgs[strings.ToLower(e.Command)] {
			return dev("persistence.password_filter", SevSuspect, 65,
				"a non-default password filter DLL receives every password change in clear text (verify the vendor)")
		}
	case "print_monitor":
		if !defaultPrintMonitors[baseName(e.Command)] || strings.ContainsAny(e.Command, `\/`) {
			return dev("persistence.print_monitor", SevNotable, 40,
				"a non-default print monitor DLL is loaded by the spooler as SYSTEM")
		}
	case "netsh_helper":
		if !defaultNetshHelpers[baseName(e.Command)] || strings.ContainsAny(e.Command, `\/`) {
			return dev("persistence.netsh_helper", SevNotable, 40,
				"a non-default netsh helper DLL is loaded every time netsh runs")
		}
	case "screensaver":
		img := imageFromCommand(e.Command)
		d := dirName(img)
		sys := strings.ToLower(strings.TrimRight(sysRoot, `\`))
		if !strings.HasSuffix(strings.ToLower(img), ".scr") || (d != "" && d != sys+`\system32` && d != sys+`\syswow64`) {
			return dev("persistence.screensaver", SevNotable, 45,
				"the screensaver is not a Windows .scr from System32 (runs as the user when idle)")
		}
	}
	return Finding{}, false
}

// unexpectedWinlogon reports whether a Shell/Userinit value lists anything
// other than its expected binary (extra comma-separated programs, a
// look-alike name, or the right name in the wrong directory).
func unexpectedWinlogon(cmd, want, wantDir, sysRoot string) bool {
	sys := strings.ToLower(strings.TrimRight(sysRoot, `\`))
	for _, part := range strings.Split(cmd, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		img := imageFromCommand(part)
		if baseName(img) != want {
			return true
		}
		if d := dirName(img); d != "" {
			exp := sys
			if wantDir != "" {
				exp += `\` + wantDir
			}
			if d != exp && !(want == "explorer.exe" && d == sys+`\syswow64`) {
				return true
			}
		}
	}
	return false
}
