package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// defenses (Windows) reads the settings an intruder weakens before doing
// what would otherwise be caught:
//
//   - Microsoft Defender: its exclusions (paths, extensions, processes and
//     addresses it won't scan, from its own preferences and group policy),
//     and its protection switched off in either place.
//   - Credentials: WDigest keeping logon passwords in clear text in LSASS
//     (Windows turned it off in 8.1; attackers turn it back on so Mimikatz
//     finds passwords after the next logon), LSA protection switched off,
//     RDP's Restricted Admin mode (which takes an NTLM hash as a logon), and
//     NTLMv1.
//
// Each area is one record holding every value read, so an absent setting
// (Windows' default) is told from one set to its default.
//
// No build tag: the judging is unit-tested on any OS; defenses_windows.go
// reads the registry.

type defensesCollector struct{}

func (*defensesCollector) Name() string        { return "defenses" }
func (*defensesCollector) Platforms() []string { return []string{"windows"} }

func (*defensesCollector) Timeout() time.Duration { return 30 * time.Second }

func (*defensesCollector) Collect(ctx context.Context) (Result, error) {
	return collectDefenses(ctx)
}

func init() { Register(func() Collector { return &defensesCollector{} }) }

// exclusion is one thing Defender won't scan.
type exclusion struct {
	Kind   string // "path", "extension", "process" or "ip"
	Value  string
	Policy bool // set by group policy rather than Defender's own preferences
}

// defenderSetting is one Defender value that switches protection off when set.
type defenderSetting struct {
	Key, Name string // under ...\Windows Defender\
	Off       uint32 // the value that means "off"
	What      string
}

// defenderSettings are read from Defender's preferences and its policy key.
var defenderSettings = []defenderSetting{
	{"", "DisableAntiSpyware", 1, "Microsoft Defender Antivirus is turned off"},
	{"", "DisableAntiVirus", 1, "Microsoft Defender Antivirus is turned off"},
	{`Real-Time Protection`, "DisableRealtimeMonitoring", 1, "real-time protection is off"},
	{`Real-Time Protection`, "DisableBehaviorMonitoring", 1, "behavior monitoring is off"},
	{`Real-Time Protection`, "DisableOnAccessProtection", 1, "on-access protection is off"},
	{`Real-Time Protection`, "DisableIOAVProtection", 1, "scanning of downloaded files and attachments is off"},
	{`Real-Time Protection`, "DisableScriptScanning", 1, "script scanning (AMSI) is off"},
	{`Spynet`, "SpynetReporting", 0, "cloud-delivered protection is off"},
}

// setting is a value read: where, and what it holds.
type setting struct {
	Path   string // the key's path under HKLM
	Name   string
	Value  uint32
	Policy bool
}

// defenderState is what Defender's settings read as.
type defenderState struct {
	Exclusions   []exclusion
	Settings     []setting // the defenderSettings found set to anything
	Tamper       *uint32   // Features\TamperProtection: 5 on, 4 off
	Unreadable   []string  // keys that couldn't be read (Exclusions wants administrator rights)
	NotInstalled bool      // no Windows Defender key at all
}

// credentialState is what the credential protections read as (nil: absent).
type credentialState struct {
	WDigest         *uint32 // SecurityProviders\WDigest\UseLogonCredential
	RunAsPPL        *uint32 // Lsa\RunAsPPL
	LsaCfgFlags     *uint32 // Lsa\LsaCfgFlags (Credential Guard)
	RestrictedAdmin *uint32 // Lsa\DisableRestrictedAdmin
	LmCompat        *uint32 // Lsa\LmCompatibilityLevel
	DsrmLogon       *uint32 // Lsa\DsrmAdminLogonBehavior (domain controllers)
}

// scriptAndBinaryExt are the extensions whose exclusion lets a payload run
// unscanned.
var scriptAndBinaryExt = map[string]bool{
	"exe": true, "dll": true, "sys": true, "scr": true, "com": true, "cpl": true, "ocx": true, "msi": true,
	"ps1": true, "psm1": true, "bat": true, "cmd": true, "vbs": true, "vbe": true, "js": true, "jse": true,
	"wsf": true, "hta": true, "jar": true, "lnk": true, "iso": true, "zip": true,
}

// lolbinHosts are programs whose exclusion lets anything they run go
// unscanned.
var lolbinHosts = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"mshta.exe": true, "wscript.exe": true, "cscript.exe": true, "msbuild.exe": true, "installutil.exe": true,
	"certutil.exe": true, "bitsadmin.exe": true, "wmic.exe": true, "msiexec.exe": true, "explorer.exe": true,
	"svchost.exe": true, "conhost.exe": true,
}

// judgeExclusion grades one exclusion: suspect when it opens a door a
// payload would use (a temporary or download folder, a whole drive, an
// executable extension, a script host), notable otherwise (software vendors
// ask for exclusions of their own folders).
func judgeExclusion(e exclusion) Finding {
	src := "Defender's preferences (Add-MpPreference, or Defender's settings)"
	if e.Policy {
		src = "group policy"
	}
	sev, conf, why := SevNotable, 35, "software vendors ask for exclusions of their own folders, and an intruder adds one to keep a payload from being scanned"
	v := strings.TrimSpace(e.Value)
	low := strings.ToLower(v)
	switch e.Kind {
	case "path":
		trimmed := strings.TrimRight(low, `\*`)
		if lvl, reason := pathRisk(v + `\x.exe`); lvl == riskHigh {
			sev, conf, why = SevSuspect, 70, "it is "+reason+", where payloads are dropped"
		} else if trimmed == "" || (len(trimmed) == 2 && trimmed[1] == ':') || low == "*" {
			sev, conf, why = SevSuspect, 75, "it is a whole drive: nothing on it is scanned"
		} else if trimmed == `c:\users` || trimmed == `c:\programdata` || trimmed == `c:\windows` || trimmed == `c:\windows\temp` {
			sev, conf, why = SevSuspect, 65, "it covers a folder every user can write to, or the Windows folder"
		}
	case "extension":
		if scriptAndBinaryExt[strings.TrimPrefix(low, ".")] {
			sev, conf, why = SevSuspect, 70, "files of that type run code, so any such file goes unscanned"
		}
	case "process":
		if lolbinHosts[baseName(low)] {
			sev, conf, why = SevSuspect, 70, "everything that program opens goes unscanned, and it runs whatever it is given"
		} else if lvl, reason := pathRisk(v); lvl == riskHigh {
			sev, conf, why = SevSuspect, 70, "the program sits in "+reason
		}
	case "ip":
		why = "network protection doesn't inspect traffic to that address"
	}
	return Finding{Rule: "defense.defender_exclusion", Severity: sev, Technique: "T1562.001", Confidence: conf,
		Detail: fmt.Sprintf("Microsoft Defender excludes the %s %s (set by %s): %s", e.Kind, v, src, why)}
}

// defenderReport is the Defender record: every exclusion and setting, with
// findings.
func defenderReport(d defenderState) (map[string]any, []Finding) {
	f := map[string]any{"area": "defender"}
	var out []Finding
	if d.NotInstalled {
		f["installed"] = false
		return f, nil
	}
	byKind := map[string][]string{}
	for _, e := range d.Exclusions {
		label := e.Value
		if e.Policy {
			label += " (policy)"
		}
		byKind[e.Kind] = append(byKind[e.Kind], label)
		out = append(out, judgeExclusion(e))
	}
	for kind, vs := range byKind {
		sort.Strings(vs)
		f["exclusions_"+kind] = vs
	}
	settings := map[string]uint32{}
	for _, s := range d.Settings {
		key := s.Name
		if s.Policy {
			key += " (policy)"
		}
		settings[key] = s.Value
		for _, ds := range defenderSettings {
			if ds.Name != s.Name || s.Value != ds.Off {
				continue
			}
			sev, conf := SevSuspect, 70
			if ds.Name == "SpynetReporting" {
				sev, conf = SevNotable, 40
			}
			src := "Defender's preferences (Set-MpPreference)"
			if s.Policy {
				src = "group policy"
			}
			out = append(out, Finding{Rule: "defense.defender_protection_off", Severity: sev, Technique: "T1562.001", Confidence: conf,
				Detail: fmt.Sprintf("Microsoft Defender: %s (%s\\%s = %d, set by %s). Defender steps aside on its own when another "+
					"antivirus product takes over; otherwise this is switched off by hand", ds.What, s.Path, s.Name, s.Value, src)})
		}
	}
	if len(settings) > 0 {
		f["settings"] = settings
	}
	if d.Tamper != nil {
		f["tamper_protection"] = *d.Tamper
		if *d.Tamper == 4 {
			out = append(out, Finding{Rule: "defense.defender_protection_off", Severity: SevNotable, Technique: "T1562.001", Confidence: 35,
				Detail: "Microsoft Defender's tamper protection is off (Features\\TamperProtection = 4), so its settings can be changed " +
					"by anything running as administrator"})
		}
	}
	if len(d.Unreadable) > 0 {
		f["unreadable"] = d.Unreadable
	}
	return f, out
}

// credentialReport is the credential-protection record.
func credentialReport(c credentialState) (map[string]any, []Finding) {
	f := map[string]any{"area": "credentials"}
	put := func(name string, v *uint32) {
		if v != nil {
			f[name] = *v
		}
	}
	put("wdigest_use_logon_credential", c.WDigest)
	put("lsa_run_as_ppl", c.RunAsPPL)
	put("lsa_cfg_flags", c.LsaCfgFlags)
	put("disable_restricted_admin", c.RestrictedAdmin)
	put("lm_compatibility_level", c.LmCompat)
	put("dsrm_admin_logon_behavior", c.DsrmLogon)
	var out []Finding
	if c.WDigest != nil && *c.WDigest == 1 {
		out = append(out, Finding{Rule: "cred.wdigest_enabled", Severity: SevSuspect, Technique: "T1112", Confidence: 75,
			Detail: "WDigest is set to keep logon passwords in clear text in LSASS's memory (SecurityProviders\\WDigest\\UseLogonCredential = 1). " +
				"Windows turned this off in 8.1; an intruder turns it back on so Mimikatz can read the passwords of whoever logs on next"})
	}
	if c.RunAsPPL != nil && *c.RunAsPPL == 0 {
		out = append(out, Finding{Rule: "cred.lsa_protection_off", Severity: SevNotable, Technique: "T1562", Confidence: 40,
			Detail: "LSA protection is switched off explicitly (Lsa\\RunAsPPL = 0): LSASS runs as an ordinary process, which any " +
				"administrator can read credentials out of"})
	}
	if c.RestrictedAdmin != nil && *c.RestrictedAdmin == 0 {
		out = append(out, Finding{Rule: "cred.restricted_admin_enabled", Severity: SevNotable, Technique: "T1550.002", Confidence: 45,
			Detail: "RDP's Restricted Admin mode is on (Lsa\\DisableRestrictedAdmin = 0). It keeps credentials off the server, but it " +
				"also accepts an NTLM hash as a logon, so intruders switch it on to pass the hash over RDP (xfreerdp /pth)"})
	}
	if c.LmCompat != nil && *c.LmCompat <= 2 {
		out = append(out, Finding{Rule: "cred.ntlmv1_allowed", Severity: SevNotable, Technique: "T1557.001", Confidence: 40,
			Detail: fmt.Sprintf("this host sends NTLMv1 (Lsa\\LmCompatibilityLevel = %d; Windows' default is 3): an NTLMv1 response "+
				"captured by a poisoner such as Responder cracks to the account's NT hash", *c.LmCompat)})
	}
	if c.DsrmLogon != nil && *c.DsrmLogon == 2 {
		out = append(out, Finding{Rule: "cred.dsrm_network_logon", Severity: SevSuspect, Technique: "T1098", Confidence: 70,
			Detail: "the Directory Services Restore Mode administrator may log on over the network (Lsa\\DsrmAdminLogonBehavior = 2). " +
				"DSRM is a domain controller's local administrator, whose password rarely changes; letting it log on while the " +
				"directory runs turns that password, or its hash, into permanent administrator access to the DC"})
	}
	return f, out
}

// defenderEventFindings judges Defender's own log: protection switched off
// (5001, 5010, 5012), a configuration change that adds an exclusion or
// switches a protection off (5007), and a change tamper protection blocked
// (5013). These date the change, which the registry doesn't.
func defenderEventFindings(ev winEvent) []Finding {
	when := ""
	if !ev.TimeCreated.IsZero() {
		when = " at " + ev.TimeCreated.UTC().Format(time.RFC3339)
	}
	switch ev.EventID {
	case 5001, 5010, 5012:
		what := map[int]string{5001: "real-time protection", 5010: "scanning for spyware and other unwanted software", 5012: "scanning for viruses"}[ev.EventID]
		return []Finding{{Rule: "defense.defender_protection_off", Severity: SevSuspect, Technique: "T1562.001", Confidence: 65,
			Detail: fmt.Sprintf("Microsoft Defender's %s was switched off%s (Defender event %d)", what, when, ev.EventID)}}
	case 5013:
		return []Finding{{Rule: "defense.defender_tamper_blocked", Severity: SevSuspect, Technique: "T1562.001", Confidence: 60,
			Detail: fmt.Sprintf("tamper protection blocked a change to Microsoft Defender's settings%s: %s (Defender event 5013)",
				when, excerpt(firstNonEmpty(evData(ev, "Value"), evData(ev, "Changed Value"), "the value isn't recorded"), 200))}}
	case 5007:
		nv := firstNonEmpty(evData(ev, "New Value"), evData(ev, "NewValue"))
		low := strings.ToLower(nv)
		switch {
		case strings.Contains(low, `\exclusions\`):
			return []Finding{{Rule: "defense.defender_exclusion", Severity: SevSuspect, Technique: "T1562.001", Confidence: 60,
				Detail: fmt.Sprintf("an exclusion was added to Microsoft Defender%s: %s (Defender event 5007)", when, excerpt(nv, 240))}}
		case strings.Contains(low, "disablerealtimemonitoring = 0x1") || strings.Contains(low, "disableantispyware = 0x1") ||
			strings.Contains(low, "disablebehaviormonitoring = 0x1") || strings.Contains(low, "disableioavprotection = 0x1") ||
			strings.Contains(low, "disablescriptscanning = 0x1"):
			return []Finding{{Rule: "defense.defender_protection_off", Severity: SevSuspect, Technique: "T1562.001", Confidence: 65,
				Detail: fmt.Sprintf("Microsoft Defender's protection was switched off%s: %s (Defender event 5007)", when, excerpt(nv, 240))}}
		}
	}
	return nil
}

// defensesReport adds the two records.
func defensesReport(res *Result, d defenderState, c credentialState) {
	f, fs := defenderReport(d)
	res.Add(f, fs...)
	f, fs = credentialReport(c)
	res.Add(f, fs...)
}

// amsiProvider is one antimalware provider registered with AMSI
// (SOFTWARE\Microsoft\AMSI\Providers\{CLSID}) and the DLL its CLSID loads.
type amsiProvider struct {
	CLSID string
	DLL   string
}

// amsiState is what AMSI's provider registration reads as.
type amsiState struct {
	Present   bool // the Providers key exists (Windows 10 and later)
	Providers []amsiProvider
}

// amsiReport adds the AMSI record: each provider judged, and none at all
// while Defender is installed (removing the provider's key blinds AMSI).
func amsiReport(res *Result, a amsiState, defenderInstalled bool) {
	if !a.Present {
		return
	}
	var listed []string
	var out []Finding
	for _, p := range a.Providers {
		listed = append(listed, "{"+strings.ToUpper(strings.Trim(p.CLSID, "{}"))+"} "+firstNonEmpty(p.DLL, "(no DLL registered)"))
		if f, ok := judgeAMSIProvider(p.CLSID, p.DLL); ok {
			out = append(out, f)
		}
	}
	if len(a.Providers) == 0 && defenderInstalled {
		out = append(out, Finding{Rule: "defense.amsi_provider_missing", Severity: SevSuspect, Technique: "T1562.001", Confidence: 60,
			Detail: "no antimalware provider is registered with AMSI although Microsoft Defender is installed: scripts, macros and " +
				"in-memory .NET assemblies go unscanned. Deleting the provider's key under SOFTWARE\\Microsoft\\AMSI\\Providers is an " +
				"AMSI bypass that survives reboots"})
	}
	res.Add(map[string]any{"area": "amsi", "providers": listed}, out...)
}

// envSource is one place the .NET runtime variables were found set: the
// system's environment, a user's, or a service's.
type envSource struct {
	Where string
	Env   map[string]string
	// Resolve maps a profiler CLSID to its DLL as COM would for this source.
	Resolve func(clsid string) string `json:"-"`
}

// runtimeEnvReport adds a record for every registry environment that sets
// one of the .NET runtime variables, judged.
func runtimeEnvReport(res *Result, sources []envSource) {
	for _, s := range sources {
		res.Add(map[string]any{"area": "environment", "where": s.Where, "variables": s.Env},
			runtimeEnvFindings(s.Where, s.Env, s.Resolve)...)
	}
}
