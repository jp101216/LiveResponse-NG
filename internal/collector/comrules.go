package collector

import "fmt"

// COM class-registration (hijacking) heuristics. A COM object is found by its
// CLSID, and the server that backs it — a DLL (InprocServer32) or an EXE
// (LocalServer32) — is named in the registry. Two properties make rewriting
// that registration a favourite persistence and defence-evasion technique
// (T1546.015, Component Object Model Hijacking):
//
//   - a user's own class store (HKCU\Software\Classes, i.e. HKU\<sid>_Classes)
//     is consulted before the machine-wide HKLM one, so a per-user
//     registration silently overrides a machine object — no admin rights, and
//     it loads whenever that object is instantiated, which for the right CLSID
//     is every logon (explorer.exe) or every Office start;
//   - TreatAs remaps one CLSID to another, so a trusted object can be shimmed.
//
// Detection here is behavioural rather than a brittle list of "known abused"
// CLSIDs: a per-user registration that shadows a machine one, a server in a
// user-writable or temporary path, a scriptlet/LOLBin server, and TreatAs
// redirection. No build tag: pure logic, unit-tested on any OS.

// COM server kinds.
const (
	comInproc = "inproc" // InprocServer32: a DLL loaded into the calling process
	comLocal  = "local"  // LocalServer32: an EXE launched as its own process
)

// comEntry is one COM class registration as the heuristics see it.
type comEntry struct {
	CLSID      string // "{guid}", lower-case
	Name       string // the class's friendly (default) value, if any
	Hive       string // where it was read: "HKLM" or "HKU\<sid>"
	User       bool   // a per-user registration (a user's own class store)
	View       string // "native" or "wow64"
	ServerKind string // comInproc / comLocal / "" (a TreatAs-only entry)
	Server     string // the server path (inproc) or command (local), expanded
	ServerRaw  string // as stored, before environment expansion
	Threading  string // ThreadingModel, for inproc servers
	TreatAs    string // a CLSID this one is remapped to, if any

	// Shadows is set for a per-user entry whose CLSID is also registered in
	// HKLM: the per-user copy wins, which is the classic hijack. ShadowServer
	// is the HKLM server it overrides, when that was recorded.
	Shadows      bool
	ShadowServer string
}

// comLOLBinServers are server images that mean a COM object launches a script
// host or LOLBin when instantiated — rare for a legitimate component, and the
// shape of a scriptlet/COM-proxy payload.
var comLOLBinServers = map[string]bool{
	"rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true,
	"powershell.exe": true, "pwsh.exe": true, "wscript.exe": true,
	"cscript.exe": true, "cmd.exe": true,
}

// judgeCOM returns the findings for one COM class registration.
func judgeCOM(e comEntry) []Finding {
	var out []Finding
	where := e.Hive + ` CLSID\` + e.CLSID
	if e.Name != "" {
		where += " (" + excerpt(e.Name, 60) + ")"
	}

	lvl, why, culprit := comServerRisk(e)

	// The classic hijack: a per-user registration overriding a machine one.
	if e.Shadows {
		sev, conf := SevSuspect, 70
		detail := fmt.Sprintf("a per-user COM registration at %s overrides the machine-wide one (a user's class store is consulted first, so this server loads in its place)", where)
		if e.Server != "" {
			detail += ": " + excerpt(e.Server, 160)
			if e.ShadowServer != "" {
				detail += " — shadows " + excerpt(e.ShadowServer, 160)
			}
		}
		if lvl == riskHigh {
			sev, conf = SevCritical, 85
		}
		out = append(out, Finding{Rule: "persistence.com_hijack_user_shadow", Severity: sev, Technique: "T1546.015", Confidence: conf, Detail: detail})
	}

	// Server in a user-writable / temporary / world-writable location.
	if lvl != riskNone {
		sev, conf := SevSuspect, 60
		if lvl == riskLow {
			sev, conf = SevNotable, 35
		}
		out = append(out, Finding{Rule: "persistence.com_server_unusual_path", Severity: sev, Technique: "T1546.015", Confidence: conf,
			Detail: fmt.Sprintf("COM server for %s runs code from %s: %s", where, why, culprit)})
	}

	// A server that is itself a scriptlet runtime or a script host / LOLBin.
	if r := comScriptServer(e); r != "" {
		out = append(out, Finding{Rule: "persistence.com_script_server", Severity: SevSuspect, Technique: "T1546.015", Confidence: 65,
			Detail: fmt.Sprintf("COM server for %s is %s: %s", where, r, excerpt(e.Server, 200))})
	}

	// TreatAs remap: the object silently resolves to a different class.
	if e.TreatAs != "" {
		out = append(out, Finding{Rule: "persistence.com_treatas_redirect", Severity: SevNotable, Technique: "T1546.015", Confidence: 45,
			Detail: fmt.Sprintf("%s is remapped by TreatAs to %s (the object resolves to a different, possibly attacker-controlled class)", where, e.TreatAs)})
	}

	// For a LocalServer32 command line, run the shared command-line analytics
	// (encoded PowerShell, download cradles, LOLBin proxies, ...).
	if e.ServerKind == comLocal && e.Server != "" {
		out = mergeFindings(out, analyzeCommandLine("COM server "+where, "", e.Server)...)
	}
	return out
}

// comServerRisk grades where a COM server runs from and returns the offending
// path. An inproc server is a bare DLL path; a LocalServer32 is a command line,
// so the payload may be an argument (commandPathRisk handles both).
func comServerRisk(e comEntry) (lvl riskLevel, why, culprit string) {
	if e.Server == "" {
		return riskNone, "", ""
	}
	if e.ServerKind == comLocal {
		return commandPathRisk(e.Server)
	}
	lvl, why = pathRisk(e.Server)
	return lvl, why, e.Server
}

// comScriptServer reports whether a COM server is a scriptlet runtime
// (scrobj.dll — the COM scriptlet / "squiblydoo" technique) or a script
// host / LOLBin, returning a short description if so.
func comScriptServer(e comEntry) string {
	if e.Server == "" {
		return ""
	}
	switch e.ServerKind {
	case comInproc:
		if baseName(e.Server) == "scrobj.dll" {
			return "scrobj.dll, the script-component runtime that runs a COM scriptlet (.sct)"
		}
	case comLocal:
		if comLOLBinServers[progName(imageFromCommand(e.Server))] {
			return "a script host / LOLBin (" + progName(imageFromCommand(e.Server)) + ")"
		}
	}
	return ""
}
