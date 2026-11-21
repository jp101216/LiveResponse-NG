package collector

import (
	"fmt"
	"net/netip"
	"strings"
)

// Directory enumeration over LDAP (T1087.002, T1069.002, T1482): users,
// groups, computers, trusts and ACLs read straight from a domain controller,
// as SharpHound, ADSearch, PowerView and a C2's in-memory net-enum do. On the
// client there is no file and no command line to see, only the connection.
// No build tag: pure logic over one connection, unit-tested on any OS.

// ldapPorts are the directory's LDAP ports.
var ldapPorts = map[uint16]string{389: "LDAP", 636: "LDAP over TLS", 3268: "the global catalog", 3269: "the global catalog over TLS"}

// unixInterpreter reports a script interpreter by name, versioned or not.
func unixInterpreter(name string) bool {
	return unixScriptProcs[name] || unixScriptProcs[strings.TrimRight(name, "0123456789.")]
}

// ldapDiscoveryFinding judges a connection this host opened to a directory's
// LDAP port. Domain controllers are on private addresses, so unlike the
// beacon rules this doesn't need a public peer. Windows reaches the
// directory from LSASS, svchost and installed programs, which pass; a
// sacrificial process, a program run from a temporary folder, PowerShell and
// script interpreters are reported.
//
// cmdline is the process's command line where the caller has it; Windows'
// own Find Users, Contacts and Groups dialog runs as rundll32 dsquery.dll.
// img may be a bare image name when the path couldn't be read, in which case
// only the name-based checks apply.
func ldapDiscoveryFinding(label, img, cmdline string, peer netip.AddrPort, when string) (Finding, bool) {
	svc, ok := ldapPorts[peer.Port()]
	ip := peer.Addr().Unmap()
	if !ok || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || img == "" {
		return Finding{}, false
	}
	exe := strings.TrimSuffix(img, deletedSuffix)
	unix := strings.HasPrefix(exe, "/")
	name := baseName(exe)
	hasDir := strings.ContainsAny(exe, `\/`)
	lvl, why := anyPathRisk(exe)
	f := Finding{Rule: "discovery.ldap_unusual_process", Severity: SevSuspect, Technique: "T1087.002"}
	switch {
	case !unix && name == "rundll32.exe" && strings.Contains(strings.ToLower(cmdline), "dsquery.dll"):
		f.Severity, f.Confidence = SevNotable, 25
		why = "Windows' Find Users, Contacts and Groups dialog (rundll32 dsquery.dll), which people open by hand"
	case !unix && spawnToHosts[name]:
		f.Confidence, why = 65, "a program C2 frameworks use as a sacrificial process, which has no reason to read the directory"
		if name == "rundll32.exe" && cmdline == "" {
			why += " (unless it is Windows' Find Users dialog, rundll32 dsquery.dll,OpenQueryWindow)"
		}
	case lvl == riskHigh:
		f.Confidence, why = 60, "a program running from "+why
	case !unix && tokenScriptHosts[name] && name != "cmd.exe":
		f.Severity, f.Confidence = SevNotable, 30
		why = "PowerShell, which administrators' scripts query the directory from too ([adsisearcher]), as does PowerView"
	case unix && unixInterpreter(name):
		f.Severity, f.Confidence = SevNotable, 30
		why = "a script interpreter: Python's LDAP libraries are how BloodHound.py and ldapdomaindump read a domain, and " +
			"administrators' scripts too"
	case !hasDir || packagedProgram(exe):
		return Finding{}, false
	default:
		f.Severity, f.Confidence = SevNotable, 40
		why = "a program outside the places software is installed"
	}
	f.Detail = fmt.Sprintf("%s connected to %s on %s%s. The process is %s; reading the directory over LDAP is how users, "+
		"groups, computers, trusts and ACLs are enumerated ahead of lateral movement (SharpHound, ADSearch, PowerView, a "+
		"C2's net-enum)", label, svc, peer, when, why)
	return f, true
}
