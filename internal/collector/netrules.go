package collector

import (
	"fmt"
	"net/netip"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Network heuristics beyond module A: who is listening, and which programs
// that have no business on the internet are talking to it. No build tag:
// pure logic, unit-tested on any OS.

// connView is what the network heuristics need to know about one socket.
type connView struct {
	State      string // MIB_TCP_STATE name: LISTEN, ESTABLISHED, ...
	Local      netip.Addr
	LocalPort  uint16
	Remote     netip.Addr
	RemotePort uint16
	PID        uint32
	Process    string // image name, lower or mixed case
	ImagePath  string // "" when unknown
	Self       bool
}

// listenerHosts are interpreters and LOLBins that don't normally accept
// connections; one listening on a non-loopback address looks like a bind
// shell or an ad-hoc file server.
var listenerHosts = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true,
	"cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
	"certutil.exe": true, "msbuild.exe": true, "installutil.exe": true, "nc.exe": true,
	"ncat.exe": true, "nc64.exe": true, "socat.exe": true,
}

// proxyBeaconHosts are signed binaries that proxy-execute attacker code and
// rarely reach the internet themselves; an outbound public connection from
// one is a common beacon shape (T1218).
var proxyBeaconHosts = map[string]bool{
	"rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true, "msbuild.exe": true,
	"installutil.exe": true, "regasm.exe": true, "regsvcs.exe": true, "cmstp.exe": true,
	"wscript.exe": true, "cscript.exe": true, "certutil.exe": true, "odbcconf.exe": true,
	"control.exe": true, "msiexec.exe": true, "hh.exe": true,
}

// analyzeConnection returns the generic network findings for one socket.
func analyzeConnection(c connView) []Finding {
	if c.Self || c.PID == 0 || c.PID == 4 {
		return nil
	}
	name := baseName(c.Process)
	label := fmt.Sprintf("%s (pid %d)", c.Process, c.PID)
	var out []Finding

	if c.State == "LISTEN" && listenerHosts[name] && c.Local.IsValid() && !c.Local.IsLoopback() {
		out = append(out, Finding{
			Rule: "network.script_host_listener", Severity: SevSuspect, Technique: "T1059", Confidence: 65,
			Detail: fmt.Sprintf("%s is listening on %s port %d — interpreters and LOLBins don't normally accept connections (bind shell?)",
				label, c.Local, c.LocalPort),
		})
	}

	outbound := (c.State == "ESTABLISHED" || c.State == "SYN_SENT") && aidetect.PublicAddr(c.Remote)
	if !outbound {
		return out
	}
	peer := netip.AddrPortFrom(c.Remote, c.RemotePort).String()
	switch {
	case proxyBeaconHosts[name]:
		out = append(out, Finding{
			Rule: "network.lolbin_outbound", Severity: SevSuspect, Technique: "T1218", Confidence: 65,
			Detail: fmt.Sprintf("%s has a connection to public address %s — signed proxy-execution binaries rarely talk to the internet themselves (beacon?)",
				label, peer),
		})
	case name == "powershell.exe" || name == "pwsh.exe" || name == "cmd.exe":
		out = append(out, Finding{
			Rule: "network.script_host_outbound", Severity: SevNotable, Technique: "T1059.001", Confidence: 40,
			Detail: fmt.Sprintf("%s has a connection to public address %s", label, peer),
		})
	}
	if lvl, why := pathRisk(c.ImagePath); lvl == riskHigh {
		out = append(out, Finding{
			Rule: "network.unusual_path_outbound", Severity: SevSuspect, Technique: "T1071", Confidence: 55,
			Detail: fmt.Sprintf("%s runs from %s (%s) and has a connection to public address %s", label, why, c.ImagePath, peer),
		})
	}
	return out
}
