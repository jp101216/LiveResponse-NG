package collector

import (
	"fmt"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Linux network heuristics — the counterpart to netrules.go, whose listener and
// beacon maps are keyed on Windows .exe names. No build tag: pure logic over a
// connView, unit-tested on any OS. Module A (LLM-callout detection) is shared
// and OS-agnostic, so the Linux network collector reuses it directly; this file
// adds the generic "who has no business on the network" findings for Linux.

// unixShellProcs are interpreters and dual-use network tools that don't normally
// listen for connections, and whose outbound traffic is worth a look.
var unixShellProcs = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true,
}

// unixScriptProcs legitimately make outbound connections far more often, so they
// rate a lower severity than a bare shell does.
var unixScriptProcs = map[string]bool{
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "node": true, "lua": true, "awk": true,
}

// linuxConnFindings returns the generic network findings for one Linux socket.
func linuxConnFindings(c connView) []Finding {
	if c.Self || c.PID == 0 {
		return nil
	}
	name := unixBaseName(c.Process)
	label := fmt.Sprintf("%s (pid %d)", c.Process, c.PID)
	var out []Finding

	// A shell or netcat listening on a non-loopback address is a bind shell or
	// an ad-hoc server.
	if c.State == "LISTEN" && (unixShellProcs[name] || unixScriptProcs[name]) &&
		c.Local.IsValid() && !c.Local.IsLoopback() {
		out = append(out, Finding{
			Rule: "network.shell_listener", Severity: SevSuspect, Technique: "T1059.004", Confidence: 60,
			Detail: fmt.Sprintf("%s is listening on %s port %d — shells and interpreters don't normally accept connections (bind shell?)",
				label, c.Local, c.LocalPort),
		})
	}

	outbound := (c.State == "ESTABLISHED" || c.State == "SYN_SENT") && aidetect.PublicAddr(c.Remote)
	if !outbound {
		return out
	}
	peer := c.Remote.String()
	switch {
	case unixShellProcs[name]:
		out = append(out, Finding{
			Rule: "network.shell_outbound", Severity: SevSuspect, Technique: "T1059.004", Confidence: 55,
			Detail: fmt.Sprintf("%s has a connection to public address %s:%d — a shell/netcat talking to the internet (reverse shell or beacon?)",
				label, peer, c.RemotePort),
		})
	case unixScriptProcs[name]:
		out = append(out, Finding{
			Rule: "network.interpreter_outbound", Severity: SevNotable, Technique: "T1059", Confidence: 35,
			Detail: fmt.Sprintf("%s has a connection to public address %s:%d", label, peer, c.RemotePort),
		})
	}
	if lvl, why := unixPathRisk(c.ImagePath); lvl == riskHigh {
		out = append(out, Finding{
			Rule: "network.unusual_path_outbound", Severity: SevSuspect, Technique: "T1071", Confidence: 55,
			Detail: fmt.Sprintf("%s runs from %s (%s) and has a connection to public address %s:%d",
				label, why, c.ImagePath, peer, c.RemotePort),
		})
	}
	return out
}
