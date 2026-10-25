package collector

import (
	"fmt"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Linux network heuristics — the counterpart to netrules.go, whose listener and
// beacon maps are keyed on Windows .exe names. No build tag: pure logic over a
// connView, unit-tested on any OS. Module A (LLM-callout detection) is shared
// and OS-agnostic, so the Linux network collector reuses it directly; this file
// adds the generic "who has no business on the network" findings for Linux.

// unixShellProcs are shells and dual-use network tools that don't normally
// listen for connections, and whose outbound traffic is worth a look.
var unixShellProcs = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true,
}

// unixScriptProcs are script interpreters. They run application servers and
// API clients every day, so their listeners and connections rate a lower
// severity than a bare shell's.
var unixScriptProcs = map[string]bool{
	"python": true, "python2": true, "python3": true, "pypy": true, "perl": true,
	"ruby": true, "php": true, "node": true, "nodejs": true, "lua": true,
	"awk": true, "gawk": true, "mawk": true,
}

// unixProcClass says whether a process is a shell/netcat or a script
// interpreter, judged by both of its names: comm, and the file name of its
// executable. They differ for a script run through its #! line (comm is the
// script's name, the exe is /bin/bash or python3.12) and for a process that
// renamed itself, so a reverse shell launched as ./update.sh is still a shell.
// Versioned interpreter names (python3.12, perl5.36.0) count as the interpreter.
func unixProcClass(comm, exe string) (shell, script bool) {
	for _, n := range []string{unixBaseName(comm), unixBaseName(strings.TrimSuffix(exe, deletedSuffix))} {
		if n == "" {
			continue
		}
		if unixShellProcs[n] {
			shell = true
		}
		if unixScriptProcs[n] || unixScriptProcs[strings.TrimRight(n, "0123456789.")] {
			script = true
		}
	}
	return shell, script
}

// linuxConnFindings returns the generic network findings for one Linux socket.
func linuxConnFindings(c connView) []Finding {
	if c.Self || c.PID == 0 {
		return nil
	}
	shell, script := unixProcClass(c.Process, c.ImagePath)
	label := fmt.Sprintf("%s (pid %d)", c.Process, c.PID)
	if exe := unixBaseName(strings.TrimSuffix(c.ImagePath, deletedSuffix)); exe != "" && exe != unixBaseName(c.Process) {
		label = fmt.Sprintf("%s [%s] (pid %d)", c.Process, exe, c.PID)
	}
	var out []Finding

	// A shell or netcat listening on a non-loopback address is a bind shell or
	// an ad-hoc server. An interpreter listening is usually an application
	// server (gunicorn, a node app), so it is context, not an accusation.
	if c.State == "LISTEN" && c.Local.IsValid() && !c.Local.IsLoopback() {
		switch {
		case shell:
			out = append(out, Finding{
				Rule: "network.shell_listener", Severity: SevSuspect, Technique: "T1059.004", Confidence: 60,
				Detail: fmt.Sprintf("%s is listening on %s port %d — shells and netcat don't normally accept connections (bind shell?)",
					label, c.Local, c.LocalPort),
			})
		case script:
			out = append(out, Finding{
				Rule: "network.interpreter_listener", Severity: SevNotable, Technique: "T1059", Confidence: 30,
				Detail: fmt.Sprintf("%s (a script interpreter) is listening on %s port %d — an application server, or an ad-hoc listener",
					label, c.Local, c.LocalPort),
			})
		}
	}

	// Outbound: this host opened the connection. A connection accepted on one
	// of the host's listening ports is a client of a local server, not the
	// process reaching out, so it isn't judged as outbound.
	outbound := (c.State == "SYN_SENT" || (c.State == "ESTABLISHED" && !c.Inbound)) && aidetect.PublicAddr(c.Remote)
	if !outbound {
		return out
	}
	peer := c.Remote.String()
	switch {
	case shell:
		out = append(out, Finding{
			Rule: "network.shell_outbound", Severity: SevSuspect, Technique: "T1059.004", Confidence: 55,
			Detail: fmt.Sprintf("%s has a connection to public address %s:%d — a shell/netcat talking to the internet (reverse shell or beacon?)",
				label, peer, c.RemotePort),
		})
	case script:
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
