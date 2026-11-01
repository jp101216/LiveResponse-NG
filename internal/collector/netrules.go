package collector

import (
	"fmt"
	"net/netip"
	"strings"

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
	Process    string // image name (Linux: comm), lower or mixed case
	ImagePath  string // "" when unknown
	Self       bool
	// Inbound marks an established connection accepted on one of the host's
	// own listening sockets (a client of a local server). Set on Linux.
	Inbound bool
	// PeerListener is the process listening on RemotePort when the peer is
	// this host (loopback), "" otherwise.
	PeerListener string
}

// localLLMServers are the default API ports of local LLM servers, each with
// the listener names that serve it (a server in WSL or a container is reached
// through the relay that listens for it).
var localLLMServers = map[uint16]struct {
	name      string
	listeners []string
}{
	11434: {"Ollama", []string{"ollama", "wslrelay", "com.docker.backend", "docker-proxy", "vpnkit"}},
	1234:  {"LM Studio", []string{"lm studio", "lm-studio", "lms"}},
	4891:  {"GPT4All", []string{"gpt4all", "chat"}},
	1337:  {"Jan", []string{"jan", "cortex"}},
}

// localLLMClients are programs expected to talk to a local model: the
// servers' own front ends, editors and AI clients, and browsers (web UIs).
var localLLMClients = set("ollama", "ollama.exe", "ollama app.exe", "lm studio.exe", "lm studio", "lms.exe", "lms", "gpt4all.exe",
	"gpt4all", "chat.exe", "jan.exe", "jan", "msty.exe", "msty", "anythingllm.exe", "anythingllm", "chatbox.exe", "chatbox",
	"open-webui", "code.exe", "code", "cursor.exe", "cursor", "windsurf.exe", "windsurf", "zed.exe", "zed", "chrome.exe", "chrome",
	"msedge.exe", "firefox.exe", "firefox", "brave.exe", "brave", "claude.exe", "claude", "docker.exe", "com.docker.backend.exe",
	"wslrelay.exe", "vpnkit.exe", "docker-proxy", "msedgewebview2.exe")

// localLLMRuntimes are interpreters developers script local models from.
var localLLMRuntimes = set("python.exe", "python3.exe", "pythonw.exe", "python", "python3", "node.exe", "node", "java.exe", "java",
	"deno.exe", "deno", "bun.exe", "bun", "uv.exe", "uv", "ruby", "ruby.exe", "go", "go.exe")

// llmServerFindings judges a connection to a local LLM server's API port: a
// program that isn't an AI client asking a model on this machine for output
// (how LLM-orchestrated malware, such as the PromptLock proof of concept,
// generates its scripts without a cloud API), or any program reaching an
// Ollama API on the internet.
func llmServerFindings(c connView, label string) []Finding {
	if c.State != "ESTABLISHED" && c.State != "SYN_SENT" {
		return nil
	}
	srv, ok := localLLMServers[c.RemotePort]
	if !ok {
		return nil
	}
	name := baseName(c.Process)
	if c.RemotePort == 11434 && aidetect.PublicAddr(c.Remote) {
		return []Finding{{Rule: "ai.remote_llm_server", Severity: SevSuspect, Technique: "T1071.001", Confidence: 55,
			Detail: fmt.Sprintf("%s is connected to an Ollama API on public address %s: a model served from someone else's "+
				"machine, which LLM-orchestrated malware can use to write its next steps", label, netip.AddrPortFrom(c.Remote, c.RemotePort))}}
	}
	if !c.Remote.IsLoopback() || c.PeerListener == "" || localLLMClients[name] {
		return nil
	}
	listener := strings.ToLower(c.PeerListener)
	served := false
	for _, l := range srv.listeners {
		served = served || strings.Contains(listener, l)
	}
	if !served {
		return nil
	}
	f := Finding{Rule: "ai.local_llm_client", Severity: SevSuspect, Technique: "T1059", Confidence: 55,
		Detail: fmt.Sprintf("%s is talking to the local %s server (%s, port %d): a program that isn't an AI client asking a model "+
			"on this machine for output, which is how LLM-orchestrated malware such as the PromptLock proof of concept generates "+
			"its scripts without a cloud API", label, srv.name, c.PeerListener, c.RemotePort)}
	if localLLMRuntimes[name] {
		f.Severity, f.Confidence = SevNotable, 30
		f.Detail += ". It is a script interpreter, which developers use with local models every day"
	}
	return []Finding{f}
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

	out = append(out, llmServerFindings(c, label)...)
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
