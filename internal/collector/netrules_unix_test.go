package collector

import (
	"net/netip"
	"strings"
	"testing"
)

func cvRules(c connView) []string {
	var out []string
	for _, f := range linuxConnFindings(c) {
		out = append(out, f.Rule)
	}
	return out
}

func TestLinuxConnBindShell(t *testing.T) {
	c := connView{
		State: "LISTEN", Local: netip.MustParseAddr("0.0.0.0"), LocalPort: 4444,
		PID: 100, Process: "bash",
	}
	if !hasRuleName(cvRules(c), "network.shell_listener") {
		t.Errorf("bash listening on 0.0.0.0 should be a bind shell, got %v", cvRules(c))
	}
	// A normal daemon listening is fine (not a shell).
	c.Process = "nginx"
	if len(cvRules(c)) != 0 {
		t.Errorf("nginx listener should be quiet, got %v", cvRules(c))
	}
	// A shell on loopback only is not flagged.
	c.Process, c.Local = "bash", netip.MustParseAddr("127.0.0.1")
	if len(cvRules(c)) != 0 {
		t.Errorf("loopback shell listener should be quiet, got %v", cvRules(c))
	}
}

func TestLinuxConnOutbound(t *testing.T) {
	// A shell talking to a public address.
	c := connView{
		State: "ESTABLISHED", Remote: netip.MustParseAddr("203.0.113.9"), RemotePort: 443,
		PID: 101, Process: "bash",
	}
	if !hasRuleName(cvRules(c), "network.shell_outbound") {
		t.Errorf("bash outbound to public should flag, got %v", cvRules(c))
	}
	// An interpreter is lower severity but still noted.
	c.Process = "python3"
	if !hasRuleName(cvRules(c), "network.interpreter_outbound") {
		t.Errorf("python outbound should be noted, got %v", cvRules(c))
	}
	// Outbound to a private address is not flagged.
	c.Process, c.Remote = "bash", netip.MustParseAddr("10.0.0.5")
	if len(cvRules(c)) != 0 {
		t.Errorf("outbound to RFC1918 should be quiet, got %v", cvRules(c))
	}
}

func TestLinuxConnUnusualPath(t *testing.T) {
	c := connView{
		State: "ESTABLISHED", Remote: netip.MustParseAddr("203.0.113.9"), RemotePort: 443,
		PID: 102, Process: "x", ImagePath: "/tmp/.x/payload",
	}
	if !hasRuleName(cvRules(c), "network.unusual_path_outbound") {
		t.Errorf("outbound from /tmp should flag unusual path, got %v", cvRules(c))
	}
}

func TestLinuxConnSelfAndSystem(t *testing.T) {
	c := connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("203.0.113.9"), RemotePort: 443, PID: 1, Process: "bash", Self: true}
	if len(cvRules(c)) != 0 {
		t.Errorf("self connections must never be judged, got %v", cvRules(c))
	}
}

// TestLinuxConnJudgedByExecutable covers a script run through its #! line: its
// comm is the script's name, so only the executable says it is a shell.
func TestLinuxConnJudgedByExecutable(t *testing.T) {
	c := connView{
		State: "ESTABLISHED", Remote: netip.MustParseAddr("203.0.113.9"), RemotePort: 4444,
		PID: 103, Process: "rev.sh", ImagePath: "/usr/bin/bash",
	}
	if !hasRuleName(cvRules(c), "network.shell_outbound") {
		t.Errorf("a #! shell script talking out should be judged as bash, got %v", cvRules(c))
	}
	fs := linuxConnFindings(c)
	if len(fs) == 0 || !strings.Contains(fs[0].Detail, "rev.sh [bash]") {
		t.Errorf("detail should name both identities: %+v", fs)
	}
	// busybox: comm is the applet, the exe is busybox.
	c.Process, c.ImagePath = "nc", "/bin/busybox"
	if !hasRuleName(cvRules(c), "network.shell_outbound") {
		t.Errorf("busybox nc should be judged by its applet name, got %v", cvRules(c))
	}
	// A versioned interpreter binary behind a script name.
	c.Process, c.ImagePath = "sync-agent", "/usr/bin/python3.12"
	if !hasRuleName(cvRules(c), "network.interpreter_outbound") {
		t.Errorf("python3.12 should count as an interpreter, got %v", cvRules(c))
	}
}

// TestLinuxConnInterpreterListenerIsContext: an interpreter listening is usually
// an application server, so it is notable context, not a bind-shell accusation.
func TestLinuxConnInterpreterListenerIsContext(t *testing.T) {
	c := connView{
		State: "LISTEN", Local: netip.MustParseAddr("0.0.0.0"), LocalPort: 8000,
		PID: 200, Process: "gunicorn", ImagePath: "/usr/bin/python3.11",
	}
	got := linuxConnFindings(c)
	if len(got) != 1 || got[0].Rule != "network.interpreter_listener" || got[0].Severity != SevNotable {
		t.Fatalf("want one notable interpreter_listener, got %+v", got)
	}
	c.Process, c.ImagePath = "x", "/usr/bin/ncat"
	if !hasRuleName(cvRules(c), "network.shell_listener") {
		t.Errorf("ncat listening should stay a shell listener, got %v", cvRules(c))
	}
}

// TestLinuxConnInboundIsNotOutbound: a client connected to a local server is
// not the server process reaching out to the internet.
func TestLinuxConnInboundIsNotOutbound(t *testing.T) {
	c := connView{
		State: "ESTABLISHED", Local: netip.MustParseAddr("10.0.0.2"), LocalPort: 3000,
		Remote: netip.MustParseAddr("203.0.113.50"), RemotePort: 51234,
		PID: 300, Process: "node", ImagePath: "/usr/bin/node", Inbound: true,
	}
	if got := cvRules(c); len(got) != 0 {
		t.Errorf("an inbound client of a node app should be quiet, got %v", got)
	}
	c.Inbound = false
	if !hasRuleName(cvRules(c), "network.interpreter_outbound") {
		t.Errorf("the same connection opened by node is outbound, got %v", cvRules(c))
	}
	c.State, c.Inbound = "SYN_SENT", true // a SYN_SENT socket is always this host connecting out
	if !hasRuleName(cvRules(c), "network.interpreter_outbound") {
		t.Errorf("SYN_SENT is outbound regardless, got %v", cvRules(c))
	}
}
