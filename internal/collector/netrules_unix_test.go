package collector

import (
	"net/netip"
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
