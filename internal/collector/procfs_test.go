package collector

import "testing"

func TestParseProcStatus(t *testing.T) {
	data := []byte("Name:\tsshd\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
	s := parseProcStatus(data)
	if s.Name != "sshd" {
		t.Errorf("Name = %q, want sshd", s.Name)
	}
	if s.State != "S" {
		t.Errorf("State = %q, want S", s.State)
	}
	if s.PPID != 1 {
		t.Errorf("PPID = %d, want 1", s.PPID)
	}
	if s.UID != 0 {
		t.Errorf("UID = %d, want 0", s.UID)
	}
}

func TestParseStarttimeTicks(t *testing.T) {
	// A comm with spaces and a ')' inside, to exercise the last-')' split.
	stat := []byte("1234 (weird ):) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 10 20 0 0 20 0 1 0 987654 12345678 500 ")
	tks, ok := parseStarttimeTicks(stat)
	if !ok {
		t.Fatal("expected to parse starttime")
	}
	if tks != 987654 {
		t.Errorf("starttime = %d, want 987654", tks)
	}

	if _, ok := parseStarttimeTicks([]byte("garbage no paren")); ok {
		t.Error("expected failure on a line with no ')'")
	}
}

func TestParseBtime(t *testing.T) {
	data := []byte("cpu  1 2 3\nintr 100\nbtime 1700000000\nprocesses 42\n")
	bt, ok := parseBtime(data)
	if !ok || bt != 1700000000 {
		t.Errorf("btime = %d ok=%v, want 1700000000", bt, ok)
	}
	if _, ok := parseBtime([]byte("no btime here")); ok {
		t.Error("expected no btime")
	}
}

func TestParseCmdline(t *testing.T) {
	if got := parseCmdline([]byte("python3\x00-c\x00import os\x00")); got != "python3 -c import os" {
		t.Errorf("parseCmdline = %q", got)
	}
	if got := parseCmdline(nil); got != "" {
		t.Errorf("empty cmdline = %q, want empty (kernel thread)", got)
	}
}

func TestParsePasswdAndUIDMap(t *testing.T) {
	data := []byte("root:x:0:0:root:/root:/bin/bash\n# comment\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbad:line\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n")
	entries := parsePasswd(data)
	if len(entries) != 3 { // the "# comment" and "bad:line" are skipped
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	m := uidNameMap(entries)
	if m[0] != "root" || m[1000] != "alice" {
		t.Errorf("uid map = %v", m)
	}
	if entries[2].Shell != "/bin/zsh" || entries[2].Home != "/home/alice" {
		t.Errorf("alice entry = %+v", entries[2])
	}
}

func TestParseGroup(t *testing.T) {
	data := []byte("root:x:0:\nsudo:x:27:alice,bob\nwheel:x:10:carol\n")
	groups := parseGroup(data)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	var sudo groupEntry
	for _, g := range groups {
		if g.Name == "sudo" {
			sudo = g
		}
	}
	if len(sudo.Members) != 2 || sudo.Members[0] != "alice" {
		t.Errorf("sudo members = %v", sudo.Members)
	}
}
