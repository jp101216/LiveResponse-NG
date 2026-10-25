package collector

import "testing"

func TestUnixPathRisk(t *testing.T) {
	cases := []struct {
		path string
		want riskLevel
	}{
		{"/tmp/payload", riskHigh},
		{"/var/tmp/.x/evil", riskHigh},
		{"/dev/shm/x", riskHigh},
		{"/run/user/1000/sh", riskHigh},
		{"/usr/bin/python3 (deleted)", riskHigh},
		{"/memfd:abc (deleted)", riskHigh},
		{"/home/alice/.config/autostart/x", riskLow},
		{"/home/alice/Downloads/installer", riskLow},
		{"/root/.ssh/x", riskLow},
		{"/var/www/html/shell.php", riskLow},
		{"/usr/local/bin/tool", riskNone},
		{"/opt/vendor/app", riskNone},
		{"/tmpfoo/x", riskNone}, // not actually under /tmp
		{"", riskNone},
	}
	for _, c := range cases {
		got, _ := unixPathRisk(c.path)
		if got != c.want {
			t.Errorf("unixPathRisk(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestUnixSuspiciousPathAndBaseName(t *testing.T) {
	if !unixSuspiciousPath("/dev/shm/x") {
		t.Error("/dev/shm/x should be suspicious")
	}
	if unixSuspiciousPath("/usr/sbin/sshd") {
		t.Error("/usr/sbin/sshd should not be suspicious")
	}
	if got := unixBaseName("/usr/lib/systemd/systemd"); got != "systemd" {
		t.Errorf("unixBaseName = %q, want systemd", got)
	}
}

func TestHasPathPrefix(t *testing.T) {
	if !hasPathPrefix("/tmp/x", "/tmp") {
		t.Error("/tmp/x is under /tmp")
	}
	if !hasPathPrefix("/tmp", "/tmp") {
		t.Error("/tmp equals /tmp")
	}
	if hasPathPrefix("/tmpfoo", "/tmp") {
		t.Error("/tmpfoo is not under /tmp")
	}
}

func TestReplacedSystemFile(t *testing.T) {
	present := map[string]bool{"/usr/lib/x86_64-linux-gnu/libssl.so.3": true, "/usr/sbin/sshd": true, "/tmp/x": true}
	exists := func(p string) bool { return present[p] }
	cases := map[string]bool{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)": true,  // upgraded, restart pending
		"/usr/sbin/sshd (deleted)":                        true,  // upgraded binary
		"/usr/lib/libgone.so (deleted)":                   false, // deleted, nothing replaced it
		"/tmp/x (deleted)":                                false, // replaced, but not a system location
		"/memfd:x (deleted)":                              false, // never a file
		"/usr/sbin/sshd":                                  false, // not deleted at all
		"/usrlocal/x (deleted)":                           false, // not under /usr
		" (deleted)":                                      false,
	}
	for p, want := range cases {
		if got := replacedSystemFile(p, exists); got != want {
			t.Errorf("replacedSystemFile(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestHomePathRiskRootIsAComponent(t *testing.T) {
	if lvl, _ := unixPathRisk("/rootfs/.cache/x"); lvl != riskNone {
		t.Errorf("/rootfs is not root's home, got %v", lvl)
	}
	if lvl, _ := unixPathRisk("/root/.cache/x"); lvl != riskLow {
		t.Errorf("a hidden dir in /root should be low risk, got %v", lvl)
	}
}
