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
