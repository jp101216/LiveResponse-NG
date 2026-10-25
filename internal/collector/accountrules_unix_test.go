package collector

import (
	"strings"
	"testing"
)

func TestParseAuthorizedKeys(t *testing.T) {
	data := []byte(strings.Join([]string{
		"# admin keys",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA admin@laptop",
		"",
		// Forced command with a quoted value containing spaces: restricted.
		`command="/usr/bin/gitlab-shell key-42",no-port-forwarding,no-pty ssh-rsa AAAAB3Nza git@ci`,
		// restrict/no-pty alone don't pin the command: still unrestricted.
		"restrict,no-pty ecdsa-sha2-nistp256 AAAAE2VjZHNh deploy",
		// Option names are case-insensitive.
		`COMMAND="echo hi" sk-ssh-ed25519@openssh.com AAAAGnNr fido`,
		// A certificate key type.
		"ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1 cert",
		// Not a key line.
		"garbage without a key type",
	}, "\n"))
	got := parseAuthorizedKeys(data)
	if got.Total != 5 {
		t.Errorf("Total = %d, want 5", got.Total)
	}
	if got.Unrestricted != 3 { // plain ed25519, restrict+no-pty ecdsa, cert
		t.Errorf("Unrestricted = %d, want 3", got.Unrestricted)
	}
}

func TestHasForcedCommandIgnoresQuotedCommas(t *testing.T) {
	// The comma inside the quoted command must not split the option list.
	if !hasForcedCommand(`from="10.0.0.0/8",command="a,b c"`) {
		t.Error("expected a forced command")
	}
	// "command" appearing only inside another option's value is not a forced command.
	if hasForcedCommand(`environment="X=command"`) {
		t.Error("command inside another option's value should not count")
	}
}

func TestAuthorizedKeysFiles(t *testing.T) {
	// No sshd config: sshd's default pair, relative to home.
	got := authorizedKeysFiles(nil, "postgres", "/var/lib/postgresql")
	want := []string{"/var/lib/postgresql/.ssh/authorized_keys", "/var/lib/postgresql/.ssh/authorized_keys2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("default = %v, want %v", got, want)
	}

	// A centralised location with tokens; the drop-in wins over sshd_config.
	dropin := []byte("AuthorizedKeysFile /etc/ssh/keys/%u .ssh/authorized_keys\n")
	main := []byte("AuthorizedKeysFile .ssh/other\n")
	got = authorizedKeysFiles([][]byte{dropin, main}, "svc", "/srv/svc")
	want = []string{"/etc/ssh/keys/svc", "/srv/svc/.ssh/authorized_keys"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("custom = %v, want %v", got, want)
	}

	// '=' syntax, %h and %%.
	got = authorizedKeysFiles([][]byte{[]byte("AuthorizedKeysFile=%h/keys%%1\n")}, "u", "/home/u")
	if len(got) != 1 || got[0] != "/home/u/keys%1" {
		t.Errorf("= syntax / tokens = %v", got)
	}

	// A directive inside a Match block is conditional and ignored.
	cfg := []byte("PermitRootLogin no\nMatch User git\n    AuthorizedKeysFile /git/%u\n")
	got = authorizedKeysFiles([][]byte{cfg}, "git", "/home/git")
	if len(got) != 2 || got[0] != "/home/git/.ssh/authorized_keys" {
		t.Errorf("Match-block directive should be ignored: %v", got)
	}

	// "none" disables key files.
	if got = authorizedKeysFiles([][]byte{[]byte("AuthorizedKeysFile none\n")}, "u", "/home/u"); len(got) != 0 {
		t.Errorf("none = %v, want no files", got)
	}

	// With no home, relative entries can't be anchored and are dropped.
	if got = authorizedKeysFiles(nil, "x", ""); len(got) != 0 {
		t.Errorf("no home = %v, want no files", got)
	}
}

func TestSystemShellLoginFinding(t *testing.T) {
	pg := passwdEntry{Name: "postgres", UID: 102, Shell: "/bin/bash", Home: "/var/lib/postgresql"}

	// The distro default: password locked, no keys. Quiet, and verified.
	if _, fire, unverified := systemShellLoginFinding(pg, loginEvidence{Password: pwLocked}); fire || unverified {
		t.Errorf("locked + no keys: fire=%v unverified=%v, want both false", fire, unverified)
	}

	// Someone set a password: flagged as account manipulation.
	f, fire, _ := systemShellLoginFinding(pg, loginEvidence{Password: pwUsable})
	if !fire || f.Technique != "T1098" || !strings.Contains(f.Detail, "usable password") {
		t.Errorf("usable password: fire=%v %+v", fire, f)
	}

	// An empty password also makes it loginable.
	if _, fire, _ := systemShellLoginFinding(pg, loginEvidence{Password: pwEmpty}); !fire {
		t.Error("empty password should fire")
	}

	// An unrestricted SSH key: flagged as T1098.004.
	f, fire, _ = systemShellLoginFinding(pg, loginEvidence{Password: pwLocked, Keys: sshKeyCount{Total: 1, Unrestricted: 1}})
	if !fire || f.Technique != "T1098.004" {
		t.Errorf("unrestricted key: fire=%v technique=%s", fire, f.Technique)
	}

	// Only forced-command keys (git hosting): quiet.
	if _, fire, _ := systemShellLoginFinding(pg, loginEvidence{Password: pwLocked, Keys: sshKeyCount{Total: 3}}); fire {
		t.Error("forced-command-only keys should not fire")
	}

	// Without root: shadow unreadable, so it can't tell — unverified, not flagged.
	if _, fire, unverified := systemShellLoginFinding(pg, loginEvidence{}); fire || !unverified {
		t.Errorf("unreadable evidence: fire=%v unverified=%v, want false/true", fire, unverified)
	}
	// Key files unreadable even though the password is known locked: unverified.
	if _, _, unverified := systemShellLoginFinding(pg, loginEvidence{Password: pwLocked, KeysUnknown: true}); !unverified {
		t.Error("unreadable key files should leave the account unverified")
	}
}
