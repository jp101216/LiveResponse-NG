package collector

import (
	"fmt"
	"path"
	"strings"
)

// Linux account heuristics — whether a service account with an interactive shell
// has actually been enabled for login. No build tag: pure logic over parsed
// file contents, unit-tested on any OS. (POSIX paths are joined with "path", not
// "path/filepath", so behaviour is identical when the tests run on Windows.)
//
// A service account (UID 100–999) with a real shell is common and usually benign
// — Debian's postgres user ships with /bin/bash so admins can `su - postgres`.
// What turns it into a lead is evidence someone made it *loginable*: a usable
// password hash, an empty password, or an SSH key that isn't pinned to a forced
// command. Flagging only those cases keeps the rule quiet on distro defaults and
// loud on the classic backdoor (a key dropped into www-data's home).

// sshKeyCount summarises one or more authorized_keys files.
type sshKeyCount struct {
	Total        int // key lines
	Unrestricted int // keys without a forced command — usable for an arbitrary login
}

// parseAuthorizedKeys counts the keys in an authorized_keys file and how many are
// unrestricted. A key whose options include command="…" can only run that
// command (GitLab/Gitea's git user works this way), so it doesn't make the
// account interactively loginable; restrict/no-pty alone don't stop commands
// from running, so those keys still count as unrestricted.
func parseAuthorizedKeys(data []byte) sshKeyCount {
	var c sshKeyCount
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		opts, ok := authorizedKeyOptions(line)
		if !ok {
			continue // no key type on the line: not a key
		}
		c.Total++
		if !hasForcedCommand(opts) {
			c.Unrestricted++
		}
	}
	return c
}

// authorizedKeyOptions returns the options that precede the key type on an
// authorized_keys line ("" when the line starts with the key type). Tokenising
// respects double quotes, since option values like command="a b" contain spaces.
func authorizedKeyOptions(line string) (string, bool) {
	toks := splitQuoted(line, func(r rune) bool { return r == ' ' || r == '\t' })
	for i, t := range toks {
		if isSSHKeyType(t) {
			return strings.Join(toks[:i], " "), true
		}
	}
	return "", false
}

// hasForcedCommand reports whether an options string sets command="…".
func hasForcedCommand(opts string) bool {
	if opts == "" {
		return false
	}
	for _, o := range splitQuoted(opts, func(r rune) bool { return r == ',' }) {
		name, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(strings.TrimSpace(name), "command") {
			return true
		}
	}
	return false
}

// isSSHKeyType reports whether a token is an OpenSSH public-key type, including
// FIDO (sk-) keys and certificates (…-cert-v01@openssh.com).
func isSSHKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-sha2-") ||
		strings.HasPrefix(t, "sk-ssh-") || strings.HasPrefix(t, "sk-ecdsa-")
}

// splitQuoted splits s at runes for which sep is true, except inside double
// quotes (a backslash escapes a quote within them). Empty fields are dropped.
func splitQuoted(s string, sep func(rune) bool) []string {
	var out []string
	var cur strings.Builder
	inQuote, escaped := false, false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case inQuote && r == '\\':
			escaped = true
		case r == '"':
			inQuote = !inQuote
		case !inQuote && sep(r):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// authorizedKeysFiles resolves where sshd looks for a user's keys. configs are
// sshd config files in the order sshd reads them (the sshd_config.d drop-ins,
// then sshd_config); the first global AuthorizedKeysFile wins, as in sshd.
// Directives inside a Match block are ignored (they apply only conditionally).
// %h, %u and %% are expanded, relative paths are taken from the home directory,
// and "none" means no file. Without a directive, sshd's default applies:
// .ssh/authorized_keys and .ssh/authorized_keys2.
func authorizedKeysFiles(configs [][]byte, user, home string) []string {
	spec := []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
found:
	for _, cfg := range configs {
		for _, line := range strings.Split(string(cfg), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, rest := splitDirective(line)
			if strings.EqualFold(key, "Match") {
				break // the rest of this file is conditional
			}
			if strings.EqualFold(key, "AuthorizedKeysFile") && rest != "" {
				spec = strings.Fields(rest)
				break found
			}
		}
	}
	var out []string
	for _, p := range spec {
		if strings.EqualFold(p, "none") {
			continue
		}
		p = expandSSHTokens(p, user, home)
		if !strings.HasPrefix(p, "/") {
			if home == "" {
				continue // nothing to anchor a relative path to
			}
			p = path.Join(home, p)
		}
		out = append(out, path.Clean(p))
	}
	return out
}

// splitDirective splits an sshd_config line into its keyword and arguments; the
// two may be separated by whitespace or by '='.
func splitDirective(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return line[:i], strings.TrimSpace(rest)
}

// expandSSHTokens expands the AuthorizedKeysFile tokens %h (home), %u (user) and
// %% (a literal percent sign).
func expandSSHTokens(p, user, home string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' || i+1 >= len(p) {
			b.WriteByte(p[i])
			continue
		}
		i++
		switch p[i] {
		case 'h':
			b.WriteString(home)
		case 'u':
			b.WriteString(user)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(p[i])
		}
	}
	return b.String()
}

// loginEvidence is what was learned about whether an account can be logged into.
type loginEvidence struct {
	Password    string      // pwUsable, pwEmpty, pwLocked, pwNone; "" when /etc/shadow was unreadable
	Keys        sshKeyCount // across every authorized_keys file sshd would read
	KeysUnknown bool        // a key file couldn't be read (permissions) and no keys were found
}

// systemShellLoginFinding decides whether a service account with an interactive
// shell has been enabled for login. fire is true (with the finding) when the
// evidence shows a usable or empty password, or an unrestricted SSH key.
// unverified is true when it couldn't tell — the evidence needs root to read.
func systemShellLoginFinding(u passwdEntry, ev loginEvidence) (f Finding, fire, unverified bool) {
	var reasons []string
	tech := "T1098" // Account Manipulation: an existing account made loginable
	switch ev.Password {
	case pwUsable:
		reasons = append(reasons, "a usable password set")
	case pwEmpty:
		reasons = append(reasons, "no password at all")
	}
	if n := ev.Keys.Unrestricted; n > 0 {
		reasons = append(reasons, fmt.Sprintf("%d SSH key(s) not pinned to a forced command", n))
		tech = "T1098.004" // SSH Authorized Keys
	}
	if len(reasons) == 0 {
		return Finding{}, false, ev.Password == "" || ev.KeysUnknown
	}
	return Finding{
		Rule: "accounts.system_account_login_shell", Severity: SevNotable, Technique: tech, Confidence: 55,
		Detail: fmt.Sprintf("service account %q (uid %d) has a login shell (%s) and %s — it can be logged into "+
			"interactively; service accounts normally use nologin", u.Name, u.UID, u.Shell, strings.Join(reasons, " and ")),
	}, true, false
}
