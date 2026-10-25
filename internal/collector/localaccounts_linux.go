//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Linux local-accounts collector: the users in /etc/passwd (with their UID,
// shell, home, password state and SSH keys), the members of the
// privilege-granting groups, and the account-level findings that matter for
// triage — a non-root UID-0 account (a backdoor superuser), a passwordless login,
// a service account that has been made loginable, a shared UID, and membership of
// root-equivalent groups.
//
// The password state comes from /etc/shadow and the SSH keys from the files sshd
// would read (AuthorizedKeysFile, default ~/.ssh/authorized_keys{,2}); both need
// root, and when they can't be read the gap is reported in meta rather than
// guessed at.

// disabledShells are login-shell values that don't give an interactive session.
var disabledShells = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true,
	"/usr/bin/false": true, "/bin/true": true, "": true,
	// Single-purpose pseudo-shells shipped for historical system accounts;
	// they aren't usable interactive logins.
	"/bin/sync": true, "/sbin/shutdown": true, "/sbin/halt": true,
	"/usr/sbin/shutdown": true, "/usr/sbin/halt": true,
}

// privilegedGroups grant administrative power; membership is worth listing.
var privilegedGroups = map[string]bool{
	"sudo": true, "wheel": true, "root": true, "admin": true,
	"adm": true, "docker": true, "lxd": true,
}

func collectLocalAccounts(ctx context.Context) (Result, error) {
	res := NewResult("localaccounts")

	passwd := readFileSafe("/etc/passwd")
	if passwd == nil {
		return res.Finish(), fmt.Errorf("could not read /etc/passwd")
	}
	users := parsePasswd(passwd)

	// /etc/shadow is root-only; without it password state is unknown.
	var shadow map[string]string
	if sh := readFileSafe("/etc/shadow"); sh != nil {
		shadow = parseShadow(sh)
	}
	sshdConfigs := readSSHDConfigs()

	uidCount := map[int]int{}
	for _, u := range users {
		uidCount[u.UID]++
	}

	serviceShells := 0
	var unverified []string
	for _, u := range users {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		system := u.UID < 1000 && u.UID != 0
		hasLoginShell := !disabledShells[u.Shell]
		fields := map[string]any{
			"kind":        "user",
			"name":        u.Name,
			"uid":         u.UID,
			"gid":         u.GID,
			"home":        u.Home,
			"shell":       u.Shell,
			"login_shell": hasLoginShell,
		}

		ev := loginEvidence{}
		if shadow != nil {
			if h, ok := shadow[u.Name]; ok {
				ev.Password = passwordState(h)
			} else {
				ev.Password = pwNone
			}
			fields["password_state"] = ev.Password
		}
		ev.Keys, ev.KeysUnknown = readAuthorizedKeys(authorizedKeysFiles(sshdConfigs, u.Name, u.Home))
		if ev.Keys.Total > 0 {
			fields["ssh_keys"] = ev.Keys.Total
			fields["ssh_keys_unrestricted"] = ev.Keys.Unrestricted
		}

		var findings []Finding
		if u.UID == 0 && u.Name != "root" {
			findings = append(findings, Finding{
				Rule: "accounts.uid0_nonroot", Severity: SevSuspect, Technique: "T1136.001", Confidence: 80,
				Detail: fmt.Sprintf("account %q has UID 0 — a second superuser besides root (backdoor account?)", u.Name),
			})
		}
		if ev.Password == pwEmpty {
			findings = append(findings, Finding{
				Rule: "accounts.empty_password", Severity: SevSuspect, Technique: "T1078", Confidence: 75,
				Detail: fmt.Sprintf("account %q has no password set — it can log in with an empty password", u.Name),
			})
		}
		if system && hasLoginShell {
			serviceShells++
			f, fire, unknown := systemShellLoginFinding(u, ev)
			switch {
			case fire:
				findings = append(findings, f)
			case unknown:
				unverified = append(unverified, u.Name)
			}
		}
		if uidCount[u.UID] > 1 {
			findings = append(findings, Finding{
				Rule: "accounts.duplicate_uid", Severity: SevNotable, Technique: "T1078", Confidence: 45,
				Detail: fmt.Sprintf("UID %d is shared by more than one account (including %q) — a hidden alias to another user's privileges",
					u.UID, u.Name),
			})
		}
		res.Add(fields, findings...)
	}

	// Privileged group memberships.
	if g := readFileSafe("/etc/group"); g != nil {
		for _, grp := range parseGroup(g) {
			if !privilegedGroups[grp.Name] {
				continue
			}
			for _, m := range grp.Members {
				f := map[string]any{"kind": "group_member", "group": grp.Name, "gid": grp.GID, "member": m}
				var findings []Finding
				if grp.Name == "docker" || grp.Name == "lxd" {
					findings = append(findings, Finding{
						Rule: "accounts.root_equiv_group", Severity: SevNotable, Technique: "T1078.003", Confidence: 45,
						Detail: fmt.Sprintf("%q is in the %q group — effectively root (it can mount the host or run privileged containers)", m, grp.Name),
					})
				}
				res.Add(f, findings...)
			}
		}
	}

	res.SetMeta("platform", "linux")
	res.SetMeta("users", len(users))
	res.SetMeta("shadow_readable", shadow != nil)
	res.SetMeta("service_accounts_with_shell", serviceShells)
	if len(unverified) > 0 {
		res.SetMeta("service_accounts_unverified", unverified)
		res.SetMeta("service_accounts_note", "these service accounts have an interactive shell, but their password "+
			"state or SSH keys couldn't be read; run as root to check whether they can actually be logged into")
	}
	return res.Finish(), nil
}

// readSSHDConfigs returns the sshd configuration in the order sshd reads it: the
// sshd_config.d drop-ins (lexical order, as the stock Include does), then
// sshd_config. Unreadable or missing files are skipped.
func readSSHDConfigs() [][]byte {
	var out [][]byte
	dropins, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	sort.Strings(dropins)
	for _, p := range append(dropins, "/etc/ssh/sshd_config") {
		if b := readFileSafe(p); b != nil {
			out = append(out, b)
		}
	}
	return out
}

// readAuthorizedKeys totals the keys across the given authorized_keys files.
// unknown is true when a file couldn't be read for lack of permission and no keys
// were found elsewhere — "no keys" can't then be stated with confidence.
func readAuthorizedKeys(paths []string) (sshKeyCount, bool) {
	var total sshKeyCount
	denied := false
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				denied = true
			}
			continue // a missing file simply holds no keys
		}
		c := parseAuthorizedKeys(data)
		total.Total += c.Total
		total.Unrestricted += c.Unrestricted
	}
	return total, denied && total.Total == 0
}
