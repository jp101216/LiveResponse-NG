//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
	"adm": true, "docker": true, "lxd": true, "incus-admin": true,
	"disk": true, "shadow": true, "libvirt": true,
}

// rootEquivGroups are the groups whose members are root in all but name, and
// how.
var rootEquivGroups = map[string]string{
	"docker":      "it can mount the host or run privileged containers",
	"lxd":         "it can mount the host or run privileged containers",
	"incus-admin": "it can mount the host or run privileged containers",
	"libvirt":     "it can start a virtual machine with the host's disk or root directory attached",
	"disk":        "it can read and write the raw disks (debugfs, dd): every file, /etc/shadow included, whatever its permissions",
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

		ev := loginEvidence{Password: effectivePasswordState(u, shadow)}
		if ev.Password != "" {
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
		if u.Passwd != "x" && ev.Password == pwUsable {
			findings = append(findings, Finding{
				Rule: "accounts.passwd_hash", Severity: SevSuspect, Technique: "T1136.001", Confidence: 65,
				Detail: fmt.Sprintf("account %q keeps its password hash in world-readable /etc/passwd instead of /etc/shadow — "+
					"how a backdoor account is added by hand (openssl passwd), and any local user can crack it offline", u.Name),
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

	// Privileged group memberships, listed in /etc/group or held as a
	// user's primary group (the GID column of /etc/passwd, which /etc/group
	// doesn't repeat).
	if g := readFileSafe("/etc/group"); g != nil {
		for _, m := range privilegedMemberships(parseGroup(g), users) {
			res.Add(m.fields(), m.findings()...)
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

// groupMembership is one account's membership of a privileged group.
type groupMembership struct {
	group   string
	gid     int
	member  string
	uid     int // -1 when the member isn't in /etc/passwd
	primary bool
}

// privilegedMemberships lists the members of privilegedGroups: those
// /etc/group names, then the accounts whose primary group it is, each once.
func privilegedMemberships(groups []groupEntry, users []passwdEntry) []groupMembership {
	uidOf := map[string]int{}
	for _, u := range users {
		if _, ok := uidOf[u.Name]; !ok {
			uidOf[u.Name] = u.UID
		}
	}
	var out []groupMembership
	seen := map[string]bool{}
	add := func(m groupMembership) {
		if key := m.group + "\x00" + m.member; !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}
	for _, grp := range groups {
		if !privilegedGroups[grp.Name] {
			continue
		}
		for _, name := range grp.Members {
			uid, ok := uidOf[name]
			if !ok {
				uid = -1
			}
			add(groupMembership{group: grp.Name, gid: grp.GID, member: name, uid: uid})
		}
		for _, u := range users {
			// A group's own namesake account (root in root, a docker
			// account in docker) is how distributions set groups up.
			if u.GID == grp.GID && u.Name != grp.Name {
				add(groupMembership{group: grp.Name, gid: grp.GID, member: u.Name, uid: u.UID, primary: true})
			}
		}
	}
	return out
}

func (m groupMembership) fields() map[string]any {
	f := map[string]any{"kind": "group_member", "group": m.group, "gid": m.gid, "member": m.member}
	if m.primary {
		f["primary"] = true
	}
	return f
}

func (m groupMembership) findings() []Finding {
	how := "is in"
	if m.primary {
		how = "has as its primary group"
	}
	if why, ok := rootEquivGroups[m.group]; ok {
		f := Finding{Rule: "accounts.root_equiv_group", Severity: SevNotable, Technique: "T1078.003", Confidence: 45,
			Detail: fmt.Sprintf("%q %s the %q group — effectively root (%s)", m.member, how, m.group, why)}
		if m.primary {
			// Nobody puts a person in docker or disk through the GID column
			// by accident: useradd -g does, and so does a hand edit.
			f.Severity, f.Confidence = SevSuspect, 60
			f.Detail += "; a primary group doesn't show in /etc/group's member list, so `getent group` won't list it"
		}
		return []Finding{f}
	}
	if m.group == "shadow" && m.uid >= 1000 {
		return []Finding{{Rule: "accounts.shadow_group", Severity: SevNotable, Technique: "T1003.008", Confidence: 50,
			Detail: fmt.Sprintf("%q %s the \"shadow\" group: it can read /etc/shadow, every account's password hash. Only "+
				"system programs (unix_chkpwd, chage) need that", m.member, how)}}
	}
	if m.primary && m.uid > 0 && (m.group == "root" || m.group == "sudo" || m.group == "wheel" || m.group == "admin") {
		return []Finding{{Rule: "accounts.privileged_primary_group", Severity: SevNotable, Technique: "T1078.003", Confidence: 45,
			Detail: fmt.Sprintf("%q has the %q group (GID %d) as its primary group, set in /etc/passwd where `getent group` and "+
				"group-membership reviews don't look", m.member, m.group, m.gid)}}
	}
	return nil
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

// authorizedKeysMax bounds one authorized_keys read (a user-owned file).
const authorizedKeysMax = 4 << 20

// readAuthorizedKeys totals the keys across the given authorized_keys files.
// unknown is true when a file couldn't be read for lack of permission and no keys
// were found elsewhere — "no keys" can't then be stated with confidence.
func readAuthorizedKeys(paths []string) (sshKeyCount, bool) {
	var total sshKeyCount
	denied := false
	for _, p := range paths {
		data, _, err := readRegular(p, authorizedKeysMax)
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
