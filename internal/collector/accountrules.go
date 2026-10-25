package collector

import (
	"fmt"
	"strings"
	"time"
)

// Local-account heuristics. No build tag: pure logic, unit-tested on any OS.

// localUser is one local account as NetUserEnum reports it.
type localUser struct {
	Name, FullName, Comment string
	Priv, Flags             uint32
	PasswordAge             uint32 // seconds since the password was set
	LastLogon               uint32 // seconds since 1970; 0 = never/unknown
	AcctExpires             uint32 // seconds since 1970; 0xFFFFFFFF = never
	BadPwCount, NumLogons   uint32
	RID                     uint32
	PasswordExpired         bool
	Detailed                bool // level-3 fields are valid
}

const (
	timeqForever       = 0xFFFFFFFF // TIMEQ_FOREVER: the account never expires
	ufAccountDisable   = 0x00002
	ufLockout          = 0x00010
	ufPasswdNotreqd    = 0x00020
	ufDontExpirePasswd = 0x10000
)

// accountRecord turns a local user into a record and its findings. hidden is
// whether Winlogon's SpecialAccounts list hides it from the sign-in screen.
func accountRecord(u localUser, hidden bool, now time.Time) (map[string]any, []Finding) {
	disabled := u.Flags&ufAccountDisable != 0
	fields := map[string]any{
		"kind":                   "user",
		"name":                   u.Name,
		"privilege":              privName(u.Priv),
		"disabled":               disabled,
		"locked_out":             u.Flags&ufLockout != 0,
		"password_not_required":  u.Flags&ufPasswdNotreqd != 0,
		"password_never_expires": u.Flags&ufDontExpirePasswd != 0,
	}
	if u.Comment != "" {
		fields["comment"] = u.Comment
	}
	if hidden {
		fields["hidden_from_logon_screen"] = true
	}
	if u.Detailed {
		if u.FullName != "" {
			fields["full_name"] = u.FullName
		}
		fields["rid"] = u.RID
		fields["password_last_set"] = now.Add(-time.Duration(u.PasswordAge) * time.Second).UTC().Truncate(time.Second)
		if u.LastLogon != 0 {
			fields["last_logon"] = time.Unix(int64(u.LastLogon), 0).UTC()
		}
		fields["logon_count"] = u.NumLogons
		fields["bad_password_count"] = u.BadPwCount
		if u.AcctExpires != timeqForever && u.AcctExpires != 0 {
			fields["account_expires"] = time.Unix(int64(u.AcctExpires), 0).UTC()
		}
		if u.PasswordExpired {
			fields["password_expired"] = true
		}
	}

	var out []Finding
	label := fmt.Sprintf("local account %q", u.Name)
	if !disabled && strings.HasSuffix(u.Name, "$") {
		out = append(out, Finding{
			Rule: "accounts.dollar_suffix_user", Severity: SevSuspect, Technique: "T1564.002", Confidence: 70,
			Detail: label + " ends in '$' like a computer account, which hides it from `net user` — a known way to plant a hidden user",
		})
	}
	if hidden {
		sev, conf := SevSuspect, 65
		if disabled {
			sev, conf = SevNotable, 35
		}
		out = append(out, Finding{
			Rule: "accounts.hidden_from_logon_screen", Severity: sev, Technique: "T1564.002", Confidence: conf,
			Detail: label + " is hidden from the sign-in screen (Winlogon\\SpecialAccounts\\UserList)",
		})
	}
	if !disabled && (u.RID == 501 || u.Priv == 0) && (u.Detailed || u.Priv == 0) {
		out = append(out, Finding{
			Rule: "accounts.guest_enabled", Severity: SevNotable, Technique: "T1078.001", Confidence: 45,
			Detail: label + " is the Guest account (or has guest privilege) and is enabled",
		})
	}
	if !disabled && u.Flags&ufPasswdNotreqd != 0 {
		out = append(out, Finding{
			Rule: "accounts.password_not_required", Severity: SevNotable, Technique: "T1078.003", Confidence: 40,
			Detail: label + " is enabled and flagged PASSWD_NOTREQD: it may have an empty password",
		})
	}
	return fields, out
}

// sidUsageName names a SID_NAME_USE value.
func sidUsageName(u uint32) string {
	names := [...]string{1: "user", 2: "group", 3: "domain", 4: "alias", 5: "well_known_group",
		6: "deleted_account", 7: "invalid", 8: "unknown", 9: "computer", 10: "label", 11: "logon_session"}
	if int(u) < len(names) && names[u] != "" {
		return names[u]
	}
	return ""
}
