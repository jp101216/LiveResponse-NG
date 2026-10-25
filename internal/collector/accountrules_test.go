package collector

import (
	"testing"
	"time"
)

func TestAccountRecord(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	f, fs := accountRecord(localUser{
		Name: "alice", Priv: 2, RID: 1001, PasswordAge: 3600, LastLogon: uint32(now.Add(-time.Hour).Unix()),
		AcctExpires: timeqForever, NumLogons: 12, Detailed: true,
	}, false, now)
	if len(fs) != 0 {
		t.Fatalf("ordinary admin flagged: %v", keys(rulesOf(fs)))
	}
	if f["password_last_set"] != now.Add(-time.Hour) || f["last_logon"] != now.Add(-time.Hour) || f["rid"] != uint32(1001) {
		t.Fatalf("fields %+v", f)
	}
	if _, ok := f["account_expires"]; ok {
		t.Fatal("TIMEQ_FOREVER reported as an expiry date")
	}

	cases := []struct {
		u      localUser
		hidden bool
		want   string
	}{
		{localUser{Name: "svc$", Priv: 2, RID: 1005, Detailed: true}, false, "accounts.dollar_suffix_user"},
		{localUser{Name: "support", Priv: 2, RID: 1006, Detailed: true}, true, "accounts.hidden_from_logon_screen"},
		{localUser{Name: "Guest", Priv: 0, RID: 501, Detailed: true}, false, "accounts.guest_enabled"},
		{localUser{Name: "kiosk", Priv: 1, RID: 1007, Flags: ufPasswdNotreqd, Detailed: true}, false, "accounts.password_not_required"},
	}
	for _, c := range cases {
		_, fs := accountRecord(c.u, c.hidden, now)
		if _, ok := rulesOf(fs)[c.want]; !ok {
			t.Errorf("%s: %s missing (got %v)", c.u.Name, c.want, keys(rulesOf(fs)))
		}
	}
	// Disabled accounts don't raise the "enabled" findings.
	if _, fs := accountRecord(localUser{Name: "Guest", Priv: 0, RID: 501, Flags: ufAccountDisable, Detailed: true}, false, now); len(fs) != 0 {
		t.Errorf("disabled guest flagged: %v", keys(rulesOf(fs)))
	}
	if sidUsageName(6) != "deleted_account" || sidUsageName(0) != "" || sidUsageName(99) != "" {
		t.Error("sidUsageName")
	}
}
