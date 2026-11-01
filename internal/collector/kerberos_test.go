package collector

import (
	"strings"
	"testing"
	"time"
)

func TestJudgeTickets(t *testing.T) {
	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	alice := logonSession{LogonID: 0x3a7f12, User: "alice", Domain: "CORP", LogonType: 2}
	tgt := func(client string, life time.Duration, etype int32) kerbTicket {
		return kerbTicket{Client: client, ClientRealm: "CORP.LOCAL", Server: "krbtgt/CORP.LOCAL", ServerRealm: "CORP.LOCAL",
			Start: now, End: now.Add(life), Renew: now.Add(7 * 24 * time.Hour), EncryptionType: etype, Flags: 0x40e10000}
	}
	none(t, "ordinary TGT", judgeTicket(alice, tgt("alice", 10*time.Hour, 18), true))
	f := only(t, "golden", judgeTicket(alice, tgt("alice", 10*365*24*time.Hour, 18), true), "cred.golden_ticket", SevCritical)
	if !strings.Contains(f.Detail, "10.0 years") || !strings.Contains(f.Detail, "0x3a7f12") {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "long policy", judgeTicket(alice, tgt("alice", 36*time.Hour, 18), true), "cred.golden_ticket", SevSuspect)
	only(t, "slightly long", judgeTicket(alice, tgt("alice", 12*time.Hour, 18), true), "cred.golden_ticket", SevNotable)
	only(t, "rc4 in an AES domain", judgeTicket(alice, tgt("alice", 10*time.Hour, 23), true), "cred.rc4_tgt", SevSuspect)
	only(t, "rc4 domain", judgeTicket(alice, tgt("alice", 10*time.Hour, 23), false), "cred.rc4_tgt", SevNotable)
	f = only(t, "ptt", judgeTicket(alice, tgt("Administrator", 10*time.Hour, 18), true), "cred.pass_the_ticket", SevSuspect)
	if !strings.Contains(f.Detail, `CORP\alice`) || !strings.Contains(f.Detail, "Administrator") {
		t.Errorf("detail: %s", f.Detail)
	}
	netonly := alice
	netonly.LogonType = 9
	none(t, "runas /netonly", judgeTicket(netonly, tgt("Administrator", 10*time.Hour, 18), true))
	system := logonSession{LogonID: 0x3e7, User: "WS01$", Domain: "CORP", LogonType: 0}
	none(t, "computer account", judgeTicket(system, tgt("WS01$", 10*time.Hour, 18), true))
	// Virtual accounts reach the network as the computer.
	dwm := logonSession{LogonID: 0x1a2b3, User: "DWM-1", Domain: "Window Manager", LogonType: 2}
	none(t, "virtual account", judgeTicket(dwm, tgt("WS01$", 10*time.Hour, 18), true))
	pool := logonSession{LogonID: 0x1a2b4, User: "DefaultAppPool", Domain: "IIS APPPOOL", LogonType: 5}
	none(t, "app pool", judgeTicket(pool, tgt("WS01$", 10*time.Hour, 18), true))
	// A computer's TGT in a person's session is still another account's
	// (a relayed DC certificate's ticket imported with Rubeus /ptt).
	only(t, "machine TGT in a user session", judgeTicket(alice, tgt("DC01$", 10*time.Hour, 18), true), "cred.pass_the_ticket", SevSuspect)
	only(t, "user TGT in a virtual account", judgeTicket(dwm, tgt("Administrator", 10*time.Hour, 18), true), "cred.pass_the_ticket", SevSuspect)
	// A service ticket for another account (constrained delegation, S4U) is
	// not judged as pass-the-ticket.
	svc := kerbTicket{Client: "bob", Server: "cifs/fs01.corp.local", Start: now, End: now.Add(10 * time.Hour), EncryptionType: 18}
	none(t, "service ticket", judgeTicket(alice, svc, true))
	backwards := svc
	backwards.End = now.Add(-time.Hour)
	only(t, "backwards", judgeTicket(alice, backwards, true), "cred.kerberos_ticket_anomaly", SevNotable)

	if accountPart(`CORP\Alice`) != "alice" || accountPart("alice@CORP.LOCAL") != "alice" {
		t.Error("accountPart")
	}
	if got := strings.Join(flagNames(0x40e10000), ","); got != "forwardable,renewable,initial,pre_authent,name_canonicalize" {
		t.Errorf("flags: %s", got)
	}
}

func TestKerberosReport(t *testing.T) {
	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	res := NewResult("kerberos")
	kerberosReport(res, []kerbSessionTickets{
		{Session: logonSession{LogonID: 0x99, User: "bob", Domain: "CORP", LogonType: 10}, Tickets: []kerbTicket{
			{Client: "bob", Server: "krbtgt/CORP.LOCAL", Start: now, End: now.Add(10 * time.Hour), EncryptionType: 23},
		}},
		{Session: logonSession{LogonID: 0x3e7, User: "WS01$", Domain: "CORP"}, Tickets: []kerbTicket{
			{Client: "WS01$", Server: "krbtgt/CORP.LOCAL", Start: now, End: now.Add(10 * time.Hour), EncryptionType: 18},
			{Client: "WS01$", Server: "ldap/dc01.corp.local", Start: now, End: now.Add(10 * time.Hour), EncryptionType: 18},
		}},
	})
	got := res.Finish()
	if len(got.Records) != 3 || got.Meta["tickets"] != 3 || got.Meta["sessions_read"] != 2 {
		t.Fatalf("%+v", got)
	}
	// Sessions in logon-id order; bob's RC4 TGT stands out against the AES ones.
	if got.Records[0].Fields["logon_id"] != "0x99" || got.Records[2].Fields["logon_id"] != "0x3e7" ||
		hasFinding(got.Records[0].Findings, "cred.rc4_tgt") == nil || got.Records[0].Findings[0].Severity != SevSuspect ||
		got.Records[0].Fields["encryption"] != "RC4-HMAC" || got.Records[2].Fields["tgt"] != false {
		t.Errorf("records: %+v", got.Records)
	}
}
