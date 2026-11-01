package collector

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// kerberos.go — the Kerberos tickets cached in each logon session, judged by
// what forged and stolen tickets look like: a ticket-granting ticket (TGT)
// valid far longer than a domain hands out (Mimikatz's golden tickets last ten
// years by default), one encrypted with RC4 in a domain that otherwise uses
// AES (forged from krbtgt's NT hash, or requested with a stolen one:
// overpass-the-hash), one for a different account than the session's own
// (pass-the-ticket), and times that make no sense.
//
// Only ticket metadata is read (the ticket cache list LSA gives klist); no
// ticket or session key is ever retrieved. Reading every logon session's
// cache needs the agent to run as SYSTEM; otherwise only the agent's own
// session is read, and meta says so.

type kerberosCollector struct{}

func (kerberosCollector) Name() string           { return "kerberos" }
func (kerberosCollector) Platforms() []string    { return []string{"windows"} }
func (kerberosCollector) Timeout() time.Duration { return time.Minute }

func (kerberosCollector) Collect(ctx context.Context) (Result, error) {
	return collectKerberos(ctx)
}

func init() { Register(kerberosCollector{}) }

// logonSession is a logon session as LSA describes it.
type logonSession struct {
	LogonID   uint64
	User      string
	Domain    string
	LogonType uint32
	Package   string
}

// kerbTicket is one cached ticket's metadata.
type kerbTicket struct {
	Client, ClientRealm string
	Server, ServerRealm string
	Start, End, Renew   time.Time
	EncryptionType      int32
	Flags               uint32
}

// Domain policy defaults: a TGT lasts 10 hours and renews for 7 days.
const (
	kerbMaxTicketAge = 10 * time.Hour
	kerbMaxRenewAge  = 7 * 24 * time.Hour
	kerbSkew         = 10 * time.Minute
)

// kerbEtypes names the encryption types.
var kerbEtypes = map[int32]string{1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 17: "AES128-CTS-HMAC-SHA1-96",
	18: "AES256-CTS-HMAC-SHA1-96", 23: "RC4-HMAC", 24: "RC4-HMAC-EXP", -128: "RC4-HMAC-OLD"}

// kerbFlagNames names the ticket flags (bit 31 first, as Kerberos numbers them).
var kerbFlagNames = []struct {
	bit  uint32
	name string
}{
	{0x40000000, "forwardable"}, {0x20000000, "forwarded"}, {0x10000000, "proxiable"}, {0x08000000, "proxy"},
	{0x04000000, "may_postdate"}, {0x02000000, "postdated"}, {0x01000000, "invalid"}, {0x00800000, "renewable"},
	{0x00400000, "initial"}, {0x00200000, "pre_authent"}, {0x00100000, "hw_authent"}, {0x00040000, "ok_as_delegate"},
	{0x00010000, "name_canonicalize"},
}

func etypeName(e int32) string {
	if n, ok := kerbEtypes[e]; ok {
		return n
	}
	return fmt.Sprintf("etype %d", e)
}

func flagNames(f uint32) []string {
	var out []string
	for _, n := range kerbFlagNames {
		if f&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

// isTGT reports whether a ticket is a ticket-granting ticket (krbtgt/REALM).
func (t kerbTicket) isTGT() bool {
	return strings.HasPrefix(strings.ToLower(t.Server), "krbtgt/") || strings.EqualFold(t.Server, "krbtgt")
}

func (t kerbTicket) rc4() bool {
	return t.EncryptionType == 23 || t.EncryptionType == 24 || t.EncryptionType == -128
}

// machineIdentityDomains are the authorities of virtual and service accounts
// (DWM-1, UMFD-0, NT SERVICE\..., IIS APPPOOL\..., NETWORK SERVICE), whose
// logon sessions hold the computer account's tickets.
var machineIdentityDomains = set("window manager", "font driver host", "nt service", "iis apppool", "nt virtual machine",
	"nt authority")

// accountPart is the account in "user", "user@REALM" or "DOMAIN\user", lower-cased.
func accountPart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

// judgeTicket judges one ticket in its session. aesSeen says whether any
// ticket on the host is AES-encrypted (so RC4 stands out).
func judgeTicket(s logonSession, t kerbTicket, aesSeen bool) []Finding {
	var out []Finding
	where := fmt.Sprintf("logon session 0x%x (%s)", s.LogonID, sessionLabel(s))
	life := t.End.Sub(t.Start)
	if !t.Start.IsZero() && !t.End.IsZero() && t.End.Before(t.Start) {
		out = append(out, Finding{Rule: "cred.kerberos_ticket_anomaly", Severity: SevNotable, Technique: "T1558", Confidence: 45,
			Detail: fmt.Sprintf("%s holds a ticket for %s that ends before it starts (%s to %s): times written by hand, not by a KDC",
				where, t.Server, t.Start.UTC().Format(time.RFC3339), t.End.UTC().Format(time.RFC3339))})
	}
	if t.isTGT() {
		switch {
		case life > 7*24*time.Hour:
			out = append(out, Finding{Rule: "cred.golden_ticket", Severity: SevCritical, Technique: "T1558.001", Confidence: 85,
				Detail: fmt.Sprintf("%s holds a TGT for %s valid for %s (%s to %s); a domain issues them for 10 hours by default. "+
					"A ticket-granting ticket that lives for days or years was forged with krbtgt's key: a golden ticket (Mimikatz "+
					"kerberos::golden defaults to ten years)", where, t.Client, roundDuration(life),
					t.Start.UTC().Format(time.RFC3339), t.End.UTC().Format(time.RFC3339))})
		case life > 24*time.Hour:
			out = append(out, Finding{Rule: "cred.golden_ticket", Severity: SevSuspect, Technique: "T1558.001", Confidence: 60,
				Detail: fmt.Sprintf("%s holds a TGT for %s valid for %s; a domain issues them for 10 hours by default. A domain "+
					"policy that long is rare; a forged ticket (golden ticket) is the other explanation", where, t.Client, roundDuration(life))})
		case life > kerbMaxTicketAge+kerbSkew:
			out = append(out, Finding{Rule: "cred.golden_ticket", Severity: SevNotable, Technique: "T1558.001", Confidence: 35,
				Detail: fmt.Sprintf("%s holds a TGT for %s valid for %s, longer than the 10-hour default: the domain's policy, or a "+
					"forged ticket", where, t.Client, roundDuration(life))})
		}
		if t.rc4() {
			f := Finding{Rule: "cred.rc4_tgt", Severity: SevNotable, Technique: "T1550.002", Confidence: 35,
				Detail: fmt.Sprintf("%s holds an RC4-encrypted TGT for %s: requested with an NT hash rather than a password "+
					"(overpass-the-hash: Mimikatz sekurlsa::pth, Rubeus asktgt /rc4) or forged with krbtgt's NT hash, unless the "+
					"domain still uses RC4", where, t.Client)}
			if aesSeen {
				f.Severity, f.Confidence = SevSuspect, 60
				f.Detail += "; other tickets here are AES-encrypted, so this domain doesn't need RC4"
			}
			out = append(out, f)
		}
		// Pass-the-ticket: another account's TGT in this session. A
		// NewCredentials session (runas /netonly) holds the other
		// credentials' tickets by design, and virtual and service accounts
		// reach the network as the computer and keep its tickets.
		if s.LogonType != 9 && s.User != "" && t.Client != "" && accountPart(t.Client) != accountPart(s.User) &&
			!(strings.HasSuffix(t.Client, "$") && machineIdentityDomains[strings.ToLower(s.Domain)]) {
			out = append(out, Finding{Rule: "cred.pass_the_ticket", Severity: SevSuspect, Technique: "T1550.003", Confidence: 70,
				Detail: fmt.Sprintf("%s, signed in as %s, holds a TGT for %s: a ticket imported into a session it wasn't issued to "+
					"(pass-the-ticket: Mimikatz kerberos::ptt, Rubeus ptt)", where, sessionLabel(s), t.Client)})
		}
	}
	return out
}

// roundDuration renders a ticket lifetime the way a person would say it.
func roundDuration(d time.Duration) string {
	switch {
	case d >= 365*24*time.Hour:
		return fmt.Sprintf("%.1f years", d.Hours()/(365*24))
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	default:
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
}

func sessionLabel(s logonSession) string {
	user := s.User
	if s.Domain != "" && user != "" {
		user = s.Domain + `\` + user
	}
	return firstNonEmpty(user, "an unnamed account")
}

// kerbSessionTickets is one session and its tickets.
type kerbSessionTickets struct {
	Session logonSession
	Tickets []kerbTicket
}

// kerberosReport adds one record per ticket, judged.
func kerberosReport(res *Result, sessions []kerbSessionTickets) {
	aesSeen := false
	for _, st := range sessions {
		for _, t := range st.Tickets {
			if t.EncryptionType == 17 || t.EncryptionType == 18 {
				aesSeen = true
			}
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Session.LogonID < sessions[j].Session.LogonID })
	tickets := 0
	for _, st := range sessions {
		for _, t := range st.Tickets {
			tickets++
			f := map[string]any{
				"logon_id": fmt.Sprintf("0x%x", st.Session.LogonID), "session_user": sessionLabel(st.Session),
				"logon_type": st.Session.LogonType, "client": t.Client, "client_realm": t.ClientRealm,
				"server": t.Server, "server_realm": t.ServerRealm, "encryption": etypeName(t.EncryptionType),
				"flags": flagNames(t.Flags), "tgt": t.isTGT(),
			}
			for k, v := range map[string]time.Time{"start": t.Start, "end": t.End, "renew_until": t.Renew} {
				if !v.IsZero() {
					f[k] = v.UTC()
				}
			}
			res.Add(f, judgeTicket(st.Session, t, aesSeen)...)
		}
	}
	res.SetMeta("sessions_read", len(sessions))
	res.SetMeta("tickets", tickets)
}
