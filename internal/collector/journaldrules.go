package collector

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Linux log triage over the systemd journal (journalfile.go reads it): the
// messages that matter in an investigation — SSH logons and brute force, sudo
// and su, account and group changes, cron jobs, and the kernel's own warnings
// about unsigned modules and user-memory-writing eBPF programs — parsed into
// records and judged, with commands run through the shared Unix command-line
// analytics. Rule ids match the Windows event-log rules where the meaning is
// the same (persistence.account_created, persistence.admin_group_add). No
// build tag: pure text handling, unit-tested on any OS.

// jlog is one journal entry, reduced to what the rules read.
type jlog struct {
	Time      time.Time
	Ident     string // SYSLOG_IDENTIFIER, else _COMM
	Transport string // _TRANSPORT: kernel, syslog, journal, stdout, ...
	Message   string
	PID       string
	Host      string
}

func jlogFrom(e *journalEntry) jlog {
	l := jlog{
		Ident:     e.Get("SYSLOG_IDENTIFIER"),
		Transport: e.Get("_TRANSPORT"),
		Message:   e.Get("MESSAGE"),
		PID:       e.Get("_PID"),
		Host:      e.Get("_HOSTNAME"),
	}
	if l.Ident == "" {
		l.Ident = e.Get("_COMM")
	}
	if l.PID == "" {
		l.PID = e.Get("SYSLOG_PID")
	}
	if e.Realtime > 0 {
		l.Time = time.UnixMicro(int64(e.Realtime)).UTC()
	}
	return l
}

// --- sshd ------------------------------------------------------------------

var (
	sshFailedRe   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	sshInvalidRe  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	sshAcceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
)

type sshEvent struct {
	Kind    string // failed, invalid, accepted
	Method  string
	User    string
	Addr    string
	Port    string
	Invalid bool
}

func parseSSH(msg string) (sshEvent, bool) {
	if m := sshFailedRe.FindStringSubmatch(msg); m != nil {
		return sshEvent{Kind: "failed", Method: m[1], Invalid: m[2] != "", User: m[3], Addr: m[4], Port: m[5]}, true
	}
	if m := sshAcceptedRe.FindStringSubmatch(msg); m != nil {
		return sshEvent{Kind: "accepted", Method: m[1], User: m[2], Addr: m[3], Port: m[4]}, true
	}
	if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
		return sshEvent{Kind: "invalid", User: m[1], Addr: m[2], Port: m[3], Invalid: true}, true
	}
	return sshEvent{}, false
}

// externalAddr reports a routable public address.
func externalAddr(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && aidetect.PublicAddr(ip)
}

// sshBruteThreshold is the failed attempts from one address that read as
// password guessing.
const sshBruteThreshold = 10

// judgeSSHAccepted grades a successful SSH logon. failsBefore is how many
// failed attempts came from the same address in the day before it.
func judgeSSHAccepted(ev sshEvent, failsBefore int) []Finding {
	var out []Finding
	if failsBefore >= sshBruteThreshold {
		out = append(out, Finding{Rule: "logon.ssh_bruteforce_success", Severity: SevCritical, Technique: "T1110", Confidence: 80,
			Detail: fmt.Sprintf("SSH logon as %q from %s succeeded after %d failed attempt(s) from that address: password guessing that worked",
				ev.User, ev.Addr, failsBefore)})
	}
	if externalAddr(ev.Addr) {
		sev, conf := SevNotable, 40
		what := "an external address"
		if ev.User == "root" && ev.Method == "password" {
			sev, conf, what = SevSuspect, 60, "an external address, as root with a password"
		}
		out = append(out, Finding{Rule: "logon.ssh_external", Severity: sev, Technique: "T1021.004", Confidence: conf,
			Detail: fmt.Sprintf("SSH logon as %q (%s) from %s, %s", ev.User, ev.Method, ev.Addr, what)})
	}
	return out
}

// judgeSSHFailures grades the failed attempts from one address.
func judgeSSHFailures(addr string, attempts int, users []string) []Finding {
	if attempts < sshBruteThreshold {
		return nil
	}
	where := "an internal address"
	if externalAddr(addr) {
		where = "an external address"
	}
	return []Finding{{Rule: "logon.ssh_bruteforce", Severity: SevNotable, Technique: "T1110.001", Confidence: 55,
		Detail: fmt.Sprintf("%d failed SSH logon attempt(s) from %s (%s), trying %s", attempts, addr, where, strings.Join(users, ", "))}}
}

// --- sudo and su -----------------------------------------------------------

// sudoEvent is one sudo log line:
//
//	alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c '...'
//	mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
type sudoEvent struct {
	User, Reason, TTY, PWD, RunAs, Command string
}

func parseSudo(msg string) (sudoEvent, bool) {
	user, rest, ok := strings.Cut(strings.TrimSpace(msg), " : ")
	if !ok || strings.ContainsAny(user, " \t") {
		return sudoEvent{}, false
	}
	ci := strings.Index(rest, "COMMAND=")
	if ci < 0 {
		return sudoEvent{}, false
	}
	ev := sudoEvent{User: user, Command: strings.TrimSpace(rest[ci+len("COMMAND="):])}
	for _, part := range strings.Split(rest[:ci], " ; ") {
		part = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(part), ";"))
		k, v, kv := strings.Cut(part, "=")
		switch {
		case !kv || strings.ContainsAny(k, " \t"):
			if part != "" {
				ev.Reason = part
			}
		case k == "TTY":
			ev.TTY = v
		case k == "PWD":
			ev.PWD = v
		case k == "USER":
			ev.RunAs = v
		}
	}
	return ev, true
}

func judgeSudo(ev sudoEvent) []Finding {
	var out []Finding
	lr := strings.ToLower(ev.Reason)
	switch {
	case strings.Contains(lr, "not in sudoers"), strings.Contains(lr, "command not allowed"):
		out = append(out, Finding{Rule: "privesc.sudo_denied", Severity: SevNotable, Technique: "T1548.003", Confidence: 45,
			Detail: fmt.Sprintf("sudo refused %q (%s) running as %s: %s", ev.User, ev.Reason, ev.RunAs, excerpt(ev.Command, 160))})
	case strings.Contains(lr, "incorrect password"):
		out = append(out, Finding{Rule: "privesc.sudo_auth_failure", Severity: SevInfo, Technique: "T1548.003", Confidence: 25,
			Detail: fmt.Sprintf("sudo by %q: %s", ev.User, ev.Reason)})
	}
	return mergeFindings(out, analyzeUnixCommandLine(fmt.Sprintf("sudo by %s as %s", ev.User, ev.RunAs), "", ev.Command)...)
}

var (
	suFailedRe = regexp.MustCompile(`^FAILED SU \(to (\S+)\) (\S+) on (\S+)`)
	suOKRe     = regexp.MustCompile(`^\(to (\S+)\) (\S+) on (\S+)`)
	suFailed2  = regexp.MustCompile(`^FAILED su for (\S+) by (\S+)`)
	suOK2      = regexp.MustCompile(`^Successful su for (\S+) by (\S+)`)
)

type suEvent struct {
	To, From, TTY string
	OK            bool
}

func parseSu(msg string) (suEvent, bool) {
	if m := suFailedRe.FindStringSubmatch(msg); m != nil {
		return suEvent{To: m[1], From: m[2], TTY: m[3]}, true
	}
	if m := suOKRe.FindStringSubmatch(msg); m != nil {
		return suEvent{To: m[1], From: m[2], TTY: m[3], OK: true}, true
	}
	if m := suFailed2.FindStringSubmatch(msg); m != nil {
		return suEvent{To: m[1], From: m[2]}, true
	}
	if m := suOK2.FindStringSubmatch(msg); m != nil {
		return suEvent{To: m[1], From: m[2], OK: true}, true
	}
	return suEvent{}, false
}

func judgeSu(ev suEvent) []Finding {
	if ev.OK {
		return nil
	}
	return []Finding{{Rule: "privesc.su_failed", Severity: SevNotable, Technique: "T1548", Confidence: 40,
		Detail: fmt.Sprintf("failed su from %q to %q", ev.From, ev.To)}}
}

// --- accounts and groups ---------------------------------------------------

var (
	userAddRe    = regexp.MustCompile(`new user: name=([^,]+), UID=(\d+), GID=(\d+), home=([^,]*), shell=([^,]*)`)
	userDelRe    = regexp.MustCompile(`delete user '([^']+)'`)
	groupAddRe   = regexp.MustCompile(`new group: name=([^,]+), GID=(\d+)`)
	addToGroupRe = regexp.MustCompile(`add '([^']+)' to group '([^']+)'`)
	gpasswdAddRe = regexp.MustCompile(`user (\S+) added by (\S+) to group (\S+)`)
	pwChangedRe  = regexp.MustCompile(`password changed for (\S+)`)
	pwChanged2Re = regexp.MustCompile(`password for '([^']+)' changed by '([^']+)'`)
)

// rootEquivalentGroups grant root, or a short path to it.
var rootEquivalentGroups = map[string]bool{
	"root": true, "sudo": true, "wheel": true, "admin": true, "docker": true,
	"lxd": true, "disk": true, "shadow": true, "libvirt": true,
}

// accountEvent is one account or group change.
type accountEvent struct {
	Action string // user_created, user_deleted, group_created, group_member_added, password_changed
	User   string
	UID    string
	Group  string
	Home   string
	Shell  string
	By     string
}

func parseAccount(msg string) (accountEvent, bool) {
	// usermod logs each group change twice, for /etc/group and /etc/gshadow;
	// the "shadow group" line mirrors the other and is skipped.
	if strings.Contains(msg, " to shadow group ") {
		return accountEvent{}, false
	}
	if m := userAddRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "user_created", User: m[1], UID: m[2], Home: m[4], Shell: strings.TrimSpace(m[5])}, true
	}
	if m := addToGroupRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "group_member_added", User: m[1], Group: m[2]}, true
	}
	if m := gpasswdAddRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "group_member_added", User: m[1], By: m[2], Group: m[3]}, true
	}
	if m := userDelRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "user_deleted", User: m[1]}, true
	}
	if m := groupAddRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "group_created", Group: m[1]}, true
	}
	if m := pwChanged2Re.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "password_changed", User: m[1], By: m[2]}, true
	}
	if m := pwChangedRe.FindStringSubmatch(msg); m != nil {
		return accountEvent{Action: "password_changed", User: m[1]}, true
	}
	return accountEvent{}, false
}

func judgeAccount(ev accountEvent) []Finding {
	switch ev.Action {
	case "user_created":
		if uid, _ := strconv.Atoi(ev.UID); ev.UID != "" && uid == 0 && ev.User != "root" {
			return []Finding{{Rule: "persistence.account_created", Severity: SevCritical, Technique: "T1136.001", Confidence: 85,
				Detail: fmt.Sprintf("account %q was created with UID 0: a second root", ev.User)}}
		}
		return []Finding{{Rule: "persistence.account_created", Severity: SevNotable, Technique: "T1136.001", Confidence: 50,
			Detail: fmt.Sprintf("account %q was created (UID %s, shell %s)", ev.User, ev.UID, ev.Shell)}}
	case "group_member_added":
		if rootEquivalentGroups[ev.Group] {
			return []Finding{{Rule: "persistence.admin_group_add", Severity: SevSuspect, Technique: "T1098", Confidence: 70,
				Detail: fmt.Sprintf("%q was added to group %q, which grants root or a short path to it", ev.User, ev.Group)}}
		}
	case "password_changed":
		if ev.User == "root" {
			return []Finding{{Rule: "persistence.password_changed", Severity: SevNotable, Technique: "T1098", Confidence: 35,
				Detail: "the root password was changed"}}
		}
	}
	return nil
}

// --- cron and the kernel ---------------------------------------------------

var cronCmdRe = regexp.MustCompile(`^\((\S+)\) CMD \((.*)\)$`)

func parseCron(msg string) (user, cmd string, ok bool) {
	m := cronCmdRe.FindStringSubmatch(strings.TrimSpace(msg))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

var (
	kmodUnsignedRe = regexp.MustCompile(`(?:^(\S+): )?module verification failed: signature and/or required key missing`)
	bpfWriteUserRe = regexp.MustCompile(`(\S+)\[(\d+)\] is installing a program with bpf_probe_write_user helper`)
)

// kernelEvent is a kernel warning the rules act on.
type kernelEvent struct {
	Event  string // unsigned_module, bpf_write_user
	Module string
	Comm   string
	PID    string
}

func parseKernel(l jlog) (kernelEvent, bool) {
	if m := kmodUnsignedRe.FindStringSubmatch(l.Message); m != nil {
		mod := m[1]
		if mod == "" && l.Ident != "kernel" {
			mod = l.Ident // journald splits "evilmod: ..." into the identifier
		}
		return kernelEvent{Event: "unsigned_module", Module: mod}, true
	}
	if m := bpfWriteUserRe.FindStringSubmatch(l.Message); m != nil {
		return kernelEvent{Event: "bpf_write_user", Comm: m[1], PID: m[2]}, true
	}
	return kernelEvent{}, false
}

func judgeKernel(ev kernelEvent) []Finding {
	switch ev.Event {
	case "unsigned_module":
		return []Finding{{Rule: "persistence.kmod_unsigned_loaded", Severity: SevNotable, Technique: "T1547.006", Confidence: 50,
			Detail: fmt.Sprintf("the kernel loaded module %q without a valid signature (from the kernel log; the module may since have been unloaded or hidden)", ev.Module)}}
	case "bpf_write_user":
		return []Finding{{Rule: "persistence.ebpf_write_user", Severity: SevSuspect, Technique: "T1014", Confidence: 75,
			Detail: fmt.Sprintf("%s[%s] loaded an eBPF program that writes into user-space memory (bpf_probe_write_user), per the kernel log; it may since have been unloaded", ev.Comm, ev.PID)}}
	}
	return nil
}
