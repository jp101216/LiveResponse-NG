package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// journaldCollector triages the systemd journal (journaldrules.go): it reads
// every journal file journald keeps — persistent under /var/log/journal and
// volatile under /run/log/journal, newest first, within a byte budget — with
// the dependency-free reader in journalfile.go, so nothing is shelled out to
// journalctl. Only security-relevant events become records; SSH failures are
// aggregated per source address. It only reads files, so the scan takes a
// root directory and is tested against fixture trees on any OS.
type journaldCollector struct{}

func (journaldCollector) Name() string        { return "journald" }
func (journaldCollector) Platforms() []string { return []string{"linux"} }

func (journaldCollector) Collect(ctx context.Context) (Result, error) {
	return scanJournald(ctx, "/"), nil
}

func init() { Register(func() Collector { return journaldCollector{} }) }

const (
	journalFileMax       = 512 << 20 // a larger file is read up to this
	journalTotalMax      = 2 << 30   // across all files
	journalMaxRecords    = 5000      // records without a finding stop being kept past this
	journalMaxSources    = 1000      // SSH source addresses tracked
	journalMaxFailTimes  = 20000     // failure times kept per address
	sshCorrelationWindow = 24 * time.Hour
)

// journalDirs are where journald keeps its files: persistent, then volatile.
var journalDirs = []string{"/var/log/journal", "/run/log/journal"}

// journalFiles lists journal files under root, newest first: each machine
// (and namespace) directory's *.journal and *.journal~ (a file journald set
// aside as dirty or corrupt).
func journalFiles(root string) []string {
	type f struct {
		path string
		mod  time.Time
	}
	var files []f
	for _, d := range journalDirs {
		subdirs, err := os.ReadDir(filepath.Join(root, d))
		if err != nil {
			continue
		}
		for _, sd := range subdirs {
			if !sd.IsDir() {
				continue
			}
			dir := d + "/" + sd.Name()
			entries, err := os.ReadDir(filepath.Join(root, dir))
			if err != nil {
				continue
			}
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() || !(strings.HasSuffix(name, ".journal") || strings.HasSuffix(name, ".journal~")) {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				files = append(files, f{dir + "/" + name, info.ModTime()})
			}
		}
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	out := make([]string, len(files))
	for i, x := range files {
		out[i] = x.path
	}
	return out
}

// readHead reads at most max bytes from the start of a file.
func readHead(path string, max int64) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return io.ReadAll(io.LimitReader(fh, max))
}

// sshSource accumulates the failed SSH attempts from one address.
type sshSource struct {
	attempts    int
	times       []time.Time
	users       map[string]bool
	failedPorts map[string]bool
	invalid     []string // ports of "Invalid user" lines, counted unless a "Failed" line shares the port
	first, last time.Time
}

type sshAccept struct {
	ev sshEvent
	l  jlog
}

// journalTriage turns journal entries into records.
type journalTriage struct {
	res       *Result
	sources   map[string]*sshSource
	accepts   []sshAccept
	kept      int
	dropped   int
	byKind    map[string]int
	truncated bool
}

func (t *journalTriage) record(kind string, l jlog, fields map[string]any, findings []Finding) {
	t.byKind[kind]++
	if len(findings) == 0 && t.kept >= journalMaxRecords {
		t.dropped++
		return
	}
	fields["kind"] = kind
	if !l.Time.IsZero() {
		fields["time"] = l.Time
	}
	if l.Host != "" {
		fields["host"] = l.Host
	}
	if l.Ident != "" {
		fields["identifier"] = l.Ident
	}
	if l.PID != "" {
		fields["pid"] = l.PID
	}
	if l.Transport != "" {
		fields["transport"] = l.Transport
	}
	fields["message"] = excerpt(l.Message, 400)
	t.res.Add(fields, findings...)
	t.kept++
}

// journalSource names the program a message claims to come from, for the
// programs whose messages are parsed: "" for anything else.
func journalSource(l jlog) string {
	ident := strings.ToLower(l.Ident)
	switch {
	case l.Transport == "kernel" || ident == "kernel":
		return "kernel"
	case ident == "sshd" || strings.HasPrefix(ident, "sshd-"):
		return "sshd"
	case ident == "sudo", ident == "su":
		return ident
	case accountTools[ident]:
		return "account"
	case ident == "cron" || ident == "crond":
		return "cron"
	}
	return ""
}

// journalSourceTrusted checks a message's claimed source against what journald
// records itself. SYSLOG_IDENTIFIER is chosen by the sender — any user can run
// `logger -t sshd "Accepted password for root from 203.0.113.9 port 1 ssh2"` —
// but _TRANSPORT, _UID and _COMM come from journald and the kernel. Kernel
// messages arrive on the kernel transport only; the others run as root when
// they log (setuid or root daemons), under their own process name. A field the
// entry doesn't carry (journald couldn't read /proc in time, or an imported
// journal) isn't held against it.
func journalSourceTrusted(src string, l jlog) bool {
	if src == "kernel" {
		return l.Transport == "kernel" || l.Transport == ""
	}
	if l.Transport == "kernel" || (l.UID != "" && l.UID != "0") {
		return false
	}
	if l.Comm == "" {
		return true
	}
	comm := strings.ToLower(l.Comm)
	switch src {
	case "sshd":
		return strings.HasPrefix(comm, "sshd")
	case "cron":
		return comm == "cron" || comm == "crond"
	case "account":
		return accountTools[comm]
	default:
		return comm == src
	}
}

func (t *journalTriage) add(l jlog) {
	if l.Message == "" {
		return
	}
	src := journalSource(l)
	if src == "" {
		return
	}
	if !journalSourceTrusted(src, l) {
		t.spoofed(src, l)
		return
	}
	switch src {
	case "kernel":
		if !strings.Contains(l.Message, "module verification failed") && !strings.Contains(l.Message, "bpf_probe_write_user") {
			return
		}
		if ev, ok := parseKernel(l); ok {
			f := map[string]any{"event": ev.Event}
			if ev.Module != "" {
				f["module"] = ev.Module
			}
			if ev.Comm != "" {
				f["comm"], f["comm_pid"] = ev.Comm, ev.PID
			}
			t.record("kernel", l, f, judgeKernel(ev))
		}
	case "sshd":
		ev, ok := parseSSH(l.Message)
		if !ok {
			return
		}
		if ev.Kind == "accepted" {
			t.accepts = append(t.accepts, sshAccept{ev, l})
			return
		}
		t.sshFailure(ev, l.Time)
	case "sudo":
		if ev, ok := parseSudo(l.Message); ok {
			f := map[string]any{"user": ev.User, "run_as": ev.RunAs, "command": ev.Command}
			if ev.TTY != "" {
				f["tty"] = ev.TTY
			}
			if ev.PWD != "" {
				f["pwd"] = ev.PWD
			}
			if ev.Reason != "" {
				f["reason"] = ev.Reason
			}
			t.record("sudo", l, f, judgeSudo(ev))
		}
	case "su":
		if ev, ok := parseSu(l.Message); ok {
			f := map[string]any{"from_user": ev.From, "to_user": ev.To, "success": ev.OK}
			if ev.TTY != "" {
				f["tty"] = ev.TTY
			}
			t.record("su", l, f, judgeSu(ev))
		}
	case "account":
		if ev, ok := parseAccount(l.Message); ok {
			f := map[string]any{"action": ev.Action}
			for k, v := range map[string]string{"user": ev.User, "uid": ev.UID, "group": ev.Group, "home": ev.Home, "shell": ev.Shell, "by": ev.By} {
				if v != "" {
					f[k] = v
				}
			}
			t.record("account", l, f, judgeAccount(ev))
		}
	case "cron":
		if user, cmd, ok := parseCron(l.Message); ok {
			if fs := analyzeUnixCommandLine("cron job of "+user, "", cmd); len(fs) > 0 {
				t.record("cron", l, map[string]any{"user": user, "command": cmd}, fs)
			}
		}
	}
}

// spoofed records a message that names sshd, sudo, su, an account tool, cron
// or the kernel as its source while journald saw another sender. Its content
// isn't parsed — it is the forger's text — but planting such lines is itself
// worth an analyst's look: fake logons and sudo runs mislead an investigation.
func (t *journalTriage) spoofed(src string, l jlog) {
	sender := "a process"
	if l.Comm != "" {
		sender = fmt.Sprintf("%q", l.Comm)
	}
	if l.UID != "" {
		sender += " (uid " + l.UID + ")"
	}
	via := ""
	if l.Transport != "" {
		via = " over the " + l.Transport + " transport"
	}
	f := map[string]any{"claimed_source": src}
	if l.Comm != "" {
		f["sender_comm"] = l.Comm
	}
	if l.UID != "" {
		f["sender_uid"] = l.UID
	}
	t.record("spoofed", l, f, []Finding{{
		Rule: "defense.log_spoofing", Severity: SevNotable, Technique: "T1036", Confidence: 50,
		Detail: fmt.Sprintf("a journal message claims to come from %s (identifier %q) but was sent by %s%s — "+
			"forged log lines (fake logons, sudo runs or account changes) planted to mislead an investigation: %s",
			src, l.Ident, sender, via, excerpt(l.Message, 160)),
	}})
}

// accountTools are the shadow-utils and adduser programs that log account
// and group changes.
var accountTools = map[string]bool{
	"useradd": true, "usermod": true, "userdel": true, "groupadd": true, "groupmod": true,
	"groupdel": true, "gpasswd": true, "passwd": true, "chpasswd": true, "adduser": true,
	"deluser": true, "newusers": true, "chage": true,
}

func (t *journalTriage) sshFailure(ev sshEvent, at time.Time) {
	s := t.sources[ev.Addr]
	if s == nil {
		if len(t.sources) >= journalMaxSources {
			t.truncated = true
			return
		}
		s = &sshSource{users: map[string]bool{}, failedPorts: map[string]bool{}}
		t.sources[ev.Addr] = s
	}
	if ev.User != "" && len(s.users) < 10 {
		s.users[ev.User] = true
	}
	if ev.Kind == "invalid" {
		s.invalid = append(s.invalid, ev.Port)
		return
	}
	s.attempts++
	s.failedPorts[ev.Port] = true
	if !at.IsZero() {
		if len(s.times) < journalMaxFailTimes {
			s.times = append(s.times, at)
		}
		if s.first.IsZero() || at.Before(s.first) {
			s.first = at
		}
		if at.After(s.last) {
			s.last = at
		}
	}
}

// finish emits the SSH records: one per address with failures, and one per
// successful logon, judged against the failures from its address in the day
// before it.
func (t *journalTriage) finish() {
	for _, addr := range sortedKeys(t.sources) {
		s := t.sources[addr]
		for _, p := range s.invalid {
			if p == "" || !s.failedPorts[p] {
				s.attempts++ // an attempt that never reached a password prompt
			}
		}
		users := sortedKeys(s.users)
		f := map[string]any{"kind": "ssh_failed_logons", "source": addr, "attempts": s.attempts, "users": users, "external": externalAddr(addr)}
		if !s.first.IsZero() {
			f["first_attempt"], f["last_attempt"] = s.first, s.last
		}
		t.byKind["ssh_failed_logons"]++
		t.res.Add(f, judgeSSHFailures(addr, s.attempts, users)...)
	}
	for _, a := range t.accepts {
		fails := 0
		if s := t.sources[a.ev.Addr]; s != nil {
			for _, ft := range s.times {
				if ft.Before(a.l.Time) && a.l.Time.Sub(ft) <= sshCorrelationWindow {
					fails++
				}
			}
		}
		f := map[string]any{"user": a.ev.User, "method": a.ev.Method, "source": a.ev.Addr, "port": a.ev.Port, "external": externalAddr(a.ev.Addr)}
		if fails > 0 {
			f["failures_before"] = fails
		}
		t.record("ssh_login", a.l, f, judgeSSHAccepted(a.ev, fails))
	}
}

func scanJournald(ctx context.Context, root string) Result {
	res := NewResult("journald")
	t := &journalTriage{res: res, sources: map[string]*sshSource{}, byKind: map[string]int{}}
	files := journalFiles(root)
	if len(files) == 0 {
		res.SetMeta("note", "no journal files under /var/log/journal or /run/log/journal (journald not in use, or storage=none)")
		return res.Finish()
	}
	var (
		total, scanned, undecoded int
		budget                    int64 = journalTotalMax
		fileMeta                  []map[string]any
		oldest, newest            time.Time
	)
	for _, f := range files {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		if budget <= 0 {
			res.SetMeta("budget_note", "older journal files were not read: the byte budget was spent on newer ones")
			break
		}
		data, err := readHead(filepath.Join(root, f), min(journalFileMax, budget))
		if err != nil {
			res.Fail(f + ": " + err.Error())
			continue
		}
		budget -= int64(len(data))
		j, err := openJournal(data)
		if err != nil {
			res.Fail(f + ": " + err.Error())
			continue
		}
		n := 0
		j.entries(func(e *journalEntry) bool {
			n++
			undecoded += e.Undecoded
			l := jlogFrom(e)
			if !l.Time.IsZero() {
				if oldest.IsZero() || l.Time.Before(oldest) {
					oldest = l.Time
				}
				if l.Time.After(newest) {
					newest = l.Time
				}
			}
			t.add(l)
			return ctx.Err() == nil
		})
		scanned += n
		total += len(data)
		states := map[byte]string{0: "offline", 1: "online", 2: "archived"}
		fileMeta = append(fileMeta, map[string]any{"path": f, "state": states[j.state], "bytes": len(data), "entries": n, "compact": j.compact})
	}
	t.finish()

	res.SetMeta("files", fileMeta)
	res.SetMeta("entries_scanned", scanned)
	res.SetMeta("bytes_read", total)
	res.SetMeta("events", t.byKind)
	if undecoded > 0 {
		res.SetMeta("undecoded_fields", undecoded)
		res.SetMeta("undecoded_note", "fields journald compressed with xz, or past the reader's size limits (16 MiB a field, 128 MiB a file), aren't decoded; journalctl shows them")
	}
	if !oldest.IsZero() {
		res.SetMeta("covers_from", oldest)
		res.SetMeta("covers_to", newest)
	}
	if t.dropped > 0 {
		res.SetMeta("records_dropped", t.dropped)
	}
	if t.truncated {
		res.SetMeta("ssh_sources_truncated", true)
	}
	return res.Finish()
}
