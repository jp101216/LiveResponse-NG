package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

const win = 15 * time.Minute

var local = netip.MustParseAddrPort("10.0.0.5:50000")

type stream struct {
	r  *rand.Rand
	ev []Event
}

func newStream() *stream { return &stream{r: rand.New(rand.NewSource(7))} }

func (s *stream) add(e Event) { s.ev = append(s.ev, e) }

func (s *stream) proc(pid uint32, image string) {
	s.add(Event{Time: t0, Kind: ProcSeen, PID: pid, Image: image})
}

func (s *stream) resolve(at time.Time, pid uint32, name string, ips ...string) {
	s.add(Event{Time: at, Kind: DNS, PID: pid, Query: name, QType: 1, Answers: ips})
}

// beacon connects every period ±jitter for the window, sending and receiving
// a roughly constant amount each time.
func (s *stream) beacon(pid uint32, dst string, period time.Duration, jitter float64) {
	remote := netip.MustParseAddrPort(dst)
	port := uint16(50000)
	for at := t0.Add(5 * time.Second); at.Before(t0.Add(win)); {
		port++
		src := netip.AddrPortFrom(local.Addr(), port)
		s.add(Event{Time: at, Kind: TCPConnect, PID: pid, Local: src, Remote: remote})
		s.add(Event{Time: at.Add(50 * time.Millisecond), Kind: TCPSend, PID: pid, Local: src, Remote: remote, Bytes: 420})
		s.add(Event{Time: at.Add(90 * time.Millisecond), Kind: TCPRecv, PID: pid, Local: src, Remote: remote, Bytes: 1200 + uint32(s.r.Intn(40))})
		s.add(Event{Time: at.Add(time.Second), Kind: TCPClose, PID: pid, Local: src, Remote: remote})
		at = at.Add(time.Duration(float64(period) * (1 + jitter*(2*s.r.Float64()-1))))
	}
}

func (s *stream) aggregate(self ...uint32) *Aggregator {
	a := NewAggregator(t0, Limits{}, self...)
	for _, e := range s.ev {
		a.Add(e)
	}
	a.Close(t0.Add(win))
	return a
}

func analyze(t *testing.T, a *Aggregator, opts Options) collector.Result {
	t.Helper()
	return Analyze(a, Window{Source: "test"}, opts)
}

func findings(r collector.Result, rule string) []collector.Finding {
	var out []collector.Finding
	for _, rec := range r.Records {
		for _, f := range rec.Findings {
			if f.Rule == rule {
				out = append(out, f)
			}
		}
	}
	return out
}

func recordWith(r collector.Result, rule string) *collector.Record {
	for i := range r.Records {
		for _, f := range r.Records[i].Findings {
			if f.Rule == rule {
				return &r.Records[i]
			}
		}
	}
	return nil
}

func TestBeaconFound(t *testing.T) {
	s := newStream()
	img := `C:\Users\alice\AppData\Local\Temp\updater.exe`
	s.proc(1200, img)
	s.resolve(t0.Add(time.Second), 1200, "c2.cdn-update.net", "::ffff:203.0.113.7")
	s.beacon(1200, "203.0.113.7:443", time.Minute, 0.1)
	r := analyze(t, s.aggregate(), Options{})
	fs := findings(r, RuleBeacon)
	if len(fs) != 1 {
		t.Fatalf("beacon findings = %d, want 1; records %v", len(fs), r.Records)
	}
	f := fs[0]
	if f.Technique != "T1071.001" || f.Severity != collector.SevCritical {
		t.Errorf("finding = %+v; want T1071.001, critical (score >= 0.8, unusual folder)", f)
	}
	rec := recordWith(r, RuleBeacon)
	if rec.Fields["destination"] != "cdn-update.net" || rec.Fields["remote_addr"] != "203.0.113.7" ||
		rec.Fields["transport"] != "https" || rec.Fields["image_path"] != img {
		t.Errorf("record fields = %v", rec.Fields)
	}
	if hosts, _ := rec.Fields["remote_hosts"].([]string); len(hosts) != 1 || hosts[0] != "c2.cdn-update.net" {
		t.Errorf("remote_hosts = %v", rec.Fields["remote_hosts"])
	}
	if rec.Fields["s_size"] == nil || rec.Fields["bytes_median"] == nil {
		t.Errorf("sizes weren't attributed to check-ins: %v", rec.Fields)
	}
	for _, want := range []string{"updater.exe", "cdn-update.net", "times over 15m0s, every 5", "unusual folder"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q lacks %q", f.Detail, want)
		}
	}
	// A periodic lookup by the same program isn't reported a second time.
	if len(findings(r, RuleDNSPeriodic)) != 0 {
		t.Error("the beacon's own lookups were reported again")
	}
}

func TestAllowlistedServiceIsRecordedNotFlagged(t *testing.T) {
	s := newStream()
	s.proc(900, `C:\Windows\System32\svchost.exe`)
	s.beacon(900, "198.51.100.20:443", time.Minute, 0)
	s.proc(901, `C:\Users\Public\svchost.exe`) // same name, wrong folder
	s.beacon(901, "198.51.100.21:443", time.Minute, 0)
	r := analyze(t, s.aggregate(), Options{})
	if fs := findings(r, RuleBeacon); len(fs) != 1 || !strings.Contains(fs[0].Detail, `Public`) {
		t.Fatalf("findings = %v; want only the copy outside System32", fs)
	}
	allowed := 0
	for _, rec := range r.Records {
		if rec.Fields["allowlisted"] == "Windows service host" {
			allowed++
		}
	}
	if allowed != 1 || r.Meta["flows_allowlisted"] != 1 {
		t.Errorf("allowlisted records = %d, meta %v", allowed, r.Meta["flows_allowlisted"])
	}
	// The snapshot finding it unsigned overrides the allowlist.
	snap := []collector.Result{{Collector: "processes", Records: []collector.Record{{Fields: map[string]any{
		"pid": uint32(900), "image_path": `C:\Windows\System32\svchost.exe`, "signature_state": "unsigned"}}}}}
	r = analyze(t, s.aggregate(), Options{Snapshot: snap})
	if len(findings(r, RuleBeacon)) != 2 {
		t.Error("an unsigned svchost was still excused")
	}
	// -allow-beacon names a program on any path.
	r = analyze(t, s.aggregate(), Options{Allow: NewAllowlist([]string{"SVCHOST.EXE"})})
	if len(findings(r, RuleBeacon)) != 0 {
		t.Error("-allow-beacon didn't excuse the named program")
	}
}

func TestRandomTrafficIsNotABeacon(t *testing.T) {
	s := newStream()
	s.proc(300, `C:\Program Files\Tool\tool.exe`)
	remote := netip.MustParseAddrPort("192.0.2.9:443")
	// Bursts of requests a few seconds apart, then idle: a person using an app.
	for at := t0; at.Before(t0.Add(win)); at = at.Add(time.Duration(s.r.ExpFloat64() * 4 * float64(time.Minute))) {
		for k := 3 + s.r.Intn(8); k > 0; k-- {
			at = at.Add(time.Duration((2 + 6*s.r.Float64()) * float64(time.Second)))
			s.add(Event{Time: at, Kind: TCPConnect, PID: 300, Local: local, Remote: remote})
		}
	}
	r := analyze(t, s.aggregate(), Options{})
	if len(findings(r, RuleBeacon)) != 0 {
		t.Fatalf("random arrivals flagged: %v", r.Records)
	}
}

func TestLocalAndSelfTrafficExcluded(t *testing.T) {
	s := newStream()
	s.proc(10, `C:\x\a.exe`)
	s.proc(11, `C:\x\lrng.exe`)
	s.beacon(10, "127.0.0.1:8080", time.Minute, 0)
	s.beacon(10, "[ff02::1]:5353", time.Minute, 0)
	s.beacon(11, "203.0.113.1:443", time.Minute, 0)
	r := analyze(t, s.aggregate(11), Options{})
	if len(r.Records) != 0 {
		t.Fatalf("records = %v", r.Records)
	}
	if r.Meta["excluded_local_destinations"].(int64) == 0 || r.Meta["dropped"].(map[string]int64)["self"] == 0 {
		t.Errorf("meta = %v", r.Meta)
	}
}

func TestRotatingBeacon(t *testing.T) {
	s := newStream()
	s.proc(500, `C:\ProgramData\svc\agent.exe`)
	dests := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.10:443"),
		netip.MustParseAddrPort("198.51.100.10:443"),
		netip.MustParseAddrPort("192.0.2.10:8080"),
		netip.MustParseAddrPort("192.0.2.11:53"),
	}
	i := 0
	for at := t0.Add(3 * time.Second); at.Before(t0.Add(win)); at = at.Add(time.Duration(60e9 * (0.95 + 0.1*s.r.Float64()))) {
		s.add(Event{Time: at, Kind: TCPConnect, PID: 500, Local: local, Remote: dests[i%len(dests)]})
		i++
	}
	r := analyze(t, s.aggregate(), Options{})
	if len(findings(r, RuleBeacon)) != 0 {
		t.Fatal("a single destination with under 6 check-ins was scored")
	}
	fs := findings(r, RuleBeaconRotating)
	if len(fs) != 1 || fs[0].Technique != "T1008" {
		t.Fatalf("rotating findings = %v", fs)
	}
	rec := recordWith(r, RuleBeaconRotating)
	if d, _ := rec.Fields["destinations"].([]string); len(d) != 4 {
		t.Errorf("destinations = %v", rec.Fields["destinations"])
	}
}

func TestQUICCheckInsCoalesce(t *testing.T) {
	s := newStream()
	s.proc(42, `C:\Users\bob\Downloads\quicky.exe`)
	remote := netip.MustParseAddrPort("203.0.113.44:443")
	for at := t0; at.Before(t0.Add(win)); at = at.Add(time.Minute) {
		for k := 0; k < 8; k++ { // a burst of datagrams is one check-in
			s.add(Event{Time: at.Add(time.Duration(k) * 100 * time.Millisecond), Kind: UDPSend, PID: 42, Local: local, Remote: remote, Bytes: 1200})
			s.add(Event{Time: at.Add(time.Duration(k)*100*time.Millisecond + 30*time.Millisecond), Kind: UDPRecv, PID: 42, Local: local, Remote: remote, Bytes: 900})
		}
	}
	r := analyze(t, s.aggregate(), Options{})
	rec := recordWith(r, RuleBeacon)
	if rec == nil || rec.Fields["transport"] != "quic" || rec.Fields["check_ins"] != 15 {
		t.Fatalf("QUIC beacon record = %v", rec)
	}
}

func TestPeriodicDNSAndTunnel(t *testing.T) {
	s := newStream()
	s.proc(70, `C:\Users\eve\AppData\Roaming\x\x.exe`)
	for at := t0.Add(2 * time.Second); at.Before(t0.Add(win)); at = at.Add(30 * time.Second) {
		s.add(Event{Time: at, Kind: DNS, PID: 70, Query: "check.example-cdn.com", QType: 1, Status: 9003})
	}
	s.proc(71, `C:\Users\eve\AppData\Local\Temp\t.exe`)
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	for k := 0; k < 120; k++ {
		label := make([]byte, 40)
		for i := range label {
			label[i] = letters[s.r.Intn(len(letters))]
		}
		s.add(Event{Time: t0.Add(time.Minute + time.Duration(k)*time.Second), Kind: DNS, PID: 71, Query: string(label) + ".t.exfil.org", QType: qtypeTXT})
	}
	r := analyze(t, s.aggregate(), Options{})
	if fs := findings(r, RuleDNSPeriodic); len(fs) != 1 || !strings.Contains(fs[0].Detail, "example-cdn.com") {
		t.Fatalf("periodic DNS = %v", fs)
	}
	if rec := recordWith(r, RuleDNSPeriodic); rec.Fields["failed_queries"] != 30 {
		t.Errorf("failed queries = %v", rec.Fields["failed_queries"])
	}
	fs := findings(r, RuleDNSTunnel)
	if len(fs) != 1 || fs[0].Severity != collector.SevCritical {
		t.Fatalf("tunnel = %v (want critical: the image is in a temporary folder)", fs)
	}
	rec := recordWith(r, RuleDNSTunnel)
	if rec.Fields["domain"] != "exfil.org" || rec.Fields["peak_unique_per_minute"].(int) < 30 {
		t.Errorf("tunnel record = %v", rec.Fields)
	}
}

func TestPeriodicSpawn(t *testing.T) {
	s := newStream()
	for i := 0; i < 8; i++ {
		at := t0.Add(time.Duration(i)*2*time.Minute + 10*time.Second)
		s.add(Event{Time: at, Kind: ProcStart, PID: uint32(2000 + i), PPID: 600, Image: `C:\Windows\System32\cmd.exe`, CmdLine: `cmd.exe  /c whoami`})
		s.add(Event{Time: at, Kind: ProcStart, PID: uint32(3000 + i), PPID: 4, Image: `C:\Windows\System32\conhost.exe`, CmdLine: `conhost.exe 0xffffffff`})
	}
	r := analyze(t, s.aggregate(), Options{})
	fs := findings(r, RulePeriodicSpawn)
	if len(fs) != 1 || fs[0].Technique != "T1053" || !strings.Contains(fs[0].Detail, "cmd.exe /c whoami started 8 times") {
		t.Fatalf("spawn findings = %v", fs)
	}
}

func TestSnapshotCorroboration(t *testing.T) {
	s := newStream()
	img := `C:\Program Files\Vendor\agent.exe`
	s.proc(800, img)
	s.beacon(800, "203.0.113.80:8443", time.Minute, 0.05)
	r := analyze(t, s.aggregate(), Options{})
	if f := findings(r, RuleBeacon); len(f) != 1 || f[0].Severity != collector.SevSuspect {
		t.Fatalf("without corroboration = %v; want suspect", f)
	}
	snap := []collector.Result{
		{Collector: "processes", Records: []collector.Record{{Fields: map[string]any{"pid": uint32(800), "image_path": img, "image_sha256": "ab12"}}}},
		{Collector: "memory", Records: []collector.Record{{Fields: map[string]any{"pid": float64(800), "image_path": img},
			Findings: []collector.Finding{{Rule: "memory.stack_unbacked", Severity: collector.SevSuspect}}}}},
	}
	intel := func(a netip.Addr) []string {
		if a == netip.MustParseAddr("203.0.113.80") {
			return []string{"hosting"}
		}
		return nil
	}
	r = analyze(t, s.aggregate(), Options{Snapshot: snap, Intel: intel})
	f := findings(r, RuleBeacon)
	if len(f) != 1 || f[0].Severity != collector.SevCritical {
		t.Fatalf("with corroboration = %v; want critical", f)
	}
	rec := recordWith(r, RuleBeacon)
	if rec.Fields["image_sha256"] != "ab12" || !strings.Contains(fmt.Sprint(rec.Fields["corroboration"]), "memory finding memory.stack_unbacked") ||
		!strings.Contains(f[0].Detail, "hosting infrastructure") {
		t.Errorf("record = %v; detail %q", rec.Fields, f[0].Detail)
	}
	// A reused PID running something else doesn't borrow the finding.
	snap[1].Records[0].Fields["image_path"] = `C:\other.exe`
	r = analyze(t, s.aggregate(), Options{Snapshot: snap})
	if fmt.Sprint(recordWith(r, RuleBeacon).Fields["corroboration"]) != "<nil>" {
		t.Error("corroborated from a different image under the same PID")
	}
}

func TestLimits(t *testing.T) {
	a := NewAggregator(t0, Limits{MaxFlows: 10, PerFlow: 8, MaxHeld: 1000})
	for i := 0; i < 40; i++ {
		remote := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 443)
		for k := 0; k <= i%5; k++ {
			a.Add(Event{Time: t0.Add(time.Duration(k) * time.Minute), Kind: TCPConnect, PID: 1, Remote: remote})
		}
	}
	if len(a.flows) > 10 || a.dropped["flows_evicted"] == 0 {
		t.Fatalf("flows %d, dropped %v", len(a.flows), a.dropped)
	}
	// The ring keeps the most recent PerFlow check-ins, in order.
	remote := netip.MustParseAddrPort("203.0.113.200:443")
	b := NewAggregator(t0, Limits{PerFlow: 8})
	for k := 0; k < 20; k++ {
		b.Add(Event{Time: t0.Add(time.Duration(k) * time.Minute), Kind: TCPConnect, PID: 2, Remote: remote})
	}
	ts, _ := b.flows[flowKey{2, remote, protoTCP}].checkIns()
	if len(ts) != 8 || !ts[0].Equal(t0.Add(12*time.Minute)) || !ts[7].Equal(t0.Add(19*time.Minute)) {
		t.Fatalf("ring = %v", ts)
	}
	c := NewAggregator(t0, Limits{MaxHeld: 5})
	for k := 0; k < 10; k++ {
		c.Add(Event{Time: t0.Add(time.Duration(k) * time.Minute), Kind: TCPConnect, PID: 3, Remote: remote})
	}
	if c.held != 5 || c.dropped["over_event_limit"] != 5 {
		t.Fatalf("held %d, dropped %v", c.held, c.dropped)
	}
}

func TestStreamRoundTrip(t *testing.T) {
	s := newStream()
	s.proc(1200, `C:\Users\alice\AppData\Local\Temp\updater.exe`)
	s.resolve(t0.Add(time.Second), 1200, "c2.cdn-update.net", "::ffff:203.0.113.7")
	s.beacon(1200, "203.0.113.7:443", time.Minute, 0.1)
	var buf bytes.Buffer
	w, err := NewStreamWriter(&buf, Header{Source: "etw", Host: "LAB", Started: t0, Duration: win.String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range s.ev {
		if err := w.Write(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(Trailer{Ended: t0.Add(win)}); err != nil {
		t.Fatal(err)
	}
	st, err := ReadStream(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if st.Header.Host != "LAB" || st.Trailer == nil || len(st.Events) != len(s.ev) {
		t.Fatalf("stream = %+v, %d events", st.Header, len(st.Events))
	}
	replay := NewAggregator(st.Header.Started, Limits{})
	for _, e := range st.Events {
		replay.Add(e)
	}
	replay.Close(st.Trailer.Ended)
	live := analyze(t, s.aggregate(), Options{})
	again := analyze(t, replay, Options{})
	lj, _ := json.Marshal(live.Records)
	aj, _ := json.Marshal(again.Records)
	if !bytes.Equal(lj, aj) {
		t.Fatalf("replay differs from live:\n%s\n%s", lj, aj)
	}

	bad := map[string]string{
		"empty":          "",
		"not a stream":   `{"hello":1}`,
		"wrong version":  `{"type":"lrng-watch","version":9,"source":"etw","started":"2026-11-22T08:00:00Z","duration":"1m"}`,
		"unknown kind":   header() + `{"t":"2026-11-22T08:00:01Z","k":"keylog","pid":1}`,
		"unknown field":  header() + `{"t":"2026-11-22T08:00:01Z","k":"dns","pid":1,"payload":"x"}`,
		"after end":      header() + `{"type":"end","ended":"2026-11-22T08:01:00Z","interrupted":false,"events":0}` + "\n" + `{"t":"2026-11-22T08:00:01Z","k":"dns","pid":1}`,
		"count mismatch": header() + `{"type":"end","ended":"2026-11-22T08:01:00Z","interrupted":false,"events":3}`,
		"before start":   header() + `{"t":"2026-11-22T07:00:00Z","k":"dns","pid":1}`,
	}
	for name, in := range bad {
		if _, err := ReadStream(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A crashed run's stream has no end line, and still reads.
	if st, err := ReadStream(strings.NewReader(header() + `{"t":"2026-11-22T08:00:01Z","k":"dns","pid":1,"q":"a.example"}`)); err != nil || st.Trailer != nil || len(st.Events) != 1 {
		t.Errorf("stream without an end line: %v %+v", err, st)
	}
}

func header() string {
	return `{"type":"lrng-watch","version":1,"source":"etw","started":"2026-11-22T08:00:00Z","duration":"1m"}` + "\n"
}

func TestRegistrable(t *testing.T) {
	for in, want := range map[string]string{
		"a.b.example.com.":         "example.com",
		"WWW.Example.CO.UK":        "example.co.uk",
		"x.y.example.com.au":       "example.com.au",
		"evil.duckdns.org":         "evil.duckdns.org",
		"a.evil.duckdns.org":       "evil.duckdns.org",
		"abc.ngrok-free.app":       "abc.ngrok-free.app",
		"localhost":                "localhost",
		"203.0.113.7":              "203.0.113.7",
		"7.113.0.203.in-addr.arpa": "in-addr.arpa",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
	if e := entropy("aaaa"); e != 0 {
		t.Errorf("entropy(aaaa) = %v", e)
	}
	if e := entropy("abcd"); e != 2 {
		t.Errorf("entropy(abcd) = %v", e)
	}
}
