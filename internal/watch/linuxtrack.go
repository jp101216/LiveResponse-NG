package watch

import (
	"net/netip"
	"strconv"
	"time"
)

// Linux's source sees packets, not sockets: a packet socket shows a
// connection starting or a datagram leaving, sock_diag names the socket
// behind an address pair (its inode), and /proc/<pid>/fd says which process
// holds that inode. A tracker turns packets into Events with that
// attribution. It keeps no system state of its own, so it is tested on any OS.

// sockOwners is how a tracker finds the process behind a socket.
type sockOwners interface {
	// inode is the socket for a local/remote pair; 0 when no open socket
	// has it (closed, or in TIME_WAIT).
	inode(proto uint8, local, remote netip.AddrPort) uint32
	// fast is a cheap owner lookup: sockets already seen, then processes
	// started or active lately.
	fast(inode uint32) (uint32, bool)
	// learned notes that pid owned a socket, so fast lookups try it early.
	learned(pid uint32)
	// requestScan asks for a scan of every process's sockets; its result
	// arrives through tracker.scanned.
	requestScan()
	// describe returns a proc event for pid at t if the stream doesn't name
	// that process yet (a fork that never exec'd, say).
	describe(pid uint32, t time.Time) (Event, bool)
}

const (
	trackCacheTTL    = 30 * time.Second
	trackMaxCache    = 1 << 16
	trackMaxPending  = 1 << 16 // events waiting for a full scan
	trackPendingMax  = 10 * time.Second
	dnsAnswerWait    = 5 * time.Second
	dnsForwardWindow = 5 * time.Second
	dnsClaimWindow   = 10 * time.Second
	trackMaxQueries  = 8192
	trackMaxOrphans  = 4096
	trackMaxAsked    = 16384
)

type sockKey struct {
	proto         uint8
	local, remote netip.AddrPort
}

type cachedOwner struct {
	pid  uint32
	last time.Time
}

// job is everything waiting on one socket's owner.
type job struct {
	inode uint32
	first time.Time
	evs   []Event
	qs    []*dnsQ
}

type dnsKey struct {
	client, server netip.AddrPort
	id             uint16
}

// dnsQ is one lookup, emitted once both its answer (or timeout) and its
// process are known.
type dnsQ struct {
	at       time.Time
	name     string
	qtype    uint16
	pid      uint32
	pidKnown bool
	answered bool
	status   uint32
	answers  []string
	held     time.Time // answered with no process: waiting for a connection to an answer
	done     bool
}

type tracker struct {
	o     sockOwners
	emit  func(Event)
	local map[netip.Addr]bool // this host's addresses: a resolver on one is local

	cache     map[sockKey]cachedOwner
	pending   map[sockKey]*job
	npending  int
	queries   map[dnsKey]*dnsQ
	asked     map[string]time.Time // name|qtype asked of a local resolver -> when
	orphans   map[netip.Addr][]*dnsQ
	norphans  int
	lastPrune time.Time
	n         map[string]int64
}

func newTracker(o sockOwners, emit func(Event), local []netip.Addr) *tracker {
	t := &tracker{o: o, emit: emit, local: map[netip.Addr]bool{},
		cache: map[sockKey]cachedOwner{}, pending: map[sockKey]*job{}, queries: map[dnsKey]*dnsQ{},
		asked: map[string]time.Time{}, orphans: map[netip.Addr][]*dnsQ{}, n: map[string]int64{}}
	for _, a := range local {
		t.local[a.Unmap()] = true
	}
	return t
}

// packet handles one captured packet: outgoing says the host sent it.
func (t *tracker) packet(b []byte, at time.Time, outgoing bool) {
	p, ok := parsePacket(b)
	if !ok {
		t.n["packets_unparsed"]++
		return
	}
	t.n["packets"]++
	switch p.proto {
	case ipProtoTCP:
		if !outgoing || !p.syn || p.ack || !routableAddr(p.dst.Addr()) {
			return
		}
		t.attribute(sockKey{ipProtoTCP, p.src, p.dst}, at,
			&Event{Time: at, Kind: TCPConnect, Local: p.src, Remote: p.dst}, nil)
	case ipProtoUDP:
		if !outgoing {
			if p.src.Port() == 53 {
				t.answer(p)
			}
			return
		}
		var q *dnsQ
		if p.dst.Port() == 53 {
			if m, ok := parseDNS(p.payload); ok && !m.response && m.name != "" {
				if t.forwarded(m, p.dst.Addr(), at) {
					t.n["dns_forwarded"]++
					return
				}
				q = t.query(m, p, at)
			}
		}
		var ev *Event
		if routableAddr(p.dst.Addr()) {
			ev = &Event{Time: at, Kind: UDPSend, Local: p.src, Remote: p.dst, Bytes: uint32(p.size)}
		}
		if ev != nil || q != nil {
			t.attribute(sockKey{ipProtoUDP, p.src, p.dst}, at, ev, q)
		}
	}
}

func (t *tracker) isLocal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || t.local[a]
}

func askKey(name string, qtype uint16) string {
	return name + "|" + strconv.Itoa(int(qtype))
}

// forwarded is true for a local resolver passing on a lookup a program
// asked it moments ago: the program's own query already counts.
func (t *tracker) forwarded(m dnsMessage, server netip.Addr, at time.Time) bool {
	if t.isLocal(server) {
		return false
	}
	when, ok := t.asked[askKey(normName(m.name), m.qtype)]
	d := at.Sub(when)
	return ok && d > -time.Second && d <= dnsForwardWindow
}

func (t *tracker) query(m dnsMessage, p packet, at time.Time) *dnsQ {
	key := dnsKey{p.src, p.dst, m.id}
	if t.queries[key] != nil {
		return nil // a retry of a lookup already counted
	}
	if len(t.queries) >= trackMaxQueries {
		t.n["dns_queries_dropped"]++
		return nil
	}
	q := &dnsQ{at: at, name: normName(m.name), qtype: m.qtype}
	t.queries[key] = q
	if t.isLocal(p.dst.Addr()) {
		if len(t.asked) >= trackMaxAsked {
			t.asked = map[string]time.Time{}
		}
		t.asked[askKey(q.name, q.qtype)] = at
	}
	return q
}

func (t *tracker) answer(p packet) {
	m, ok := parseDNS(p.payload)
	if !ok || !m.response {
		return
	}
	key := dnsKey{client: p.dst, server: p.src, id: m.id}
	q := t.queries[key]
	if q == nil || normName(m.name) != q.name {
		return // a forwarder's upstream answer, or not ours
	}
	delete(t.queries, key)
	q.answered, q.status, q.answers = true, dnsStatus(m.rcode), m.answers
	t.settle(q, time.Time{})
}

// attribute finds the process behind key, now or after the next full scan.
func (t *tracker) attribute(key sockKey, at time.Time, ev *Event, q *dnsQ) {
	if c, ok := t.cache[key]; ok && at.Sub(c.last) < trackCacheTTL {
		if at.After(c.last) {
			c.last = at
			t.cache[key] = c
		}
		t.resolve(ev, q, c.pid, "cached", at)
		return
	}
	if j := t.pending[key]; j != nil {
		t.hold(j, ev, q, at)
		return
	}
	inode := t.o.inode(key.proto, key.local, key.remote)
	if inode == 0 {
		t.resolve(ev, q, 0, "no_socket", at)
		return
	}
	if pid, ok := t.o.fast(inode); ok {
		t.remember(key, pid, at)
		t.resolve(ev, q, pid, "socket_scan_fast", at)
		return
	}
	j := &job{inode: inode, first: at}
	t.pending[key] = j
	t.hold(j, ev, q, at)
	t.o.requestScan()
}

func (t *tracker) hold(j *job, ev *Event, q *dnsQ, at time.Time) {
	if t.npending >= trackMaxPending {
		t.resolve(ev, q, 0, "queue_full", at)
		return
	}
	if ev != nil {
		j.evs = append(j.evs, *ev)
		t.npending++
	}
	if q != nil {
		j.qs = append(j.qs, q)
		t.npending++
	}
}

func (t *tracker) remember(key sockKey, pid uint32, at time.Time) {
	if len(t.cache) >= trackMaxCache {
		t.cache = map[sockKey]cachedOwner{}
	}
	t.cache[key] = cachedOwner{pid, at}
}

// resolve emits what waited on a socket now its process is known (0: not found).
func (t *tracker) resolve(ev *Event, q *dnsQ, pid uint32, how string, at time.Time) {
	if pid != 0 {
		t.n["attributed_"+how]++
		t.o.learned(pid)
		if pe, ok := t.o.describe(pid, at); ok {
			t.emit(pe)
		}
	} else {
		t.n["unattributed_"+how]++
	}
	if ev != nil {
		ev.PID = pid
		t.emitNet(*ev)
		if pid != 0 {
			t.claim(ev.Remote.Addr(), pid, ev.Time)
		}
	}
	if q != nil {
		q.pid, q.pidKnown = pid, true
		t.settle(q, at)
	}
}

func (t *tracker) emitNet(e Event) {
	if e.PID == 0 {
		t.n["unattributed_events"]++
	}
	t.emit(e)
}

// settle emits a lookup once it is answered and its process known. A lookup
// with answers but no process waits a while for a connection to one of its
// addresses, which names the program that asked.
func (t *tracker) settle(q *dnsQ, now time.Time) {
	if q.done || !q.answered || !q.pidKnown {
		return
	}
	if q.pid == 0 && q.held.IsZero() && len(q.answers) > 0 && t.norphans < trackMaxOrphans {
		q.held = q.at
		if !now.IsZero() && now.After(q.at) {
			q.held = now
		}
		n := 0
		for _, s := range q.answers {
			if a, err := netip.ParseAddr(s); err == nil {
				t.orphans[a.Unmap()] = append(t.orphans[a.Unmap()], q)
				n++
			}
		}
		if n > 0 {
			t.norphans++
			return
		}
		q.held = time.Time{}
	}
	t.finish(q)
}

func (t *tracker) finish(q *dnsQ) {
	if q.done {
		return
	}
	q.done = true
	if !q.held.IsZero() {
		t.norphans--
	}
	t.emitNet(Event{Time: q.at, Kind: DNS, PID: q.pid, Query: q.name, QType: q.qtype, Status: q.status, Answers: q.answers})
}

// claim names the program behind unattributed lookups that answered addr.
func (t *tracker) claim(addr netip.Addr, pid uint32, at time.Time) {
	addr = addr.Unmap()
	list := t.orphans[addr]
	if len(list) == 0 {
		return
	}
	delete(t.orphans, addr)
	for _, q := range list {
		if q.done || at.Before(q.at.Add(-time.Second)) || at.Sub(q.at) > dnsClaimWindow+dnsAnswerWait {
			continue
		}
		q.pid = pid
		t.n["attributed_dns_answer_match"]++
		t.finish(q)
	}
}

// scanned resolves what waited for a full scan that began at started.
func (t *tracker) scanned(owner func(inode uint32) (uint32, bool), started time.Time) {
	for key, j := range t.pending {
		if pid, ok := owner(j.inode); ok {
			t.remember(key, pid, j.first)
			t.release(key, j, pid, "socket_scan_full")
		} else if j.first.Before(started) {
			t.release(key, j, 0, "owner_exited") // the socket closed before the scan reached it
		}
	}
	if len(t.pending) > 0 {
		t.o.requestScan()
	}
}

func (t *tracker) release(key sockKey, j *job, pid uint32, how string) {
	delete(t.pending, key)
	t.npending -= len(j.evs) + len(j.qs)
	for i := range j.evs {
		t.resolve(&j.evs[i], nil, pid, how, j.evs[i].Time)
	}
	for _, q := range j.qs {
		t.resolve(nil, q, pid, how, q.at)
	}
}

// tick times out lookups, held answers and waits.
func (t *tracker) tick(now time.Time) {
	for key, q := range t.queries {
		if now.Sub(q.at) >= dnsAnswerWait {
			delete(t.queries, key)
			q.answered, q.status = true, dnsTimeoutStatus
			t.n["dns_unanswered"]++
			t.settle(q, now)
		}
	}
	for addr, list := range t.orphans {
		keep := list[:0]
		for _, q := range list {
			switch {
			case q.done:
			case now.Sub(q.held) >= dnsClaimWindow:
				t.finish(q)
			default:
				keep = append(keep, q)
			}
		}
		if len(keep) == 0 {
			delete(t.orphans, addr)
		} else {
			t.orphans[addr] = keep
		}
	}
	for k, when := range t.asked {
		if now.Sub(when) > dnsForwardWindow {
			delete(t.asked, k)
		}
	}
	for key, j := range t.pending {
		if now.Sub(j.first) >= trackPendingMax {
			t.release(key, j, 0, "scan_timeout")
		}
	}
	if now.Sub(t.lastPrune) >= trackCacheTTL {
		for k, c := range t.cache {
			if now.Sub(c.last) >= trackCacheTTL {
				delete(t.cache, k)
			}
		}
		t.lastPrune = now
	}
}

// waiting is how many events wait for a full scan.
func (t *tracker) waiting() int { return t.npending }

// flush emits everything still waiting when the window closes.
func (t *tracker) flush(now time.Time) {
	for key, j := range t.pending {
		t.release(key, j, 0, "window_closed")
	}
	for key, q := range t.queries {
		delete(t.queries, key)
		q.answered, q.status = true, dnsTimeoutStatus
		t.n["dns_unanswered"]++
		t.settle(q, now)
	}
	for addr, list := range t.orphans {
		for _, q := range list {
			t.finish(q)
		}
		delete(t.orphans, addr)
	}
}

// scanBudget paces full socket scans: one may start whenever the budget is
// above zero, each spends its own running time, and the budget refills at
// share of wall time, up to burst.
type scanBudget struct {
	share  float64
	burst  time.Duration
	tokens time.Duration
	at     time.Time
}

func newScanBudget(share float64, burst time.Duration, now time.Time) *scanBudget {
	return &scanBudget{share: share, burst: burst, tokens: burst, at: now}
}

func (b *scanBudget) refill(now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(b.burst, b.tokens+time.Duration(float64(d)*b.share))
		b.at = now
	}
}

// ready says whether a scan may start now.
func (b *scanBudget) ready(now time.Time) bool {
	b.refill(now)
	return b.tokens > 0
}

// spend charges a finished scan's running time.
func (b *scanBudget) spend(took time.Duration, now time.Time) {
	b.refill(now)
	b.tokens -= took
}

// stats are the tracker's counters, for the window's meta.
func (t *tracker) stats() map[string]int64 {
	out := make(map[string]int64, len(t.n))
	for k, v := range t.n {
		if v != 0 {
			out[k] = v
		}
	}
	return out
}
