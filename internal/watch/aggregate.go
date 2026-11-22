package watch

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits bound what an Aggregator holds, so a long window on a busy host
// can't exhaust memory. Past them the least active flows are dropped, and
// the counts go into the result's meta: gaps matter in forensics.
type Limits struct {
	MaxFlows  int // flows held at once (default 20,000)
	PerFlow   int // check-ins kept per flow, the most recent (default 512)
	MaxHeld   int // check-ins, lookups and process starts held (default 2,000,000)
	MaxConns  int // open TCP connections tracked for byte counts (default 100,000)
	UDPBreak  time.Duration
	Coalesce  time.Duration
	TunnelMax int // unique names kept per domain for the tunnel heuristic (default 10,000)
}

// DefaultLimits are the spec's caps.
func DefaultLimits() Limits {
	return Limits{MaxFlows: 20_000, PerFlow: 512, MaxHeld: 2_000_000, MaxConns: 100_000,
		UDPBreak: 2 * time.Second, Coalesce: time.Second, TunnelMax: 10_000}
}

type proto uint8

const (
	protoTCP proto = iota + 1
	protoUDP
)

func (p proto) String() string {
	if p == protoUDP {
		return "udp"
	}
	return "tcp"
}

type flowKey struct {
	pid    uint32
	remote netip.AddrPort
	proto  proto
}

// rawFlow is one process's check-ins with one remote address and port. Its
// check-ins are a ring of the most recent PerFlow; seq numbers them all.
type rawFlow struct {
	key       flowKey
	image     string
	times     []int64  // unix nanoseconds, ring
	sizes     []uint32 // bytes sent and received in that check-in, ring
	seq       int      // check-ins seen, including any overwritten
	first     time.Time
	last      time.Time
	lastPkt   time.Time // UDP: the last datagram, to find the next check-in
	bytes     uint64
	evicted   bool
	ringLimit int
}

func (f *rawFlow) add(t time.Time) int {
	pos := f.seq % f.ringLimit
	if pos == len(f.times) {
		f.times = append(f.times, t.UnixNano())
		f.sizes = append(f.sizes, 0)
	} else {
		f.times[pos], f.sizes[pos] = t.UnixNano(), 0
	}
	f.seq++
	if f.first.IsZero() {
		f.first = t
	}
	f.last = t
	return f.seq - 1
}

func (f *rawFlow) addBytes(seq int, n uint32) {
	f.bytes += uint64(n)
	if seq < 0 || f.seq-seq > len(f.times) {
		return // that check-in has left the ring
	}
	pos := seq % f.ringLimit
	if f.sizes[pos] < ^uint32(0)-n {
		f.sizes[pos] += n
	}
}

// checkIns returns the ring in time order.
func (f *rawFlow) checkIns() ([]time.Time, []uint64) {
	n := len(f.times)
	ts := make([]time.Time, 0, n)
	sz := make([]uint64, 0, n)
	start := 0
	if f.seq > n {
		start = f.seq % f.ringLimit
	}
	for i := 0; i < n; i++ {
		p := (start + i) % n
		ts = append(ts, time.Unix(0, f.times[p]).UTC())
		sz = append(sz, uint64(f.sizes[p]))
	}
	return ts, sz
}

type connKey struct {
	pid           uint32
	local, remote netip.AddrPort
}

type connRef struct {
	flow *rawFlow
	seq  int
}

// procSpan is what a PID was running from a time on.
type procSpan struct {
	from  time.Time
	image string
	cmd   string
	ppid  uint32
}

type procStart struct {
	t     time.Time
	pid   uint32
	ppid  uint32
	image string
	cmd   string
}

type dnsQuery struct {
	t      time.Time
	pid    uint32
	name   string
	qtype  uint16
	status uint32
}

// Aggregator folds Events into bounded state. It is safe for concurrent use:
// a source's callback adds while nothing else reads until the window closes.
type Aggregator struct {
	mu      sync.Mutex
	lim     Limits
	self    map[uint32]bool
	started time.Time
	ended   time.Time

	procs    map[uint32][]procSpan
	spawns   []procStart
	flows    map[flowKey]*rawFlow
	conns    map[connKey]connRef
	queries  []dnsQuery
	names    map[netip.Addr]string // address -> the name a lookup answered it for
	held     int
	counts   map[Kind]int64
	dropped  map[string]int64
	excluded int64 // events to loopback, multicast and the like
	accepts  int64
}

// NewAggregator starts an aggregator for a window opening at started.
// Events from the self PIDs (lrng itself) are ignored.
func NewAggregator(started time.Time, lim Limits, self ...uint32) *Aggregator {
	d := DefaultLimits()
	if lim.MaxFlows <= 0 {
		lim.MaxFlows = d.MaxFlows
	}
	if lim.PerFlow <= 0 {
		lim.PerFlow = d.PerFlow
	}
	if lim.MaxHeld <= 0 {
		lim.MaxHeld = d.MaxHeld
	}
	if lim.MaxConns <= 0 {
		lim.MaxConns = d.MaxConns
	}
	if lim.UDPBreak <= 0 {
		lim.UDPBreak = d.UDPBreak
	}
	if lim.Coalesce <= 0 {
		lim.Coalesce = d.Coalesce
	}
	if lim.TunnelMax <= 0 {
		lim.TunnelMax = d.TunnelMax
	}
	a := &Aggregator{lim: lim, self: map[uint32]bool{}, started: started,
		procs: map[uint32][]procSpan{}, flows: map[flowKey]*rawFlow{}, conns: map[connKey]connRef{},
		names: map[netip.Addr]string{}, counts: map[Kind]int64{}, dropped: map[string]int64{}}
	for _, p := range self {
		a.self[p] = true
	}
	return a
}

// Close marks the end of the window.
func (a *Aggregator) Close(ended time.Time) {
	a.mu.Lock()
	a.ended = ended
	a.mu.Unlock()
}

// Add folds one event in.
func (a *Aggregator) Add(e Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.counts[e.Kind]++
	if a.self[e.PID] {
		a.dropped["self"]++
		return
	}
	switch e.Kind {
	case ProcSeen, ProcStart:
		a.addProc(e)
	case ProcStop:
		// Kept: the PID's spans already say what ran; a reused PID gets a new span.
	case TCPConnect:
		if !a.routable(e.Remote) {
			return
		}
		f := a.flow(flowKey{e.PID, e.Remote, protoTCP}, e)
		if f == nil {
			return
		}
		seq := f.add(e.Time)
		a.held++
		if len(a.conns) >= a.lim.MaxConns {
			a.dropped["connections_reset"] += int64(len(a.conns))
			a.conns = map[connKey]connRef{}
		}
		a.conns[connKey{e.PID, e.Local, e.Remote}] = connRef{f, seq}
	case TCPAccept:
		a.accepts++
	case TCPSend, TCPRecv:
		if ref, ok := a.conns[connKey{e.PID, e.Local, e.Remote}]; ok && !ref.flow.evicted {
			ref.flow.addBytes(ref.seq, e.Bytes)
		}
	case TCPClose:
		delete(a.conns, connKey{e.PID, e.Local, e.Remote})
	case UDPSend, UDPRecv:
		if !a.routable(e.Remote) {
			return
		}
		key := flowKey{e.PID, e.Remote, protoUDP}
		f := a.flows[key]
		if e.Kind == UDPRecv && f == nil {
			return // replies only count toward a flow this host started
		}
		if f == nil {
			if f = a.flow(key, e); f == nil {
				return
			}
		}
		if e.Kind == UDPSend && (f.lastPkt.IsZero() || e.Time.Sub(f.lastPkt) >= a.lim.UDPBreak) {
			f.add(e.Time)
			a.held++
		}
		if e.Time.After(f.lastPkt) {
			f.lastPkt = e.Time
		}
		f.addBytes(f.seq-1, e.Bytes)
	case DNS:
		a.addDNS(e)
	}
}

func (a *Aggregator) addProc(e Event) {
	spans := a.procs[e.PID]
	if n := len(spans); n > 0 && spans[n-1].image == e.Image && (e.Kind == ProcSeen || spans[n-1].from.Equal(e.Time)) {
		if e.CmdLine != "" {
			spans[n-1].cmd = e.CmdLine
		}
	} else {
		a.procs[e.PID] = append(spans, procSpan{from: e.Time, image: e.Image, cmd: e.CmdLine, ppid: e.PPID})
	}
	if e.Kind == ProcStart {
		if a.held >= a.lim.MaxHeld {
			a.dropped["over_event_limit"]++
			return
		}
		a.spawns = append(a.spawns, procStart{e.Time, e.PID, e.PPID, e.Image, e.CmdLine})
		a.held++
	}
}

func (a *Aggregator) addDNS(e Event) {
	name := normName(e.Query)
	if name == "" {
		return
	}
	for _, ans := range e.Answers {
		if ip, err := netip.ParseAddr(ans); err == nil {
			a.names[ip.Unmap()] = name
		}
	}
	if a.held >= a.lim.MaxHeld {
		a.dropped["over_event_limit"]++
		return
	}
	a.queries = append(a.queries, dnsQuery{e.Time, e.PID, name, e.QType, e.Status})
	a.held++
}

// routable is false for destinations that can't be a remote C2: loopback,
// unspecified, multicast and link-local.
func (a *Aggregator) routable(ap netip.AddrPort) bool {
	if !routableAddr(ap.Addr()) {
		a.excluded++
		return false
	}
	return true
}

// routableAddr is false for an address no remote C2 can have.
func routableAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// flow returns the flow for key, making it (and evicting the least active
// tenth when full) if needed. nil means the event limit is reached.
func (a *Aggregator) flow(key flowKey, e Event) *rawFlow {
	if f, ok := a.flows[key]; ok {
		if a.held >= a.lim.MaxHeld {
			a.dropped["over_event_limit"]++
			return nil
		}
		return f
	}
	if a.held >= a.lim.MaxHeld {
		a.dropped["over_event_limit"]++
		return nil
	}
	if len(a.flows) >= a.lim.MaxFlows {
		a.evict()
	}
	f := &rawFlow{key: key, image: a.imageAt(e.PID, e.Time), ringLimit: a.lim.PerFlow}
	a.flows[key] = f
	return f
}

func (a *Aggregator) evict() {
	all := make([]*rawFlow, 0, len(a.flows))
	for _, f := range a.flows {
		all = append(all, f)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].seq != all[j].seq {
			return all[i].seq < all[j].seq
		}
		return all[i].last.Before(all[j].last)
	})
	n := len(all) / 10
	if n == 0 {
		n = 1
	}
	for _, f := range all[:n] {
		delete(a.flows, f.key)
		f.evicted = true
		a.held -= len(f.times)
		a.dropped["flows_evicted"]++
		a.dropped["check_ins_evicted"] += int64(f.seq)
	}
}

// imageAt is the image a PID ran at t, "" when unknown.
func (a *Aggregator) imageAt(pid uint32, t time.Time) string {
	sp := a.spanAt(pid, t)
	if sp == nil {
		return ""
	}
	return sp.image
}

func (a *Aggregator) spanAt(pid uint32, t time.Time) *procSpan {
	spans := a.procs[pid]
	for i := len(spans) - 1; i >= 0; i-- {
		if !spans[i].from.After(t) || i == 0 {
			return &spans[i]
		}
	}
	return nil
}

func normName(n string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
}

// Started is when the window opened.
func (a *Aggregator) Started() time.Time { return a.started }
