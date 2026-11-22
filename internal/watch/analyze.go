package watch

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

// Window describes the recording an Aggregator holds.
type Window struct {
	Source      string // "etw", or "replay" for -watch-from
	Interrupted bool
	Meta        map[string]any // the source's own statistics
	Errors      []string
}

// Options tune Analyze.
type Options struct {
	MinEvents int        // check-ins a flow needs before it is scored (default 6)
	Allow     *Allowlist // nil: the built-in list only
	// Snapshot is the same run's collector results, for corroboration:
	// unsigned or unusual-path images, memory findings on the same process,
	// and QUIC, DoH or direct-DNS findings.
	Snapshot []collector.Result
	// Intel classifies a destination ("hosting", "tor", ...); nil when off.
	Intel func(netip.Addr) []string
}

// Rule names and techniques of watch mode's findings.
const (
	RuleBeacon         = "network.beacon"
	RuleBeaconRotating = "network.beacon_rotating"
	RuleDNSPeriodic    = "dns.periodic_query"
	RuleDNSTunnel      = "dns.tunnel_rate"
	RulePeriodicSpawn  = "process.periodic_spawn"
)

// DNS tunnel thresholds.
const (
	tunnelPerMinute = 30
	tunnelEntropy   = 3.5
	tunnelTXTShare  = 0.5
	spawnMinStarts  = 4
)

// identity is one program across its PIDs: image path plus the snapshot's
// SHA-256, so a restarted program merges.
type identity struct {
	key    string
	image  string
	sha256 string
	pids   map[uint32]bool
}

func (id *identity) label() string {
	if id.image != "" {
		return id.image
	}
	return "unknown image (PID " + strconv.Itoa(int(id.firstPID())) + ")"
}

func (id *identity) firstPID() uint32 {
	first := ^uint32(0)
	for p := range id.pids {
		if p < first {
			first = p
		}
	}
	return first
}

func (id *identity) pidList() []uint32 {
	out := make([]uint32, 0, len(id.pids))
	for p := range id.pids {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type analysis struct {
	a      *Aggregator
	opts   Options
	window time.Duration
	allow  *Allowlist
	cor    *corroborator
	ids    map[string]*identity
	res    *collector.Result
	stats  map[string]int
}

// Analyze scores what a holds and returns the "watch" result.
func Analyze(a *Aggregator, w Window, opts Options) collector.Result {
	a.mu.Lock()
	defer a.mu.Unlock()
	if opts.MinEvents < 4 {
		opts.MinEvents = 6
	}
	res := collector.NewResult("watch")
	res.StartedAt = a.started
	ended := a.ended
	if ended.IsZero() {
		ended = time.Now().UTC()
	}
	an := &analysis{a: a, opts: opts, window: ended.Sub(a.started), allow: opts.Allow,
		cor: newCorroborator(opts.Snapshot), ids: map[string]*identity{}, res: res, stats: map[string]int{}}
	if an.allow == nil {
		an.allow = NewAllowlist(nil)
	}
	an.cor.intel = opts.Intel
	beaconed := an.flows()
	an.dns(beaconed)
	an.spawns()

	res.SetMeta("source", w.Source)
	res.SetMeta("window_started", a.started)
	res.SetMeta("window_ended", ended)
	res.SetMeta("window_seconds", int64(an.window.Seconds()))
	res.SetMeta("interrupted", w.Interrupted)
	res.SetMeta("min_events", opts.MinEvents)
	res.SetMeta("cutoff", Cutoff)
	res.SetMeta("scorer", "lrng-beacon v1: 0.35 skew + 0.35 dispersion + 0.2 coverage + 0.1 size")
	events := map[string]int64{}
	for k, n := range a.counts {
		events[string(k)] = n
	}
	res.SetMeta("events", events)
	if len(a.dropped) > 0 {
		dropped := map[string]int64{}
		for k, n := range a.dropped {
			dropped[k] = n
		}
		res.SetMeta("dropped", dropped)
	}
	res.SetMeta("excluded_local_destinations", a.excluded)
	res.SetMeta("inbound_connections", a.accepts)
	for k, n := range an.stats {
		res.SetMeta(k, n)
	}
	for k, v := range w.Meta {
		res.SetMeta(k, v)
	}
	res.Errors = append(res.Errors, w.Errors...)
	if w.Interrupted {
		res.Fail("the watch window was interrupted; scores cover the part recorded")
	}
	out := res.Finish()
	out.Duration = an.window
	return out
}

// identityOf resolves the program behind pid at t.
func (an *analysis) identityOf(pid uint32, t time.Time, image string) *identity {
	if image == "" {
		image = an.a.imageAt(pid, t)
	}
	var key string
	sha := ""
	if image != "" {
		sha = an.cor.sha[slashLower(image)]
		key = slashLower(image) + "|" + sha
	} else {
		key = "pid:" + strconv.Itoa(int(pid))
	}
	id := an.ids[key]
	if id == nil {
		id = &identity{key: key, image: image, sha256: sha, pids: map[uint32]bool{}}
		an.ids[key] = id
	}
	id.pids[pid] = true
	return id
}

// allowed says why an identity's periodic behaviour is expected, unless the
// snapshot contradicts it (an unsigned image, a memory finding).
func (an *analysis) allowed(id *identity) string {
	why := an.allow.Match(id.image)
	if id.image == "" && id.pids[4] && len(id.pids) == 1 {
		why = "Windows kernel (System)"
	}
	if why == "" {
		return ""
	}
	if an.cor.untrusted[slashLower(id.image)] || len(an.cor.forPIDs(id)) > 0 {
		return ""
	}
	return why
}

type flowAgg struct {
	id         *identity
	dest       string
	hosts      map[string]bool
	addrs      map[netip.Addr]int
	ports      map[uint16]int
	transports map[string]bool
	tech       string
	times      []time.Time
	sizes      []uint64
	bytes      uint64
	first      time.Time
	last       time.Time
}

func transportOf(p proto, port uint16) (string, string) {
	switch {
	case port == 53:
		return "dns", "T1071.004"
	case port == 853 && p == protoTCP:
		return "dot", "T1071.004"
	case p == protoUDP && port == 443:
		return "quic", "T1071.001"
	case p == protoTCP && (port == 443 || port == 8443):
		return "https", "T1071.001"
	case p == protoTCP && (port == 80 || port == 8080 || port == 8000 || port == 8888):
		return "http", "T1071.001"
	}
	return p.String(), "T1071"
}

// flows scores each program-to-destination flow and each program's combined
// check-ins. It returns the identity|domain pairs that produced a beacon
// finding, so the DNS pass doesn't report the same check-ins twice.
func (an *analysis) flows() map[string]bool {
	byKey := map[string]*flowAgg{}
	var order []string
	for _, f := range an.a.flows {
		id := an.identityOf(f.key.pid, f.first, f.image)
		ip := f.key.remote.Addr().Unmap()
		dest := f.key.remote.String()
		host := an.a.names[ip]
		if host != "" {
			dest = Registrable(host)
		}
		k := id.key + "\x00" + dest
		fa := byKey[k]
		if fa == nil {
			fa = &flowAgg{id: id, dest: dest, hosts: map[string]bool{}, addrs: map[netip.Addr]int{},
				ports: map[uint16]int{}, transports: map[string]bool{}}
			byKey[k] = fa
			order = append(order, k)
		}
		ts, sz := f.checkIns()
		fa.times = append(fa.times, ts...)
		fa.sizes = append(fa.sizes, sz...)
		fa.bytes += f.bytes
		fa.addrs[ip] += len(ts)
		fa.ports[f.key.remote.Port()] += len(ts)
		tr, tech := transportOf(f.key.proto, f.key.remote.Port())
		fa.transports[tr] = true
		if fa.tech == "" || fa.tech == "T1071" {
			fa.tech = tech
		}
		if host != "" {
			fa.hosts[host] = true
		}
		if fa.first.IsZero() || f.first.Before(fa.first) {
			fa.first = f.first
		}
		if f.last.After(fa.last) {
			fa.last = f.last
		}
	}
	sort.Strings(order)
	an.stats["flows_seen"] = len(order)

	beaconed := map[string]bool{}
	type combo struct {
		times      []time.Time
		dests      map[string]bool
		transports map[string]bool
		best       float64
	}
	combos := map[*identity]*combo{}
	for _, k := range order {
		fa := byKey[k]
		times, sizes := coalesce(fa.times, fa.sizes, an.a.lim.Coalesce)
		c := combos[fa.id]
		if c == nil {
			c = &combo{dests: map[string]bool{}, transports: map[string]bool{}}
			combos[fa.id] = c
		}
		c.times = append(c.times, times...)
		c.dests[fa.dest] = true
		for t := range fa.transports {
			c.transports[t] = true
		}
		s, ok := ScoreSeries(times, sizes, an.window, an.opts.MinEvents)
		if !ok {
			an.stats["flows_below_minimum"]++
			continue
		}
		an.stats["flows_scored"]++
		if s.Total > c.best {
			c.best = s.Total
		}
		fields := an.flowFields(fa, s, sizes)
		why := an.allowed(fa.id)
		if why != "" {
			fields["allowlisted"] = why
			an.stats["flows_allowlisted"]++
		}
		var findings []collector.Finding
		if s.Total >= Cutoff && why == "" {
			reasons := an.cor.forFlow(fa)
			if len(reasons) > 0 {
				fields["corroboration"] = reasons
			}
			findings = append(findings, collector.Finding{
				Rule: RuleBeacon, Severity: severity(s.Total, len(reasons) > 0), Technique: fa.tech,
				Confidence: confidence(s.Total, len(reasons) > 0),
				Detail:     an.beaconDetail(fa, s, reasons),
			})
			for h := range fa.hosts {
				beaconed[fa.id.key+"|"+Registrable(h)] = true
			}
		}
		an.res.Add(fields, findings...)
	}

	// A process whose check-ins rotate across destinations or transports.
	ids := make([]*identity, 0, len(combos))
	for id := range combos {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].key < ids[j].key })
	for _, id := range ids {
		c := combos[id]
		if len(c.dests) < 2 && len(c.transports) < 2 {
			continue
		}
		times, _ := coalesce(c.times, nil, an.a.lim.Coalesce)
		s, ok := ScoreSeries(times, nil, an.window, an.opts.MinEvents)
		if !ok || s.Total < Cutoff || c.best >= Cutoff {
			continue
		}
		why := an.allowed(id)
		fields := an.base("process", id)
		fields["destinations"] = sortedKeys(c.dests)
		fields["transports"] = sortedKeys(c.transports)
		addScore(fields, s)
		if why != "" {
			fields["allowlisted"] = why
			an.res.Add(fields)
			continue
		}
		reasons := an.cor.forIdentity(id)
		if len(reasons) > 0 {
			fields["corroboration"] = reasons
		}
		an.res.Add(fields, collector.Finding{
			Rule: RuleBeaconRotating, Severity: severity(s.Total, len(reasons) > 0), Technique: "T1008",
			Confidence: confidence(s.Total, len(reasons) > 0),
			Detail: fmt.Sprintf("%s checked in %d times across %d destinations (%s) over %s, every %s ±%.0f%% combined, though no single destination was regular on its own (score %.2f)%s",
				id.label(), s.N, len(c.dests), strings.Join(sortedKeys(c.transports), ", "), fmtDur(an.window),
				fmtSecs(s.Median), 100*s.Jitter(), s.Total, reasonText(reasons)),
		})
	}
	return beaconed
}

func (an *analysis) base(kind string, id *identity) map[string]any {
	f := map[string]any{"kind": kind, "pid": id.firstPID()}
	if pids := id.pidList(); len(pids) > 1 {
		f["pids"] = pids
	}
	if id.image != "" {
		f["image_path"] = id.image
	}
	if id.sha256 != "" {
		f["image_sha256"] = id.sha256
	}
	return f
}

func (an *analysis) flowFields(fa *flowAgg, s Score, sizes []uint64) map[string]any {
	f := an.base("flow", fa.id)
	f["destination"] = fa.dest
	addr, port := topAddr(fa.addrs), topPort(fa.ports)
	f["remote_addr"] = addr.String()
	f["remote_port"] = port
	if len(fa.addrs) > 1 {
		f["remote_addrs"] = addrList(fa.addrs, 16)
	}
	if len(fa.hosts) > 0 {
		f["remote_hosts"] = sortedKeys(fa.hosts)
	}
	f["transport"] = strings.Join(sortedKeys(fa.transports), ",")
	f["first_seen"] = fa.first
	f["last_seen"] = fa.last
	f["bytes_total"] = fa.bytes
	addScore(f, s)
	if s.HasSizes {
		var known []float64
		for _, b := range sizes {
			if b > 0 {
				known = append(known, float64(b))
			}
		}
		sort.Float64s(known)
		f["bytes_median"] = uint64(quantile(known, 0.5))
	}
	return f
}

func addScore(f map[string]any, s Score) {
	f["check_ins"] = s.N
	f["median_interval_s"] = s.Median
	f["q1_interval_s"] = s.Q1
	f["q3_interval_s"] = s.Q3
	f["mad_interval_s"] = s.MAD
	f["s_skew"] = s.Skew
	f["s_disp"] = s.Disp
	f["s_cov"] = s.Cov
	if s.HasSizes {
		f["s_size"] = s.Size
	}
	f["score"] = s.Total
}

func (an *analysis) beaconDetail(fa *flowAgg, s Score, reasons []string) string {
	where := fa.dest
	if len(fa.hosts) > 0 {
		where = fmt.Sprintf("%s (%s, %s)", fa.dest, topAddr(fa.addrs), strings.Join(sortedKeys(fa.transports), ","))
	} else {
		where = fmt.Sprintf("%s (%s)", fa.dest, strings.Join(sortedKeys(fa.transports), ","))
	}
	parts := fmt.Sprintf("skew %.2f, dispersion %.2f, coverage %.2f", s.Skew, s.Disp, s.Cov)
	if s.HasSizes {
		parts += fmt.Sprintf(", sizes %.2f", s.Size)
	}
	return fmt.Sprintf("%s checked in with %s %d times over %s, every %s ±%.0f%% (score %.2f: %s)%s",
		fa.id.label(), where, s.N, fmtDur(an.window), fmtSecs(s.Median), 100*s.Jitter(), s.Total, parts, reasonText(reasons))
}

// dns scores periodic lookups and tunnel-like bursts of unique names.
func (an *analysis) dns(beaconed map[string]bool) {
	type group struct {
		id     *identity
		reg    string
		times  []time.Time
		subs   map[string]time.Time
		txt    int
		total  int
		failed int
	}
	groups := map[string]*group{}
	var order []string
	for _, q := range an.a.queries {
		id := an.identityOf(q.pid, q.t, "")
		reg := Registrable(q.name)
		k := id.key + "|" + reg
		g := groups[k]
		if g == nil {
			g = &group{id: id, reg: reg, subs: map[string]time.Time{}}
			groups[k] = g
			order = append(order, k)
		}
		g.times = append(g.times, q.t)
		g.total++
		if q.qtype == qtypeTXT || q.qtype == qtypeNULL {
			g.txt++
		}
		if q.status != 0 {
			g.failed++
		}
		if sub := subdomain(q.name, reg); sub != "" && len(g.subs) < an.a.lim.TunnelMax {
			if _, seen := g.subs[sub]; !seen {
				g.subs[sub] = q.t
			}
		}
	}
	sort.Strings(order)
	an.stats["dns_domains_seen"] = len(order)
	for _, k := range order {
		g := groups[k]
		why := an.allowed(g.id)
		// Tunnel: a burst of unique names under one domain.
		if peak := peakPerMinute(g.subs); peak >= tunnelPerMinute {
			ent := meanEntropy(g.subs)
			share := float64(g.txt) / float64(g.total)
			if ent >= tunnelEntropy || share >= tunnelTXTShare {
				fields := an.base("dns", g.id)
				fields["domain"] = g.reg
				fields["queries"] = g.total
				fields["unique_subdomains"] = len(g.subs)
				fields["peak_unique_per_minute"] = peak
				fields["mean_label_entropy"] = round3(ent)
				fields["txt_null_share"] = round3(share)
				if why != "" {
					fields["allowlisted"] = why
					an.res.Add(fields)
				} else {
					reasons := an.cor.forIdentity(g.id)
					sev := collector.SevSuspect
					if len(reasons) > 0 {
						sev = collector.SevCritical
						fields["corroboration"] = reasons
					}
					an.res.Add(fields, collector.Finding{
						Rule: RuleDNSTunnel, Severity: sev, Technique: "T1071.004", Confidence: 75,
						Detail: fmt.Sprintf("%s looked up %d unique names under %s, up to %d in one minute, with label entropy %.1f bits and %.0f%% TXT or NULL queries%s",
							g.id.label(), len(g.subs), g.reg, peak, ent, 100*share, reasonText(reasons)),
					})
				}
				continue
			}
		}
		times, _ := coalesce(g.times, nil, an.a.lim.Coalesce)
		s, ok := ScoreSeries(times, nil, an.window, an.opts.MinEvents)
		if !ok || s.Total < Cutoff || beaconed[g.id.key+"|"+g.reg] {
			continue
		}
		fields := an.base("dns", g.id)
		fields["domain"] = g.reg
		fields["queries"] = g.total
		fields["failed_queries"] = g.failed
		addScore(fields, s)
		if why != "" {
			fields["allowlisted"] = why
			an.res.Add(fields)
			continue
		}
		reasons := an.cor.forIdentity(g.id)
		if len(reasons) > 0 {
			fields["corroboration"] = reasons
		}
		an.res.Add(fields, collector.Finding{
			Rule: RuleDNSPeriodic, Severity: severity(s.Total, len(reasons) > 0), Technique: "T1071.004",
			Confidence: confidence(s.Total, len(reasons) > 0),
			Detail: fmt.Sprintf("%s looked up %s %d times over %s, every %s ±%.0f%% (score %.2f)%s",
				g.id.label(), g.reg, s.N, fmtDur(an.window), fmtSecs(s.Median), 100*s.Jitter(), s.Total, reasonText(reasons)),
		})
	}
}

// spawns scores the same command line started on a timer.
func (an *analysis) spawns() {
	type group struct {
		id    *identity
		cmd   string
		times []time.Time
		ppids map[uint32]bool
	}
	groups := map[string]*group{}
	var order []string
	for _, p := range an.a.spawns {
		id := an.identityOf(p.pid, p.t, p.image)
		cmd := strings.Join(strings.Fields(p.cmd), " ")
		k := id.key + "\x00" + strings.ToLower(cmd)
		g := groups[k]
		if g == nil {
			g = &group{id: id, cmd: cmd, ppids: map[uint32]bool{}}
			groups[k] = g
			order = append(order, k)
		}
		g.times = append(g.times, p.t)
		g.ppids[p.ppid] = true
	}
	sort.Strings(order)
	for _, k := range order {
		g := groups[k]
		times, _ := coalesce(g.times, nil, an.a.lim.Coalesce)
		s, ok := ScoreSeries(times, nil, an.window, spawnMinStarts)
		if !ok || s.Total < Cutoff {
			continue
		}
		fields := an.base("spawn", g.id)
		if g.cmd != "" {
			fields["command_line"] = g.cmd
		}
		var ppids []uint32
		for p := range g.ppids {
			ppids = append(ppids, p)
		}
		sort.Slice(ppids, func(i, j int) bool { return ppids[i] < ppids[j] })
		fields["parent_pids"] = ppids
		addScore(fields, s)
		if why := an.allowed(g.id); why != "" {
			fields["allowlisted"] = why
			an.res.Add(fields)
			continue
		}
		reasons := an.cor.forIdentity(g.id)
		if len(reasons) > 0 {
			fields["corroboration"] = reasons
		}
		what := g.id.label()
		if g.cmd != "" {
			what = g.cmd
		}
		an.res.Add(fields, collector.Finding{
			Rule: RulePeriodicSpawn, Severity: severity(s.Total, len(reasons) > 0), Technique: "T1053",
			Confidence: confidence(s.Total, len(reasons) > 0),
			Detail: fmt.Sprintf("%s started %d times over %s, every %s ±%.0f%% (score %.2f)%s",
				what, s.N, fmtDur(an.window), fmtSecs(s.Median), 100*s.Jitter(), s.Total, reasonText(reasons)),
		})
	}
}

// severity follows the spec's table: 0.80 and up is suspect, critical with a
// corroborating signal; 0.65 to 0.80 notable, suspect with one.
func severity(score float64, corroborated bool) collector.Severity {
	switch {
	case score >= Strong && corroborated:
		return collector.SevCritical
	case score >= Strong || corroborated:
		return collector.SevSuspect
	default:
		return collector.SevNotable
	}
}

func confidence(score float64, corroborated bool) int {
	c := 50 + int((score-Cutoff)/(1-Cutoff)*40)
	if corroborated {
		c += 10
	}
	if c > 95 {
		c = 95
	}
	if c < 40 {
		c = 40
	}
	return c
}

func peakPerMinute(first map[string]time.Time) int {
	ts := make([]time.Time, 0, len(first))
	for _, t := range first {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	peak, lo := 0, 0
	for hi := range ts {
		for ts[hi].Sub(ts[lo]) >= time.Minute {
			lo++
		}
		if n := hi - lo + 1; n > peak {
			peak = n
		}
	}
	return peak
}

func meanEntropy(subs map[string]time.Time) float64 {
	if len(subs) == 0 {
		return 0
	}
	sum := 0.0
	for s := range subs {
		sum += entropy(s)
	}
	return sum / float64(len(subs))
}

func topAddr(m map[netip.Addr]int) netip.Addr {
	var best netip.Addr
	n := -1
	for a, c := range m {
		if c > n || c == n && a.Less(best) {
			best, n = a, c
		}
	}
	return best
}

func topPort(m map[uint16]int) uint16 {
	var best uint16
	n := -1
	for p, c := range m {
		if c > n || c == n && p < best {
			best, n = p, c
		}
	}
	return best
}

func addrList(m map[netip.Addr]int, max int) []string {
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	if len(out) > max {
		out = out[:max]
	}
	s := make([]string, len(out))
	for i, a := range out {
		s[i] = a.String()
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func reasonText(r []string) string {
	if len(r) == 0 {
		return ""
	}
	return "; " + strings.Join(r, "; ")
}

func fmtSecs(s float64) string {
	return fmtDur(time.Duration(s * float64(time.Second)))
}

func fmtDur(d time.Duration) string {
	if d >= time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(100 * time.Millisecond).String()
}
