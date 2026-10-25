package aidetect

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity strings mirror the collector package's severity values. aidetect
// deliberately does NOT import collector — the collector maps a Callout onto
// its own Finding type. This keeps the dependency one-directional and avoids
// an import cycle (collectors import aidetect, not the reverse).
const (
	SevNotable  = "notable"
	SevSuspect  = "suspect"
	SevCritical = "critical"
)

// DefaultLookupTimeout bounds each provider-hostname lookup. A network-
// contained host often can't reach DNS at all; without a bound, the lookups
// alone could exceed the collector's whole time budget.
const DefaultLookupTimeout = 3 * time.Second

// Callout is aidetect's finding type for an LLM-callout detection. The caller
// converts it to whatever its own schema needs.
type Callout struct {
	Rule       string
	Severity   string
	Technique  string
	Confidence int
	Detail     string
}

// Resolver is the subset of *net.Resolver the detector needs; tests swap in a
// fake so they never touch real DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures BuildDetector.
type Options struct {
	// ExtraAllow adds process names treated as legitimate LLM callers. A full
	// path is accepted and reduced to its file name.
	ExtraAllow []string
	// Resolve performs live DNS lookups of the provider hostnames. These go
	// through the host's resolver and land in its DNS client cache.
	Resolve bool
	// LookupTimeout bounds each lookup; 0 means DefaultLookupTimeout.
	LookupTimeout time.Duration
	// Resolver overrides net.DefaultResolver (tests).
	Resolver Resolver
}

// Conn is one connection as the detector sees it.
type Conn struct {
	Remote     netip.Addr
	RemoteHost string // from DNS correlation, when known
	Process    string // image name, e.g. "powershell.exe"; "" if unknown
	PID        uint32
	ImagePath  string // full image path, when it could be read
	// UnusualPath is true when ImagePath is in a user-writable or temporary
	// location. Allowlisting is by name, so this catches an allowlisted name
	// running from somewhere installed software doesn't live.
	UnusualPath bool
}

// Detector matches network connections against resolved LLM endpoints and an
// allowlist of processes permitted to reach them. Build it once per run with
// BuildDetector, then call Inspect per connection.
type Detector struct {
	llmIPs map[netip.Addr]struct{}
	allow  map[string]bool

	lookupsPerformed bool
	resolved         int
	failed           []string
	ignored          []string // "host=ip" answers that weren't public addresses
	resolvedAt       time.Time
	resolveTook      time.Duration
}

func newDetector(extraAllow []string) *Detector {
	d := &Detector{llmIPs: map[netip.Addr]struct{}{}, allow: map[string]bool{}}
	for k, v := range defaultAllowlist {
		d.allow[k] = v
	}
	for _, a := range extraAllow {
		if n := normalizeName(a); n != "" {
			d.allow[n] = true
		}
	}
	return d
}

// BuildDetector merges the allowlist and, if o.Resolve is set, resolves the
// known LLM hostnames concurrently, each under its own timeout and under ctx.
// Failures are tolerated and recorded: a provider that doesn't resolve simply
// contributes no IPs this run, and Meta says so.
func BuildDetector(ctx context.Context, o Options) *Detector {
	d := newDetector(o.ExtraAllow)
	if !o.Resolve {
		return d
	}
	r := o.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	timeout := o.LookupTimeout
	if timeout <= 0 {
		timeout = DefaultLookupTimeout
	}

	d.lookupsPerformed = true
	d.resolvedAt = time.Now().UTC()

	type answer struct {
		host string
		ips  []netip.Addr
		err  error
	}
	answers := make([]answer, len(llmHostnames))
	var wg sync.WaitGroup
	for i, h := range llmHostnames {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ips, err := r.LookupNetIP(lctx, "ip", h)
			answers[i] = answer{host: h, ips: ips, err: err}
		}()
	}
	wg.Wait()

	for _, a := range answers {
		if a.err != nil || len(a.ips) == 0 {
			d.failed = append(d.failed, a.host)
			continue
		}
		usable := 0
		for _, ip := range a.ips {
			ip = ip.Unmap().WithZone("")
			if !publicAddr(ip) {
				// A DNS filter that blocks AI APIs often answers 0.0.0.0,
				// 127.0.0.1 or an internal block-page address. Matching on
				// that would flag every local connection to it, so it's
				// ignored, and recorded because it's evidence in itself.
				d.ignored = append(d.ignored, a.host+"="+ip.String())
				continue
			}
			d.llmIPs[ip] = struct{}{}
			usable++
		}
		if usable > 0 {
			d.resolved++
		}
	}
	sort.Strings(d.failed)
	sort.Strings(d.ignored)
	d.resolveTook = time.Since(d.resolvedAt)
	return d
}

// Meta reports detector coverage for the run metadata, so "no findings" can be
// told apart from "the detector had nothing to match against".
func (d *Detector) Meta() map[string]any {
	m := map[string]any{
		"dns_lookups_performed":   d.lookupsPerformed,
		"provider_hosts_total":    len(llmHostnames),
		"provider_hosts_resolved": d.resolved,
		"endpoint_ips_loaded":     len(d.llmIPs),
	}
	if d.lookupsPerformed {
		m["provider_hosts_failed"] = d.failed
		if len(d.ignored) > 0 {
			// Non-public answers usually mean DNS filtering or a sinkhole.
			m["non_public_answers_ignored"] = d.ignored
		}
		m["resolved_at"] = d.resolvedAt
		m["resolve_duration_ms"] = d.resolveTook.Milliseconds()
	}
	return m
}

// Matches reports whether a remote address/host is LLM inference
// infrastructure. Cheap; callers use it to decide whether a match is worth
// extra work (such as reading the process image path).
func (d *Detector) Matches(remote netip.Addr, remoteHost string) bool {
	_, ok := d.match(remote, remoteHost)
	return ok
}

// Inspect returns a Callout if the connection looks like an unsanctioned LLM
// callout, or nil otherwise.
func (d *Detector) Inspect(c Conn) *Callout {
	how, ok := d.match(c.Remote, c.RemoteHost)
	if !ok {
		return nil
	}
	target := c.Remote.String()
	if c.RemoteHost != "" {
		target = c.RemoteHost + " (" + target + ")"
	}

	// PID 0 owns no real connection: Windows reports TIME_WAIT sockets with
	// PID 0 after the owning process has closed them. Something on this host
	// talked to the endpoint in the last few minutes, but the table can't say
	// what, so this must not be attributed to "[System Process]".
	if c.PID == 0 {
		return &Callout{
			Rule:       "ai.llm_callout_unattributed",
			Severity:   SevNotable,
			Technique:  "T1071.001",
			Confidence: 30,
			Detail: fmt.Sprintf("closed connection (no owning process, typically TIME_WAIT) to LLM "+
				"endpoint %s via %s — a process on this host reached it within the last few "+
				"minutes; correlate with process, DNS-cache and prefetch evidence", target, how),
		}
	}

	name := normalizeName(c.Process)
	label := c.Process
	if label == "" {
		label = fmt.Sprintf("pid %d (exited before its name was read)", c.PID)
	}

	if d.allow[name] {
		if !c.UnusualPath {
			return nil // allowlisted caller from a normal location: expected
		}
		return &Callout{
			Rule:       "ai.llm_callout_unusual_path",
			Severity:   SevSuspect,
			Technique:  "T1036.005", // Masquerading: Match Legitimate Name or Location
			Confidence: 70,
			Detail: fmt.Sprintf("allowlisted name '%s' (pid %d) is running from an unusual "+
				"location (%s) and connected to LLM endpoint %s via %s — the allowlist matches "+
				"names only, so verify this binary", label, c.PID, c.ImagePath, target, how),
		}
	}

	// Severity scales with how suspicious the calling process is. A known
	// script host or a binary abused to run code is a far stronger signal than
	// an unknown-but-plausible application.
	sev, conf := SevSuspect, 60
	if isScriptHostOrLOLBin(name) {
		sev, conf = SevCritical, 85
	}
	where := ""
	if c.UnusualPath {
		conf += 10
		where = " from unusual location " + c.ImagePath
	}
	return &Callout{
		Rule:       "ai.llm_callout",
		Severity:   sev,
		Technique:  "T1071.001", // Application Layer Protocol: Web Protocols
		Confidence: conf,
		Detail: fmt.Sprintf("process '%s' (pid %d)%s connected to LLM inference endpoint %s via %s; "+
			"not on LLM-caller allowlist — possible AI-assisted malware calling out at runtime",
			label, c.PID, where, target, how),
	}
}

func (d *Detector) match(remote netip.Addr, remoteHost string) (string, bool) {
	if remote.IsValid() {
		if _, ok := d.llmIPs[remote.Unmap().WithZone("")]; ok {
			return "resolved IP match", true
		}
	}
	if remoteHost != "" {
		return MatchHostname(remoteHost)
	}
	return "", false
}

// PublicAddr reports whether ip is a routable public address — the only kind
// a commercial LLM API (or an internet C2) can genuinely live at. Private,
// loopback, link-local, multicast, unspecified and reserved ranges are not.
// (Shared 100.64/10 and 198.18/15 stay matchable: proxies with "fake-IP" DNS
// hand out unique addresses there, so a match is still meaningful.)
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),   // "this network"; a common sinkhole answer
	netip.MustParsePrefix("240.0.0.0/4"), // reserved
	netip.MustParsePrefix("100::/64"),    // IPv6 discard-only
}

func publicAddr(ip netip.Addr) bool { return PublicAddr(ip) }

// normalizeName lowercases a process name and strips any directory part, so
// "-allow C:\Tools\MyApp.exe" and "-allow myapp.exe" mean the same thing.
func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// scriptHostsAndLOLBins are interpreters and signed binaries attackers abuse to
// run code. A callout to an LLM endpoint from one of these is high-signal.
var scriptHostsAndLOLBins = map[string]bool{
	"powershell.exe": true,
	"pwsh.exe":       true,
	"cmd.exe":        true,
	"wscript.exe":    true,
	"cscript.exe":    true,
	"mshta.exe":      true,
	"rundll32.exe":   true,
	"regsvr32.exe":   true,
	"certutil.exe":   true,
	"bitsadmin.exe":  true,
	"curl.exe":       true,
	"python.exe":     true,
	"pythonw.exe":    true,
	"node.exe":       true,
}

func isScriptHostOrLOLBin(name string) bool { return scriptHostsAndLOLBins[name] }
