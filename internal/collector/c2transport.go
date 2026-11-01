package collector

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// c2transport.go — command-and-control channels that avoid HTTP(S) to a web
// server: DNS tunnelling (many long, random-looking names under one domain),
// programs that talk DNS straight to a resolver on the internet instead of
// through the host's DNS client, and QUIC (HTTP/3 over UDP 443) from programs
// that aren't browsers, which C2 frameworks have adopted because few proxies
// and sensors look inside it. Fed by Sysmon's network (3) and DNS (22)
// events, the DNS client cache, and the live connection table. Portable.

// dnsResolvers are programs whose job is to send DNS queries.
var dnsResolvers = set("svchost.exe", "dns.exe", "lsass.exe", "system", "dnscrypt-proxy.exe", "dnscrypt-proxy",
	"systemd-resolved", "dnsmasq", "named", "unbound", "coredns", "pdns_recursor", "pihole-ftl", "nscd", "kube-dns", "stubby",
	"cloudflared", "cloudflared.exe")

// dnsTools are administrators' lookup tools: a query from one is ordinary.
var dnsTools = set("nslookup.exe", "nslookup", "dig", "dig.exe", "host", "drill", "kdig", "resolvectl", "powershell.exe", "pwsh.exe", "pwsh")

// quicClients are programs expected to speak QUIC: browsers, the web views
// apps embed, and the Windows services that use it (SMB over QUIC, Delivery
// Optimization).
var quicClients = set("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "msedgewebview2.exe",
	"ms-teams.exe", "teams.exe", "svchost.exe", "system", "onedrive.exe", "discord.exe", "slack.exe", "zoom.exe", "spotify.exe",
	"code.exe", "chrome", "firefox", "msedge", "brave", "chromium", "chromium-browser", "opera", "vivaldi", "code", "discord", "slack")

// directDNSFinding judges a program sending DNS (port 53) straight to a public
// address: past the host's DNS client and whatever logs it, as DNS tunnels
// and DNS C2 implants that carry their own resolver do.
func directDNSFinding(label, image string, peer netip.AddrPort, when string) (Finding, bool) {
	name := baseName(image)
	if dnsResolvers[name] || !aidetect.PublicAddr(peer.Addr()) {
		return Finding{}, false
	}
	f := Finding{Rule: "network.direct_dns", Severity: SevSuspect, Technique: "T1071.004", Confidence: 55,
		Detail: fmt.Sprintf("%s sent DNS straight to %s%s, past the host's DNS client: DNS tunnels and DNS command-and-control "+
			"implants that carry their own resolver do this (dnscat2, iodine)", label, peer, when)}
	switch {
	case dnsTools[name]:
		f.Severity, f.Confidence = SevNotable, 30
		f.Detail += ". It is a lookup tool, which administrators point at a resolver by hand"
	case installedProgram(image):
		f.Severity, f.Confidence = SevNotable, 40
		f.Detail += ". It is an installed program; VPN clients and security products do this too"
	}
	return f, true
}

// sysmonNetworkFindings judges Sysmon's event 3 (a network connection): DNS
// sent past the DNS client, QUIC from a program that isn't a browser, and a
// signed proxy-execution binary reaching the internet.
func sysmonNetworkFindings(ev winEvent) []Finding {
	if !strings.EqualFold(strings.TrimSpace(evData(ev, "Initiated")), "true") {
		return nil
	}
	img := firstNonEmpty(evData(ev, "Image"), "a process")
	ip, err := netip.ParseAddr(strings.TrimSpace(evData(ev, "DestinationIp")))
	if err != nil || !aidetect.PublicAddr(ip) {
		return nil
	}
	port := uint16(atoiSafe(evData(ev, "DestinationPort")))
	peer := netip.AddrPortFrom(ip, port)
	shown := peer.String()
	if h := strings.TrimSpace(evData(ev, "DestinationHostname")); h != "" && h != "-" {
		shown = h + " (" + shown + ")"
	}
	proto := strings.ToLower(strings.TrimSpace(evData(ev, "Protocol")))
	name := baseName(img)
	label := fmt.Sprintf("%s (pid %s)", img, firstNonEmpty(evData(ev, "ProcessId"), "?"))
	var out []Finding
	switch {
	case port == 53:
		if f, ok := directDNSFinding(label, img, peer, eventTime(ev)); ok {
			out = append(out, f)
		}
	case port == 443 && proto == "udp" && !quicClients[name]:
		f := Finding{Rule: "network.quic_outbound", Severity: SevNotable, Technique: "T1071.001", Confidence: 40,
			Detail: fmt.Sprintf("%s spoke QUIC (UDP 443) to %s%s. Browsers and a few apps use QUIC; command-and-control frameworks "+
				"have taken it up because few proxies and network sensors look inside it", label, shown, eventTime(ev))}
		if proxyBeaconHosts[name] || listenerHosts[name] {
			f.Severity, f.Confidence = SevSuspect, 65
		} else if lvl, why := pathRisk(img); lvl == riskHigh {
			f.Severity, f.Confidence = SevSuspect, 60
			f.Detail += "; the program runs from " + why
		}
		out = append(out, f)
	}
	if proxyBeaconHosts[name] && port != 53 {
		out = append(out, Finding{Rule: "network.lolbin_outbound", Severity: SevSuspect, Technique: "T1218", Confidence: 60,
			Detail: fmt.Sprintf("%s connected to public address %s%s: signed proxy-execution binaries rarely talk to the internet "+
				"themselves (a beacon?)", label, shown, eventTime(ev))})
	}
	return out
}

// twoLevelSuffixes are the public suffixes with two labels, so the domain an
// organisation registered under one is three labels long.
var twoLevelSuffixes = set("co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
	"com.br", "com.cn", "net.cn", "org.cn", "co.in", "co.nz", "co.za", "com.mx", "com.tr", "com.tw", "com.hk", "co.kr", "com.sg",
	"com.ar", "co.il", "com.ru", "com.ua", "com.pl", "com.my", "co.id", "com.vn", "com.ph", "com.pk", "com.sa", "com.eg", "com.ng",
	"com.co", "com.pe", "co.th", "com.es", "co.at", "eu.org")

// registeredDomain splits a name into the domain registered for it and the
// labels below that ("x1y2.tunnel.example.com" → "example.com", "x1y2.tunnel").
func registeredDomain(name string) (domain, sub string) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	labels := strings.Split(name, ".")
	n := 2
	if len(labels) >= 2 && twoLevelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		n = 3
	}
	if len(labels) <= n {
		return name, ""
	}
	return strings.Join(labels[len(labels)-n:], "."), strings.Join(labels[:len(labels)-n], ".")
}

// shannon is the entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// tunnelLike reports whether the part of a name below its registered domain
// looks like data rather than a host name: long, close to random, sprinkled
// with digits or packed into a long label, and not hyphenated words (which
// is how long names that people chose are written).
func tunnelLike(sub string) bool {
	data := strings.ReplaceAll(sub, ".", "")
	if len(data) < 24 || strings.Count(data, "-") > 1 || shannon(data) < 3.5 {
		return false
	}
	digits, longest := 0, 0
	for _, r := range data {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	for _, l := range strings.Split(sub, ".") {
		longest = max(longest, len(l))
	}
	return float64(digits)/float64(len(data)) >= 0.1 || longest >= 30
}

// dnsLookupServices are domains whose own design is to answer queries for
// encoded data (antivirus and reputation lookups, mail blocklists) or that
// are content-delivery and reverse-lookup zones full of generated names.
var dnsLookupServices = set("sophosxl.net", "mcafee.com", "trendmicro.com", "spamhaus.org", "spamhaus.net", "surbl.org", "uribl.com",
	"barracudacentral.org", "senderbase.org", "dnswl.org", "sorbs.net", "mailspike.net", "akadns.net", "akamaiedge.net",
	"akamai.net", "edgekey.net", "edgesuite.net", "cloudfront.net", "amazonaws.com", "googlevideo.com", "1e100.net",
	"in-addr.arpa", "ip6.arpa", "trafficmanager.net", "azureedge.net", "fastly.net", "e5.sk", "eset.com", "avast.com",
	"avcdn.net", "kaspersky.com", "kaspersky-labs.com", "bitdefender.net", "symantec.com", "norton.com", "webroot.com",
	"cudasvc.com", "mimecast.com", "zscaler.net")

// internalSuffixes are names that never leave the organisation.
var internalSuffixes = []string{".local", ".lan", ".internal", ".home.arpa", ".corp", ".localdomain"}

// dnsTunnel is one domain that many tunnel-like names were looked up under.
type dnsTunnel struct {
	Domain   string
	Who      string // the program that looked them up ("" from the DNS cache)
	Names    []string
	Count    int // distinct tunnel-like names
	Lookups  int // lookups of them
	First    time.Time
	Last     time.Time
	Sampled  []string
	Entropy  float64 // mean, of the names' data part
	MeanSize int     // mean length of the data part
}

// Thresholds for a DNS tunnel: distinct tunnel-like names under one domain.
const (
	dnsTunnelMin      = 25
	dnsTunnelCritical = 100
	dnsTunnelSample   = 8
	dnsTunnelMaxNames = 5000 // per group, to bound memory
)

// dnsTunnelGrouper gathers names by (program, registered domain).
type dnsTunnelGrouper struct {
	groups map[string]*dnsTunnel
	seen   map[string]map[string]bool
	sumH   map[string]float64
	sumLen map[string]int
}

func newDNSTunnelGrouper() *dnsTunnelGrouper {
	return &dnsTunnelGrouper{groups: map[string]*dnsTunnel{}, seen: map[string]map[string]bool{},
		sumH: map[string]float64{}, sumLen: map[string]int{}}
}

// add folds one looked-up name in.
func (g *dnsTunnelGrouper) add(who, name string, when time.Time) {
	low := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	for _, s := range internalSuffixes {
		if strings.HasSuffix(low, s) {
			return
		}
	}
	domain, sub := registeredDomain(low)
	if sub == "" || dnsLookupServices[domain] || !tunnelLike(sub) {
		return
	}
	key := strings.ToLower(who) + "|" + domain
	t := g.groups[key]
	if t == nil {
		t = &dnsTunnel{Domain: domain, Who: who}
		g.groups[key] = t
		g.seen[key] = map[string]bool{}
	}
	t.Lookups++
	if !when.IsZero() {
		if t.First.IsZero() || when.Before(t.First) {
			t.First = when
		}
		if when.After(t.Last) {
			t.Last = when
		}
	}
	if g.seen[key][low] || len(g.seen[key]) >= dnsTunnelMaxNames {
		return
	}
	g.seen[key][low] = true
	t.Count++
	data := strings.ReplaceAll(sub, ".", "")
	g.sumH[key] += shannon(data)
	g.sumLen[key] += len(data)
	if len(t.Sampled) < dnsTunnelSample {
		t.Sampled = append(t.Sampled, low)
	}
}

// tunnels returns the groups that crossed the threshold, most names first.
func (g *dnsTunnelGrouper) tunnels() []*dnsTunnel {
	var out []*dnsTunnel
	for key, t := range g.groups {
		if t.Count < dnsTunnelMin {
			continue
		}
		t.Entropy = math.Round(g.sumH[key]/float64(t.Count)*100) / 100
		t.MeanSize = g.sumLen[key] / t.Count
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain+out[i].Who < out[j].Domain+out[j].Who
	})
	return out
}

// finding describes a tunnel.
func (t *dnsTunnel) finding(source string) Finding {
	who := "this host"
	if t.Who != "" {
		who = t.Who
	}
	span := ""
	if !t.First.IsZero() {
		span = fmt.Sprintf(" between %s and %s", t.First.UTC().Format(time.RFC3339), t.Last.UTC().Format(time.RFC3339))
	}
	f := Finding{Rule: "network.dns_tunnel", Severity: SevSuspect, Technique: "T1071.004", Confidence: 70,
		Detail: fmt.Sprintf("%s looked up %d different long, random-looking names under %s%s (%s; data part %d characters long on "+
			"average, %.2f bits of entropy per character): data carried in DNS names, the shape of a DNS tunnel or DNS "+
			"command-and-control (dnscat2, iodine, Cobalt Strike's DNS beacon). For example: %s",
			who, t.Count, t.Domain, span, source, t.MeanSize, t.Entropy, strings.Join(t.Sampled, ", "))}
	if t.Count >= dnsTunnelCritical {
		f.Severity, f.Confidence = SevCritical, 80
	}
	return f
}

// fields is the synthetic record for a tunnel.
func (t *dnsTunnel) fields() map[string]any {
	f := map[string]any{"aggregation": "dns_tunnel", "domain": t.Domain, "names": t.Count, "lookups": t.Lookups,
		"examples": t.Sampled, "mean_entropy": t.Entropy, "mean_length": t.MeanSize}
	if t.Who != "" {
		f["image"] = t.Who
	}
	if !t.First.IsZero() {
		f["time_created"] = t.First.UTC()
		f["last"] = t.Last.UTC()
	}
	return f
}

// dnsTunnelTracker gathers Sysmon's DNS query events (22) over a run.
type dnsTunnelTracker struct{ g *dnsTunnelGrouper }

func newDNSTunnelTracker() *dnsTunnelTracker { return &dnsTunnelTracker{g: newDNSTunnelGrouper()} }

func (t *dnsTunnelTracker) observe(ev winEvent) {
	if t == nil || ev.EventID != 22 || !isSysmon(ev) {
		return
	}
	t.g.add(firstNonEmpty(evData(ev, "Image"), "an unrecorded program"), evData(ev, "QueryName"), ev.TimeCreated)
}

func (t *dnsTunnelTracker) flush() []Record {
	if t == nil {
		return nil
	}
	var out []Record
	for _, tun := range t.g.tunnels() {
		out = append(out, Record{Fields: tun.fields(), Findings: []Finding{tun.finding("Sysmon DNS query events")}})
	}
	return out
}
