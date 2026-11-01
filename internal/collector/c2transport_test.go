package collector

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tunnelName is the i-th data-carrying name a DNS tunnel client would look
// up under domain: a base32 chunk split into labels, as dnscat2 and iodine do.
func tunnelName(i int, domain string) string {
	sum := sha256.Sum256([]byte{byte(i), byte(i >> 8), 7})
	data := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:]), "="))
	return data[:30] + "." + data[30:50] + "." + domain
}

func TestRegisteredDomain(t *testing.T) {
	for _, c := range [][3]string{
		{"a.b.example.com", "example.com", "a.b"},
		{"example.com", "example.com", ""},
		{"x.y.example.co.uk.", "example.co.uk", "x.y"},
		{"WWW.Example.COM", "example.com", "www"},
		{"localhost", "localhost", ""},
	} {
		if d, s := registeredDomain(c[0]); d != c[1] || s != c[2] {
			t.Errorf("%s: got %q %q", c[0], d, s)
		}
	}
	if !tunnelLike("mzxw6ytboi4tqmrzgezdgnbvgy3tqojq.gezdgnbvgy3tqojqgeza") || tunnelLike("www") ||
		tunnelLike("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") || tunnelLike("mail-server-frontend-eu") {
		t.Error("tunnelLike")
	}
}

func TestDNSTunnelGrouper(t *testing.T) {
	g := newDNSTunnelGrouper()
	base := time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC)
	for i := 0; i < 120; i++ {
		g.add(`C:\Users\bob\AppData\Local\Temp\upd.exe`, tunnelName(i, "t.example-c2.net"), base.Add(time.Duration(i)*time.Second))
	}
	for i := 0; i < 30; i++ {
		g.add("chrome.exe", tunnelName(i, "x.example-c2.net"), base) // another program, a smaller group
		g.add("svchost.exe", tunnelName(i, "sophosxl.net"), base)    // a reputation lookup service
		h := sha256.Sum256([]byte{byte(i)})
		g.add("svchost.exe", hex.EncodeToString(h[:16])+".corp.local", base)       // internal
		g.add("svchost.exe", "r"+itoa(i%5)+"---sn-ab5l6nzk.googlevideo.com", base) // CDN
		g.add("svchost.exe", strings.Repeat("1.0.", 16)+"ip6.arpa", base)          // reverse lookup
		g.add("mail.exe", "www"+itoa(i)+".example.org", base)                      // short names
	}
	for i := 0; i < 10; i++ {
		g.add("x.exe", tunnelName(i, "few.example.com"), base) // too few
	}
	tunnels := g.tunnels()
	if len(tunnels) != 2 {
		t.Fatalf("tunnels: %+v", tunnels)
	}
	big, small := tunnels[0], tunnels[1]
	if big.Domain != "example-c2.net" || big.Count != 120 || big.Who == "" || len(big.Sampled) != dnsTunnelSample ||
		!big.First.Equal(base) || !big.Last.Equal(base.Add(119*time.Second)) {
		t.Errorf("big: %+v", big)
	}
	f := big.finding("Sysmon DNS query events")
	if f.Rule != "network.dns_tunnel" || f.Severity != SevCritical || !strings.Contains(f.Detail, "120 different") {
		t.Errorf("finding: %+v", f)
	}
	if small.Who != "chrome.exe" || small.finding("x").Severity != SevSuspect {
		t.Errorf("small: %+v", small)
	}
	// The same name looked up again counts once.
	g2 := newDNSTunnelGrouper()
	for i := 0; i < 60; i++ {
		g2.add("x.exe", tunnelName(i%5, "example.net"), base)
	}
	if len(g2.tunnels()) != 0 {
		t.Errorf("repeats: %+v", g2.tunnels())
	}
}

func TestSysmonNetworkEvents(t *testing.T) {
	sysmon := func(kv ...string) winEvent {
		ev := dcEvent(3, append([]string{"Initiated", "true", "ProcessId", "4242"}, kv...)...)
		ev.Provider, ev.Channel = "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"
		return ev
	}
	f := only(t, "direct dns", eventFindings(sysmon("Image", `C:\Users\bob\AppData\Roaming\svc\agent.exe`, "Protocol", "udp",
		"DestinationIp", "8.8.8.8", "DestinationPort", "53")), "network.direct_dns", SevSuspect)
	if !strings.Contains(f.Detail, "8.8.8.8:53") || !strings.Contains(f.Detail, "agent.exe") {
		t.Errorf("detail: %s", f.Detail)
	}
	none(t, "dns client", eventFindings(sysmon("Image", `C:\Windows\System32\svchost.exe`, "Protocol", "udp",
		"DestinationIp", "8.8.8.8", "DestinationPort", "53")))
	none(t, "internal resolver", eventFindings(sysmon("Image", `C:\x\agent.exe`, "Protocol", "udp", "DestinationIp", "10.0.0.2", "DestinationPort", "53")))
	only(t, "nslookup", eventFindings(sysmon("Image", `C:\Windows\System32\nslookup.exe`, "Protocol", "udp",
		"DestinationIp", "1.1.1.1", "DestinationPort", "53")), "network.direct_dns", SevNotable)

	f = only(t, "quic", eventFindings(sysmon("Image", `C:\Users\bob\AppData\Local\Temp\x.exe`, "Protocol", "udp",
		"DestinationIp", "203.0.113.10", "DestinationPort", "443", "DestinationHostname", "cdn.example.net")), "network.quic_outbound", SevSuspect)
	if !strings.Contains(f.Detail, "cdn.example.net (203.0.113.10:443)") {
		t.Errorf("detail: %s", f.Detail)
	}
	only(t, "quic from an app", eventFindings(sysmon("Image", `C:\Program Files\Vendor\app.exe`, "Protocol", "udp",
		"DestinationIp", "203.0.113.10", "DestinationPort", "443")), "network.quic_outbound", SevNotable)
	none(t, "browser quic", eventFindings(sysmon("Image", `C:\Program Files\Google\Chrome\Application\chrome.exe`, "Protocol", "udp",
		"DestinationIp", "142.250.1.1", "DestinationPort", "443")))
	none(t, "tcp 443", eventFindings(sysmon("Image", `C:\x\app.exe`, "Protocol", "tcp", "DestinationIp", "203.0.113.10", "DestinationPort", "443")))

	only(t, "lolbin", eventFindings(sysmon("Image", `C:\Windows\System32\rundll32.exe`, "Protocol", "tcp",
		"DestinationIp", "203.0.113.10", "DestinationPort", "443")), "network.lolbin_outbound", SevSuspect)
	inbound := sysmon("Image", `C:\Windows\System32\rundll32.exe`, "Protocol", "tcp", "DestinationIp", "203.0.113.10", "DestinationPort", "443")
	inbound.Data["Initiated"] = "false"
	none(t, "inbound", eventFindings(inbound))
	other := dcEvent(3, "Initiated", "true", "Image", `C:\x\agent.exe`, "DestinationIp", "8.8.8.8", "DestinationPort", "53")
	none(t, "another provider's 3", eventFindings(other))
}

func TestLiveDirectDNS(t *testing.T) {
	c := connView{State: "ESTABLISHED", Local: netip.MustParseAddr("10.0.0.5"), LocalPort: 50000,
		Remote: netip.MustParseAddr("9.9.9.9"), RemotePort: 53, PID: 4242, Process: "beacon.exe"}
	if hasFinding(analyzeConnection(c), "network.direct_dns") == nil {
		t.Errorf("windows: %+v", analyzeConnection(c))
	}
	c.Process = "svchost.exe"
	if hasFinding(analyzeConnection(c), "network.direct_dns") != nil {
		t.Error("the DNS client")
	}
	c.Process, c.ImagePath = "dnscat", "/tmp/dnscat"
	if hasFinding(linuxConnFindings(c), "network.direct_dns") == nil {
		t.Errorf("linux: %+v", linuxConnFindings(c))
	}
	c.Process, c.ImagePath = "systemd-resolved", "/usr/lib/systemd/systemd-resolved"
	if hasFinding(linuxConnFindings(c), "network.direct_dns") != nil {
		t.Error("systemd-resolved")
	}
}

// TestDNSTunnelOffline runs Sysmon DNS queries through the offline .evtx
// path: the per-query events carry no finding, the aggregate does.
func TestDNSTunnelOffline(t *testing.T) {
	dir := t.TempDir()
	var files []string
	for i := 0; i < 30; i++ {
		img := buildEvtx(uint64(i+1), ftJun2021+uint64(i)*10_000_000, encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{
			sysNode("Microsoft-Windows-Sysmon", 22, "Microsoft-Windows-Sysmon/Operational"),
			dataNode([2]string{"QueryName", tunnelName(i, "tun.example-c2.net")}, [2]string{"QueryStatus", "0"},
				[2]string{"Image", `C:\ProgramData\x\agent.exe`}),
		}}))
		p := filepath.Join(dir, "dns-"+itoa(i)+".evtx")
		if err := os.WriteFile(p, img, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	res := ParseEventLogFiles(context.Background(), files, nil)
	if len(res.Records) != 1 || res.Records[0].Fields["aggregation"] != "dns_tunnel" ||
		hasFinding(res.Records[0].Findings, "network.dns_tunnel") == nil || res.Records[0].Fields["image"] != `C:\ProgramData\x\agent.exe` {
		t.Fatalf("records: %+v", res.Records)
	}
}
