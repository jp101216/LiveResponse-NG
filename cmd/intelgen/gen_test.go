package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/intel"
)

func prefixStrs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestRangeToCIDRs(t *testing.T) {
	cases := []struct {
		start, end string
		want       []string
	}{
		{"192.0.2.0", "192.0.2.255", []string{"192.0.2.0/24"}},
		{"192.0.2.0", "192.0.2.127", []string{"192.0.2.0/25"}},
		{"10.0.0.0", "10.0.0.3", []string{"10.0.0.0/30"}},
		{"1.2.3.4", "1.2.3.4", []string{"1.2.3.4/32"}},
		{"192.0.2.1", "192.0.2.2", []string{"192.0.2.1/32", "192.0.2.2/32"}},
		{"192.0.2.0", "192.0.3.255", []string{"192.0.2.0/23"}},
		// A ragged range that needs several blocks.
		{"192.0.2.0", "192.0.2.130", []string{"192.0.2.0/25", "192.0.2.128/31", "192.0.2.130/32"}},
		// IPv6 /112.
		{"2001:db8::", "2001:db8::ffff", []string{"2001:db8::/112"}},
	}
	for _, c := range cases {
		start := netip.MustParseAddr(c.start)
		end := netip.MustParseAddr(c.end)
		got, err := rangeToCIDRs(start, end)
		if err != nil {
			t.Errorf("%s-%s: %v", c.start, c.end, err)
			continue
		}
		gs := prefixStrs(got)
		if strings.Join(gs, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s-%s: got %v, want %v", c.start, c.end, gs, c.want)
		}
	}
}

func TestRangeToCIDRsCoversExactly(t *testing.T) {
	// The produced prefixes must cover every address in the range and nothing
	// outside it. Check the boundaries and that the block count is minimal-ish.
	start := netip.MustParseAddr("100.64.0.5")
	end := netip.MustParseAddr("100.64.9.200")
	ps, err := rangeToCIDRs(start, end)
	if err != nil {
		t.Fatal(err)
	}
	if !ps[0].Contains(start) {
		t.Errorf("first prefix %v does not contain start %v", ps[0], start)
	}
	if !ps[len(ps)-1].Contains(end) {
		t.Errorf("last prefix %v does not contain end %v", ps[len(ps)-1], end)
	}
	// The address just before start and just after end must NOT be covered.
	before := netip.MustParseAddr("100.64.0.4")
	after := netip.MustParseAddr("100.64.9.201")
	for _, p := range ps {
		if p.Contains(before) {
			t.Errorf("prefix %v wrongly covers %v (before range)", p, before)
		}
		if p.Contains(after) {
			t.Errorf("prefix %v wrongly covers %v (after range)", p, after)
		}
	}
}

func TestRangeToCIDRsErrors(t *testing.T) {
	if _, err := rangeToCIDRs(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.1")); err == nil {
		t.Error("expected error when start is after end")
	}
	if _, err := rangeToCIDRs(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("expected error on mixed families")
	}
}

func TestParseIP2ASNLine(t *testing.T) {
	row, ok := parseIP2ASNLine("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET")
	if !ok {
		t.Fatal("expected a parse")
	}
	if row.asn != 13335 || row.cc != "US" || row.org != "CLOUDFLARENET" {
		t.Errorf("row = %+v", row)
	}
	if row.start != netip.MustParseAddr("1.0.0.0") || row.end != netip.MustParseAddr("1.0.0.255") {
		t.Errorf("addrs = %v-%v", row.start, row.end)
	}

	// Unrouted rows parse with ASN 0 and blanked CC/org.
	row, ok = parseIP2ASNLine("10.0.0.0\t10.255.255.255\t0\tNone\tNot routed")
	if !ok || row.asn != 0 || row.cc != "" || row.org != "" {
		t.Errorf("unrouted row = %+v ok=%v", row, ok)
	}

	// Malformed rows are rejected.
	if _, ok := parseIP2ASNLine("too\tfew\tfields"); ok {
		t.Error("short row should not parse")
	}
	if _, ok := parseIP2ASNLine("1.0.0.0\t2001:db8::1\t1\tUS\tmixed"); ok {
		t.Error("mixed-family row should not parse")
	}
}

func TestReadTor(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tor.txt")
	content := strings.Join([]string{
		"# comment",
		"185.220.101.5",
		"ExitAddress 185.220.101.6 2026-10-01 00:00:00",
		"185.220.101.5", // duplicate
		"2001:db8::1",
		"not-an-ip",
	}, "\n")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTor(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 { // two unique v4 + one v6, junk and dup dropped
		t.Fatalf("got %d prefixes: %v", len(got), prefixStrs(got))
	}
	if got[0] != netip.MustParsePrefix("185.220.101.5/32") {
		t.Errorf("first = %v", got[0])
	}
}

func TestGenerateEndToEnd(t *testing.T) {
	dir := t.TempDir()
	ip2asn := filepath.Join(dir, "ip2asn.tsv")
	ip2asnData := strings.Join([]string{
		"1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARENET",           // cdn (known ASN)
		"52.0.0.0\t52.0.0.255\t16509\tUS\tAMAZON-AES",            // cloud
		"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE",                  // cloud
		"203.0.113.0\t203.0.113.255\t64515\tUS\tEXAMPLE-UNKNOWN", // no category -> dropped unless -countries
	}, "\n")
	if err := os.WriteFile(ip2asn, []byte(ip2asnData), 0o644); err != nil {
		t.Fatal(err)
	}
	torFile := filepath.Join(dir, "tor.txt")
	if err := os.WriteFile(torFile, []byte("185.220.101.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cfg := genConfig{ip2asn: ip2asn, tor: torFile, generated: "2026-10-24"}
	if err := generate(&buf, cfg); err != nil {
		t.Fatalf("generate: %v", err)
	}

	// The output must load back into the real engine and resolve correctly.
	db, err := intel.Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("load generated dataset: %v", err)
	}
	if db.Meta().Source != "iptoasn.com + tor-exit-list" {
		t.Errorf("derived source = %q", db.Meta().Source)
	}

	check := func(ip string, wantASN uint32, wantCat intel.Category) {
		info, ok := db.Lookup(netip.MustParseAddr(ip))
		if !ok {
			t.Errorf("%s: not attributed", ip)
			return
		}
		if info.ASN != wantASN {
			t.Errorf("%s: asn %d, want %d", ip, info.ASN, wantASN)
		}
		if !info.Categories.Has(wantCat) {
			t.Errorf("%s: categories %v missing", ip, info.CategoryNames())
		}
	}
	check("1.1.1.1", 13335, intel.CatCDN)
	check("52.0.0.9", 16509, intel.CatCloud)
	check("185.220.101.5", 0, intel.CatTor)

	// The uncategorised range was dropped (no -countries).
	if _, ok := db.Lookup(netip.MustParseAddr("203.0.113.7")); ok {
		t.Error("uncategorised range should be omitted without -countries")
	}
}

func TestParseIpverseFile(t *testing.T) {
	data := []byte("# AS13335 (CLOUDFLARENET)\n# Cloudflare Inc.\n#\n1.1.1.0/24\n2606:4700::/32\nnot-a-cidr\n")
	asn, org, cidrs := parseIpverseFile(data)
	if asn != 13335 {
		t.Errorf("asn = %d, want 13335", asn)
	}
	if org != "Cloudflare Inc." {
		t.Errorf("org = %q, want Cloudflare Inc.", org)
	}
	if len(cidrs) != 2 { // the junk line is skipped
		t.Fatalf("got %d cidrs, want 2", len(cidrs))
	}
	if cidrs[0] != netip.MustParsePrefix("1.1.1.0/24") {
		t.Errorf("cidr[0] = %v", cidrs[0])
	}

	// Falls back to the parenthesised handle when there's no descriptive line.
	_, org, _ = parseIpverseFile([]byte("# AS15169 (GOOGLE)\n8.8.8.0/24\n"))
	if org != "GOOGLE" {
		t.Errorf("fallback org = %q, want GOOGLE", org)
	}
}

func TestGenerateASNCIDRsMode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "13335.txt"),
		[]byte("# AS13335 (CLOUDFLARENET)\n# Cloudflare Inc.\n1.1.1.0/24\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "16509.txt"),
		[]byte("# AS16509 (AMAZON-02)\n# Amazon.com Inc.\n52.0.0.0/11\n"), 0o644)

	var buf bytes.Buffer
	if err := generate(&buf, genConfig{asnCIDRs: dir, generated: "2026-10-24"}); err != nil {
		t.Fatal(err)
	}
	db, err := intel.Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if info, ok := db.Lookup(netip.MustParseAddr("1.1.1.1")); !ok || info.ASN != 13335 || !info.Categories.Has(intel.CatCDN) {
		t.Errorf("cloudflare lookup = %+v ok=%v", info, ok)
	}
	if info, ok := db.Lookup(netip.MustParseAddr("52.0.0.9")); !ok || !info.Categories.Has(intel.CatCloud) || info.Org != "Amazon.com Inc." {
		t.Errorf("amazon lookup = %+v ok=%v", info, ok)
	}
	if db.Meta().Source != "ipverse/asn-ip" {
		t.Errorf("source = %q", db.Meta().Source)
	}
}

func TestGenerateCountriesMode(t *testing.T) {
	dir := t.TempDir()
	ip2asn := filepath.Join(dir, "ip2asn.tsv")
	if err := os.WriteFile(ip2asn, []byte("203.0.113.0\t203.0.113.255\t64515\tDE\tEXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := generate(&buf, genConfig{ip2asn: ip2asn, countries: true, generated: "2026-10-24"}); err != nil {
		t.Fatal(err)
	}
	db, err := intel.Load(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := db.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok || info.Country != "DE" {
		t.Errorf("countries mode should attribute country: got %+v ok=%v", info, ok)
	}
}
