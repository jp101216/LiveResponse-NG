package intel

import (
	"net/netip"
	"strings"
	"testing"
)

// loadString is a test helper: parse a dataset from a literal.
func loadString(t *testing.T, s string) *DB {
	t.Helper()
	db, err := Load(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return db
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

func TestLookupLongestPrefixWins(t *testing.T) {
	db := loadString(t, strings.Join([]string{
		"10.0.0.0/8\t1\tUS\thosting\tBroad",
		"10.1.0.0/16\t2\tUS\tcloud\tNarrow",
		"10.1.2.0/24\t3\tUS\tcdn\tNarrowest",
	}, "\n"))

	cases := []struct {
		ip      string
		wantASN uint32
		wantOrg string
	}{
		{"10.1.2.5", 3, "Narrowest"}, // most specific /24
		{"10.1.9.9", 2, "Narrow"},    // falls back to /16
		{"10.9.9.9", 1, "Broad"},     // falls back to /8
	}
	for _, c := range cases {
		info, ok := db.Lookup(mustAddr(t, c.ip))
		if !ok {
			t.Fatalf("%s: expected a match", c.ip)
		}
		if info.ASN != c.wantASN || info.Org != c.wantOrg {
			t.Errorf("%s: got AS%d %q, want AS%d %q", c.ip, info.ASN, info.Org, c.wantASN, c.wantOrg)
		}
	}
}

func TestLookupMiss(t *testing.T) {
	db := loadString(t, "203.0.113.0/24\t64496\tUS\thosting\tExample")
	if _, ok := db.Lookup(mustAddr(t, "198.51.100.1")); ok {
		t.Error("expected no match for an address outside every prefix")
	}
	// Empty DB attributes nothing.
	empty := loadString(t, "# just a comment\n")
	if _, ok := empty.Lookup(mustAddr(t, "8.8.8.8")); ok {
		t.Error("empty dataset should match nothing")
	}
}

func TestLookupDefaultRouteAndHostRoute(t *testing.T) {
	db := loadString(t, strings.Join([]string{
		"0.0.0.0/0\t0\t\thosting\tDefault",
		"192.0.2.7/32\t64500\tGB\ttor\tHostRoute",
	}, "\n"))
	// /0 catches everything not otherwise matched.
	if info, ok := db.Lookup(mustAddr(t, "123.45.67.89")); !ok || info.Org != "Default" {
		t.Errorf("default route: got %+v ok=%v", info, ok)
	}
	// /32 is the most specific possible.
	info, ok := db.Lookup(mustAddr(t, "192.0.2.7"))
	if !ok || info.Org != "HostRoute" || !info.Categories.Has(CatTor) {
		t.Errorf("host route: got %+v ok=%v", info, ok)
	}
}

func TestLookupIPv6AndMappedV4(t *testing.T) {
	db := loadString(t, strings.Join([]string{
		"2606:4700::/32\t13335\t\tcdn,dns\tCloudflare",
		"8.8.8.0/24\t15169\t\tdns\tGoogle",
	}, "\n"))

	if info, ok := db.Lookup(mustAddr(t, "2606:4700:4700::1111")); !ok || info.ASN != 13335 {
		t.Errorf("v6 lookup: got %+v ok=%v", info, ok)
	}
	// An IPv4-mapped IPv6 address must resolve via the v4 table.
	if info, ok := db.Lookup(mustAddr(t, "::ffff:8.8.8.8")); !ok || info.ASN != 15169 {
		t.Errorf("v4-mapped v6 lookup: got %+v ok=%v", info, ok)
	}
}

func TestMaskHelpers(t *testing.T) {
	// /23 straddles a byte boundary: second-to-last bit of byte 1 is the edge.
	in4 := [4]byte{10, 1, 3, 200}
	if got := mask4(in4, 23); got != [4]byte{10, 1, 2, 0} {
		t.Errorf("mask4 /23 = %v, want [10 1 2 0]", got)
	}
	if got := mask4(in4, 0); got != [4]byte{} {
		t.Errorf("mask4 /0 = %v, want zero", got)
	}
	if got := mask4(in4, 32); got != in4 {
		t.Errorf("mask4 /32 = %v, want unchanged", got)
	}
	var in6 [16]byte
	in6[0], in6[1], in6[2] = 0xff, 0xff, 0xff
	got := mask6(in6, 12)
	want := [16]byte{}
	want[0], want[1] = 0xff, 0xf0
	if got != want {
		t.Errorf("mask6 /12 = %v, want %v", got, want)
	}
}

func TestParseFieldsTolerant(t *testing.T) {
	db := loadString(t, strings.Join([]string{
		"# source: unit-test",
		"# generated: 2026-01-02",
		"# notes: hello world",
		"",
		"not-a-cidr\t1\tUS\tcloud\tJunk", // skipped
		"1.2.3.0/24\tAS7\tus\tcloud,boguscat\tLower CC and AS-prefix",
		"4.5.6.0/24\t\t\t\t", // minimal: CIDR only
	}, "\n"))

	m := db.Meta()
	if m.Source != "unit-test" || m.Generated != "2026-01-02" || m.Notes != "hello world" {
		t.Errorf("meta not parsed: %+v", m)
	}
	if m.Entries != 2 { // the junk line is skipped
		t.Errorf("entries = %d, want 2", m.Entries)
	}
	info, ok := db.Lookup(mustAddr(t, "1.2.3.4"))
	if !ok {
		t.Fatal("expected match for 1.2.3.4")
	}
	if info.ASN != 7 {
		t.Errorf("AS-prefixed ASN parse: got %d, want 7", info.ASN)
	}
	if info.Country != "US" { // lower-cased input normalised
		t.Errorf("CC normalise: got %q, want US", info.Country)
	}
	if !info.Categories.Has(CatCloud) {
		t.Error("expected cloud category")
	}
	if names := info.CategoryNames(); len(names) != 1 || names[0] != "cloud" {
		t.Errorf("unknown category should be dropped: got %v", names)
	}
}

func TestParseASNForms(t *testing.T) {
	for in, want := range map[string]uint32{
		"":        0,
		"0":       0,
		"13335":   13335,
		"AS13335": 13335,
		"as13335": 13335,
		"garbage": 0,
	} {
		if got := parseASN(in); got != want {
			t.Errorf("parseASN(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestCategoryNamesOrder(t *testing.T) {
	set := CatAnonymizer | CatCloud | CatDNS // deliberately out of canonical order
	got := set.Names()
	want := []string{"cloud", "dns", "anonymizer"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Names() = %v, want %v (canonical order)", got, want)
	}
}

func TestLastPrefixWins(t *testing.T) {
	// A later duplicate of the same prefix overrides the earlier one, so an
	// overlay can refine a base dataset.
	db := loadString(t, strings.Join([]string{
		"5.5.5.0/24\t1\tUS\thosting\tBase",
		"5.5.5.0/24\t2\tUS\thosting,tor\tOverlay",
	}, "\n"))
	info, ok := db.Lookup(mustAddr(t, "5.5.5.5"))
	if !ok || info.ASN != 2 || !info.Categories.Has(CatTor) {
		t.Errorf("last-wins override failed: got %+v ok=%v", info, ok)
	}
}

func TestBuiltinDatasetSane(t *testing.T) {
	db, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if !db.Meta().Builtin {
		t.Error("builtin meta should have Builtin=true")
	}
	if db.Meta().Entries < 100 {
		t.Errorf("seed looks too small: %d entries", db.Meta().Entries)
	}
	if db.Meta().Source == "" || db.Meta().Generated == "" {
		t.Errorf("seed is missing provenance: %+v", db.Meta())
	}

	// Spot-check a few well-known, stable allocations in the seed.
	spot := []struct {
		ip   string
		asn  uint32
		cat  Category
		note string
	}{
		{"1.1.1.1", 13335, CatDNS, "Cloudflare resolver"},
		{"8.8.8.8", 15169, CatDNS, "Google resolver"},
		{"151.101.1.1", 54113, CatCDN, "Fastly edge"},
		{"128.31.0.39", 3, CatTor, "Tor directory authority"},
	}
	for _, s := range spot {
		info, ok := db.Lookup(mustAddr(t, s.ip))
		if !ok {
			t.Errorf("%s (%s): not attributed by seed", s.ip, s.note)
			continue
		}
		if info.ASN != s.asn {
			t.Errorf("%s: ASN %d, want %d", s.ip, info.ASN, s.asn)
		}
		if !info.Categories.Has(s.cat) {
			t.Errorf("%s: categories %v missing %v", s.ip, info.CategoryNames(), s.cat)
		}
	}
}

func TestBuiltinPrefixReported(t *testing.T) {
	db, _ := Builtin()
	info, ok := db.Lookup(mustAddr(t, "8.8.8.8"))
	if !ok {
		t.Fatal("8.8.8.8 should be attributed")
	}
	// The matched prefix should contain the queried address and be the /24.
	if !info.Prefix.Contains(mustAddr(t, "8.8.8.8")) {
		t.Errorf("matched prefix %v does not contain the query", info.Prefix)
	}
	if info.Prefix.Bits() != 24 {
		t.Errorf("expected a /24 match for 8.8.8.0/24, got %v", info.Prefix)
	}
}
