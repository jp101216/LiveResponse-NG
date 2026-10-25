package collector

import (
	"strings"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/intel"
)

// testIntelDB builds a small dataset covering public test ranges. The TEST-NET
// blocks (192.0.2/24, 198.51.100/24, 203.0.113/24) are globally-unicast and so
// count as "public" to the address filter, which makes them safe, stable
// fixtures that never touch a real network.
func testIntelDB(t *testing.T) *intel.DB {
	t.Helper()
	db, err := intel.Load(strings.NewReader(strings.Join([]string{
		"# source: unit-test",
		"# generated: 2026-02-03",
		"192.0.2.0/24\t64500\tUS\thosting\tTest Host",
		"198.51.100.0/24\t64510\tNL\tanonymizer\tTest VPN",
		"203.0.113.0/24\t64515\tUS\tcloud\tTest Cloud",
		"185.220.100.0/22\t0\tDE\ttor\tTest Tor",
	}, "\n")))
	if err != nil {
		t.Fatalf("load test db: %v", err)
	}
	return db
}

// findIntelRecord returns the intel result record for an address, or nil.
func findIntelRecord(res Result, addr string) map[string]any {
	for _, rec := range res.Records {
		if a, _ := rec.Fields["address"].(string); a == addr {
			return rec.Fields
		}
	}
	return nil
}

func recordByAddr(res Result, addr string) (Record, bool) {
	for _, rec := range res.Records {
		if a, _ := rec.Fields["address"].(string); a == addr {
			return rec, true
		}
	}
	return Record{}, false
}

func TestAnnotateIntelAttributes(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "203.0.113.7", "local_addr": "192.168.1.5"})
	res := AnnotateIntel([]Result{net.Finish()}, db)

	f := findIntelRecord(res, "203.0.113.7")
	if f == nil {
		t.Fatal("203.0.113.7 should be attributed")
	}
	if f["attributed"] != true {
		t.Errorf("attributed = %v, want true", f["attributed"])
	}
	if f["asn"].(uint32) != 64515 {
		t.Errorf("asn = %v, want 64515", f["asn"])
	}
	if f["country"].(string) != "US" {
		t.Errorf("country = %v, want US", f["country"])
	}
	if f["version"].(string) != "ipv4" {
		t.Errorf("version = %v, want ipv4", f["version"])
	}
	cats := f["categories"].([]string)
	if len(cats) != 1 || cats[0] != "cloud" {
		t.Errorf("categories = %v, want [cloud]", cats)
	}
	// The private local address must not appear.
	if findIntelRecord(res, "192.168.1.5") != nil {
		t.Error("private local address should not be attributed")
	}
}

func TestAnnotateIntelExcludesLocalAndPrivate(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	// A public address, but on the socket's local side — the host doesn't look
	// itself up.
	net.Add(map[string]any{"remote_addr": "203.0.113.7", "local_addr": "198.51.100.9"})
	res := AnnotateIntel([]Result{net.Finish()}, db)

	if findIntelRecord(res, "198.51.100.9") != nil {
		t.Error("a public address in a local_addr field must be excluded")
	}
	if findIntelRecord(res, "203.0.113.7") == nil {
		t.Error("the remote address should still be attributed")
	}
}

func TestAnnotateIntelTorAndAnonymizerFindings(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "185.220.101.5"}) // tor
	net.Add(map[string]any{"remote_addr": "198.51.100.9"})  // anonymizer
	net.Add(map[string]any{"remote_addr": "203.0.113.7"})   // cloud: context only
	res := AnnotateIntel([]Result{net.Finish()}, db)

	tor, ok := recordByAddr(res, "185.220.101.5")
	if !ok {
		t.Fatal("Tor address not in result")
	}
	torF := hasFinding(tor.Findings, "intel.tor_endpoint")
	if torF == nil {
		t.Fatal("expected intel.tor_endpoint finding on the Tor address")
	}
	if torF.Severity != SevSuspect {
		t.Errorf("tor finding severity = %v, want suspect", torF.Severity)
	}
	if torF.Technique != "T1090.003" {
		t.Errorf("tor technique = %v, want T1090.003", torF.Technique)
	}
	anon, ok := recordByAddr(res, "198.51.100.9")
	if !ok || hasFinding(anon.Findings, "intel.anonymizer_endpoint") == nil {
		t.Error("expected intel.anonymizer_endpoint finding on the VPN address")
	}
	cloud, _ := recordByAddr(res, "203.0.113.7")
	if len(cloud.Findings) != 0 {
		t.Errorf("cloud address should carry no finding, got %v", cloud.Findings)
	}
}

func TestAnnotateIntelSortsHighSignalFirst(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "203.0.113.7"})   // cloud (rank 0)
	net.Add(map[string]any{"remote_addr": "185.220.101.5"}) // tor (suspect)
	res := AnnotateIntel([]Result{net.Finish()}, db)

	if len(res.Records) < 2 {
		t.Fatalf("expected 2 records, got %d", len(res.Records))
	}
	if a, _ := res.Records[0].Fields["address"].(string); a != "185.220.101.5" {
		t.Errorf("highest-signal address should sort first, got %q", a)
	}
}

func TestAnnotateIntelDedupAndSources(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(
		map[string]any{"remote_addr": "203.0.113.7"},
		Finding{Rule: "net.beacon", Severity: SevSuspect, Confidence: 80, Detail: "x"},
	)
	dns := NewResult("dnscache")
	dns.Add(map[string]any{"resolved_addr": "203.0.113.7"})

	res := AnnotateIntel([]Result{net.Finish(), dns.Finish()}, db)
	f := findIntelRecord(res, "203.0.113.7")
	if f == nil {
		t.Fatal("expected a single deduplicated record")
	}
	if f["source_count"].(int) != 2 {
		t.Errorf("source_count = %v, want 2", f["source_count"])
	}
	srcs := f["sources"].([]map[string]any)
	if len(srcs) != 2 {
		t.Errorf("sources len = %d, want 2", len(srcs))
	}
	// The co-located finding on one of the source records should be carried.
	if f["co_max_severity"] != SevSuspect {
		t.Errorf("co_max_severity = %v, want suspect", f["co_max_severity"])
	}
	coRules := f["co_rules"].([]string)
	if len(coRules) != 1 || coRules[0] != "net.beacon" {
		t.Errorf("co_rules = %v, want [net.beacon]", coRules)
	}
	// Exactly one intel record total (deduped).
	if len(res.Records) != 1 {
		t.Errorf("expected 1 record, got %d", len(res.Records))
	}
}

func TestAnnotateIntelEnrichesIOCs(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "203.0.113.7"})
	iocs := NewResult("iocs")
	iocs.Add(map[string]any{"type": "ipv4", "value": "203.0.113.7", "max_severity": SevSuspect})
	iocs.Add(map[string]any{"type": "domain", "value": "evil.example"})

	results := []Result{net.Finish(), iocs.Finish()}
	_ = AnnotateIntel(results, db)

	// results[1] is the iocs result, enriched in place.
	ioc := results[1].Records[0].Fields
	if ioc["intel_asn"].(uint32) != 64515 {
		t.Errorf("iocs enrichment intel_asn = %v, want 64515", ioc["intel_asn"])
	}
	if ioc["intel_org"].(string) != "Test Cloud" {
		t.Errorf("intel_org = %v, want Test Cloud", ioc["intel_org"])
	}
	if ioc["intel_country"].(string) != "US" {
		t.Errorf("intel_country = %v, want US", ioc["intel_country"])
	}
	// The domain indicator is untouched.
	if _, ok := results[1].Records[1].Fields["intel_asn"]; ok {
		t.Error("domain indicator should not be enriched")
	}
}

func TestAnnotateIntelSkipsDerivedViews(t *testing.T) {
	db := testIntelDB(t)
	// An address that appears ONLY inside a derived view must not be attributed
	// (those records are not real observations).
	tl := NewResult("timeline")
	tl.Add(map[string]any{"detail": "203.0.113.7 at 12:00"})
	res := AnnotateIntel([]Result{tl.Finish()}, db)
	if len(res.Records) != 0 {
		t.Errorf("derived-view addresses should be skipped, got %d records", len(res.Records))
	}
}

func TestAnnotateIntelMetaProvenance(t *testing.T) {
	db := testIntelDB(t)
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "203.0.113.7"})
	net.Add(map[string]any{"remote_addr": "185.220.101.5"})
	net.Add(map[string]any{"remote_addr": "100.64.0.1"}) // CGNAT-shared: PublicAddr keeps it matchable, but it isn't in the dataset -> not attributed
	res := AnnotateIntel([]Result{net.Finish()}, db)

	ds, ok := res.Meta["dataset"].(map[string]any)
	if !ok {
		t.Fatal("dataset meta missing")
	}
	if ds["source"] != "unit-test" || ds["generated"] != "2026-02-03" {
		t.Errorf("dataset provenance wrong: %+v", ds)
	}
	if res.Meta["addresses"].(int) < 2 {
		t.Errorf("addresses meta = %v", res.Meta["addresses"])
	}
	byCat := res.Meta["by_category"].(map[string]int)
	if byCat["cloud"] != 1 || byCat["tor"] != 1 {
		t.Errorf("by_category = %v", byCat)
	}
}

func TestAnnotateIntelNilDB(t *testing.T) {
	net := NewResult("network")
	net.Add(map[string]any{"remote_addr": "203.0.113.7"})
	res := AnnotateIntel([]Result{net.Finish()}, nil)
	if res.Collector != "intel" {
		t.Errorf("collector = %q, want intel", res.Collector)
	}
	if len(res.Records) != 0 {
		t.Error("nil db should attribute nothing")
	}
	if _, ok := res.Meta["note"]; !ok {
		t.Error("nil db should set an explanatory note")
	}
}
