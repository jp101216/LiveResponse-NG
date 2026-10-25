package collector

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
	"github.com/jp101216/liveresponse-ng/internal/intel"
)

// intel.go — offline endpoint intelligence: attribute every public remote
// address the run observed to who owns it (ASN / organisation), where it is
// allocated (country), and what kind of infrastructure it is (cloud, CDN,
// hosting/VPS, public DNS, Tor, anonymiser), using a bundled, air-gapped dataset
// (internal/intel). Emitted as a synthetic "intel" collector result.
//
// The other collectors tell you a host talked to an address; this pass tells you
// what that address *is*. On a contained or air-gapped box a live WHOIS/geo
// lookup isn't available (and would tip off a watching attacker), so the lookup
// is a pure in-memory longest-prefix match against data compiled ahead of time.
//
// Scope is every public remote address across the real collector records — not
// only detection-linked ones — because attribution is useful context on all of
// a host's external contacts, and because an address the host reached that turns
// out to be Tor or an anonymiser is itself a lead the raw collectors can't raise.
// The socket's local side is never attributed (a host doesn't look itself up),
// and private/reserved space is skipped (nothing to attribute). Addresses are
// deduplicated across the run and each points back to the records it appeared in.
//
// Two high-signal categories raise a finding of their own: a contact with Tor
// infrastructure (T1090.003) or with a known anonymising VPN/proxy (T1090.002),
// both classic anonymised-C2 / exfiltration channels. Cloud, CDN, hosting and
// DNS are reported as context only — far too common to flag. Every finding is
// only as good as the dataset, so the result records the dataset's provenance and
// generation date; a stale lookup is visible as such, and a miss is reported as
// "not attributed" rather than guessed.
//
// Like the IOC and timeline passes it carries no build tag — it works on the
// structured results before serialisation, so it is portable and unit-tested on
// any OS — and it runs after correlation and alongside those passes, skipping
// their derived results so nothing feeds back on itself. When an "iocs" result is
// present it also writes the attribution onto each IP indicator there, so a
// blocklist ships with its "who/where/what" attached.

const (
	intelMaxAddresses = 20000 // unique addresses kept in the result
	intelSourcesMax   = 20    // source back-pointers kept per address
	intelRulesMax     = 16    // co-located rule ids kept per address
)

// intelAgg accumulates everything known about one unique public address seen in
// the run, before the dataset lookup is applied.
type intelAgg struct {
	ip        netip.Addr
	sources   []iocSource
	count     int
	coRules   map[string]bool // rules on the records where this address appeared
	coMaxSev  Severity
	coMaxRank int
}

// AnnotateIntel attributes the public remote addresses in results against db and
// returns a synthetic "intel" Result. It also enriches an "iocs" result in
// results in place, when one is present, with each IP indicator's attribution.
// db must be non-nil; callers load it (embedded or from a file) before the run.
func AnnotateIntel(results []Result, db *intel.DB) Result {
	res := NewResult("intel")
	if db == nil {
		res.SetMeta("note", "endpoint-intelligence dataset unavailable; no attribution performed")
		return res.Finish()
	}

	aggs := map[string]*intelAgg{}
	var order []string // first-seen order, for stable output among equal ranks
	for ri := range results {
		r := &results[ri]
		switch r.Collector {
		case "intel", "iocs", "timeline":
			continue // don't attribute a derived view
		}
		for i := range r.Records {
			rec := r.Records[i]
			rules, sev, rank := recordRulesAndSeverity(rec)
			for _, key := range sortedFieldKeys(rec.Fields) {
				walkIOCStrings(key, rec.Fields[key], func(field, s string) {
					ip, ok := publicAddrFromField(field, s)
					if !ok {
						return
					}
					k := ip.String()
					a := aggs[k]
					if a == nil {
						a = &intelAgg{ip: ip, coRules: map[string]bool{}}
						aggs[k] = a
						order = append(order, k)
					}
					a.count++
					if len(a.sources) < intelSourcesMax {
						a.sources = append(a.sources, iocSource{collector: r.Collector, record: i, field: field})
					}
					for _, rl := range rules {
						a.coRules[rl] = true
					}
					if rank > a.coMaxRank {
						a.coMaxRank, a.coMaxSev = rank, sev
					}
				})
			}
		}
	}

	// Resolve each address against the dataset and build its record.
	type built struct {
		fields   map[string]any
		findings []Finding
		rank     int // sort key: strongest of (own finding, co-located finding)
	}
	out := make([]built, 0, len(order))
	byCat := map[string]int{}
	byCountry := map[string]int{}
	attributed := 0
	for _, k := range order {
		a := aggs[k]
		info, found := db.Lookup(a.ip)

		fields := map[string]any{
			"address":      a.ip.String(),
			"version":      ipVersion(a.ip),
			"attributed":   found,
			"source_count": a.count,
			"sources":      sourcesToMaps(a.sources),
		}
		if a.coMaxRank > 0 {
			fields["co_max_severity"] = a.coMaxSev
			rules := sortedStringSet(a.coRules)
			if len(rules) > intelRulesMax {
				rules = rules[:intelRulesMax]
			}
			fields["co_rules"] = rules
		}

		var findings []Finding
		ownRank := 0
		if found {
			attributed++
			fields["prefix"] = info.Prefix.String()
			if info.ASN != 0 {
				fields["asn"] = info.ASN
			}
			if info.Org != "" {
				fields["org"] = info.Org
			}
			if info.Country != "" {
				fields["country"] = info.Country
				byCountry[info.Country]++
			}
			if names := info.CategoryNames(); len(names) > 0 {
				fields["categories"] = names
				for _, n := range names {
					byCat[n]++
				}
			}
			findings = intelFindings(a.ip, info)
			for _, f := range findings {
				if r := sevRank(f.Severity); r > ownRank {
					ownRank = r
				}
			}
		}

		rank := ownRank
		if a.coMaxRank > rank {
			rank = a.coMaxRank
		}
		out = append(out, built{fields: fields, findings: findings, rank: rank})
	}

	// Most interesting first: strongest finding (own or co-located), then
	// address for a stable, cleanly-diffing order.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank > out[j].rank
		}
		return out[i].fields["address"].(string) < out[j].fields["address"].(string)
	})

	total := len(out)
	truncated := false
	if len(out) > intelMaxAddresses {
		out = out[:intelMaxAddresses]
		truncated = true
	}
	for _, b := range out {
		res.Add(b.fields, b.findings...)
	}

	// Enrich an IOC result in place, so the blocklist carries attribution too.
	for ri := range results {
		if results[ri].Collector == "iocs" {
			enrichIOCsWithIntel(&results[ri], db)
		}
	}

	m := db.Meta()
	dataset := map[string]any{
		"source":    m.Source,
		"generated": m.Generated,
		"entries":   m.Entries,
		"builtin":   m.Builtin,
	}
	if m.Notes != "" {
		dataset["notes"] = m.Notes
	}
	res.SetMeta("dataset", dataset)
	res.SetMeta("note", "public remote addresses attributed against the bundled endpoint-intelligence dataset; "+
		"attribution is only as current as that dataset (generated "+nonEmpty(m.Generated, "unknown")+") — refresh it with intelgen")
	res.SetMeta("scope", "public remote addresses across collected records (local side and private/reserved space excluded)")
	res.SetMeta("addresses", len(out))
	res.SetMeta("attributed", attributed)
	res.SetMeta("by_category", byCat)
	res.SetMeta("by_country", byCountry)
	if truncated {
		res.SetMeta("addresses_total", total)
		res.SetMeta("truncated", true)
		res.SetMeta("truncation_note", "lowest-ranked addresses dropped past the cap; narrow the collectors for the full set")
	}
	return res.Finish()
}

// publicAddrFromField reports the address in a field value when it is a public IP
// worth attributing: parseable, public, and not the socket's local side.
func publicAddrFromField(field, s string) (netip.Addr, bool) {
	if iocLocalAddrFields[field] {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !aidetect.PublicAddr(ip) {
		return netip.Addr{}, false
	}
	return ip, true
}

// intelFindings raises the findings a dataset category warrants. Only the two
// anonymised-transport categories are high-signal enough to flag; the rest are
// context carried on the record's fields.
func intelFindings(ip netip.Addr, info intel.Info) []Finding {
	var fs []Finding
	if info.Categories.Has(intel.CatTor) {
		fs = append(fs, Finding{
			Rule:       "intel.tor_endpoint",
			Severity:   SevSuspect,
			Technique:  "T1090.003",
			Confidence: 75,
			Detail: fmt.Sprintf("remote address %s is Tor network infrastructure (%s); "+
				"anonymised ingress/egress is a common C2 and exfiltration channel", ip, orgOrUnknown(info)),
		})
	}
	if info.Categories.Has(intel.CatAnonymizer) {
		fs = append(fs, Finding{
			Rule:       "intel.anonymizer_endpoint",
			Severity:   SevNotable,
			Technique:  "T1090.002",
			Confidence: 55,
			Detail: fmt.Sprintf("remote address %s is a known anonymising VPN/proxy (%s); "+
				"it masks the true peer behind the connection", ip, orgOrUnknown(info)),
		})
	}
	return fs
}

// enrichIOCsWithIntel writes attribution onto each IP indicator in an iocs
// result, so an exported blocklist shows who owns each address and what it is.
func enrichIOCsWithIntel(iocs *Result, db *intel.DB) {
	for i := range iocs.Records {
		f := iocs.Records[i].Fields
		typ, _ := f["type"].(string)
		if typ != iocIPv4 && typ != iocIPv6 {
			continue
		}
		val, _ := f["value"].(string)
		ip, err := netip.ParseAddr(val)
		if err != nil {
			continue
		}
		info, ok := db.Lookup(ip.Unmap())
		if !ok {
			continue
		}
		if info.ASN != 0 {
			f["intel_asn"] = info.ASN
		}
		if info.Org != "" {
			f["intel_org"] = info.Org
		}
		if info.Country != "" {
			f["intel_country"] = info.Country
		}
		if names := info.CategoryNames(); len(names) > 0 {
			f["intel_categories"] = names
		}
	}
}

// sourcesToMaps renders back-pointers as the result's JSON shape.
func sourcesToMaps(src []iocSource) []map[string]any {
	out := make([]map[string]any, len(src))
	for i, s := range src {
		out[i] = map[string]any{"collector": s.collector, "record": s.record, "field": s.field}
	}
	return out
}

func ipVersion(ip netip.Addr) string {
	if ip.Is4() {
		return iocIPv4
	}
	return iocIPv6
}

func orgOrUnknown(info intel.Info) string {
	if info.Org != "" {
		return info.Org
	}
	return "unknown operator"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
