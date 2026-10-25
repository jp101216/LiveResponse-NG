package collector

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// iocs.go — indicator extraction: distil the detection-linked artifacts the
// other collectors gathered into one deduplicated, ranked set of indicators of
// compromise, emitted as a synthetic "iocs" collector result.
//
// Detection is where triage ends; response is where it goes next. A responder
// who has a flagged host wants the short list of things to act on across the
// rest of the fleet — the addresses to block at the firewall, the hashes to
// sweep for in the EDR, the domains to search in DNS logs. Those indicators are
// already in the report, but scattered through nested records: the remote
// address on a beaconing connection, the SHA-256 on a masquerading process, the
// cached name behind an LLM callout. This pass pulls them into one place.
//
// Scope is deliberately tight: only records that carry a finding contribute, so
// the result is the set of indicators tied to something the tool actually
// flagged — an actionable blocklist, not a full host inventory. Each indicator
// is deduplicated across every record it appeared in and ranked by the highest
// severity of the detections that referenced it, so the ones worth blocking
// first sort to the top. Every indicator points back to its source records, so
// an analyst can see why it is here before acting on it.
//
// No build tag: it works on the structured results (before serialisation, where
// addresses are still plain strings and hashes still hex), so it is portable and
// unit-tested on any OS. It is a post-pass, invoked after Correlate (so a
// cross-collector finding's indicators are captured too) and alongside the
// timeline; its own result and the timeline's are skipped, so neither feeds back
// into the other.

// Caps keep the result bounded on a badly infected or very large host.
const (
	iocsMax       = 50000 // total unique indicators kept
	iocSourcesMax = 20    // source back-pointers kept per indicator
	iocRulesMax   = 16    // contributing rule ids kept per indicator
)

// Indicator type tags (the "type" field of each record).
const (
	iocIPv4     = "ipv4"
	iocIPv6     = "ipv6"
	iocDomain   = "domain"
	iocSHA256   = "sha256"
	iocSHA1     = "sha1"
	iocFilePath = "filepath"
)

var (
	reHex64          = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reHex40          = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	reFilePathPrefix = regexp.MustCompile(`^(?:[A-Za-z]:\\|\\\\[^\\?.])`) // drive path or UNC share
	rePosixPath      = regexp.MustCompile(`^/[^/\x00]+(?:/[^/\x00]+)+$`)  // absolute, at least two components
	reDomainName     = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}\.?$`)
)

// iocPathFields are the record fields whose value, when it has the shape of a
// file-system path, is an on-disk indicator worth extracting. Registry keys and
// task paths live in other fields (task_path, key names) and don't have this
// shape, so they are not mistaken for files.
var iocPathFields = map[string]bool{
	"image_path": true, "image_path_raw": true, "image": true,
	"path": true, "program": true, "server": true, "dll": true,
	"library": true, "suspicious_modules": true, "deleted_modules": true,
}

// iocLocalAddrFields hold the host's own endpoint of a socket, not a remote
// indicator, so IPs there are not extracted (a host doesn't block itself).
var iocLocalAddrFields = map[string]bool{
	"local_addr": true, "local_address": true,
}

// iocSource is one place an indicator was seen: a back-pointer into
// results[].records[], plus the field it came from.
type iocSource struct {
	collector string
	record    int
	field     string
}

// iocAgg accumulates everything known about one unique indicator across the run.
type iocAgg struct {
	typ     string
	value   string // display value (canonical for IPs; first-seen original for paths)
	sources []iocSource
	count   int // total occurrences (may exceed len(sources) once capped)
	rules   map[string]bool
	maxSev  Severity
	maxRank int
}

// ExtractIOCs distils the indicators out of every detection-linked record into
// one deduplicated, ranked Result. Safe to call on any result set; callers run
// it after collection and correlation, so the indicators reflect the findings
// as finally scored. The result carries no findings of its own, so it does not
// inflate the report's finding counts.
func ExtractIOCs(results []Result) Result {
	res := NewResult("iocs")
	res.SetMeta("note", "deduplicated indicators drawn from records that carry a finding, ranked by the "+
		"highest severity of the detections referencing each; every indicator points back to its source records")
	res.SetMeta("scope", "detection-linked artifacts (records with at least one finding)")

	aggs := map[string]*iocAgg{}
	for ri := range results {
		r := &results[ri]
		if r.Collector == "iocs" || r.Collector == "timeline" {
			continue // don't fold a derived view back into this one
		}
		for i := range r.Records {
			rec := r.Records[i]
			if len(rec.Findings) == 0 {
				continue // detection-linked only
			}
			rules, sev, rank := recordRulesAndSeverity(rec)
			if rank < sevRank(SevNotable) {
				continue // info-level annotations don't make an artifact an indicator
			}
			emit := func(typ, norm, display, field string) {
				key := typ + "\x00" + norm
				a := aggs[key]
				if a == nil {
					a = &iocAgg{typ: typ, value: display, rules: map[string]bool{}}
					aggs[key] = a
				}
				a.count++
				if len(a.sources) < iocSourcesMax {
					a.sources = append(a.sources, iocSource{collector: r.Collector, record: i, field: field})
				}
				for _, rl := range rules {
					a.rules[rl] = true
				}
				if rank > a.maxRank {
					a.maxRank, a.maxSev = rank, sev
				}
			}
			extractRecordIOCs(r.Collector, rec, emit)
		}
	}

	list := make([]*iocAgg, 0, len(aggs))
	for _, a := range aggs {
		list = append(list, a)
	}
	// Rank: most severe first, then by type and value, so the output is both
	// triage-ordered and stable across runs (reports diff cleanly).
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].maxRank != list[j].maxRank {
			return list[i].maxRank > list[j].maxRank
		}
		if list[i].typ != list[j].typ {
			return list[i].typ < list[j].typ
		}
		return strings.ToLower(list[i].value) < strings.ToLower(list[j].value)
	})

	total := len(list)
	truncated := false
	if len(list) > iocsMax {
		list = list[:iocsMax] // keep the most severe
		truncated = true
	}

	byType := map[string]int{}
	for _, a := range list {
		byType[a.typ]++
		rules := sortedStringSet(a.rules)
		if len(rules) > iocRulesMax {
			rules = rules[:iocRulesMax]
		}
		srcs := make([]map[string]any, len(a.sources))
		for k, s := range a.sources {
			srcs[k] = map[string]any{"collector": s.collector, "record": s.record, "field": s.field}
		}
		res.Add(map[string]any{
			"type":         a.typ,
			"value":        a.value,
			"max_severity": a.maxSev,
			"rules":        rules,
			"sources":      srcs,
			"source_count": a.count,
		})
	}

	res.SetMeta("indicators", len(list))
	res.SetMeta("indicators_total", total)
	res.SetMeta("by_type", byType)
	if truncated {
		res.SetMeta("truncated", true)
		res.SetMeta("truncation_note", "lowest-severity indicators dropped past the cap; narrow the collectors for the full set")
	}
	return res.Finish()
}

// extractRecordIOCs walks one record's fields and emits every indicator it
// carries. The collector name scopes which fields are read as hostnames (so a
// process named like a domain isn't mistaken for one).
func extractRecordIOCs(collectorName string, rec Record, emit func(typ, norm, display, field string)) {
	for _, key := range sortedFieldKeys(rec.Fields) {
		walkIOCStrings(key, rec.Fields[key], func(field, s string) {
			classifyIOC(collectorName, field, s, emit)
		})
	}
}

// classifyIOC decides what kind of indicator a single (field, value) pair is, if
// any, and emits it normalised. The order matters: an IP is tried before a
// domain (so a numeric address isn't read as a name), and the exact shapes
// (hash, path) gate on both the field and the value so ordinary text doesn't
// masquerade as an indicator.
func classifyIOC(collectorName, field, s string, emit func(typ, norm, display, field string)) {
	v := strings.TrimSpace(s)
	if v == "" {
		return
	}

	// IP address: a remote or resolved endpoint. Public only (a host doesn't
	// block itself or RFC1918 space), and never the socket's local side.
	if ip, err := netip.ParseAddr(v); err == nil {
		if iocLocalAddrFields[field] || !aidetect.PublicAddr(ip) {
			return
		}
		ip = ip.Unmap()
		typ := iocIPv6
		if ip.Is4() {
			typ = iocIPv4
		}
		emit(typ, ip.String(), ip.String(), field)
		return
	}

	// File hash: unambiguous by shape (bare hex of the right length).
	switch {
	case reHex64.MatchString(v):
		emit(iocSHA256, strings.ToLower(v), strings.ToLower(v), field)
		return
	case reHex40.MatchString(v):
		emit(iocSHA1, strings.ToLower(v), strings.ToLower(v), field)
		return
	}

	// Hostname: only from fields that hold one, so arbitrary dotted text isn't
	// swept up as a domain.
	if fieldIsDomainBearing(collectorName, field) && isDomainName(v) {
		norm := strings.ToLower(strings.TrimSuffix(v, "."))
		emit(iocDomain, norm, norm, field)
		return
	}

	// On-disk path: a dropper or payload location, from a path-bearing field.
	// Windows paths are case-insensitive, so they dedupe case-folded; POSIX
	// paths are case-sensitive and dedupe as written. A Linux path the kernel
	// marked " (deleted)" is the location the payload ran from, so the marker
	// is dropped; a memfd is no location at all.
	if !iocPathFields[field] {
		return
	}
	switch {
	case reFilePathPrefix.MatchString(v):
		emit(iocFilePath, strings.ToLower(v), v, field)
	case strings.HasPrefix(v, "/"):
		p := strings.TrimSuffix(v, deletedSuffix)
		if !isMemfdPath(p) && rePosixPath.MatchString(p) {
			emit(iocFilePath, p, p, field)
		}
	}
}

// walkIOCStrings yields every string value reachable from a field value,
// descending into the nested maps (event_data/user_data) and slices records
// use. Maps are walked in sorted key order so captured sources are
// deterministic. The yielded field is the leaf key, so a value in
// event_data.IpAddress is seen under "IpAddress".
func walkIOCStrings(key string, v any, visit func(field, s string)) {
	switch x := v.(type) {
	case string:
		visit(key, x)
	case []string:
		for _, s := range x {
			visit(key, s)
		}
	case []any:
		for _, e := range x {
			walkIOCStrings(key, e, visit)
		}
	case map[string]string:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			visit(k, x[k])
		}
	case map[string]any:
		for _, k := range sortedFieldKeys(x) {
			walkIOCStrings(k, x[k], visit)
		}
	}
}

// recordRulesAndSeverity returns the distinct rule ids on a record (sorted) and
// the highest severity among its findings.
func recordRulesAndSeverity(rec Record) ([]string, Severity, int) {
	seen := map[string]bool{}
	var rules []string
	var maxSev Severity
	maxRank := 0
	for _, f := range rec.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			rules = append(rules, f.Rule)
		}
		if r := sevRank(f.Severity); r > maxRank {
			maxRank, maxSev = r, f.Severity
		}
	}
	sort.Strings(rules)
	return rules, maxSev, maxRank
}

// fieldIsDomainBearing reports whether a field holds a hostname. The DNS cache's
// "name" is one; a connection's correlated "remote_hosts" are; a bare "name"
// anywhere else (a process, a service) is not.
func fieldIsDomainBearing(collectorName, field string) bool {
	switch field {
	case "remote_hosts", "hostnames", "dns_name":
		return true
	case "name":
		return collectorName == "dnscache"
	}
	return false
}

// isDomainName reports whether s has the shape of a DNS hostname (at least one
// dot, an alphabetic-leading TLD, valid labels) and is not an IP literal.
func isDomainName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(s, ".")); err == nil {
		return false // it's an address, not a name
	}
	return reDomainName.MatchString(s)
}

// sortedStringSet returns the keys of a set, sorted.
func sortedStringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
