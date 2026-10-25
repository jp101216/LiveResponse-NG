package collector

import (
	"testing"
)

// finding is a tiny helper to attach a finding to a record in these tests.
func finding(rule string, sev Severity) Finding {
	return Finding{Rule: rule, Severity: sev, Confidence: 50, Detail: rule}
}

// iocByValue indexes an iocs Result's records by (type,value) for assertions.
func iocByValue(res Result) map[string]Record {
	m := map[string]Record{}
	for _, rec := range res.Records {
		typ, _ := rec.Fields["type"].(string)
		val, _ := rec.Fields["value"].(string)
		m[typ+"|"+val] = rec
	}
	return m
}

func recField[T any](t *testing.T, rec Record, key string) T {
	t.Helper()
	v, ok := rec.Fields[key].(T)
	if !ok {
		t.Fatalf("field %q missing or wrong type (have %T)", key, rec.Fields[key])
	}
	return v
}

func TestExtractIOCs_NetworkAndDomain(t *testing.T) {
	results := []Result{{
		Collector: "network",
		Records: []Record{{
			Fields: map[string]any{
				"remote_addr":  "203.0.113.7",
				"local_addr":   "192.168.1.10", // host's own side: not an indicator
				"remote_hosts": []string{"c2.evil.example", "203.0.113.7"},
				"remote_port":  443,
			},
			Findings: []Finding{finding("network.lolbin_outbound", SevSuspect)},
		}},
	}}

	got := iocByValue(ExtractIOCs(results))

	if _, ok := got["ipv4|203.0.113.7"]; !ok {
		t.Fatalf("expected the public remote address to be extracted; got keys %v", keysOf(got))
	}
	if _, ok := got["ipv4|192.168.1.10"]; ok {
		t.Errorf("local_addr (and a private RFC1918 address) must not be extracted")
	}
	if _, ok := got["domain|c2.evil.example"]; !ok {
		t.Errorf("expected the correlated remote hostname to be extracted as a domain")
	}
	// The IP sitting in remote_hosts should classify as an IP, never a domain.
	if _, ok := got["domain|203.0.113.7"]; ok {
		t.Errorf("an address in a hostname field must not be recorded as a domain")
	}

	ipRec := got["ipv4|203.0.113.7"]
	if sev := recField[Severity](t, ipRec, "max_severity"); sev != SevSuspect {
		t.Errorf("max_severity = %q, want suspect", sev)
	}
	rules := recField[[]string](t, ipRec, "rules")
	if len(rules) != 1 || rules[0] != "network.lolbin_outbound" {
		t.Errorf("rules = %v, want [network.lolbin_outbound]", rules)
	}
}

func TestExtractIOCs_DedupAndEscalation(t *testing.T) {
	// The same address appears twice: once suspect, once critical. It should
	// collapse to one indicator carrying the higher severity, both rules, and a
	// source count of 2.
	results := []Result{{
		Collector: "network",
		Records: []Record{
			{
				Fields:   map[string]any{"remote_addr": "198.51.100.5"},
				Findings: []Finding{finding("network.script_host_outbound", SevNotable)},
			},
			{
				Fields:   map[string]any{"remote_addr": "198.51.100.5"},
				Findings: []Finding{finding("ai.llm_callout", SevCritical)},
			},
		},
	}}

	res := ExtractIOCs(results)
	got := iocByValue(res)
	rec, ok := got["ipv4|198.51.100.5"]
	if !ok {
		t.Fatalf("address not extracted")
	}
	if n := recField[int](t, rec, "source_count"); n != 2 {
		t.Errorf("source_count = %d, want 2", n)
	}
	if sev := recField[Severity](t, rec, "max_severity"); sev != SevCritical {
		t.Errorf("max_severity = %q, want critical (the higher of the two)", sev)
	}
	rules := recField[[]string](t, rec, "rules")
	if len(rules) != 2 {
		t.Errorf("rules = %v, want both contributing rules", rules)
	}
	srcs := recField[[]map[string]any](t, rec, "sources")
	if len(srcs) != 2 {
		t.Errorf("sources = %v, want 2 back-pointers", srcs)
	}
	// Only one unique indicator overall.
	if len(res.Records) != 1 {
		t.Errorf("records = %d, want 1 deduplicated indicator", len(res.Records))
	}
}

func TestExtractIOCs_HashesAndPaths(t *testing.T) {
	const sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	results := []Result{{
		Collector: "processes",
		Records: []Record{{
			Fields: map[string]any{
				"name":         "svchost.exe",
				"image_path":   `C:\Users\Public\svchost.exe`,
				"image_sha256": sha256,
				"sha1":         sha1,
				"command_line": `svchost.exe -k netsvcs`, // not an indicator field
			},
			Findings: []Finding{finding("process.masquerade_path", SevCritical)},
		}},
	}}

	got := iocByValue(ExtractIOCs(results))
	if _, ok := got["sha256|"+sha256]; !ok {
		t.Errorf("sha256 not extracted")
	}
	if _, ok := got["sha1|"+sha1]; !ok {
		t.Errorf("sha1 not extracted")
	}
	// iocByValue indexes on the display value, which keeps the original casing
	// even though dedup is case-insensitive.
	rec, ok := got[`filepath|C:\Users\Public\svchost.exe`]
	if !ok {
		t.Fatalf("image path not extracted as a filepath indicator; keys %v", keysOf(got))
	}
	if v := recField[string](t, rec, "value"); v != `C:\Users\Public\svchost.exe` {
		t.Errorf("filepath value = %q, want original casing preserved", v)
	}
}

func TestExtractIOCs_FilePathCaseInsensitiveDedup(t *testing.T) {
	// Windows paths differing only in case are one indicator.
	results := []Result{{
		Collector: "processes",
		Records: []Record{
			{
				Fields:   map[string]any{"image_path": `C:\Temp\Beacon.exe`},
				Findings: []Finding{finding("process.unusual_path", SevSuspect)},
			},
			{
				Fields:   map[string]any{"image_path": `c:\temp\beacon.exe`},
				Findings: []Finding{finding("modules.unusual_path", SevNotable)},
			},
		},
	}}
	res := ExtractIOCs(results)
	if n := len(res.Records); n != 1 {
		t.Fatalf("records = %d, want 1 (case-insensitive dedup)", n)
	}
	if n := recField[int](t, res.Records[0], "source_count"); n != 2 {
		t.Errorf("source_count = %d, want 2", n)
	}
}

func TestExtractIOCs_OnlyDetectionLinked(t *testing.T) {
	// A record with no findings contributes nothing, even though it holds a
	// perfectly good public address and hash.
	results := []Result{{
		Collector: "network",
		Records: []Record{{
			Fields: map[string]any{"remote_addr": "203.0.113.200"},
			// no findings
		}},
	}}
	res := ExtractIOCs(results)
	if len(res.Records) != 0 {
		t.Errorf("records = %d, want 0 (nothing was flagged)", len(res.Records))
	}
}

func TestExtractIOCs_DomainFieldScoping(t *testing.T) {
	// A process literally named like a domain must not become a domain
	// indicator; the dnscache "name" field, however, is a hostname.
	results := []Result{
		{
			Collector: "processes",
			Records: []Record{{
				Fields:   map[string]any{"name": "update.example.com"},
				Findings: []Finding{finding("process.unusual_path", SevNotable)},
			}},
		},
		{
			Collector: "dnscache",
			Records: []Record{{
				Fields:   map[string]any{"name": "api.openai.com", "addresses": []string{"203.0.113.9"}},
				Findings: []Finding{finding("ai.llm_dns_cache", SevNotable)},
			}},
		},
	}
	got := iocByValue(ExtractIOCs(results))
	if _, ok := got["domain|update.example.com"]; ok {
		t.Errorf("a process name must not be read as a domain")
	}
	if _, ok := got["domain|api.openai.com"]; !ok {
		t.Errorf("a dnscache name should be read as a domain")
	}
	if _, ok := got["ipv4|203.0.113.9"]; !ok {
		t.Errorf("a resolved address in dnscache.addresses should be extracted")
	}
}

func TestExtractIOCs_RegistryAndTaskPathsNotFiles(t *testing.T) {
	// Values that aren't file paths (a task path, a registry key) must not be
	// recorded as filepath indicators.
	results := []Result{{
		Collector: "scheduledtasks",
		Records: []Record{{
			Fields: map[string]any{
				"path":      `\Microsoft\Windows\Updater`,  // task path, single leading slash
				"image":     `HKLM\SOFTWARE\Classes\CLSID`, // not a file
				"task_path": `\Updater`,
			},
			Findings: []Finding{finding("persistence.scheduled_task_hidden", SevSuspect)},
		}},
	}}
	for k := range iocByValue(ExtractIOCs(results)) {
		t.Errorf("unexpected indicator %q from non-file path values", k)
	}
}

func TestExtractIOCs_EventDataNestedMap(t *testing.T) {
	// An indicator buried in a nested event_data map is still found, under its
	// leaf key.
	results := []Result{{
		Collector: "eventlog",
		Records: []Record{{
			Fields: map[string]any{
				"event_id": 4625,
				"event_data": map[string]string{
					"IpAddress":       "203.0.113.77",
					"TargetUserName":  "administrator",
					"WorkstationName": "-",
				},
			},
			Findings: []Finding{finding("logon.failed_external", SevNotable)},
		}},
	}}
	got := iocByValue(ExtractIOCs(results))
	rec, ok := got["ipv4|203.0.113.77"]
	if !ok {
		t.Fatalf("nested event_data IP not extracted; keys %v", keysOf(got))
	}
	srcs := recField[[]map[string]any](t, rec, "sources")
	if len(srcs) != 1 || srcs[0]["field"] != "IpAddress" {
		t.Errorf("source field = %v, want IpAddress (the leaf key)", srcs)
	}
}

func TestExtractIOCs_SkipsDerivedCollectors(t *testing.T) {
	// A prior timeline/iocs result in the slice must not feed back in.
	results := []Result{
		{
			Collector: "timeline",
			Records: []Record{{
				Fields:   map[string]any{"detail": "203.0.113.1"},
				Findings: []Finding{finding("whatever", SevCritical)},
			}},
		},
		{
			Collector: "iocs",
			Records: []Record{{
				Fields:   map[string]any{"value": "203.0.113.2", "type": "ipv4"},
				Findings: nil,
			}},
		},
	}
	if res := ExtractIOCs(results); len(res.Records) != 0 {
		t.Errorf("records = %d, want 0 (derived collectors skipped)", len(res.Records))
	}
}

func TestExtractIOCs_Ordering(t *testing.T) {
	// Critical sorts before suspect before notable, regardless of input order.
	results := []Result{{
		Collector: "network",
		Records: []Record{
			{Fields: map[string]any{"remote_addr": "203.0.113.10"}, Findings: []Finding{finding("a.notable", SevNotable)}},
			{Fields: map[string]any{"remote_addr": "203.0.113.30"}, Findings: []Finding{finding("c.critical", SevCritical)}},
			{Fields: map[string]any{"remote_addr": "203.0.113.20"}, Findings: []Finding{finding("b.suspect", SevSuspect)}},
		},
	}}
	res := ExtractIOCs(results)
	want := []string{"203.0.113.30", "203.0.113.20", "203.0.113.10"}
	if len(res.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(res.Records))
	}
	for i, w := range want {
		if got := res.Records[i].Fields["value"]; got != w {
			t.Errorf("record %d value = %v, want %v (severity order)", i, got, w)
		}
	}
	// by_type meta should count three IPv4 indicators.
	if bt, ok := res.Meta["by_type"].(map[string]int); !ok || bt[iocIPv4] != 3 {
		t.Errorf("by_type = %v, want ipv4:3", res.Meta["by_type"])
	}
}

func TestExtractIOCs_IPv6AndAnySlice(t *testing.T) {
	const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	results := []Result{{
		Collector: "network",
		Records: []Record{{
			Fields: map[string]any{
				"remote_addr": "2001:db8::1",
				// a heterogeneous slice, as a JSON-decoded field can be
				"related": []any{sha1, "not-an-indicator"},
			},
			Findings: []Finding{finding("network.unusual_path_outbound", SevSuspect)},
		}},
	}}
	got := iocByValue(ExtractIOCs(results))
	if _, ok := got["ipv6|2001:db8::1"]; !ok {
		t.Errorf("IPv6 remote address not extracted; keys %v", keysOf(got))
	}
	if _, ok := got["sha1|"+sha1]; !ok {
		t.Errorf("hash inside a []any field not extracted; keys %v", keysOf(got))
	}
}

func TestIsDomainName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"api.openai.com", true},
		{"a.co", true},
		{"sub.domain.example.com.", true}, // trailing dot tolerated
		{"localhost", false},              // single label
		{"203.0.113.7", false},            // IPv4 literal
		{"2001:db8::1", false},            // IPv6 literal
		{"", false},
		{"no spaces.com here", false},
	}
	for _, c := range cases {
		if got := isDomainName(c.in); got != c.want {
			t.Errorf("isDomainName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func keysOf(m map[string]Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestExtractIOCs_LinuxPaths(t *testing.T) {
	results := []Result{
		{Collector: "processes", Records: []Record{
			{Fields: map[string]any{"image_path": "/tmp/.x/Payload (deleted)"},
				Findings: []Finding{finding("process.deleted_binary", SevSuspect)}},
			{Fields: map[string]any{"image_path": "/tmp/.x/payload"},
				Findings: []Finding{finding("process.unusual_exec_path", SevSuspect)}},
			{Fields: map[string]any{"image_path": "/memfd:stage2 (deleted)"},
				Findings: []Finding{finding("process.memfd_exec", SevSuspect)}},
		}},
		{Collector: "modules", Records: []Record{
			{Fields: map[string]any{"suspicious_modules": []string{"/dev/shm/.l/hook.so"}},
				Findings: []Finding{finding("modules.unusual_path", SevSuspect)}},
		}},
		{Collector: "autoruns", Records: []Record{
			{Fields: map[string]any{"library": "/usr/local/lib/libpreload.so", "program": "/var/tmp/.u/updater"},
				Findings: []Finding{finding("persistence.ld_preload", SevSuspect)}},
		}},
	}
	got := iocByValue(ExtractIOCs(results))
	for _, want := range []string{
		"filepath|/tmp/.x/Payload", // the deleted marker dropped: this is where it ran from
		"filepath|/tmp/.x/payload", // POSIX paths are case-sensitive: a different file
		"filepath|/dev/shm/.l/hook.so",
		"filepath|/usr/local/lib/libpreload.so",
		"filepath|/var/tmp/.u/updater",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; have %v", want, keysOfRecords(got))
		}
	}
	for k := range got {
		if k == "filepath|/memfd:stage2" || k == "filepath|/memfd:stage2 (deleted)" {
			t.Errorf("a memfd is not an on-disk location: %s", k)
		}
	}
}

func TestExtractIOCs_InfoOnlyRecordsAreNotIndicators(t *testing.T) {
	results := []Result{{
		Collector: "modules",
		Records: []Record{{
			Fields:   map[string]any{"image_path": "/usr/sbin/sshd", "remote_addr": "203.0.113.77"},
			Findings: []Finding{finding("modules.replaced_on_disk", SevInfo)},
		}},
	}}
	if res := ExtractIOCs(results); len(res.Records) != 0 {
		t.Fatalf("an info-only record must not feed the blocklist, got %d indicator(s)", len(res.Records))
	}
}

func keysOfRecords(m map[string]Record) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
