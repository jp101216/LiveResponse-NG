package collector

import "testing"

// TestSigmaMatchingSemantics pins the engine to the Sigma specification's
// value-matching rules, one small rule per behaviour. The base64 fixtures are
// what Python's base64 module produces for the quoted text.
func TestSigmaMatchingSemantics(t *testing.T) {
	type tc struct {
		name, det string
		data      map[string]string
		want      bool
	}
	ev := func(d map[string]string) winEvent {
		return winEvent{EventID: 1, Channel: "Microsoft-Windows-Sysmon/Operational", Data: d}
	}
	cases := []tc{
		{"wild-star", "  sel:\n    Image: '*\\cmd.exe'\n  condition: sel", map[string]string{"Image": `C:\Windows\System32\cmd.exe`}, true},
		{"wild-q", "  sel:\n    Image|endswith: '\\cm?.exe'\n  condition: sel", map[string]string{"Image": `C:\Windows\System32\cmd.exe`}, true},
		{"escaped-star", "  sel:\n    CommandLine|contains: 'a\\*b'\n  condition: sel", map[string]string{"CommandLine": `xa*by`}, true},
		{"escaped-star-neg", "  sel:\n    CommandLine|contains: 'a\\*b'\n  condition: sel", map[string]string{"CommandLine": `xaZZby`}, false},
		{"backslash-literal", "  sel:\n    Image|endswith: '\\\\cmd.exe'\n  condition: sel", map[string]string{"Image": `C:\x\cmd.exe`}, true},
		{"all", "  sel:\n    CommandLine|contains|all:\n      - foo\n      - bar\n  condition: sel", map[string]string{"CommandLine": `bar and FOO`}, true},
		{"all-neg", "  sel:\n    CommandLine|contains|all:\n      - foo\n      - baz\n  condition: sel", map[string]string{"CommandLine": `bar and FOO`}, false},
		{"list-or", "  sel:\n    Image|endswith:\n      - '\\a.exe'\n      - '\\b.exe'\n  condition: sel", map[string]string{"Image": `c:\b.exe`}, true},
		{"1-of", "  sel_a:\n    X: 1\n  sel_b:\n    Y: 2\n  condition: 1 of sel_*", map[string]string{"Y": "2"}, true},
		{"all-of", "  sel_a:\n    X: 1\n  sel_b:\n    Y: 2\n  condition: all of sel_*", map[string]string{"Y": "2"}, false},
		{"not-1-of", "  sel:\n    X: 1\n  filter_a:\n    Y: 2\n  condition: sel and not 1 of filter_*", map[string]string{"X": "1", "Y": "2"}, false},
		{"all-of-them", "  a:\n    X: 1\n  b:\n    Y: 2\n  condition: all of them", map[string]string{"X": "1", "Y": "2"}, true},
		{"null", "  sel:\n    X: null\n  condition: sel", map[string]string{"Y": "2"}, true},
		{"empty", "  sel:\n    X: ''\n  condition: sel", map[string]string{"X": ""}, true},
		{"re", "  sel:\n    CommandLine|re: '^a+b$'\n  condition: sel", map[string]string{"CommandLine": "aaab"}, true},
		{"re-case", "  sel:\n    CommandLine|re: '^a+b$'\n  condition: sel", map[string]string{"CommandLine": "AAAB"}, false},
		{"re-i", "  sel:\n    CommandLine|re|i: '^a+b$'\n  condition: sel", map[string]string{"CommandLine": "AAAB"}, true},
		{"cased", "  sel:\n    X|cased: 'Abc'\n  condition: sel", map[string]string{"X": "abc"}, false},
		{"num-eq", "  sel:\n    EventID: 1\n  condition: sel", nil, true},
		{"gt", "  sel:\n    X|gt: 5\n  condition: sel", map[string]string{"X": "6"}, true},
		{"cidr", "  sel:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: sel", map[string]string{"DestinationIp": "10.2.3.4"}, true},
		{"base64", "  sel:\n    CommandLine|base64|contains: 'hello'\n  condition: sel", map[string]string{"CommandLine": "x aGVsbG8= y"}, true},
		{"base64offset", "  sel:\n    CommandLine|base64offset|contains: 'http://'\n  condition: sel", map[string]string{"CommandLine": "IEX aHR0cDovL2V2aWw="}, true},
		{"windash", "  sel:\n    CommandLine|windash|contains: ' -enc '\n  condition: sel", map[string]string{"CommandLine": "powershell /enc AAAA"}, true},
		{"keywords", "  kw:\n    - 'mimikatz'\n  condition: kw", map[string]string{"CommandLine": "x MIMIKATZ y"}, true},
		{"list-of-maps", "  sel:\n    - X: 1\n    - Y: 2\n  condition: sel", map[string]string{"Y": "2"}, true},
		{"paren-or", "  a:\n    X: 1\n  b:\n    Y: 2\n  c:\n    Z: 3\n  condition: a and (b or c)", map[string]string{"X": "1", "Z": "3"}, true},
		{"precedence", "  a:\n    X: 1\n  b:\n    Y: 2\n  c:\n    Z: 3\n  condition: a or b and c", map[string]string{"X": "1"}, true},
		{"exists", "  sel:\n    X|exists: true\n  condition: sel", map[string]string{"X": "q"}, true},
		{"exists-f", "  sel:\n    X|exists: false\n  condition: sel", map[string]string{"X": "q"}, false},
		{"contains-wild", "  sel:\n    CommandLine|contains: 'a*b'\n  condition: sel", map[string]string{"CommandLine": "xxaZZbxx"}, true},
		{"startswith", "  sel:\n    Image|startswith: 'C:\\Users\\'\n  condition: sel", map[string]string{"Image": `c:\users\x\a.exe`}, true},
		{"int-vs-str", "  sel:\n    LogonType: 3\n  condition: sel", map[string]string{"LogonType": "3"}, true},
		{"int-vs-str2", "  sel:\n    LogonType: 3\n  condition: sel", map[string]string{"LogonType": "30"}, false},
		{"multi-val-newline", "  sel:\n    X|endswith: 'b'\n  condition: sel", map[string]string{"X": "a\nb"}, true},
		{"star-newline", "  sel:\n    X: 'a*b'\n  condition: sel", map[string]string{"X": "a\nzz\nb"}, true},
		{"not", "  sel:\n    X: 1\n  f:\n    Y: 2\n  condition: sel and not f", map[string]string{"X": "1"}, true},
		{"them-1", "  a:\n    X: 1\n  b:\n    Y: 2\n  condition: 1 of them", map[string]string{"Y": "2"}, true},
		{"empty-absent", "  sel:\n    X: ''\n  condition: sel", map[string]string{"Y": "1"}, false},
		{"exists-empty", "  sel:\n    X|exists: true\n  condition: sel", map[string]string{"X": ""}, true},
		{"re-s", "  sel:\n    X|re|s: '^a.b$'\n  condition: sel", map[string]string{"X": "a\nb"}, true},
		{"unicode-wild", "  sel:\n    X: 'café*'\n  condition: sel", map[string]string{"X": "CAFÉ au lait"}, true},
		{"wide-b64off", "  sel:\n    CommandLine|wide|base64offset|contains: 'IEX'\n  condition: sel", map[string]string{"CommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"}, true},
		{"b64off-len10", "  sel:\n    CommandLine|base64offset|contains: 'powershell'\n  condition: sel", map[string]string{"CommandLine": "echo eCBwb3dlcnNoZWxsIC1ub3A= | base64 -d"}, true},
		{"b64off-len10b", "  sel:\n    CommandLine|base64offset|contains: 'powershell'\n  condition: sel", map[string]string{"CommandLine": "echo cG93ZXJzaGVsbCAtbm9w | base64 -d"}, true},
		{"b64off-len10c", "  sel:\n    CommandLine|base64offset|contains: 'powershell'\n  condition: sel", map[string]string{"CommandLine": "echo eHggcG93ZXJzaGVsbCAtbm9w | base64 -d"}, true},
		{"glob-ident", "  a_sel:\n    X: 1\n  b_sel:\n    Y: 2\n  condition: 1 of *_sel", map[string]string{"Y": "2"}, true},
		{"hex-id", "  sel:\n    Status: '0xC000006A'\n  condition: sel", map[string]string{"Status": "0xc000006a"}, true},
	}
	for _, c := range cases {
		rs := &SigmaRuleset{}
		rs.compileFile(c.name+".yml", []byte("title: "+c.name+"\nlogsource:\n  product: windows\ndetection:\n"+c.det+"\nlevel: high\n"))
		if rs.Loaded != 1 {
			t.Errorf("%s: not loaded: skipped=%v failed=%v", c.name, rs.Skipped, rs.Failed)
			continue
		}
		got := len(rs.match(ev(c.data))) == 1
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// BenchmarkSigmaBuiltinMatch measures the per-event cost of the bundled pack on
// an event no rule matches — the overwhelmingly common case on a real log.
func BenchmarkSigmaBuiltinMatch(b *testing.B) {
	rs, err := LoadBuiltinSigmaRules()
	if err != nil {
		b.Fatal(err)
	}
	ev := winEvent{EventID: 4688, Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", Data: map[string]string{
		"NewProcessName": `C:\Windows\System32\svchost.exe`, "CommandLine": `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule`,
		"ParentProcessName": `C:\Windows\System32\services.exe`, "SubjectUserName": "SYSTEM", "TokenElevationType": "%%1936",
	}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = rs.match(ev)
	}
}
