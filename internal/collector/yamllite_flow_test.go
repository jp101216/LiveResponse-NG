package collector

import (
	"strings"
	"testing"
)

// TestSigmaRuleFileShapes loads one rule in the shapes rule files really arrive
// in — CRLF line endings, a byte-order mark, two-space indents, several
// documents — and checks it both fires and honours its filter, which is
// written as a flow mapping holding a flow sequence.
func TestSigmaRuleFileShapes(t *testing.T) {
	base := "title: Shape Test # trailing comment\nid: 1234\nstatus: test\ndescription: |\n    multi-line\n    text: with colon\nreferences:\n    - https://example.com/a#frag\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection_img:\n        - Image|endswith: '\\powershell.exe'\n        - OriginalFileName: 'PowerShell.EXE'\n    selection_cli:\n        CommandLine|contains:\n            - ' -enc '\n            - \" -e: \"\n            - 'it''s'\n    filter_main: {User|contains: ['SYSTEM', \"AUTHORI\"]}\n    condition: all of selection_* and not 1 of filter_*\nfalsepositives:\n    - Unknown\nlevel: high\ntags: [attack.execution, attack.t1059.001]\n"
	ev := winEvent{EventID: 1, Channel: "Microsoft-Windows-Sysmon/Operational", Data: map[string]string{
		"Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "CommandLine": "powershell -enc AAAA", "User": "CORP\\bob"}}
	variants := map[string]string{
		"lf":              base,
		"crlf":            strings.ReplaceAll(base, "\n", "\r\n"),
		"bom":             "\ufeff" + base,
		"bom-crlf":        "\ufeff" + strings.ReplaceAll(base, "\n", "\r\n"),
		"docsep":          "---\n" + base + "---\n" + strings.Replace(base, "Shape Test", "Second", 1),
		"2space":          strings.ReplaceAll(base, "    ", "  "),
		"tab-after-colon": strings.Replace(base, "level: high", "level:\thigh", 1),
		"trailing-ws":     strings.ReplaceAll(base, "\n", "   \n"),
	}
	for name, doc := range variants {
		rs := &SigmaRuleset{}
		rs.compileFile(name+".yml", []byte(doc))
		want := 1
		if name == "docsep" {
			want = 2
		}
		if rs.Loaded != want {
			t.Errorf("%s: loaded=%d skipped=%v failed=%v", name, rs.Loaded, rs.Skipped, rs.Failed)
			continue
		}
		fs := rs.match(ev)
		if len(fs) != want {
			t.Errorf("%s: findings=%+v", name, fs)
			continue
		}
		if fs[0].Severity != SevSuspect && fs[0].Severity != SevCritical {
			t.Errorf("%s: severity %s tech %s", name, fs[0].Severity, fs[0].Technique)
		}
		if fs[0].Technique != "T1059.001" {
			t.Errorf("%s: technique %q", name, fs[0].Technique)
		}
		ev2 := ev
		ev2.Data = map[string]string{"Image": ev.Data["Image"], "CommandLine": ev.Data["CommandLine"], "User": `NT AUTHORITY\SYSTEM`}
		if len(rs.match(ev2)) != 0 {
			t.Errorf("%s: filter did not apply", name)
		}
	}
}

func TestYAMLFlowCollectionsNestAndRespectQuotes(t *testing.T) {
	doc := func(src string) *yamlNode {
		t.Helper()
		docs, err := parseYAMLDocuments([]byte(src))
		if err != nil || len(docs) != 1 {
			t.Fatalf("%q: %v (%d documents)", src, err, len(docs))
		}
		return docs[0]
	}
	strs := func(n *yamlNode) []string {
		t.Helper()
		if n == nil || n.Kind != yamlSeq {
			t.Fatalf("not a sequence: %+v", n)
		}
		var out []string
		for _, it := range n.Seq {
			if it.Kind != yamlScalar {
				t.Fatalf("non-scalar item: %+v", it)
			}
			out = append(out, it.Str)
		}
		return out
	}
	eq := func(got []string, want ...string) {
		t.Helper()
		if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	// A sequence inside a mapping, and collections inside a sequence.
	eq(strs(doc("a: {k|contains: ['x', \"y\"], n: 1}\n").get("a").get("k|contains")), "x", "y")
	nested := doc("a: [{k: v}, [1, 2], plain]\n").get("a")
	if len(nested.Seq) != 3 || nested.Seq[0].get("k").scalar() != "v" || nested.Seq[2].Str != "plain" {
		t.Errorf("nested flow sequence = %+v", nested.Seq)
	}
	eq(strs(nested.Seq[1]), "1", "2")

	// An escaped quote doesn't end a double-quoted scalar; a comma, colon or
	// '#' inside quotes is text; an apostrophe mid-word opens nothing.
	eq(strs(doc(`a: ['it''s', "q\"x, y", a:b, 'c: d', don't, e]`+"\n").get("a")), "it's", `q"x, y`, "a:b", "c: d", "don't", "e")
	if got := doc(`a: "say \"hi\" # not a comment" # a comment` + "\n").get("a").scalar(); got != `say "hi" # not a comment` {
		t.Errorf("escaped quotes before a comment: %q", got)
	}
	if got := doc("a: don't # a comment\n").get("a").scalar(); got != "don't" {
		t.Errorf("apostrophe before a comment: %q", got)
	}

	// Hostile nesting is refused, not recursed into.
	if _, err := parseYAMLDocuments([]byte("a: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n")); err == nil {
		t.Error("absurdly deep flow nesting was accepted")
	}
}
