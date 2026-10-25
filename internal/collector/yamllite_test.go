package collector

import "testing"

const sigmaRuleProcCreate = `title: Encoded PowerShell Command Line
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: |
  Detects a suspicious encoded PowerShell command line.
  Multi-line description that must not break parsing.
author: Jessie
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
    filter:
        CommandLine|contains: 'KnownGoodTool'
    condition: selection and not filter
fields:
    - CommandLine
tags:
    - attack.execution
    - attack.t1059.001
level: high
`

func TestYAMLParseSigmaProcCreate(t *testing.T) {
	docs, err := parseYAMLDocuments([]byte(sigmaRuleProcCreate))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("docs = %d, want 1", len(docs))
	}
	r := docs[0]
	if r.get("title").scalar() != "Encoded PowerShell Command Line" {
		t.Errorf("title = %q", r.get("title").scalar())
	}
	if r.get("level").scalar() != "high" {
		t.Errorf("level = %q", r.get("level").scalar())
	}
	// logsource map
	ls := r.get("logsource")
	if ls.get("category").scalar() != "process_creation" || ls.get("product").scalar() != "windows" {
		t.Errorf("logsource = %+v", ls)
	}
	// tags list
	tags := r.get("tags")
	if tags == nil || tags.Kind != yamlSeq || len(tags.Seq) != 2 || tags.Seq[1].scalar() != "attack.t1059.001" {
		t.Fatalf("tags = %+v", tags)
	}
	// detection.selection with a nested list under a modifier key
	det := r.get("detection")
	sel := det.get("selection")
	if sel.get("EventID").scalar() != "4688" {
		t.Errorf("EventID = %q", sel.get("EventID").scalar())
	}
	if got := sel.get(`NewProcessName|endswith`).scalar(); got != `\powershell.exe` {
		t.Errorf("endswith value = %q", got)
	}
	cc := sel.get("CommandLine|contains")
	if cc == nil || cc.Kind != yamlSeq || len(cc.Seq) != 2 || cc.Seq[0].scalar() != "-enc" {
		t.Fatalf("CommandLine|contains = %+v", cc)
	}
	if det.get("condition").scalar() != "selection and not filter" {
		t.Errorf("condition = %q", det.get("condition").scalar())
	}
	// multi-line block scalar description must not have eaten following keys
	if r.get("author").scalar() != "Jessie" {
		t.Errorf("author = %q (block scalar likely over-consumed)", r.get("author").scalar())
	}
}

const sigmaRuleListOfMaps = `title: Service Install Variants
logsource:
    service: system
detection:
    selection:
        - EventID: 7045
          ServiceName|contains: 'psexec'
        - EventID: 7045
          ImagePath|contains: '\users\public\'
    keywords:
        - 'mimikatz'
        - 'cobaltstrike'
    condition: selection or keywords
level: critical
`

func TestYAMLParseListOfMapsAndKeywords(t *testing.T) {
	docs, err := parseYAMLDocuments([]byte(sigmaRuleListOfMaps))
	if err != nil {
		t.Fatal(err)
	}
	det := docs[0].get("detection")
	sel := det.get("selection")
	if sel == nil || sel.Kind != yamlSeq || len(sel.Seq) != 2 {
		t.Fatalf("selection should be a 2-item sequence of maps: %+v", sel)
	}
	first := sel.Seq[0]
	if first.Kind != yamlMap || first.get("EventID").scalar() != "7045" || first.get("ServiceName|contains").scalar() != "psexec" {
		t.Fatalf("first selection map = %+v", first)
	}
	if got := sel.Seq[1].get("ImagePath|contains").scalar(); got != `\users\public\` {
		t.Errorf("second map image = %q", got)
	}
	kw := det.get("keywords")
	if kw == nil || kw.Kind != yamlSeq || len(kw.Seq) != 2 || kw.Seq[0].scalar() != "mimikatz" {
		t.Fatalf("keywords = %+v", kw)
	}
}

func TestYAMLFlowAndQuoting(t *testing.T) {
	src := `a: [one, two, 'three four']
b: "line\twith\ttabs"
c: ~
d: 'it''s quoted'
`
	docs, err := parseYAMLDocuments([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	m := docs[0]
	a := m.get("a")
	if a.Kind != yamlSeq || len(a.Seq) != 3 || a.Seq[2].scalar() != "three four" {
		t.Fatalf("flow seq = %+v", a)
	}
	if m.get("b").scalar() != "line\twith\ttabs" {
		t.Errorf("double-quote escapes = %q", m.get("b").scalar())
	}
	if !m.get("c").Null {
		t.Errorf("c should be null")
	}
	if m.get("d").scalar() != "it's quoted" {
		t.Errorf("single-quote escape = %q", m.get("d").scalar())
	}
}

func TestYAMLMultipleDocuments(t *testing.T) {
	src := "title: one\nlevel: low\n---\ntitle: two\nlevel: high\n"
	docs, err := parseYAMLDocuments([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].get("title").scalar() != "one" || docs[1].get("title").scalar() != "two" {
		t.Fatalf("docs = %+v", docs)
	}
}
