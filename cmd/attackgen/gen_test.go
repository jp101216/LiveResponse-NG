package main

import (
	"strings"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/attack"
)

// A small bundle in MITRE's shape: a collection, a matrix listing two tactics
// in order, active techniques, a revoked one with its revoked-by
// relationship, a deprecated one, an ID present on both a revoked and an
// active object, and things the table ignores.
const bundle = `{"type":"bundle","id":"bundle--1","objects":[
 {"type":"x-mitre-collection","id":"x-mitre-collection--1","x_mitre_version":"99.1"},
 {"type":"x-mitre-matrix","id":"x-mitre-matrix--1","external_references":[{"source_name":"mitre-attack","external_id":"enterprise-attack"}],
  "tactic_refs":["x-mitre-tactic--ia","x-mitre-tactic--st"]},
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--st","name":"Stealth","x_mitre_shortname":"stealth","external_references":[{"source_name":"mitre-attack","external_id":"TA0005"}]},
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--ia","name":"Initial Access","x_mitre_shortname":"initial-access","external_references":[{"source_name":"mitre-attack","external_id":"TA0001"}]},
 {"type":"x-mitre-tactic","id":"x-mitre-tactic--old","name":"Defense Evasion","x_mitre_shortname":"defense-evasion","x_mitre_deprecated":true,"external_references":[{"source_name":"mitre-attack","external_id":"TA0099"}]},
 {"type":"attack-pattern","id":"attack-pattern--a","name":"Both\ttactics","external_references":[{"source_name":"mitre-attack","external_id":"T1000"}],
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"stealth"},{"kill_chain_name":"mitre-attack","phase_name":"initial-access"},{"kill_chain_name":"other","phase_name":"impact"}]},
 {"type":"attack-pattern","id":"attack-pattern--b","name":"Old one","revoked":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1001.001"}]},
 {"type":"attack-pattern","id":"attack-pattern--c","name":"New one","external_references":[{"source_name":"mitre-attack","external_id":"T1002"}],
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"stealth"}]},
 {"type":"attack-pattern","id":"attack-pattern--d","name":"Gone","x_mitre_deprecated":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1003"}]},
 {"type":"attack-pattern","id":"attack-pattern--e1","name":"Reused (old)","revoked":true,"external_references":[{"source_name":"mitre-attack","external_id":"T1004"}]},
 {"type":"attack-pattern","id":"attack-pattern--e2","name":"Reused","external_references":[{"source_name":"mitre-attack","external_id":"T1004"}],
  "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]},
 {"type":"attack-pattern","id":"attack-pattern--x","name":"Not ATT&CK","external_references":[{"source_name":"capec","external_id":"CAPEC-1"}]},
 {"type":"relationship","id":"relationship--1","relationship_type":"revoked-by","source_ref":"attack-pattern--b","target_ref":"attack-pattern--c"},
 {"type":"relationship","id":"relationship--2","relationship_type":"uses","source_ref":"intrusion-set--1","target_ref":"attack-pattern--a"},
 {"type":"intrusion-set","id":"intrusion-set--1","name":"Group"}
]}`

func TestConvert(t *testing.T) {
	m, err := convert([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if m.version != "99.1" || len(m.tactics) != 2 || m.tactics[0].short != "initial-access" || m.tactics[1].short != "stealth" {
		t.Fatalf("version/tactics wrong: %+v", m)
	}
	var b strings.Builder
	if err := writeTable(&b, m, "test bundle", "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	tb, err := attack.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("generated table doesn't parse: %v\n%s", err, b.String())
	}
	if tb.Version != "99.1" || tb.Source != "test bundle" || tb.Generated != "2026-01-01" || tb.Len() != 5 {
		t.Fatalf("table header or size wrong: %+v (%d IDs)", tb, tb.Len())
	}
	if tc, _ := tb.Lookup("T1000"); strings.Join(tc.Tactics, ",") != "initial-access,stealth" || tc.Name != "Both tactics" {
		t.Errorf("T1000 = %+v: tactics in matrix order, other kill chains dropped, tabs flattened", tc)
	}
	if r := tb.Resolve("T1001.001"); r.ID != "T1002" || r.Status != attack.Revoked {
		t.Errorf("revoked-by not followed: %+v", r)
	}
	if tc, _ := tb.Lookup("T1003"); tc.Status != attack.Deprecated {
		t.Errorf("T1003 should be deprecated: %+v", tc)
	}
	if tc, _ := tb.Lookup("T1004"); tc.Status != attack.Active || tc.Name != "Reused" {
		t.Errorf("an ID on a revoked and an active object should keep the active one: %+v", tc)
	}
	// Deterministic: the same bundle gives the same bytes.
	m2, _ := convert([]byte(bundle))
	var b2 strings.Builder
	_ = writeTable(&b2, m2, "test bundle", "2026-01-01")
	if b.String() != b2.String() {
		t.Error("output differs between runs")
	}
}

func TestConvertRejects(t *testing.T) {
	for name, body := range map[string]string{
		"not json":   `nope`,
		"no objects": `{"type":"bundle","objects":[]}`,
		"no version": strings.Replace(bundle, `"x_mitre_version":"99.1"`, `"x_mitre_version":""`, 1),
		"no matrix":  strings.Replace(bundle, `"external_id":"enterprise-attack"`, `"external_id":"mobile-attack"`, 1),
		"tacticless": strings.Replace(bundle, `"kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"initial-access"}]`, `"kill_chain_phases":[]`, 1),
	} {
		if _, err := convert([]byte(body)); err == nil {
			t.Errorf("%s: converted, want an error", name)
		}
	}
}

func TestViewerBlockRoundTrip(t *testing.T) {
	m, err := convert([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	_ = writeTable(&b, m, "x", "y")
	tb, _ := attack.Parse([]byte(b.String()))
	block, err := attack.ViewerBlock(tb)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`["ia", "Initial access"]`, `["st", "Stealth"]`, `T1000: "ia st"`, `T1004: "ia"`} {
		if !strings.Contains(block, want) {
			t.Errorf("viewer block lacks %s:\n%s", want, block)
		}
	}
	if strings.Contains(block, "T1003") {
		t.Error("a deprecated technique shouldn't be in the viewer map")
	}
	page := "<script>\n" + attack.ViewerBegin + "\n" + attack.ViewerEnd + "\n</script>"
	out, err := attack.ReplaceViewerBlock(page, block)
	if err != nil || !strings.Contains(out, block) || !strings.HasSuffix(out, "</script>") {
		t.Fatalf("replace failed: %v\n%s", err, out)
	}
	if _, err := attack.ReplaceViewerBlock("<script></script>", block); err == nil {
		t.Error("a viewer without markers should be an error")
	}
}
