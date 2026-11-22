// Command attackgen compiles the Enterprise ATT&CK technique table that lrng
// bundles (internal/attack/data/enterprise.tsv) from MITRE's published STIX
// bundle, and refreshes the report viewer's technique -> tactic map from it:
//
//	curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//	attackgen -in enterprise-attack.json -out internal/attack/data/enterprise.tsv \
//	          -viewer viewer/lrng-viewer.html
//
// Kept per technique ID: its name, its tactics (in matrix order), and whether
// it is active, revoked (and by which ID, from MITRE's revoked-by
// relationships) or deprecated. Kept per tactic: its ID, short name and name,
// in the order of the Enterprise matrix. Everything else in the bundle
// (descriptions, detections, groups, software, references) is left out.
//
// Output is sorted, so the same bundle always gives the same file, and the
// diff of a refresh shows exactly what changed in ATT&CK. The tool uses the
// standard library only, like the rest of the Go tree.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/attack"
)

func main() {
	var (
		in      = flag.String("in", "", "MITRE's enterprise-attack.json STIX bundle")
		out     = flag.String("out", "", "output table path (default: stdout)")
		viewer  = flag.String("viewer", "", "also rewrite the generated block of this report viewer HTML")
		source  = flag.String("source", "mitre-attack/attack-stix-data enterprise-attack.json", "value for the table's 'source' line (say which commit or date)")
		date    = flag.String("date", "", "value for the 'generated' line (default: today, UTC)")
		verbose = flag.Bool("v", false, "print counts to stderr")
	)
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "attackgen: -in enterprise-attack.json is required")
		flag.Usage()
		os.Exit(2)
	}
	if *date == "" {
		*date = time.Now().UTC().Format("2006-01-02")
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	m, err := convert(raw)
	if err != nil {
		fail(err)
	}
	var buf strings.Builder
	if err := writeTable(&buf, m, *source, *date); err != nil {
		fail(err)
	}
	table, err := attack.Parse([]byte(buf.String())) // the agent must be able to read what was written
	if err != nil {
		fail(fmt.Errorf("generated table doesn't parse: %w", err))
	}
	if *verbose {
		var active, revoked, deprecated int
		for _, t := range m.techniques {
			switch t.status {
			case "active":
				active++
			case "revoked":
				revoked++
			default:
				deprecated++
			}
		}
		fmt.Fprintf(os.Stderr, "attackgen: ATT&CK v%s, %d tactics, %d technique IDs (%d active, %d revoked, %d deprecated)\n",
			m.version, len(m.tactics), len(m.techniques), active, revoked, deprecated)
	}
	write := func(w io.Writer) error { _, err := io.WriteString(w, buf.String()); return err }
	if *out == "" {
		if err := write(os.Stdout); err != nil {
			fail(err)
		}
	} else if err := writeFileAtomic(*out, write); err != nil {
		fail(err)
	}
	if *viewer != "" {
		block, err := attack.ViewerBlock(table)
		if err != nil {
			fail(err)
		}
		html, err := os.ReadFile(*viewer)
		if err != nil {
			fail(err)
		}
		updated, err := attack.ReplaceViewerBlock(string(html), block)
		if err != nil {
			fail(err)
		}
		if err := writeFileAtomic(*viewer, func(w io.Writer) error { _, err := io.WriteString(w, updated); return err }); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "attackgen: error:", err)
	os.Exit(1)
}

type tactic struct{ id, short, name string }

type technique struct {
	id, name, status, revokedBy string
	tactics                     []string
}

type model struct {
	version    string
	tactics    []tactic
	techniques []technique
}

type stixObject struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Revoked    bool     `json:"revoked"`
	Deprecated bool     `json:"x_mitre_deprecated"`
	Version    string   `json:"x_mitre_version"`
	Shortname  string   `json:"x_mitre_shortname"`
	TacticRefs []string `json:"tactic_refs"`
	RelType    string   `json:"relationship_type"`
	SourceRef  string   `json:"source_ref"`
	TargetRef  string   `json:"target_ref"`
	ExtRefs    []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
	} `json:"external_references"`
	Phases []struct {
		Chain string `json:"kill_chain_name"`
		Phase string `json:"phase_name"`
	} `json:"kill_chain_phases"`
}

func (o *stixObject) attackID() string {
	for _, r := range o.ExtRefs {
		if r.SourceName == "mitre-attack" {
			return r.ExternalID
		}
	}
	return ""
}

func (o *stixObject) current() bool { return !o.Revoked && !o.Deprecated }

// convert reads a STIX 2.1 bundle into the table's model.
func convert(raw []byte) (model, error) {
	var bundle struct {
		Type    string       `json:"type"`
		Objects []stixObject `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return model{}, fmt.Errorf("not a STIX bundle: %w", err)
	}
	if bundle.Type != "bundle" || len(bundle.Objects) == 0 {
		return model{}, errors.New("not a STIX bundle with objects")
	}
	var m model
	byStix := map[string]*stixObject{}
	var matrix *stixObject
	for i := range bundle.Objects {
		o := &bundle.Objects[i]
		byStix[o.ID] = o
		switch o.Type {
		case "x-mitre-collection":
			m.version = o.Version
		case "x-mitre-matrix":
			if o.current() && o.attackID() == "enterprise-attack" {
				matrix = o
			}
		}
	}
	if m.version == "" {
		return model{}, errors.New("the bundle has no x-mitre-collection version")
	}
	if matrix == nil {
		return model{}, errors.New("the bundle has no current enterprise-attack matrix")
	}
	order := map[string]int{}
	for _, ref := range matrix.TacticRefs {
		o := byStix[ref]
		if o == nil || o.Type != "x-mitre-tactic" || !o.current() || o.Shortname == "" {
			return model{}, fmt.Errorf("matrix tactic %s is missing or not current", ref)
		}
		order[o.Shortname] = len(m.tactics)
		m.tactics = append(m.tactics, tactic{id: o.attackID(), short: o.Shortname, name: o.Name})
	}
	revokedBy := map[string]string{} // STIX ID -> STIX ID
	for i := range bundle.Objects {
		o := &bundle.Objects[i]
		if o.Type == "relationship" && o.RelType == "revoked-by" {
			revokedBy[o.SourceRef] = o.TargetRef
		}
	}
	tech := map[string]technique{}
	for i := range bundle.Objects {
		o := &bundle.Objects[i]
		if o.Type != "attack-pattern" {
			continue
		}
		id := o.attackID()
		if !attack.IDRe.MatchString(id) {
			continue
		}
		t := technique{id: id, name: oneLine(o.Name)}
		switch {
		case o.Revoked:
			t.status = "revoked"
			if target := byStix[revokedBy[o.ID]]; target != nil {
				t.revokedBy = target.attackID()
			}
		case o.Deprecated:
			t.status = "deprecated"
		default:
			t.status = "active"
			seen := map[string]bool{}
			for _, p := range o.Phases {
				if _, ok := order[p.Phase]; ok && p.Chain == "mitre-attack" && !seen[p.Phase] {
					seen[p.Phase] = true
					t.tactics = append(t.tactics, p.Phase)
				}
			}
			sort.Slice(t.tactics, func(a, b int) bool { return order[t.tactics[a]] < order[t.tactics[b]] })
			if len(t.tactics) == 0 {
				return model{}, fmt.Errorf("active technique %s has no Enterprise tactic", id)
			}
		}
		if prev, ok := tech[id]; ok && rank(prev) >= rank(t) {
			continue // an ID on two objects: keep the current one
		}
		tech[id] = t
	}
	for id, t := range tech {
		if t.revokedBy != "" {
			if _, ok := tech[t.revokedBy]; !ok {
				return model{}, fmt.Errorf("%s is revoked by %s, which isn't in the bundle", id, t.revokedBy)
			}
		}
	}
	for _, t := range tech {
		m.techniques = append(m.techniques, t)
	}
	sort.Slice(m.techniques, func(a, b int) bool { return m.techniques[a].id < m.techniques[b].id })
	return m, nil
}

// rank prefers an active object, then a revoked one that names its successor.
func rank(t technique) int {
	switch {
	case t.status == "active":
		return 3
	case t.status == "revoked" && t.revokedBy != "":
		return 2
	}
	return 1
}

func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '\t' || r == '\n' || r == '\r' }), " ")
}

func writeTable(w io.Writer, m model, source, date string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# liveresponse-ng Enterprise ATT&CK technique table\n")
	fmt.Fprintf(&b, "# source: %s\n", oneLine(source))
	fmt.Fprintf(&b, "# attack_version: %s\n", oneLine(m.version))
	fmt.Fprintf(&b, "# generated: %s\n", oneLine(date))
	fmt.Fprintf(&b, "# notes: generated by cmd/attackgen from MITRE ATT&CK (https://attack.mitre.org), %d tactics, %d technique IDs.\n", len(m.tactics), len(m.techniques))
	fmt.Fprintf(&b, "#   ATT&CK is (c) The MITRE Corporation, reproduced and distributed with its permission (LICENSE.attack, next to this file).\n")
	fmt.Fprintf(&b, "# format: a tactic line per Enterprise matrix column, in matrix order, then a line per technique ID (- is empty):\n")
	fmt.Fprintf(&b, "#   tactic<TAB>id<TAB>short name<TAB>name\n")
	fmt.Fprintf(&b, "#   tech<TAB>id<TAB>active|revoked|deprecated<TAB>revoked by<TAB>tactics (comma-separated)<TAB>name\n")
	for _, t := range m.tactics {
		fmt.Fprintf(&b, "tactic\t%s\t%s\t%s\n", t.id, t.short, oneLine(t.name))
	}
	for _, t := range m.techniques {
		fmt.Fprintf(&b, "tech\t%s\t%s\t%s\t%s\t%s\n", t.id, t.status, orDash(t.revokedBy), orDash(strings.Join(t.tactics, ",")), t.name)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeFileAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	err = write(tmp)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o644)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}
