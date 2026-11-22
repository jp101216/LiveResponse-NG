package attack

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func bundled(t *testing.T) *Table {
	t.Helper()
	tb, err := Bundled()
	if err != nil {
		t.Fatalf("bundled table: %v", err)
	}
	return tb
}

func TestBundledTable(t *testing.T) {
	tb := bundled(t)
	if tb.Version == "" || tb.Source == "" || tb.Generated == "" {
		t.Fatalf("provenance missing: version %q source %q generated %q", tb.Version, tb.Source, tb.Generated)
	}
	if tb.Len() < 800 {
		t.Fatalf("only %d technique IDs; the table looks truncated", tb.Len())
	}
	shorts := map[string]bool{}
	for _, tac := range tb.Tactics {
		shorts[tac.ShortName] = true
	}
	// v19 retired Defense Evasion in favour of these two.
	for _, want := range []string{"stealth", "defense-impairment", "initial-access", "impact"} {
		if !shorts[want] {
			t.Errorf("tactic %s missing", want)
		}
	}
	if shorts["defense-evasion"] {
		t.Error("defense-evasion is retired but still listed")
	}
}

func TestResolve(t *testing.T) {
	tb := bundled(t)
	cases := []struct {
		id, want string
		status   Status
		remapped bool
	}{
		{"T1003.003", "T1003.003", Active, false},
		{"T1562.001", "T1685", Revoked, true}, // merged into Disable or Modify Tools in v19
		{"T1562", "T1685", Revoked, true},
		{"T1070.001", "T1685.005", Revoked, true}, // Clear Windows Event Logs moved to Defense Impairment
		{"T1656", "T1684.001", Revoked, true},     // Impersonation became a Social Engineering sub-technique
		{"T9999", "", 0, false},
	}
	for _, c := range cases {
		r := tb.Resolve(c.id)
		if r.ID != c.want || r.Status != c.status || r.Remapped() != c.remapped || r.From != c.id {
			t.Errorf("Resolve(%s) = %+v, want ID %q status %v remapped %v", c.id, r, c.want, c.status, c.remapped)
		}
	}
	if r := tb.Resolve("T1685"); r.Name != "Disable or Modify Tools" {
		t.Errorf("T1685 name = %q", r.Name)
	}
	if got := tb.TacticsOf("T1685"); len(got) != 1 || got[0] != "defense-impairment" {
		t.Errorf("TacticsOf(T1685) = %v", got)
	}
}

const synthetic = `# attack_version: 1.0
tactic	TA0001	initial-access	Initial Access
tactic	TA0005	stealth	Stealth
tech	T1000	active	-	initial-access,stealth	Parent
tech	T1001	revoked	T1002	-	Old
tech	T1002	revoked	T1003	-	Middle
tech	T1003	active	-	stealth	New
tech	T1004	deprecated	-	-	Gone
tech	T1005	revoked	T1004	-	Into gone
tech	T1006	revoked	-	-	Nowhere
`

func TestResolveChains(t *testing.T) {
	tb, err := Parse([]byte(synthetic))
	if err != nil {
		t.Fatal(err)
	}
	if r := tb.Resolve("T1001"); r.ID != "T1003" || r.Status != Revoked || r.Name != "New" {
		t.Errorf("two-hop revocation = %+v", r)
	}
	if r := tb.Resolve("T1004"); r.ID != "T1004" || r.Status != Deprecated || r.Remapped() {
		t.Errorf("deprecated = %+v", r)
	}
	if r := tb.Resolve("T1005"); r.ID != "T1004" || r.Status != Deprecated {
		t.Errorf("revoked into deprecated = %+v", r)
	}
	if r := tb.Resolve("T1006"); r.ID != "" || r.Status != Revoked {
		t.Errorf("revoked without successor = %+v", r)
	}
	if got := tb.TacticsOf("T1000.001"); strings.Join(got, ",") != "initial-access,stealth" {
		t.Errorf("sub-technique should take its parent's tactics, got %v", got)
	}
}

func TestParseRejects(t *testing.T) {
	head := "# attack_version: 1.0\ntactic\tTA0001\tinitial-access\tInitial Access\n"
	for name, body := range map[string]string{
		"no version":      "tactic\tTA0001\tinitial-access\tInitial Access\ntech\tT1000\tactive\t-\tinitial-access\tX\n",
		"bad id":          head + "tech\tT10\tactive\t-\tinitial-access\tX\n",
		"duplicate":       head + "tech\tT1000\tactive\t-\tinitial-access\tX\ntech\tT1000\tactive\t-\tinitial-access\tX\n",
		"unknown tactic":  head + "tech\tT1000\tactive\t-\tstealth\tX\n",
		"active no tac":   head + "tech\tT1000\tactive\t-\t-\tX\n",
		"dangling revoke": head + "tech\tT1000\trevoked\tT1001\t-\tX\n",
		"bad status":      head + "tech\tT1000\tretired\t-\t-\tX\n",
		"short line":      head + "tech\tT1000\tactive\n",
		"unknown record":  head + "group\tG0001\n",
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		}
	}
}

// The viewer carries its own copy of the technique -> tactic map; it must be
// the one cmd/attackgen renders from the bundled table.
func TestViewerBlockMatchesTable(t *testing.T) {
	html, err := os.ReadFile(filepath.Join("..", "..", "viewer", "lrng-viewer.html"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ExtractViewerBlock(string(html))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ViewerBlock(bundled(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("viewer/lrng-viewer.html's technique map is stale: run cmd/attackgen with -viewer (make attack-data)")
	}
	replaced, err := ReplaceViewerBlock(string(html), want)
	if err != nil || replaced != string(html) {
		t.Fatalf("replacing the block with itself changed the file (err %v)", err)
	}
}

// Every technique ID lrng's own rules name must be current in the bundled
// ATT&CK version, so a new ATT&CK release that revokes one fails here rather
// than putting retired IDs in reports. Third-party datasets (LOLDrivers) are
// left as published; the Navigator export remaps their IDs at export time.
func TestRulesNameCurrentTechniques(t *testing.T) {
	tb := bundled(t)
	root := filepath.Join("..", "..")
	quoted := regexp.MustCompile(`"(T\d{4}(?:\.\d{3})?)"`)
	sigmaTag := regexp.MustCompile(`(?i)\battack\.(t\d{4}(?:\.\d{3})?)\b`)
	var problems []string
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "target", "testdata", "node_modules", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		var re *regexp.Regexp
		switch {
		case strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go"):
			re = quoted
		case strings.HasPrefix(rel, "sidecar-rs/src/") && strings.HasSuffix(rel, ".rs"):
			re = quoted
		case strings.HasPrefix(rel, "internal/collector/sigmarules/") && (strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")):
			re = sigmaTag
		default:
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for n := 1; sc.Scan(); n++ {
			for _, m := range re.FindAllStringSubmatch(sc.Text(), -1) {
				id := strings.ToUpper(m[1])
				seen[id] = true
				tc, ok := tb.Lookup(id)
				switch {
				case !ok:
					problems = append(problems, fmt.Sprintf("%s:%d: %s isn't an Enterprise ATT&CK v%s technique", rel, n, id, tb.Version))
				case tc.Status == Revoked:
					problems = append(problems, fmt.Sprintf("%s:%d: %s was revoked; use %s", rel, n, id, tc.RevokedBy))
				case tc.Status == Deprecated:
					problems = append(problems, fmt.Sprintf("%s:%d: %s is deprecated", rel, n, id))
				}
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) < 50 {
		t.Fatalf("found only %d technique IDs in the rules; the scan is not reading them", len(seen))
	}
	for _, p := range problems {
		t.Error(p)
	}
}
