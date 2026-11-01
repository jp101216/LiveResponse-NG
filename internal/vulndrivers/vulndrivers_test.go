package vulndrivers

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The bundled dataset parses, is the size LOLDrivers is, and finds a known
// vulnerable driver (szkg64.sys) by each of its four hashes.
func TestBundledDataset(t *testing.T) {
	s, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if s.Info.Drivers < 600 || s.Info.Samples < 2000 {
		t.Fatalf("a suspiciously small dataset: %+v", s.Info)
	}
	if !strings.Contains(s.Info.Source, "LOLDrivers") || s.Info.Generated == "" {
		t.Errorf("dataset metadata %+v", s.Info)
	}
	checks := []struct {
		by   string
		find func() (Match, bool)
	}{
		{"file SHA-256", func() (Match, bool) {
			return s.FileSHA256([32]byte(mustHex(t, "6bc0e1c104fac4a8caa4237c7ae181ca11a043a3ee26426aeb7a90dc40281fad")))
		}},
		{"file SHA-1", func() (Match, bool) {
			return s.FileSHA1([20]byte(mustHex(t, "d7698828cdc3c96cc17fe2d4ff6d93bb0cd355d8")))
		}},
		{"Authenticode SHA-256", func() (Match, bool) {
			return s.AuthentihashSHA256([32]byte(mustHex(t, "95ca14e045618fb38834d17c5cc176162a29d846c1463b840c9129fb9af47c68")))
		}},
		{"file SHA-256", func() (Match, bool) {
			return s.FileHex("6BC0E1C104FAC4A8CAA4237C7AE181CA11A043A3EE26426AEB7A90DC40281FAD")
		}},
	}
	for _, c := range checks {
		m, ok := c.find()
		if !ok {
			t.Fatalf("%s: szkg64.sys not found", c.by)
		}
		d := m.Driver
		if m.By != c.by || d.ID != "375e8de3-aae4-488d-8273-66744978b45f" || d.Category != Vulnerable ||
			d.Label() != "szkg64.sys" || d.Technique != "T1068" || !d.Verified {
			t.Errorf("%s: %+v %+v", c.by, m, *d)
		}
		if d.URL() != "https://www.loldrivers.io/drivers/375e8de3-aae4-488d-8273-66744978b45f/" {
			t.Errorf("url %s", d.URL())
		}
	}
	if _, ok := s.FileHex("d41d8cd98f00b204e9800998ecf8427e"); ok { // an MD5: never matched
		t.Error("an MD5 matched")
	}
	if _, ok := s.FileSHA256([32]byte{}); ok {
		t.Error("the zero hash matched")
	}
	mal := 0
	for _, sm := range s.samples {
		if sm.Driver.Category == Malicious {
			mal++
		}
	}
	if mal < 100 {
		t.Errorf("only %d malicious samples", mal)
	}
}

const tiny = `# source: test
# generated: 2026-01-01
D	11111111-1111-1111-1111-111111111111	vulnerable	no	T1068	CVE-2019-16098	a.sys,b.sys
S	` + h64a + `	-	-	-	yes
S	` + h64b + `	` + h40 + `	-	-	-
D	22222222-2222-2222-2222-222222222222	malicious	yes	-	-	-
S	` + h64b + `	-	` + h64a + `	-	no
`

const (
	h64a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h64b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	h40  = "cccccccccccccccccccccccccccccccccccccccc"
)

func TestParse(t *testing.T) {
	s, err := Parse([]byte(tiny))
	if err != nil {
		t.Fatal(err)
	}
	if s.Info != (Info{Source: "test", Generated: "2026-01-01", Drivers: 2, Samples: 3}) {
		t.Errorf("info %+v", s.Info)
	}
	m, ok := s.FileHex(h64a)
	if !ok || m.Driver.CVEs[0] != "CVE-2019-16098" || m.HVCI != HVCILoads || m.Driver.Names[1] != "b.sys" {
		t.Errorf("a: %+v", m)
	}
	// Listed by both entries: the malicious one wins.
	if m, ok := s.FileHex(h64b); !ok || m.Driver.Category != Malicious || m.HVCI != HVCIBlocked || m.Driver.Label() == "" {
		t.Errorf("b: %+v", m)
	}
	if m, ok := s.FileHex(h40); !ok || m.Driver.Category != Vulnerable || m.By != "file SHA-1" {
		t.Errorf("sha1: %+v", m)
	}
	if m, ok := s.AuthentihashSHA256([32]byte(mustHex(t, h64a))); !ok || m.Driver.Category != Malicious {
		t.Errorf("authentihash: %+v", m)
	}
	if _, ok := s.AuthentihashSHA1([20]byte(mustHex(t, h40))); ok {
		t.Error("a file hash matched as an Authenticode hash")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for name, data := range map[string]string{
		"empty":           "# nothing\n",
		"sample first":    "S\t" + h64a + "\t-\t-\t-\t-\n",
		"short driver":    "D\t11111111-1111-1111-1111-111111111111\tvulnerable\n",
		"bad id":          "D\tnot-a-uuid\tvulnerable\tno\t-\t-\t-\n",
		"bad category":    "D\t11111111-1111-1111-1111-111111111111\tcursed\tno\t-\t-\t-\n",
		"bad technique":   "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\tX1\t-\t-\n",
		"bad cve":         "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\t-\tCVE-1\t-\n",
		"short hash":      "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\t-\t-\t-\nS\tabc\t-\t-\t-\t-\n",
		"upper-case hash": "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\t-\t-\t-\nS\t" + strings.ToUpper(h64a) + "\t-\t-\t-\t-\n",
		"no hash":         "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\t-\t-\t-\nS\t-\t-\t-\t-\t-\n",
		"bad hvci":        "D\t11111111-1111-1111-1111-111111111111\tvulnerable\tno\t-\t-\t-\nS\t" + h64a + "\t-\t-\t-\tmaybe\n",
		"unknown type":    "X\tfoo\n",
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
