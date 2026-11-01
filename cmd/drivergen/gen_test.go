package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/vulndrivers"
)

// drivers.json in the shapes LOLDrivers has used: CVE as a list, a string or
// absent; LoadsDespiteHVCI on the sample or under ResearchEvidence; samples
// repeated, hashes in upper case or malformed, a sample with no hash.
var fixture = `[
 {"Id": "BBBBBBBB-1111-4111-8111-111111111111", "Category": "malicious", "Verified": "TRUE", "MitreID": "T1014",
  "Tags": ["evil.sys", "has space.sys"], "CVE": null,
  "KnownVulnerableSamples": [
   {"SHA256": "` + strings.Repeat("B", 64) + `", "Authentihash": {"SHA256": "` + strings.Repeat("c", 64) + `", "MD5": "x"}},
   {"SHA256": "` + strings.Repeat("b", 64) + `"}
  ]},
 {"Id": "aaaaaaaa-1111-4111-8111-111111111111", "Category": "vulnerable driver", "Verified": "FALSE", "MitreID": "T1542, T1068",
  "Tags": ["rtcore64.sys"], "CVE": ["CVE-2019-16098", ""], "CVEs": ["CVE-2019-16098"],
  "KnownVulnerableSamples": [
   {"SHA1": "` + strings.Repeat("d", 40) + `", "LoadsDespiteHVCI": "TRUE"},
   {"SHA256": "deadbeef", "Authentihash": {"SHA1": "` + strings.Repeat("e", 40) + `"},
    "ResearchEvidence": {"LoadsDespiteHVCI": "FALSE"}},
   {"MD5": "` + strings.Repeat("f", 32) + `"}
  ]},
 {"Id": "cccccccc-1111-4111-8111-111111111111", "Category": "vulnerable driver", "MitreID": "", "Tags": [],
  "CVE": "CVE-2020-12138", "KnownVulnerableSamples": [{"MD5": "` + strings.Repeat("0", 32) + `"}]},
 {"Id": "dddddddd-1111-4111-8111-111111111111", "Category": "something new", "Tags": [],
  "KnownVulnerableSamples": [{"SHA256": "` + strings.Repeat("1", 64) + `"}]}
]`

func TestConvertAndParse(t *testing.T) {
	ds, st, err := convert([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || st.samples != 4 || st.badHashes != 1 || st.hashless != 2 || st.badCategory != 1 {
		t.Fatalf("drivers %d, stats %+v", len(ds), st)
	}
	var buf bytes.Buffer
	if err := writeDataset(&buf, ds, "fixture", "2026-10-31"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Sorted by id, de-duplicated, lower-cased; the name with a space dropped.
	wantLines := []string{
		"D\taaaaaaaa-1111-4111-8111-111111111111\tvulnerable\tno\tT1542\tCVE-2019-16098\trtcore64.sys",
		"S\t-\t-\t-\t" + strings.Repeat("e", 40) + "\tno",
		"S\t-\t" + strings.Repeat("d", 40) + "\t-\t-\tyes",
		"D\tbbbbbbbb-1111-4111-8111-111111111111\tmalicious\tyes\tT1014\t-\tevil.sys",
		"S\t" + strings.Repeat("b", 64) + "\t-\t-\t-\t-",
		"S\t" + strings.Repeat("b", 64) + "\t-\t" + strings.Repeat("c", 64) + "\t-\t-",
	}
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(l, "#") {
			got = append(got, l)
		}
	}
	if strings.Join(got, "\n") != strings.Join(wantLines, "\n") {
		t.Fatalf("dataset:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantLines, "\n"))
	}

	set, err := vulndrivers.Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("lrng can't read what drivergen wrote: %v", err)
	}
	if set.Info.Source != "fixture" || set.Info.Drivers != 2 || set.Info.Samples != 4 {
		t.Errorf("info %+v", set.Info)
	}
	if m, ok := set.FileHex(strings.Repeat("d", 40)); !ok || m.Driver.Label() != "rtcore64.sys" || m.HVCI != vulndrivers.HVCILoads {
		t.Errorf("sha1 lookup: %+v", m)
	}

	// The same input always gives the same bytes.
	ds2, _, _ := convert([]byte(fixture))
	var again bytes.Buffer
	_ = writeDataset(&again, ds2, "fixture", "2026-10-31")
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Error("output isn't deterministic")
	}
}

func TestConvertRejects(t *testing.T) {
	for name, in := range map[string]string{
		"not json":   "{",
		"empty list": "[]",
		"bad id":     `[{"Id": "x", "Category": "malicious"}]`,
		"no hashes":  `[{"Id": "aaaaaaaa-1111-4111-8111-111111111111", "Category": "malicious", "KnownVulnerableSamples": [{"MD5": "x"}]}]`,
	} {
		if _, _, err := convert([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWriteFileAtomicLeavesTargetOnFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loldrivers.tsv")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writeFileAtomic(path, func(w io.Writer) error {
		_, _ = w.Write([]byte("half"))
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("no error")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Fatalf("target changed to %q", b)
	}
}
