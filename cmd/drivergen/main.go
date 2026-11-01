// Command drivergen compiles the known vulnerable and malicious driver dataset
// that lrng bundles (internal/vulndrivers/data/loldrivers.tsv) from LOLDrivers'
// published API file, drivers.json:
//
//	curl -LO https://www.loldrivers.io/api/drivers.json
//	drivergen -in drivers.json -source "LOLDrivers <commit or date>" \
//	          -out internal/vulndrivers/data/loldrivers.tsv
//
// Kept per driver: its LOLDrivers id, category (vulnerable or malicious),
// whether it is verified, its ATT&CK technique, CVEs, and known file names.
// Kept per sample: the file SHA-256 and SHA-1, the Authenticode SHA-256 and
// SHA-1, and whether it loads with HVCI on. Everything else in drivers.json
// (commands, references, metadata of each file) is context lrng doesn't
// need. MD5s are left out: nothing lrng reads offers only an MD5.
//
// Output is sorted and de-duplicated, so the same input always gives the same
// file, and the diff of a refresh shows exactly what changed. Hashes that
// aren't well-formed hex of the right length are dropped and counted (-v).
// The tool uses the standard library only, like the rest of the Go tree.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func main() {
	var (
		in      = flag.String("in", "", "LOLDrivers drivers.json")
		out     = flag.String("out", "", "output dataset path (default: stdout)")
		source  = flag.String("source", "LOLDrivers drivers.json", "value for the dataset's 'source' line (say which commit or date)")
		date    = flag.String("date", "", "value for the 'generated' line (default: today, UTC)")
		verbose = flag.Bool("v", false, "print counts to stderr")
	)
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "drivergen: -in drivers.json is required")
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
	ds, st, err := convert(raw)
	if err != nil {
		fail(err)
	}
	if *verbose {
		fmt.Fprintf(os.Stderr, "drivergen: %d drivers, %d samples; dropped %d malformed hash(es), %d hashless sample(s), %d entr(ies) of unknown category\n",
			len(ds), st.samples, st.badHashes, st.hashless, st.badCategory)
	}
	write := func(w io.Writer) error { return writeDataset(w, ds, *source, *date) }
	if *out == "" {
		if err := write(os.Stdout); err != nil {
			fail(err)
		}
		return
	}
	if err := writeFileAtomic(*out, write); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "drivergen: error:", err)
	os.Exit(1)
}

// The parts of drivers.json used here. Fields that changed shape across
// LOLDrivers versions (CVE is absent, a string, or a list) are raw JSON.
type jsonDriver struct {
	ID       string          `json:"Id"`
	Category string          `json:"Category"`
	Verified string          `json:"Verified"`
	MitreID  string          `json:"MitreID"`
	CVE      json.RawMessage `json:"CVE"`
	CVEs     json.RawMessage `json:"CVEs"`
	Tags     []string        `json:"Tags"`
	Samples  []jsonSample    `json:"KnownVulnerableSamples"`
}

type jsonSample struct {
	SHA256       string `json:"SHA256"`
	SHA1         string `json:"SHA1"`
	Authentihash struct {
		SHA256 string `json:"SHA256"`
		SHA1   string `json:"SHA1"`
	} `json:"Authentihash"`
	// LoadsDespiteHVCI moved into ResearchEvidence in later versions.
	LoadsDespiteHVCI string `json:"LoadsDespiteHVCI"`
	Evidence         struct {
		LoadsDespiteHVCI string `json:"LoadsDespiteHVCI"`
	} `json:"ResearchEvidence"`
}

type driver struct {
	id, category, verified, technique string
	cves, names                       []string
	samples                           []string // rendered S lines
}

type stats struct{ samples, badHashes, hashless, badCategory int }

var (
	idRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	techRe = regexp.MustCompile(`T\d{4}(?:\.\d{3})?`)
	cveRe  = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
	nameRe = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`) // printable ASCII, no spaces
)

func convert(raw []byte) ([]driver, stats, error) {
	var in []jsonDriver
	var st stats
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, st, fmt.Errorf("drivers.json: %w", err)
	}
	if len(in) == 0 {
		return nil, st, errors.New("drivers.json lists no drivers")
	}
	byID := map[string]*driver{}
	for _, j := range in {
		id := strings.ToLower(strings.TrimSpace(j.ID))
		if !idRe.MatchString(id) {
			return nil, st, fmt.Errorf("driver id %q is not a UUID", j.ID)
		}
		var cat string
		switch strings.ToLower(strings.TrimSpace(j.Category)) {
		case "vulnerable driver", "vulnerable":
			cat = "vulnerable"
		case "malicious":
			cat = "malicious"
		default:
			st.badCategory++
			continue
		}
		d := byID[id]
		if d == nil {
			d = &driver{id: id, category: cat, verified: "no", technique: "-"}
			byID[id] = d
		}
		if strings.EqualFold(strings.TrimSpace(j.Verified), "true") {
			d.verified = "yes"
		}
		if t := techRe.FindString(j.MitreID); t != "" {
			d.technique = t
		}
		d.cves = append(d.cves, cveRe.FindAllString(string(j.CVE)+" "+string(j.CVEs), -1)...)
		for _, n := range j.Tags {
			n = strings.TrimSpace(n)
			if nameRe.MatchString(n) && !strings.Contains(n, ",") {
				d.names = append(d.names, n)
			}
		}
		for _, s := range j.Samples {
			hashes := []string{
				hexOrDash(s.SHA256, 32, &st), hexOrDash(s.SHA1, 20, &st),
				hexOrDash(s.Authentihash.SHA256, 32, &st), hexOrDash(s.Authentihash.SHA1, 20, &st),
			}
			if strings.Join(hashes, "") == "----" {
				st.hashless++
				continue
			}
			hvci := "-"
			switch strings.ToUpper(firstNonEmpty(s.Evidence.LoadsDespiteHVCI, s.LoadsDespiteHVCI)) {
			case "TRUE":
				hvci = "yes"
			case "FALSE":
				hvci = "no"
			}
			d.samples = append(d.samples, "S\t"+strings.Join(hashes, "\t")+"\t"+hvci)
		}
	}
	out := make([]driver, 0, len(byID))
	for _, d := range byID {
		d.cves = uniqueSorted(d.cves)
		d.names = uniqueSorted(d.names)
		d.samples = uniqueSorted(d.samples)
		if len(d.samples) == 0 {
			continue
		}
		st.samples += len(d.samples)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	if len(out) == 0 {
		return nil, st, errors.New("no driver in drivers.json has a usable hash")
	}
	return out, st, nil
}

// hexOrDash normalises a hash to lower-case hex of n bytes, or "-" when it is
// absent or malformed (counted).
func hexOrDash(v string, n int, st *stats) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "-" {
		return "-"
	}
	if b, err := hex.DecodeString(v); err != nil || len(b) != n {
		st.badHashes++
		return "-"
	}
	return v
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func uniqueSorted(v []string) []string {
	sort.Strings(v)
	out := v[:0]
	for i, s := range v {
		if i == 0 || s != v[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func orDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ",")
}

func writeDataset(w io.Writer, ds []driver, source, generated string) error {
	bw := bufio.NewWriter(w)
	samples := 0
	for _, d := range ds {
		samples += len(d.samples)
	}
	fmt.Fprintln(bw, "# liveresponse-ng known vulnerable and malicious Windows driver dataset")
	fmt.Fprintf(bw, "# source: %s\n", strings.ReplaceAll(source, "\n", " "))
	fmt.Fprintf(bw, "# generated: %s\n", generated)
	fmt.Fprintf(bw, "# notes: generated by cmd/drivergen from LOLDrivers (https://www.loldrivers.io), %d drivers, %d samples.\n", len(ds), samples)
	fmt.Fprintln(bw, "#   LOLDrivers is licensed under the Apache License 2.0 (LICENSE.loldrivers, next to this file).")
	fmt.Fprintln(bw, "#   Only exact hashes identify a driver; names are hunting leads, never matched on.")
	fmt.Fprintln(bw, "# format: a D line per driver, then an S line per known sample of it (- is empty):")
	fmt.Fprintln(bw, "#   D<TAB>id<TAB>category<TAB>verified<TAB>technique<TAB>cves<TAB>names")
	fmt.Fprintln(bw, "#   S<TAB>sha256<TAB>sha1<TAB>authentihash_sha256<TAB>authentihash_sha1<TAB>loads_despite_hvci")
	for _, d := range ds {
		fmt.Fprintf(bw, "D\t%s\t%s\t%s\t%s\t%s\t%s\n", d.id, d.category, d.verified, d.technique, orDash(d.cves), orDash(d.names))
		for _, s := range d.samples {
			fmt.Fprintln(bw, s)
		}
	}
	return bw.Flush()
}

// writeFileAtomic writes path through a temporary file in the same directory,
// renamed into place only once write has succeeded, so a failed run leaves the
// bundled dataset untouched.
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
