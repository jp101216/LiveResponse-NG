// Package vulndrivers knows the Windows drivers published as vulnerable or
// malicious, by hash, so a host's drivers can be checked offline.
//
// Bring your own vulnerable driver (BYOVD): an attacker with administrator
// rights installs a legitimately signed driver with a known flaw (a
// read/write-anything IOCTL, say) and uses it to run code in the kernel: to
// kill or blind EDR, strip process protection, or load an unsigned rootkit.
// Windows loads the driver because its signature is valid, so the reliable
// tell is the driver itself. The bundled dataset is LOLDrivers
// (https://www.loldrivers.io, Apache License 2.0; see LICENSE.loldrivers),
// generated into data/loldrivers.tsv by cmd/drivergen.
//
// Only exact hashes identify a driver: the file's SHA-256 or SHA-1, or its
// Authenticode digest (internal/pehash), which stays the same when a driver
// is re-signed. LOLDrivers' file names are hunting leads, not detections (a
// patched build of a driver keeps its name), so they are carried as context
// only and never matched on.
package vulndrivers

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed data/loldrivers.tsv
var embedded []byte

// Category says what kind of entry a driver is.
type Category uint8

const (
	Vulnerable Category = 1 // a legitimate driver with an exploitable flaw
	Malicious  Category = 2 // a driver written to do harm (rootkits, EDR killers)
)

func (c Category) String() string {
	switch c {
	case Vulnerable:
		return "vulnerable"
	case Malicious:
		return "malicious"
	}
	return "unknown"
}

// Driver is one dataset entry: a driver and every known build of it.
type Driver struct {
	ID        string   // the LOLDrivers identifier (a UUID)
	Category  Category //
	Verified  bool     // LOLDrivers' maintainers have verified the entry
	Technique string   // ATT&CK technique LOLDrivers maps it to ("" if none)
	CVEs      []string
	Names     []string // file names it is known by (hunting leads, never matched on)
}

// URL is the driver's LOLDrivers page.
func (d *Driver) URL() string { return "https://www.loldrivers.io/drivers/" + d.ID + "/" }

// Label is a short name for the driver: its first known file name, or its
// identifier.
func (d *Driver) Label() string {
	if len(d.Names) > 0 {
		return d.Names[0]
	}
	return d.ID
}

// HVCI says whether a sample still loads with memory integrity (HVCI) on,
// which enforces Microsoft's vulnerable driver blocklist.
type HVCI uint8

const (
	HVCIUnknown HVCI = iota
	HVCILoads        // loads even with HVCI on
	HVCIBlocked      // HVCI keeps it from loading
)

// Sample is one known build of a driver.
type Sample struct {
	Driver *Driver
	HVCI   HVCI
}

// Match is a sample found by one of its hashes.
type Match struct {
	Sample
	// By names the hash that matched: "file SHA-256", "file SHA-1",
	// "Authenticode SHA-256" or "Authenticode SHA-1".
	By string
}

// Info describes a dataset, for run metadata.
type Info struct {
	Source    string `json:"source"`
	Generated string `json:"generated"`
	Drivers   int    `json:"drivers"`
	Samples   int    `json:"samples"`
}

// Set is a parsed dataset. Safe for concurrent lookups.
type Set struct {
	Info    Info
	samples []Sample
	file256 map[[32]byte]int32
	file1   map[[20]byte]int32
	auth256 map[[32]byte]int32
	auth1   map[[20]byte]int32
}

var (
	defaultOnce sync.Once
	defaultSet  *Set
	defaultErr  error
)

// Default returns the bundled dataset, parsed on first use.
func Default() (*Set, error) {
	defaultOnce.Do(func() { defaultSet, defaultErr = Parse(embedded) })
	return defaultSet, defaultErr
}

// Lookup methods. A hash shared by several entries resolves to the most
// severe one (malicious before vulnerable), then the first in the file.

func (s *Set) FileSHA256(sum [32]byte) (Match, bool) { return s.get(s.file256[sum], "file SHA-256") }
func (s *Set) FileSHA1(sum [20]byte) (Match, bool)   { return s.get(s.file1[sum], "file SHA-1") }
func (s *Set) AuthentihashSHA256(sum [32]byte) (Match, bool) {
	return s.get(s.auth256[sum], "Authenticode SHA-256")
}
func (s *Set) AuthentihashSHA1(sum [20]byte) (Match, bool) {
	return s.get(s.auth1[sum], "Authenticode SHA-1")
}

// FileHex looks up a file hash given in hex: 64 digits for SHA-256, 40 for
// SHA-1, any case. Anything else (an MD5, an IMPHASH, junk) is no match.
func (s *Set) FileHex(h string) (Match, bool) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return Match{}, false
	}
	switch len(b) {
	case 32:
		return s.FileSHA256([32]byte(b))
	case 20:
		return s.FileSHA1([20]byte(b))
	}
	return Match{}, false
}

func (s *Set) get(i int32, by string) (Match, bool) {
	if i <= 0 { // 0 is the zero value of a missing key; samples are 1-based
		return Match{}, false
	}
	return Match{Sample: s.samples[i-1], By: by}, true
}

var (
	idRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	techRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	cveRe  = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
)

// Parse reads a dataset in the format cmd/drivergen writes:
//
//	# comment and metadata lines ("# source: ...", "# generated: ...")
//	D<TAB>id<TAB>category<TAB>verified<TAB>technique<TAB>cves<TAB>names
//	S<TAB>sha256<TAB>sha1<TAB>authentihash_sha256<TAB>authentihash_sha1<TAB>hvci
//
// An S line belongs to the D line above it; "-" is an empty value. A
// malformed line is an error that names it: the dataset is generated, so a bad
// line means a bad build, not something to skip quietly.
func Parse(data []byte) (*Set, error) {
	s := &Set{
		file256: map[[32]byte]int32{},
		file1:   map[[20]byte]int32{},
		auth256: map[[32]byte]int32{},
		auth1:   map[[20]byte]int32{},
	}
	var cur *Driver
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line[1:]), ":"); ok {
				switch strings.TrimSpace(k) {
				case "source":
					s.Info.Source = strings.TrimSpace(v)
				case "generated":
					s.Info.Generated = strings.TrimSpace(v)
				}
			}
			continue
		}
		f := strings.Split(line, "\t")
		bad := func(why string) error { return fmt.Errorf("vulndrivers: line %d: %s", n, why) }
		switch f[0] {
		case "D":
			if len(f) != 7 {
				return nil, bad("a driver line needs 7 fields")
			}
			d := &Driver{ID: f[1], Technique: dash(f[4])}
			if !idRe.MatchString(d.ID) {
				return nil, bad("bad driver id " + f[1])
			}
			switch f[2] {
			case "vulnerable":
				d.Category = Vulnerable
			case "malicious":
				d.Category = Malicious
			default:
				return nil, bad("unknown category " + f[2])
			}
			switch f[3] {
			case "yes":
				d.Verified = true
			case "no":
			default:
				return nil, bad("verified must be yes or no")
			}
			if d.Technique != "" && !techRe.MatchString(d.Technique) {
				return nil, bad("bad technique " + f[4])
			}
			for _, c := range list(f[5]) {
				if !cveRe.MatchString(c) {
					return nil, bad("bad CVE " + c)
				}
				d.CVEs = append(d.CVEs, c)
			}
			d.Names = list(f[6])
			cur = d
			s.Info.Drivers++
		case "S":
			if len(f) != 6 {
				return nil, bad("a sample line needs 6 fields")
			}
			if cur == nil {
				return nil, bad("a sample before any driver")
			}
			sm := Sample{Driver: cur}
			switch f[5] {
			case "yes":
				sm.HVCI = HVCILoads
			case "no":
				sm.HVCI = HVCIBlocked
			case "-":
			default:
				return nil, bad("hvci must be yes, no or -")
			}
			s.samples = append(s.samples, sm)
			idx := int32(len(s.samples))
			hashed := false
			for i, size := range []int{32, 20, 32, 20} {
				v := f[1+i]
				if v == "-" {
					continue
				}
				b, err := hex.DecodeString(v)
				if err != nil || len(b) != size || strings.ToLower(v) != v {
					return nil, bad(fmt.Sprintf("bad hash %q", v))
				}
				hashed = true
				switch i {
				case 0:
					s.add256(s.file256, [32]byte(b), idx)
				case 1:
					s.add1(s.file1, [20]byte(b), idx)
				case 2:
					s.add256(s.auth256, [32]byte(b), idx)
				case 3:
					s.add1(s.auth1, [20]byte(b), idx)
				}
			}
			if !hashed {
				return nil, bad("a sample with no hash")
			}
			s.Info.Samples++
		default:
			return nil, bad("unknown line type " + f[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("vulndrivers: %w", err)
	}
	if s.Info.Samples == 0 {
		return nil, fmt.Errorf("vulndrivers: the dataset has no samples")
	}
	return s, nil
}

// add256 and add1 index a hash, keeping a malicious entry over a vulnerable
// one when two entries list the same hash.
func (s *Set) add256(m map[[32]byte]int32, k [32]byte, idx int32) {
	if old, ok := m[k]; !ok || s.worse(idx, old) {
		m[k] = idx
	}
}

func (s *Set) add1(m map[[20]byte]int32, k [20]byte, idx int32) {
	if old, ok := m[k]; !ok || s.worse(idx, old) {
		m[k] = idx
	}
}

func (s *Set) worse(a, b int32) bool {
	return s.samples[a-1].Driver.Category > s.samples[b-1].Driver.Category
}

func dash(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

func list(v string) []string {
	if v == "-" || v == "" {
		return nil
	}
	return strings.Split(v, ",")
}
