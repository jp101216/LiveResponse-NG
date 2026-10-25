// Command intelgen compiles the endpoint-intelligence dataset that lrng bundles
// (internal/intel/data/endpoints.tsv) from authoritative public sources. The
// tool itself needs a network to *fetch* those sources, but the dataset it
// produces is wholly offline — that is the point: do the lookups once, here, so
// a live-response host never has to.
//
// Inputs (all optional; at least one source is required):
//
//	-ip2asn <file>   the free iptoasn.com combined table, giving, per IP range,
//	                 its origin AS, country, and AS description:
//	                   range_start <TAB> range_end <TAB> ASN <TAB> CC <TAB> AS_description
//	                 .gz is read transparently. Download:
//	                   https://iptoasn.com/data/ip2asn-combined.tsv.gz
//	-tor <file>      a Tor node list, one IP per line (bulk exit list or relay
//	                 dump); each is tagged as Tor infrastructure. Download:
//	                   https://check.torproject.org/torbulkexitlist
//	-cats <file>     optional ASN->categories overrides/additions, one per line:
//	                   <ASN> <TAB> cloud,cdn,hosting,dns,anonymizer
//	                 (merged over the built-in provider map below)
//
// Output is the dataset TSV (-out, default stdout). By default only ranges that
// get a category (from the ASN map) plus the Tor set are emitted, which keeps the
// dataset to the "interesting infrastructure" and small; -countries emits a
// country for every range in the ip2asn table as well (far larger).
//
// Example:
//
//	intelgen -ip2asn ip2asn-combined.tsv.gz -tor torbulkexitlist \
//	         -out internal/intel/data/endpoints.tsv
//
// The tool is dependency-free (standard library only), matching the rest of the
// Go tree.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	var (
		ip2asnPath = flag.String("ip2asn", "", "iptoasn.com combined TSV (plain or .gz): range_start,range_end,ASN,CC,description")
		asnCIDRs   = flag.String("asn-cidrs", "", "directory of ipverse/asn-ip aggregated files (each '# AS<n> (NAME)' + CIDRs); tagged by the ASN->category map")
		torPath    = flag.String("tor", "", "Tor node list, one IP per line (tagged as Tor infrastructure)")
		catsPath   = flag.String("cats", "", "optional ASN->categories overrides: '<ASN>\\t<cat,cat>' per line")
		outPath    = flag.String("out", "", "output dataset path (default: stdout)")
		countries  = flag.Bool("countries", false, "also emit a country for every ip2asn range (much larger dataset)")
		source     = flag.String("source", "", "value for the dataset 'source' metadata (default: derived from inputs)")
		verbose    = flag.Bool("v", false, "print progress and counts to stderr")
	)
	flag.Parse()

	if *ip2asnPath == "" && *torPath == "" && *asnCIDRs == "" {
		fmt.Fprintln(os.Stderr, "intelgen: need at least one of -ip2asn, -asn-cidrs or -tor")
		flag.Usage()
		os.Exit(2)
	}

	cfg := genConfig{
		ip2asn:    *ip2asnPath,
		asnCIDRs:  *asnCIDRs,
		tor:       *torPath,
		cats:      *catsPath,
		countries: *countries,
		source:    *source,
		generated: time.Now().UTC().Format("2006-01-02"),
		verbose:   *verbose,
	}

	if *outPath == "" {
		if err := generate(os.Stdout, cfg); err != nil {
			fail(err)
		}
		return
	}
	if err := writeFileAtomic(*outPath, func(w io.Writer) error { return generate(w, cfg) }); err != nil {
		fail(err)
	}
}

// writeFileAtomic writes path through a temporary file in the same directory,
// renamed into place only once write has succeeded. The usual -out target is
// the dataset lrng embeds, so a failed run (a missing or truncated input) must
// leave the existing file untouched rather than empty or half-written.
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
		err = os.Chmod(name, 0o644) // a checked-in data file, not a secret
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "intelgen: error:", err)
	os.Exit(1)
}

type genConfig struct {
	ip2asn, asnCIDRs, tor, cats string
	countries                   bool
	source, generated           string
	verbose                     bool
}

// outEntry is one dataset row to emit.
type outEntry struct {
	prefix netip.Prefix
	asn    uint32
	cc     string
	cats   string // comma-separated category names
	org    string
}

// generate compiles the dataset and writes it to w.
func generate(w io.Writer, cfg genConfig) error {
	catByASN, err := buildCategoryMap(cfg.cats)
	if err != nil {
		return err
	}

	var entries []outEntry

	if cfg.ip2asn != "" {
		n, err := readIP2ASN(cfg.ip2asn, catByASN, cfg.countries, func(e outEntry) {
			entries = append(entries, e)
		})
		if err != nil {
			return fmt.Errorf("ip2asn: %w", err)
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "intelgen: ip2asn rows kept: %d (%d prefixes)\n", n, len(entries))
		}
	}

	if cfg.asnCIDRs != "" {
		before := len(entries)
		files, err := readASNCIDRs(cfg.asnCIDRs, catByASN, func(e outEntry) {
			entries = append(entries, e)
		})
		if err != nil {
			return fmt.Errorf("asn-cidrs: %w", err)
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "intelgen: asn-cidrs files: %d (%d prefixes)\n", files, len(entries)-before)
		}
	}

	if cfg.tor != "" {
		tor, err := readTor(cfg.tor)
		if err != nil {
			return fmt.Errorf("tor: %w", err)
		}
		for _, p := range tor {
			entries = append(entries, outEntry{prefix: p, cats: "tor", org: "Tor node"})
		}
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "intelgen: tor nodes: %d\n", len(tor))
		}
	}

	// Overlay well-known specifics the coarse, by-ASN feeds get wrong or miss:
	// public DNS resolvers (otherwise tagged by their host ASN's category) and
	// the stable Tor directory authorities. Emitted last so last-wins dedup and
	// longest-prefix match favour them for those exact prefixes.
	entries = append(entries, builtinOverlay()...)

	entries = sortAndDedup(entries)

	source := cfg.source
	if source == "" {
		source = deriveSource(cfg)
	}
	return writeDataset(w, entries, source, cfg.generated)
}

// writeDataset emits the header and sorted records.
func writeDataset(w io.Writer, entries []outEntry, source, generated string) error {
	bw := bufio.NewWriter(w)
	fmt.Fprintln(bw, "# liveresponse-ng endpoint-intelligence dataset")
	fmt.Fprintf(bw, "# source: %s\n", source)
	fmt.Fprintf(bw, "# generated: %s\n", generated)
	fmt.Fprintln(bw, "# notes: generated by cmd/intelgen; attribution is only as current as the source data")
	fmt.Fprintln(bw, "# format: CIDR<TAB>ASN<TAB>CC<TAB>CATEGORIES<TAB>ORG")
	for _, e := range entries {
		asn := ""
		if e.asn != 0 {
			asn = strconv.FormatUint(uint64(e.asn), 10)
		}
		fmt.Fprintf(bw, "%s\t%s\t%s\t%s\t%s\n", e.prefix, asn, e.cc, e.cats, e.org)
	}
	return bw.Flush()
}

// deriveSource names the inputs that fed a run, for the dataset metadata.
func deriveSource(cfg genConfig) string {
	var parts []string
	if cfg.ip2asn != "" {
		parts = append(parts, "iptoasn.com")
	}
	if cfg.asnCIDRs != "" {
		parts = append(parts, "ipverse/asn-ip")
	}
	if cfg.tor != "" {
		parts = append(parts, "tor-exit-list")
	}
	return strings.Join(parts, " + ")
}

// builtinOverlay returns curated, stable specifics layered on top of the live
// feeds: public DNS resolvers (so a resolver reads as "dns" rather than its host
// ASN's category) and the Tor directory authorities (stable infrastructure the
// exit-list feed doesn't include). These are few and well-known; everything else
// comes from the feeds.
func builtinOverlay() []outEntry {
	mk := func(cidr string, asn uint32, cc, cats, org string) outEntry {
		return outEntry{prefix: netip.MustParsePrefix(cidr), asn: asn, cc: cc, cats: cats, org: org}
	}
	return []outEntry{
		// Public DNS resolvers.
		mk("1.1.1.0/24", 13335, "", "cdn,dns", "Cloudflare"),
		mk("1.0.0.0/24", 13335, "", "cdn,dns", "Cloudflare"),
		mk("8.8.8.0/24", 15169, "", "dns", "Google Public DNS"),
		mk("8.8.4.0/24", 15169, "", "dns", "Google Public DNS"),
		mk("9.9.9.0/24", 19281, "", "dns", "Quad9"),
		mk("149.112.112.0/24", 19281, "", "dns", "Quad9"),
		mk("208.67.222.0/24", 36692, "", "dns", "OpenDNS"),
		mk("208.67.220.0/24", 36692, "", "dns", "OpenDNS"),
		mk("94.140.14.0/24", 212772, "", "dns", "AdGuard DNS"),
		// Tor directory authorities (stable; the exit-list feed omits them).
		mk("128.31.0.39/32", 3, "US", "tor", "Tor directory authority (moria1)"),
		mk("86.59.21.38/32", 0, "AT", "tor", "Tor directory authority (tor26)"),
		mk("194.109.206.212/32", 3265, "NL", "tor", "Tor directory authority (dizum)"),
		mk("131.188.40.189/32", 680, "DE", "tor", "Tor directory authority (gabelmoo)"),
		mk("193.23.244.244/32", 0, "DE", "tor", "Tor directory authority (dannenberg)"),
		mk("171.25.193.9/32", 198093, "SE", "tor", "Tor directory authority (maatuska)"),
		mk("154.35.175.225/32", 0, "US", "tor", "Tor directory authority (Faravahar)"),
		mk("199.58.81.140/32", 0, "US", "tor", "Tor directory authority (longclaw)"),
		mk("204.13.164.118/32", 0, "US", "tor", "Tor directory authority (bastet)"),
	}
}

// readASNCIDRs reads a directory of ipverse/asn-ip aggregated files, emitting a
// dataset entry per CIDR tagged with the ASN's category and organisation. It
// returns the number of files parsed.
func readASNCIDRs(dir string, catByASN map[uint32]string, emit func(outEntry)) (int, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	files := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		asn, org, cidrs := parseIpverseFile(data)
		if asn == 0 || len(cidrs) == 0 {
			continue
		}
		files++
		cats := catByASN[asn]
		for _, p := range cidrs {
			emit(outEntry{prefix: p, asn: asn, cats: cats, org: org})
		}
	}
	return files, nil
}

// parseIpverseFile parses one ipverse/asn-ip aggregated file:
//
//	# AS13335 (CLOUDFLARENET)
//	# Cloudflare Inc.
//	#
//	1.1.1.0/24
//	...
//
// returning the ASN, a display organisation (the descriptive comment if present,
// else the parenthesised handle), and the CIDRs.
func parseIpverseFile(data []byte) (uint32, string, []netip.Prefix) {
	var (
		asn    uint32
		handle string
		org    string
		cidrs  []netip.Prefix
	)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			body := strings.TrimSpace(strings.TrimLeft(line, "#"))
			if body == "" {
				continue
			}
			if asn == 0 && strings.HasPrefix(body, "AS") {
				// "AS13335 (CLOUDFLARENET)"
				rest := body[2:]
				numEnd := 0
				for numEnd < len(rest) && rest[numEnd] >= '0' && rest[numEnd] <= '9' {
					numEnd++
				}
				if n, err := strconv.ParseUint(rest[:numEnd], 10, 32); err == nil {
					asn = uint32(n)
				}
				if i := strings.IndexByte(rest, '('); i >= 0 {
					handle = strings.TrimRight(strings.TrimSpace(rest[i+1:]), ")")
				}
			} else if org == "" {
				org = body // the descriptive org line (e.g. "Cloudflare Inc.")
			}
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			cidrs = append(cidrs, p)
		}
	}
	if org == "" {
		org = handle
	}
	return asn, org, cidrs
}

// readIP2ASN streams the iptoasn table, emitting a dataset entry for every range
// that gets a category from catByASN (always) or any range at all when
// allCountries is set. It returns the number of source rows kept.
func readIP2ASN(path string, catByASN map[uint32]string, allCountries bool, emit func(outEntry)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		r = gz
	}

	kept := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		row, ok := parseIP2ASNLine(sc.Text())
		if !ok {
			continue
		}
		cats := catByASN[row.asn]
		if cats == "" && !allCountries {
			continue // not interesting infrastructure, and not in country mode
		}
		cidrs, err := rangeToCIDRs(row.start, row.end)
		if err != nil {
			continue // skip a malformed range rather than abort
		}
		kept++
		for _, p := range cidrs {
			emit(outEntry{prefix: p, asn: row.asn, cc: row.cc, cats: cats, org: row.org})
		}
	}
	return kept, sc.Err()
}

type ip2asnRow struct {
	start, end netip.Addr
	asn        uint32
	cc         string
	org        string
}

// parseIP2ASNLine parses one iptoasn combined-table row. A row whose ASN is 0
// ("not routed") is still parsed; the caller decides whether to keep it.
func parseIP2ASNLine(line string) (ip2asnRow, bool) {
	f := strings.SplitN(strings.TrimRight(line, "\r"), "\t", 5)
	if len(f) < 5 {
		return ip2asnRow{}, false
	}
	start, err := netip.ParseAddr(strings.TrimSpace(f[0]))
	if err != nil {
		return ip2asnRow{}, false
	}
	end, err := netip.ParseAddr(strings.TrimSpace(f[1]))
	if err != nil {
		return ip2asnRow{}, false
	}
	if start.Is4() != end.Is4() {
		return ip2asnRow{}, false
	}
	asn64, _ := strconv.ParseUint(strings.TrimSpace(f[2]), 10, 32)
	cc := strings.ToUpper(strings.TrimSpace(f[3]))
	if cc == "NONE" || len(cc) != 2 {
		cc = ""
	}
	org := strings.TrimSpace(f[4])
	if org == "Not routed" {
		org = ""
	}
	return ip2asnRow{start: start, end: end, asn: uint32(asn64), cc: cc, org: org}, true
}

// readTor reads a Tor node list (one IP per line, '#' comments allowed) into
// host-route prefixes.
func readTor(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netip.Prefix
	seen := map[netip.Addr]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Some exit lists prefix fields like "ExitAddress <ip> <date>".
		if fields := strings.Fields(line); len(fields) > 1 {
			if strings.EqualFold(fields[0], "ExitAddress") || strings.EqualFold(fields[0], "ExitNode") {
				line = fields[1]
			} else {
				line = fields[0]
			}
		}
		addr, err := netip.ParseAddr(line)
		if err != nil || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, sc.Err()
}

// buildCategoryMap starts from the built-in provider map and layers any
// overrides from an optional file on top.
func buildCategoryMap(path string) (map[uint32]string, error) {
	m := map[uint32]string{}
	for asn, cat := range builtinASNCategories {
		m[asn] = cat
	}
	if path == "" {
		return m, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(parts[0]), "AS"), 10, 32)
		if err != nil {
			continue
		}
		m[uint32(asn)] = parts[1]
	}
	return m, sc.Err()
}

// sortAndDedup orders entries for a clean, stable, diffable dataset and drops
// exact-duplicate prefixes (last wins, matching the loader).
func sortAndDedup(entries []outEntry) []outEntry {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i].prefix, entries[j].prefix
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4() // IPv4 block first
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	out := entries[:0]
	var last netip.Prefix
	haveLast := false
	for _, e := range entries {
		if haveLast && e.prefix == last {
			out[len(out)-1] = e // last wins
			continue
		}
		out = append(out, e)
		last = e.prefix
		haveLast = true
	}
	return out
}

// rangeToCIDRs decomposes an inclusive [start,end] address range into the
// minimal set of aligned CIDR prefixes. start and end must be the same family.
func rangeToCIDRs(start, end netip.Addr) ([]netip.Prefix, error) {
	start, end = start.Unmap(), end.Unmap()
	if start.Is4() != end.Is4() {
		return nil, fmt.Errorf("mixed address families: %s and %s", start, end)
	}
	maxBits := 32
	if start.Is6() {
		maxBits = 128
	}
	cur := addrToInt(start)
	last := addrToInt(end)
	if cur.Cmp(last) > 0 {
		return nil, fmt.Errorf("start %s is after end %s", start, end)
	}

	var out []netip.Prefix
	one := big.NewInt(1)
	for cur.Cmp(last) <= 0 {
		// Largest aligned block that starts at cur: limited by cur's trailing
		// zero bits (alignment) ...
		align := maxBits
		if cur.Sign() != 0 {
			align = int(cur.TrailingZeroBits())
		}
		// ... and by how many addresses remain (end-cur+1).
		span := new(big.Int).Sub(last, cur)
		span.Add(span, one)
		fit := span.BitLen() - 1 // floor(log2(span))
		hostBits := align
		if fit < hostBits {
			hostBits = fit
		}
		if hostBits > maxBits {
			hostBits = maxBits
		}
		prefixLen := maxBits - hostBits
		out = append(out, netip.PrefixFrom(intToAddr(cur, start.Is4()), prefixLen))

		// Advance cur by the block size (2^hostBits).
		blk := new(big.Int).Lsh(one, uint(hostBits))
		cur = new(big.Int).Add(cur, blk)
	}
	return out, nil
}

func addrToInt(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func intToAddr(i *big.Int, is4 bool) netip.Addr {
	if is4 {
		var b [4]byte
		i.FillBytes(b[:])
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	i.FillBytes(b[:])
	return netip.AddrFrom16(b)
}

// builtinASNCategories maps well-known provider ASNs to a category, so a
// by-ASN pass tags the common cloud / CDN / hosting / DNS infrastructure
// without any external overlay. It is intentionally conservative — transit-only
// carriers are omitted — and fully overridable with -cats.
var builtinASNCategories = map[uint32]string{
	// Cloud / IaaS
	16509:  "cloud", // Amazon AWS
	14618:  "cloud", // Amazon AWS
	8075:   "cloud", // Microsoft Azure
	15169:  "cloud", // Google (GCP + services)
	396982: "cloud", // Google Cloud
	31898:  "cloud", // Oracle Cloud
	45102:  "cloud", // Alibaba Cloud (intl)
	37963:  "cloud", // Alibaba Cloud
	132203: "cloud", // Tencent Cloud
	45090:  "cloud", // Tencent Cloud
	// CDN / edge
	13335: "cdn", // Cloudflare
	54113: "cdn", // Fastly
	20940: "cdn", // Akamai
	16625: "cdn", // Akamai
	12222: "cdn", // Akamai
	15133: "cdn", // Edgecast / Verizon Media
	22822: "cdn", // Limelight / Edgio
	19551: "cdn", // Imperva / Incapsula
	// Hosting / VPS / dedicated
	14061: "hosting", // DigitalOcean
	16276: "hosting", // OVH
	24940: "hosting", // Hetzner
	63949: "hosting", // Akamai Linode
	20473: "hosting", // Vultr / Choopa
	51167: "hosting", // Contabo
	9009:  "hosting", // M247
	60781: "hosting", // LeaseWeb NL
	16265: "hosting", // LeaseWeb
	12876: "hosting", // Scaleway / Online SAS
	47583: "hosting", // Hostinger
	// Public DNS resolvers
	19281:  "dns", // Quad9
	36692:  "dns", // OpenDNS
	212772: "dns", // AdGuard DNS
}
