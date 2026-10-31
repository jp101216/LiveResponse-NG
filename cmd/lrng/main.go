// Command lrng is the Live Response NG agent: a fast triage collector that
// emits one structured JSON report per run, on Windows and Linux; it builds
// anywhere.
//
// Usage examples:
//
//	lrng -list                       # show collectors available on this OS
//	lrng                             # run the default collectors, JSON to stdout
//	lrng -collectors processes,network -out report.json
//	lrng -collectors default,dnscache -out host.json   # defaults + DNS cache
//	lrng -no-dns -out E:\case42\host.json   # don't touch the host DNS cache
//	lrng -format jsonl -out host.jsonl      # one event per line for a SIEM
//	lrng -ping-sidecar               # sidecar next to lrng, or -sidecar <path>
//	lrng -prompt-scan suspicious.ps1
//	lrng -yara .\rules -out host.json       # default collectors + memory scan
//	lrng -mem-scan 4242 -yara .\rules      # one process, results to the console
//	lrng -evtx E:\case42\Security.evtx -out logs.json   # offline log triage (any OS)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/hostinfo"
	"github.com/jp101216/liveresponse-ng/internal/intel"
	"github.com/jp101216/liveresponse-ng/internal/output"
	"github.com/jp101216/liveresponse-ng/internal/sidecar"
)

// Set at build time: go build -ldflags "-X main.version=... -X main.commit=...".
// These must be vars — -X silently does nothing to a const.
var (
	version = "0.11.1"
	commit  = ""
)

func main() {
	cfg := config.Default()

	var (
		list        = flag.Bool("list", false, "list collectors available on this OS and exit")
		showVer     = flag.Bool("version", false, "print version and exit")
		collectors  = flag.String("collectors", "", `comma-separated collectors to run; "default" is the default set (default: default)`)
		allow       = flag.String("allow", "", "comma-separated extra process names allowed to call LLM APIs")
		pingSide    = flag.Bool("ping-sidecar", false, "check the Rust sidecar is reachable and exit")
		promptScan  = flag.String("prompt-scan", "", "scan a file for embedded LLM prompt artifacts via the sidecar and exit")
		memScan     = flag.Int("mem-scan", 0, "scan one process's memory (YARA via -yara, plus prompt scan), print results and exit")
		memPIDs     = flag.String("mem-pids", "", "memory collector: only scan these comma-separated PIDs")
		evtxOffline = flag.String("evtx", "", "offline mode: triage the given .evtx file(s) or directory (comma-separated) and exit; works on any OS")
	)
	flag.IntVar(&cfg.Workers, "workers", cfg.Workers, "max collectors to run concurrently")
	flag.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "per-collector timeout (0 = none)")
	flag.StringVar(&cfg.Output, "out", "", "write the report to this path, plus <path>.sha256 (default: stdout)")
	flag.StringVar(&cfg.Format, "format", cfg.Format, "report format: json (one envelope) or jsonl (one event per line)")
	flag.BoolVar(&cfg.Force, "force", false, "allow -out to overwrite an existing file")
	flag.BoolVar(&cfg.Pretty, "pretty", cfg.Pretty, "indent JSON output (json format only)")
	flag.BoolVar(&cfg.Quiet, "quiet", false, "don't print the findings summary to stderr")
	flag.BoolVar(&cfg.NoHash, "no-hash", false, "don't SHA-256 the binaries the report names (fewer file reads, faster)")
	flag.BoolVar(&cfg.NoSign, "no-sign", false, "don't verify the Authenticode signatures of process images")
	flag.StringVar(&cfg.FailOn, "fail-on", "", "exit with status 3 if any finding is at or above this severity (info, notable, suspect, critical)")
	flag.BoolVar(&cfg.NoDNS, "no-dns", false, "skip module A's live DNS lookups of LLM providers (they add entries to the host DNS cache)")
	flag.StringVar(&cfg.SidecarPath, "sidecar", "", "path to the Rust sidecar binary (default: next to lrng)")
	flag.StringVar(&cfg.YaraRules, "yara", "", "YARA rules file or directory; enables the memory collector")
	flag.StringVar(&cfg.SigmaRules, "sigma", "", "Sigma rules to evaluate against the event log: a file, a directory, or \"builtin\" for the bundled starter pack (comma-separated; live and -evtx)")
	flag.BoolVar(&cfg.Timeline, "timeline", false, "add a unified super-timeline of every timestamped artifact (a 'timeline' result)")
	flag.BoolVar(&cfg.IOCs, "iocs", false, "add a deduplicated, ranked set of indicators (IPs, domains, hashes, paths) from detection-linked records (an 'iocs' result)")
	flag.BoolVar(&cfg.Intel, "intel", false, "attribute public remote addresses offline (ASN, country, cloud/CDN/hosting/DNS/Tor) against the bundled dataset (an 'intel' result)")
	flag.StringVar(&cfg.IntelDB, "intel-db", "", "use this endpoint-intelligence dataset file instead of the bundled one (from cmd/intelgen); implies -intel")
	flag.DurationVar(&cfg.MemBudget, "mem-budget", cfg.MemBudget, "memory scan: time budget per process")
	flag.DurationVar(&cfg.MemTimeout, "mem-timeout", cfg.MemTimeout, "memory scan: time limit for the whole memory collector")
	flag.IntVar(&cfg.MemWorkers, "mem-workers", cfg.MemWorkers, "memory scan: processes scanned in parallel")
	flag.BoolVar(&cfg.MemNoPrompts, "mem-no-prompts", false, "memory scan: skip the prompt-artifact scan (YARA, the heuristics and image integrity still run)")
	flag.BoolVar(&cfg.MemIncludeLsass, "mem-include-lsass", false, "memory scan: also scan lsass.exe (skipped by default; trips EDR credential-theft protection)")
	flag.Usage = usage
	flag.Parse()

	usageErrorOn(validate(cfg, flag.Args(), *memScan))
	if cfg.IntelDB != "" {
		cfg.Intel = true // naming a dataset means you want attribution
	}
	cfg.AllowlistExtra = splitCSV(*allow)
	cfg.Collectors = splitCSV(*collectors)
	pids, err := parsePIDs(*memPIDs)
	usageErrorOn(err)
	cfg.MemPIDs = pids

	// Ctrl+C — or SIGTERM, which `timeout`, systemd and a plain `kill` send —
	// cancels collection, and whatever was gathered is still written. A second
	// signal stops waiting and exits at once (a report write stuck on a dead
	// network share, say).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sigs
		fmt.Fprintf(os.Stderr, "\nlrng: %v: stopping collection and writing what was gathered (repeat to abort)\n", s)
		cancel()
		<-sigs
		fmt.Fprintln(os.Stderr, "lrng: aborted")
		os.Exit(exitAborted)
	}()

	switch {
	case *showVer:
		fmt.Println(versionString())
		return
	case *list:
		doList()
		return
	case *pingSide:
		exitOn(doPing(ctx, cfg))
		return
	case *promptScan != "":
		exitOn(doPromptScan(ctx, cfg, *promptScan))
		return
	case *memScan != 0:
		exitOn(doMemScan(ctx, cfg, *memScan))
		return
	case *evtxOffline != "":
		rep, err := doEvtxOffline(ctx, cfg, *evtxOffline)
		exitOn(err)
		if failOnMet(rep.Summary, cfg.FailOn) {
			os.Exit(exitFindings)
		}
		return
	}

	rep, err := doRun(ctx, cfg)
	exitOn(err)
	if failOnMet(rep.Summary, cfg.FailOn) {
		os.Exit(exitFindings)
	}
}

// validate rejects option combinations that would otherwise be silently
// misread — on a live response, a typo should stop the run, not change it.
func validate(cfg config.Config, args []string, memScan int) error {
	switch {
	case len(args) > 0:
		return fmt.Errorf("unexpected argument %q (flags go before values: -out path)", args[0])
	case cfg.Workers < 1:
		return errors.New("-workers must be at least 1")
	case cfg.MemWorkers < 1:
		return errors.New("-mem-workers must be at least 1")
	case cfg.Timeout < 0 || cfg.MemTimeout < 0 || cfg.MemBudget < 0:
		return errors.New("timeouts and budgets can't be negative")
	case cfg.Format != output.FormatJSON && cfg.Format != output.FormatJSONL:
		return fmt.Errorf("-format must be %s or %s", output.FormatJSON, output.FormatJSONL)
	case memScan < 0:
		return errors.New("-mem-scan needs a positive PID")
	case cfg.FailOn != "" && collector.SeverityRank(collector.Severity(cfg.FailOn)) == 0:
		return fmt.Errorf("-fail-on must be one of info, notable, suspect, critical")
	}
	return nil
}

// Exit statuses: 0 done, 1 error, 2 bad usage (the flag package's own
// convention), 3 -fail-on threshold met, 130 aborted by a second interrupt
// (the shell's 128+SIGINT).
const (
	exitError    = 1
	exitUsage    = 2
	exitFindings = 3
	exitAborted  = 130
)

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, `Live Response NG %s: live-response triage for Windows and Linux hosts

Usage: lrng [flags]

  lrng -out host.json                  default collectors; also writes host.json.sha256
  lrng -collectors default,dnscache    add an opt-in collector to the default set
  lrng -no-dns -out host.json          skip module A's LLM-provider DNS lookups
  lrng -format jsonl -out host.jsonl   one event per line, for a SIEM
  lrng -fail-on suspect -quiet         exit status 3 when a suspect or critical finding exists
  lrng -yara rules -out host.json      also scan process memory (needs lrng-sidecar)
  lrng -evtx Security.evtx -out logs.json   offline: triage a saved .evtx (any OS)
  lrng -sigma builtin -out host.json   evaluate the bundled starter Sigma pack over the event log
  lrng -timeline -out host.json        add a unified super-timeline of timestamped artifacts
  lrng -iocs -out host.json            add a deduplicated indicator set (IPs, domains, hashes, paths)
  lrng -intel -iocs -out host.json     attribute remote IPs offline (ASN/country/cloud/Tor); enriches the IOC set
  lrng -list                           collectors available on this OS

Exit status: 0 done, 1 error, 2 bad usage, 3 -fail-on threshold met.
Ctrl+C or SIGTERM stops collection and still writes the report; a second one
aborts at once (exit status 130).

Flags:
`, version)
	flag.PrintDefaults()
}

// failOnMet reports whether any finding reaches the -fail-on severity.
func failOnMet(s output.Summary, failOn string) bool {
	if failOn == "" {
		return false
	}
	min := collector.SeverityRank(collector.Severity(failOn))
	for sev, n := range s.BySeverity {
		if n > 0 && collector.SeverityRank(sev) >= min {
			return true
		}
	}
	return false
}

func versionString() string {
	v := "lrng " + version
	if commit != "" {
		v += " (" + commit + ")"
	}
	return v + " " + runtime.GOOS + "/" + runtime.GOARCH
}

func doList() {
	fmt.Printf("%s — collectors available here:\n", versionString())
	avail := collector.Available()
	width := 0
	for _, c := range avail {
		width = max(width, len(c.Name()))
	}
	for _, c := range avail {
		note := ""
		if collector.IsOptIn(c) {
			switch c.Name() {
			case "memory":
				note = "  opt-in: name it, or pass -yara / -mem-pids"
			case "dnscache":
				note = "  opt-in: name it (also turns on DNS correlation for network)"
			default:
				note = "  opt-in: name it in -collectors"
			}
		}
		fmt.Printf("  %-*s  (%s)%s\n", width, c.Name(), strings.Join(c.Platforms(), ","), note)
	}
	fmt.Println(`Use -collectors default,<name> to add an opt-in collector to the default set.`)
}

// selectCollectors resolves -collectors, adding the memory collector when
// -yara or -mem-pids asks for it.
func selectCollectors(cfg config.Config) ([]collector.Collector, error) {
	selected, err := collector.Select(cfg.Collectors)
	if err != nil {
		return nil, err
	}
	if cfg.YaraRules != "" || len(cfg.MemPIDs) > 0 {
		mem, ok := collector.Lookup("memory")
		if !ok {
			return nil, fmt.Errorf("memory scanning is not available on %s", runtime.GOOS)
		}
		found := false
		for _, c := range selected {
			found = found || c.Name() == "memory"
		}
		if !found {
			selected = append(selected, mem)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no collectors available on %s", runtime.GOOS)
	}
	return selected, nil
}

func doRun(ctx context.Context, cfg config.Config) (output.Report, error) {
	started := time.Now().UTC()
	selected, err := selectCollectors(cfg)
	if err != nil {
		return output.Report{}, err
	}
	names := make([]string, len(selected))
	dnsCache := false
	for i, c := range selected {
		names[i] = c.Name()
		dnsCache = dnsCache || c.Name() == "dnscache"
	}

	run := output.RunInfo{
		StartedAt:      started,
		PID:            os.Getpid(),
		Args:           os.Args[1:],
		Collectors:     names,
		Workers:        cfg.Workers,
		Timeout:        cfg.Timeout.String(),
		DNSLookups:     !cfg.NoDNS,
		DNSCorrelation: dnsCache,
		Hashing:        !cfg.NoHash,
		YaraRules:      cfg.YaraRules,
		Intel:          cfg.Intel,
	}
	if elev, err := hostinfo.Elevated(); err == nil {
		run.Elevated = &elev
		if !elev {
			fmt.Fprintln(os.Stderr, "lrng: warning: not running elevated; protected and other users' processes will be incomplete")
		}
	} else {
		run.ElevationErr = err.Error()
	}
	var selfPaths []string
	if exe, err := os.Executable(); err == nil {
		run.ExePath = exe
		selfPaths = append(selfPaths, exe)
		if sum, err := output.FileSHA256(exe); err == nil {
			run.ExeSHA256 = sum
		}
	}
	if sc, err := sidecar.Locate(cfg.SidecarPath); err == nil {
		selfPaths = append(selfPaths, sc)
	}
	var hasher *collector.FileHasher
	if !cfg.NoHash {
		hasher = collector.NewFileHasher()
	}
	var signer *collector.SignatureVerifier
	if !cfg.NoSign {
		signer = collector.NewSignatureVerifier()
	}
	sigmaRS, err := loadSigma(cfg)
	if err != nil {
		return output.Report{}, fmt.Errorf("sigma rules: %w", err)
	}
	var intelDB *intel.DB
	if cfg.Intel {
		intelDB, err = loadIntelDB(cfg)
		if err != nil {
			return output.Report{}, fmt.Errorf("intel dataset: %w", err)
		}
		run.IntelDataset = intelProvenance(intelDB, cfg)
	}

	collector.ConfigureAll(selected, collector.RunOptions{
		ExtraAllowlist:  cfg.AllowlistExtra,
		ResolveLLMHosts: !cfg.NoDNS,
		DNSCorrelate:    dnsCache,
		SidecarPath:     cfg.SidecarPath,
		Hasher:          hasher,
		Signer:          signer,
		SelfPID:         os.Getpid(),
		SelfPaths:       selfPaths,
		Memory:          memoryOptions(cfg),
		Sigma:           sigmaRS,
	})

	d := &collector.Dispatcher{Workers: cfg.Workers, Timeout: cfg.Timeout}
	results := d.Run(ctx, selected)
	collector.Correlate(results) // cross-reference the event log against the live state
	if cfg.Timeline {
		results = append(results, collector.BuildTimeline(results))
	}
	if cfg.IOCs {
		results = append(results, collector.ExtractIOCs(results))
	}
	if cfg.Intel {
		results = append(results, collector.AnnotateIntel(results, intelDB))
	}

	run.FinishedAt = time.Now().UTC()
	run.Interrupted = ctx.Err() != nil

	host := cfg.Host
	if host == "" {
		host, _ = os.Hostname()
	}
	hi := hostinfo.Gather()
	rep := output.Report{
		Schema:    output.SchemaVersion,
		Tool:      "liveresponse-ng",
		Version:   version,
		Commit:    commit,
		RunID:     output.NewRunID(),
		Host:      host,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Collected: started,
		HostInfo:  &hi,
		Run:       run,
		Results:   results,
		Summary:   output.Summarise(results),
	}

	if cfg.Output == "" {
		if err := output.Write(os.Stdout, rep, cfg.Format, cfg.Pretty); err != nil {
			return rep, fmt.Errorf("write report: %w", err)
		}
	} else {
		sum, err := output.WriteFile(cfg.Output, rep, cfg.Format, cfg.Pretty, cfg.Force)
		if err != nil {
			return rep, fmt.Errorf("write report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\nsha256 %s\n", cfg.Output, sum)
	}
	if !cfg.Quiet {
		output.WriteConsoleSummary(os.Stderr, rep, 10)
	}
	return rep, nil
}

// doEvtxOffline triages supplied .evtx files (a file, a directory, or a
// comma-separated list of either) and writes the same report envelope as a live
// run — so -out, -format, -fail-on, -pretty and the sha256 sidecar all apply.
// It runs on any OS: only reading a host's live logs needs Windows.
func doEvtxOffline(ctx context.Context, cfg config.Config, spec string) (output.Report, error) {
	started := time.Now().UTC()
	files, err := expandEvtxPaths(spec)
	if err != nil {
		return output.Report{}, err
	}
	if len(files) == 0 {
		return output.Report{}, fmt.Errorf("-evtx %q matched no .evtx files", spec)
	}

	sigmaRS, err := loadSigma(cfg)
	if err != nil {
		return output.Report{}, fmt.Errorf("sigma rules: %w", err)
	}
	var (
		intelDB   *intel.DB
		intelProv string
	)
	if cfg.Intel {
		intelDB, err = loadIntelDB(cfg)
		if err != nil {
			return output.Report{}, fmt.Errorf("intel dataset: %w", err)
		}
		intelProv = intelProvenance(intelDB, cfg)
	}
	results := []collector.Result{collector.ParseEventLogFiles(ctx, files, sigmaRS)}
	collector.Correlate(results) // e.g. measure a 1102 clear against the surviving records
	if cfg.Timeline {
		results = append(results, collector.BuildTimeline(results))
	}
	if cfg.IOCs {
		results = append(results, collector.ExtractIOCs(results))
	}
	if cfg.Intel {
		results = append(results, collector.AnnotateIntel(results, intelDB))
	}

	run := output.RunInfo{
		StartedAt:    started,
		FinishedAt:   time.Now().UTC(),
		PID:          os.Getpid(),
		Args:         os.Args[1:],
		Collectors:   []string{"eventlog"},
		Workers:      1,
		Timeout:      "0s",
		Intel:        cfg.Intel,
		IntelDataset: intelProv,
		Interrupted:  ctx.Err() != nil,
	}
	if exe, err := os.Executable(); err == nil {
		run.ExePath = exe
		if sum, err := output.FileSHA256(exe); err == nil {
			run.ExeSHA256 = sum
		}
	}
	rep := output.Report{
		Schema:    output.SchemaVersion,
		Tool:      "liveresponse-ng",
		Version:   version,
		Commit:    commit,
		RunID:     output.NewRunID(),
		Host:      "(offline)", // triaging supplied files, not this host
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Collected: started,
		Run:       run,
		Results:   results,
		Summary:   output.Summarise(results),
	}

	if cfg.Output == "" {
		if err := output.Write(os.Stdout, rep, cfg.Format, cfg.Pretty); err != nil {
			return rep, fmt.Errorf("write report: %w", err)
		}
	} else {
		sum, err := output.WriteFile(cfg.Output, rep, cfg.Format, cfg.Pretty, cfg.Force)
		if err != nil {
			return rep, fmt.Errorf("write report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\nsha256 %s\n", cfg.Output, sum)
	}
	if !cfg.Quiet {
		output.WriteConsoleSummary(os.Stderr, rep, 10)
	}
	return rep, nil
}

// expandEvtxPaths turns the -evtx value (comma-separated files and/or
// directories) into a deduplicated, ordered list of .evtx files. A directory
// contributes its *.evtx entries; a named file is taken as given.
func expandEvtxPaths(spec string) ([]string, error) {
	var files []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	for _, entry := range splitCSV(spec) {
		info, err := os.Stat(entry)
		if err != nil {
			return nil, fmt.Errorf("-evtx %q: %w", entry, err)
		}
		if info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(entry, "*.evtx"))
			if err != nil {
				return nil, fmt.Errorf("-evtx %q: %w", entry, err)
			}
			sort.Strings(matches)
			for _, m := range matches {
				add(m)
			}
			continue
		}
		add(entry)
	}
	return files, nil
}

// loadSigma compiles the Sigma ruleset named by -sigma (if any) and reports a
// one-line summary to stderr. A nil ruleset (no -sigma) disables Sigma matching.
func loadSigma(cfg config.Config) (*collector.SigmaRuleset, error) {
	if cfg.SigmaRules == "" {
		return nil, nil
	}
	rs, err := collector.LoadSigmaSpec(cfg.SigmaRules)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "sigma: %d rule(s) loaded from %s", rs.Loaded, cfg.SigmaRules)
	if len(rs.Skipped) > 0 {
		fmt.Fprintf(os.Stderr, ", %d skipped (unsupported constructs)", len(rs.Skipped))
	}
	if len(rs.Failed) > 0 {
		fmt.Fprintf(os.Stderr, ", %d failed to parse", len(rs.Failed))
	}
	fmt.Fprintln(os.Stderr)
	if rs.Empty() {
		fmt.Fprintln(os.Stderr, "sigma: warning: no usable rules were loaded")
	}
	return rs, nil
}

// loadIntelDB loads the endpoint-intelligence dataset for a run: the file named
// by -intel-db, or the bundled dataset otherwise. It reports a one-line summary
// to stderr, mirroring loadSigma.
func loadIntelDB(cfg config.Config) (*intel.DB, error) {
	if cfg.IntelDB != "" {
		f, err := os.Open(cfg.IntelDB)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		db, err := intel.Load(f)
		if err != nil {
			return nil, err
		}
		m := db.Meta()
		fmt.Fprintf(os.Stderr, "intel: %d entries from %s (generated %s)\n", m.Entries, cfg.IntelDB, nonEmptyStr(m.Generated, "unknown"))
		return db, nil
	}
	db, err := intel.Builtin()
	if err != nil {
		return nil, err
	}
	m := db.Meta()
	fmt.Fprintf(os.Stderr, "intel: %d entries from the bundled dataset (%s, generated %s)\n",
		m.Entries, nonEmptyStr(m.Source, "unknown"), nonEmptyStr(m.Generated, "unknown"))
	return db, nil
}

// intelProvenance is the compact dataset description recorded in the report's
// run section, so a reader can judge the attribution's freshness.
func intelProvenance(db *intel.DB, cfg config.Config) string {
	m := db.Meta()
	src := cfg.IntelDB
	if m.Builtin {
		src = "builtin:" + nonEmptyStr(m.Source, "curated-seed")
	}
	return fmt.Sprintf("%s · generated %s · %d entries", src, nonEmptyStr(m.Generated, "unknown"), m.Entries)
}

func nonEmptyStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func doPing(ctx context.Context, cfg config.Config) error {
	c, err := sidecar.New(cfg.SidecarPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := c.Ping(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("sidecar OK: %s %v\n", c.Path, resp.Meta["version"])
	if caps, ok := resp.Meta["capabilities"].(map[string]any); ok {
		fmt.Printf("  capabilities: scan_prompts=%v scan_memory=%v yara=%v\n",
			caps["scan_prompts"], caps["scan_memory"], caps["yara"])
	}
	return nil
}

func doPromptScan(ctx context.Context, cfg config.Config, path string) error {
	c, err := sidecar.New(cfg.SidecarPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.Call(ctx, sidecar.Request{Op: sidecar.OpScanPrompts, Path: path})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("scan failed: %s", resp.Error)
	}
	m := resp.Meta
	fmt.Printf("prompt scan of %s — verdict %v (score %v), %d hit(s), %v bytes scanned",
		path, m["verdict"], m["score"], len(resp.Hits), m["bytes_scanned"])
	if t, _ := m["truncated"].(bool); t {
		fmt.Print(" [TRUNCATED: file larger than scan cap]")
	}
	fmt.Println()
	for _, h := range resp.Hits {
		fmt.Printf("  [%-8s] %-24s @%-9d %-8s conf=%-3d %s\n",
			h.Severity, h.Rule, h.Offset, h.Encoding, h.Confidence, h.Context)
	}
	return nil
}

func memoryOptions(cfg config.Config) collector.MemoryOptions {
	return collector.MemoryOptions{
		YaraRules:        cfg.YaraRules,
		PIDs:             cfg.MemPIDs,
		Budget:           cfg.MemBudget,
		Timeout:          cfg.MemTimeout,
		Workers:          cfg.MemWorkers,
		NoPrompts:        cfg.MemNoPrompts,
		IncludeSensitive: cfg.MemIncludeLsass,
	}
}

// doMemScan scans one process and prints the result: a quick look without
// writing a report.
func doMemScan(ctx context.Context, cfg config.Config, pid int) error {
	c, err := sidecar.New(cfg.SidecarPath)
	if err != nil {
		return err
	}
	// -mem-budget 0 means the default, as it does for the memory collector;
	// the deadline here must outlast whatever budget the sidecar applies.
	budget := cfg.MemBudget
	if budget <= 0 {
		budget = config.Default().MemBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget+30*time.Second)
	defer cancel()
	prompts := !cfg.MemNoPrompts
	var resp *sidecar.Response
	err = c.Stream(ctx, sidecar.Request{
		Op:               sidecar.OpScanMemory,
		PID:              pid,
		RulesPath:        cfg.YaraRules,
		Prompts:          &prompts,
		BudgetMS:         budget.Milliseconds(),
		IncludeSensitive: cfg.MemIncludeLsass,
	}, func(r *sidecar.Response) { resp = r })
	if resp == nil {
		if err == nil {
			err = fmt.Errorf("sidecar returned no result")
		}
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s (%s)", resp.Error, resp.MetaString("status"))
	}
	m := resp.Meta
	fmt.Printf("memory scan of pid %d %s — %s, %d of %d bytes (%v%%) in %d ms, %d hit(s)\n",
		pid, resp.MetaString("image"), resp.MetaString("status"), resp.MetaInt("bytes_scanned"),
		resp.MetaInt("bytes_total"), m["coverage_pct"], resp.MetaInt("elapsed_ms"), len(resp.Hits))
	if s, _ := m["stopped_early"].(string); s != "" {
		fmt.Printf("  stopped early: %s\n", s)
	}
	if y, ok := m["yara"].(map[string]any); ok {
		fmt.Printf("  yara: %v rules from %v file(s)", y["rules_loaded"], y["rule_files"])
		if f, _ := y["rules_failed"].([]any); len(f) > 0 {
			fmt.Printf(", %d file(s) failed to compile", len(f))
		}
		if mi, _ := y["module_imports"].([]any); len(mi) > 0 {
			fmt.Printf(", %d file(s) import modules (those conditions can't match in memory)", len(mi))
		}
		fmt.Println()
	}
	for _, h := range resp.Hits {
		where := ""
		if r := h.Region; r != nil {
			where = fmt.Sprintf(" %s/%s", r.Kind, r.Protect)
			if r.File != "" {
				where += " " + r.File
			}
		}
		fmt.Printf("  [%-8s] %-28s 0x%-14x%s conf=%d  %s\n",
			h.Severity, h.Rule, uint64(h.Offset), where, h.Confidence, h.Context)
	}
	return nil
}

func parsePIDs(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range splitCSV(s) {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("-mem-pids: %q is not a PID", p)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitError)
	}
}

func usageErrorOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		fmt.Fprintln(os.Stderr, "run lrng -h for usage")
		os.Exit(exitUsage)
	}
}
