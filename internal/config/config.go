// Package config holds run configuration resolved from CLI flags (and,
// later, a config file). Kept small and explicit so a run is reproducible
// from the recorded settings alone — the report's "run" section records them.
package config

import "time"

// Config is the resolved settings for one triage run.
type Config struct {
	// Collectors to run by name. Empty means the default set: every collector
	// available on this OS except the opt-in ones (memory, dnscache).
	Collectors []string
	// Workers bounds concurrent collectors.
	Workers int
	// Timeout per collector; 0 disables.
	Timeout time.Duration
	// Output path for the JSON report; empty means stdout.
	Output string
	// Force allows Output to replace an existing file.
	Force bool
	// Pretty indents the JSON for human reading.
	Pretty bool
	// Format is the report format: "json" (one envelope) or "jsonl" (one
	// event per line, for SIEM pipelines).
	Format string
	// Quiet suppresses the human summary printed to stderr after a run.
	Quiet bool
	// NoHash turns off SHA-256 hashing of reported binaries.
	NoHash bool
	// NoSign turns off Authenticode signature verification of process images.
	NoSign bool
	// FailOn makes the run exit with status 3 when any finding is at or
	// above this severity ("" = never), for scripted sweeps.
	FailOn string
	// SidecarPath is the Rust sidecar binary; empty means "next to lrng".
	SidecarPath string
	// AllowlistExtra are process names treated as legitimate LLM-API callers
	// in addition to the built-in defaults (paths are reduced to names).
	AllowlistExtra []string
	// NoDNS disables module A's live provider-hostname lookups, which would
	// otherwise add entries to the host's DNS client cache.
	NoDNS bool
	// Host identifies the machine in output; defaults to os.Hostname().
	Host string
	// SigmaRules is a Sigma rule file or directory evaluated against the event
	// log (live and offline); empty disables Sigma matching.
	SigmaRules string
	// Timeline adds a unified super-timeline of every timestamped artifact as a
	// synthetic "timeline" result.
	Timeline bool
	// IOCs adds a deduplicated, ranked set of indicators (IPs, domains, hashes,
	// file paths) drawn from detection-linked records, as a synthetic "iocs"
	// result for blocking and threat-hunting.
	IOCs bool
	// Intel attributes the run's public remote addresses against a bundled,
	// offline endpoint-intelligence dataset (ASN, country, infrastructure
	// category), as a synthetic "intel" result and as attribution on the IOCs.
	Intel bool
	// IntelDB overrides the embedded endpoint-intelligence dataset with one
	// loaded from this path (as produced by cmd/intelgen); setting it implies
	// Intel. Empty uses the bundled dataset.
	IntelDB string

	// Memory scanning (the opt-in "memory" collector and -mem-scan).
	YaraRules       string        // .yar/.yara file or directory
	MemPIDs         []int         // restrict to these PIDs (empty = all)
	MemBudget       time.Duration // per process
	MemTimeout      time.Duration // whole memory collector
	MemWorkers      int           // sidecars scanning in parallel
	MemNoPrompts    bool          // skip the module-B prompt scan of memory
	MemIncludeLsass bool          // scan lsass.exe (skipped by default)
}

// Default returns baseline settings.
func Default() Config {
	return Config{
		Workers:    6,
		Timeout:    60 * time.Second,
		Pretty:     true,
		Format:     "json",
		MemBudget:  60 * time.Second,
		MemTimeout: 15 * time.Minute,
		MemWorkers: 2,
	}
}
