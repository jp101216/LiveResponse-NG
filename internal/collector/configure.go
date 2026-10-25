package collector

import (
	"os"
	"strings"
	"time"
)

// RunOptions carries per-run settings that some collectors need. It's passed
// to every collector implementing Configurable before dispatch.
type RunOptions struct {
	// ExtraAllowlist adds process image names treated as legitimate LLM-API
	// callers, on top of the built-in defaults.
	ExtraAllowlist []string
	// ResolveLLMHosts lets module A resolve provider hostnames live. Doing so
	// sends DNS queries from the host and adds entries to its DNS client
	// cache, so it can be switched off when that cache is evidence.
	ResolveLLMHosts bool
	// DNSCorrelate attaches the hostnames in the DNS client cache to network
	// connections (and lets module A match regional endpoints by name). It
	// reads the cache through the same undocumented API as the opt-in
	// dnscache collector, so it is on only when that collector is selected.
	// The cache is snapshotted once, before module A resolves anything.
	DNSCorrelate bool
	// SidecarPath is the Rust sidecar binary ("" = next to lrng), for
	// collectors that offload memory/prompt scanning to it.
	SidecarPath string
	// Hasher computes SHA-256 of reported binaries; nil disables hashing.
	Hasher *FileHasher
	// Signer verifies the Authenticode signature of process images; nil
	// disables signature checking.
	Signer *SignatureVerifier
	// SelfPID and SelfPaths identify lrng and its sidecar so they are never
	// judged: an analyst who runs lrng from a Downloads folder must not get
	// findings about lrng itself.
	SelfPID   int
	SelfPaths []string

	// Memory scanning (the opt-in "memory" collector).
	Memory MemoryOptions

	// Sigma is a compiled Sigma ruleset evaluated against event-log records by
	// the eventlog collector; nil disables Sigma matching.
	Sigma *SigmaRuleset
}

// isSelf reports whether a process is lrng or one of its components.
func (o RunOptions) isSelf(pid uint32, imagePath string) bool {
	self := o.SelfPID
	if self == 0 {
		self = os.Getpid()
	}
	if int(pid) == self {
		return true
	}
	if imagePath == "" {
		return false
	}
	for _, p := range o.SelfPaths {
		if p != "" && strings.EqualFold(p, imagePath) {
			return true
		}
	}
	return false
}

// MemoryOptions configures the memory collector.
type MemoryOptions struct {
	// YaraRules is a .yar/.yara file or a directory of them. Empty runs the
	// module-B prompt scan only.
	YaraRules string
	// PIDs restricts the scan to these processes; empty means all.
	PIDs []int
	// Budget is the time allowed per process.
	Budget time.Duration
	// Timeout bounds the whole memory collector.
	Timeout time.Duration
	// Workers is how many sidecars scan in parallel.
	Workers int
	// NoPrompts disables the module-B prompt scan of memory.
	NoPrompts bool
	// IncludeSensitive scans processes skipped by default (lsass.exe).
	IncludeSensitive bool
}

// Configurable is implemented by collectors that accept RunOptions.
type Configurable interface {
	Configure(RunOptions)
}

// ConfigureAll applies opts to every collector that implements Configurable.
func ConfigureAll(cs []Collector, opts RunOptions) {
	for _, c := range cs {
		if cc, ok := c.(Configurable); ok {
			cc.Configure(opts)
		}
	}
}
