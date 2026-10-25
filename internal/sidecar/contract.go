// Package sidecar is the Go side of the Go<->Rust boundary. The Rust sidecar
// does the work that benefits from memory safety on hostile input: scanning
// live process memory with YARA, and scanning byte buffers for embedded LLM
// prompt artifacts (AI module B).
//
// The two processes speak newline-delimited JSON over stdin/stdout: Go writes
// one Request line; Rust writes one Response line per result (scan_memory
// with several PIDs streams one line per PID). Running Rust as a separate
// process (rather than linking it via cgo/FFI) is a deliberate v1 choice:
//   - the scanner eats malformed samples; a panic there dies alone instead of
//     taking down the whole agent,
//   - no cgo toolchain coupling,
//   - the boundary is a stable JSON schema either side can evolve.
//
// A future version can swap the transport for a static FFI lib without
// changing these types.
package sidecar

// Op names the sidecar operation.
type Op string

const (
	OpPing        Op = "ping"         // health check + capabilities
	OpScanMemory  Op = "scan_memory"  // YARA + prompt scan over live process memory
	OpScanPrompts Op = "scan_prompts" // embedded LLM prompt artifacts (AI module B)
)

// Request is one line Go sends to the sidecar.
type Request struct {
	Op Op `json:"op"`
	// PID targets one process for scan_memory.
	PID int `json:"pid,omitempty"`
	// PIDs targets several processes for scan_memory: rules compile once and
	// the sidecar streams one Response line per PID.
	PIDs []int `json:"pids,omitempty"`
	// Path targets a file for scan_prompts (sidecar reads it itself so large
	// buffers never cross the pipe).
	Path string `json:"path,omitempty"`
	// Data is inline text for scan_prompts when there's no file. It is
	// scanned as its raw UTF-8 bytes (not base64) — keep binary content in a
	// file and use Path.
	Data string `json:"data,omitempty"`
	// RulesPath points scan_memory at a YARA rules file or directory.
	RulesPath string `json:"rules_path,omitempty"`
	// Prompts runs the module-B prompt scan on each memory region (sidecar
	// default: true).
	Prompts *bool `json:"prompts,omitempty"`
	// BudgetMS is the per-process time budget for scan_memory.
	BudgetMS int64 `json:"budget_ms,omitempty"`
	// MaxBytes caps bytes read per process for scan_memory.
	MaxBytes int64 `json:"max_bytes,omitempty"`
	// IncludeSensitive scans processes excluded by default (lsass.exe).
	IncludeSensitive bool `json:"include_sensitive,omitempty"`
}

// Response is one line the sidecar returns.
type Response struct {
	Op    Op     `json:"op"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Hits are matches found by the requested scan.
	Hits []Hit `json:"hits,omitempty"`
	// Meta carries op-specific scalars (bytes scanned, rules loaded, ...).
	Meta map[string]any `json:"meta,omitempty"`
}

// Hit is a single scanner match, shaped to map cleanly onto a collector
// Finding on the Go side.
type Hit struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Technique string `json:"technique,omitempty"`
	// Offset is a file offset, or a virtual address for scan_memory.
	Offset int64 `json:"offset"`
	// Encoding is how the match was stored: "ascii" (also covers UTF-8) or
	// "utf-16le" (Windows wide strings, .NET string literals). Empty for YARA.
	Encoding   string     `json:"encoding,omitempty"`
	Context    string     `json:"context,omitempty"` // sanitised snippet / rule summary
	Confidence int        `json:"confidence"`        // 0-100
	Region     *HitRegion `json:"region,omitempty"`  // scan_memory only
}

// HitRegion describes the memory region holding a scan_memory match.
type HitRegion struct {
	Base    uint64 `json:"base"`
	Size    uint64 `json:"size"`
	Protect string `json:"protect"` // Windows "RX", "RWX", ...; Linux maps perms
	Kind    string `json:"kind"`    // Windows image|mapped|private; Linux file|anon|heap|stack
	File    string `json:"file,omitempty"`
}

// MetaString / MetaInt read typed values out of Response.Meta.
func (r *Response) MetaString(k string) string {
	s, _ := r.Meta[k].(string)
	return s
}

func (r *Response) MetaInt(k string) int64 {
	switch v := r.Meta[k].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}
