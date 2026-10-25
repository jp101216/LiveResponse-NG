// Package collector defines the collection framework: the Collector
// interface every triage module implements, the structured result types
// they emit, and a shared registry. Collectors are OS-specific
// implementations hidden behind build tags; the framework stays portable.
package collector

import (
	"context"
	"time"
)

// Severity ranks a finding so an analyst (or a SIEM rule) can triage
// output without reading every record.
type Severity string

const (
	SevInfo     Severity = "info"
	SevNotable  Severity = "notable"  // worth a human glance
	SevSuspect  Severity = "suspect"  // matches a known-bad heuristic
	SevCritical Severity = "critical" // high-confidence malicious indicator
)

// SeverityRank orders severities (critical highest) for sorting and
// roll-ups; an unknown severity ranks 0.
func SeverityRank(s Severity) int { return sevRank(s) }

// Record is a single observation produced by a collector — one process,
// one network connection, one autorun entry. Fields is the raw data;
// Findings are heuristic annotations the collector (or a detector) added.
type Record struct {
	// Fields holds the collected data. Kept as a map so the JSON schema
	// stays stable across collectors while each contributes its own keys.
	Fields map[string]any `json:"fields"`
	// Findings are analyst-facing annotations. Empty for a plain artifact.
	Findings []Finding `json:"findings,omitempty"`
}

// Finding is a heuristic hit attached to a record: what fired, how severe,
// and which ATT&CK technique it maps to (so output lines up with a matrix).
type Finding struct {
	Rule       string   `json:"rule"`
	Severity   Severity `json:"severity"`
	Technique  string   `json:"technique,omitempty"` // e.g. "T1071.001"
	Confidence int      `json:"confidence"`          // 0-100
	Detail     string   `json:"detail"`
}

// Result is one collector's complete output for a run.
type Result struct {
	Collector string        `json:"collector"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
	Records   []Record      `json:"records"`
	// Meta describes the collection itself rather than the host: detector
	// coverage, table sizes, options in effect. Kept out of Records so record
	// counts and SIEM parsers only ever see real artifacts.
	Meta map[string]any `json:"meta,omitempty"`
	// Errors are non-fatal problems (an access-denied process, a handle
	// that vanished mid-read). Collection continues; these are reported
	// rather than swallowed, because gaps matter in forensics.
	Errors []string `json:"errors,omitempty"`
}

// Collector is the one interface every triage module implements.
type Collector interface {
	// Name is the stable identifier used in output and on the CLI.
	Name() string
	// Platforms lists the GOOS values this collector supports.
	Platforms() []string
	// Collect gathers artifacts. It should honour ctx cancellation and
	// return partial results with Errors populated rather than failing
	// the whole run on a single bad record.
	Collect(ctx context.Context) (Result, error)
}

// NewResult starts a Result for a collector, stamping the start time.
func NewResult(name string) *Result {
	return &Result{Collector: name, StartedAt: time.Now().UTC(), Records: []Record{}}
}

// Add appends a record built from a field map.
func (r *Result) Add(fields map[string]any, findings ...Finding) {
	r.Records = append(r.Records, Record{Fields: fields, Findings: findings})
}

// SetMeta records a fact about the collection run itself.
func (r *Result) SetMeta(key string, value any) {
	if r.Meta == nil {
		r.Meta = map[string]any{}
	}
	r.Meta[key] = value
}

// Fail records a non-fatal error.
func (r *Result) Fail(msg string) { r.Errors = append(r.Errors, msg) }

// Finish stamps the elapsed duration and returns the value.
func (r *Result) Finish() Result {
	r.Duration = time.Since(r.StartedAt)
	return *r
}
