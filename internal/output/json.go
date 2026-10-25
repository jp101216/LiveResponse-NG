// Package output serialises a run into a stable JSON envelope designed to be
// ingested by a SIEM or piped into jq: one object per run with per-collector
// results nested inside (format "json"), or one event per line — run,
// collector, record and finding events sharing a run_id — for line-oriented
// pipelines (format "jsonl").
package output

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/hostinfo"
)

// SchemaVersion lets downstream parsers detect format changes.
//
//	1.1: added "run"; collector metadata moved from a "_meta" record into
//	     results[].meta; network records gained "family"; process records
//	     gained command_line, created_at, user, user_sid, parent_name.
//	1.2: added run_id, host_info, summary.by_rule and summary.top_findings;
//	     the JSONL format; new collector fields (see CHANGELOG).
const SchemaVersion = "1.2"

// Formats accepted by Write/WriteFile.
const (
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
)

// maxTopFindings bounds summary.top_findings.
const maxTopFindings = 25

// Report is the top-level envelope.
type Report struct {
	Schema    string             `json:"schema_version"`
	Tool      string             `json:"tool"`
	Version   string             `json:"tool_version"`
	Commit    string             `json:"tool_commit,omitempty"`
	RunID     string             `json:"run_id"`
	Host      string             `json:"host"`
	OS        string             `json:"os"`
	Arch      string             `json:"arch"`
	Collected time.Time          `json:"collected_at"`
	HostInfo  *hostinfo.Info     `json:"host_info,omitempty"`
	Run       RunInfo            `json:"run"`
	Results   []collector.Result `json:"results"`
	Summary   Summary            `json:"summary"`
}

// RunInfo records how and when the run happened, so a report can be
// reproduced and its gaps explained (a non-elevated run can't see everything).
type RunInfo struct {
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	PID        int       `json:"pid"`
	// Elevated is null when it couldn't be determined.
	Elevated       *bool    `json:"elevated"`
	Args           []string `json:"args"`
	Collectors     []string `json:"collectors"`
	Workers        int      `json:"workers"`
	Timeout        string   `json:"timeout"`
	DNSLookups     bool     `json:"dns_lookups"`
	DNSCorrelation bool     `json:"dns_correlation"`
	Hashing        bool     `json:"hashing"`
	YaraRules      string   `json:"yara_rules,omitempty"`
	Intel          bool     `json:"intel,omitempty"`
	IntelDataset   string   `json:"intel_dataset,omitempty"`
	Interrupted    bool     `json:"interrupted,omitempty"`
	ExeSHA256      string   `json:"exe_sha256,omitempty"`
	ExePath        string   `json:"exe_path,omitempty"`
	ElevationErr   string   `json:"elevation_error,omitempty"`
}

// Summary rolls up findings so an analyst sees the headline before
// scrolling the full record set.
type Summary struct {
	Collectors int                        `json:"collectors"`
	Records    int                        `json:"records"`
	Findings   int                        `json:"findings"`
	Errors     int                        `json:"errors"`
	BySeverity map[collector.Severity]int `json:"by_severity"`
	ByRule     map[string]int             `json:"by_rule"`
	// CollectorsWithErrors names the collectors whose coverage has gaps.
	CollectorsWithErrors []string `json:"collectors_with_errors,omitempty"`
	// TopFindings lists the most severe findings first (at most 25), each
	// pointing back at its record: results[result].records[record].
	TopFindings []TopFinding `json:"top_findings"`
}

// TopFinding is one finding lifted into the summary.
type TopFinding struct {
	collector.Finding
	Collector string `json:"collector"`
	Result    int    `json:"result"`
	Record    int    `json:"record"`
}

// Summarise computes the rollup from a set of results.
func Summarise(results []collector.Result) Summary {
	s := Summary{
		BySeverity:  map[collector.Severity]int{},
		ByRule:      map[string]int{},
		TopFindings: []TopFinding{},
	}
	s.Collectors = len(results)
	var all []TopFinding
	for ri, r := range results {
		s.Records += len(r.Records)
		s.Errors += len(r.Errors)
		if len(r.Errors) > 0 {
			s.CollectorsWithErrors = append(s.CollectorsWithErrors, r.Collector)
		}
		for i, rec := range r.Records {
			for _, f := range rec.Findings {
				s.Findings++
				s.BySeverity[f.Severity]++
				s.ByRule[f.Rule]++
				all = append(all, TopFinding{Finding: f, Collector: r.Collector, Result: ri, Record: i})
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if ra, rb := collector.SeverityRank(a.Severity), collector.SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		return a.Confidence > b.Confidence
	})
	if len(all) > maxTopFindings {
		all = all[:maxTopFindings]
	}
	s.TopFindings = append(s.TopFindings, all...)
	return s
}

// NewRunID returns a random identifier tying together everything one run
// produced (the report, its JSONL events, its checksum file).
func NewRunID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("run-%d", time.Now().UnixNano())
	}
	b[6] = b[6]&0x0f | 0x40 // RFC 4122 version 4
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Write serialises the report to w in the given format ("" means JSON).
func Write(w io.Writer, rep Report, format string, pretty bool) error {
	switch format {
	case "", FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		if pretty {
			enc.SetIndent("", "  ")
		}
		return enc.Encode(rep)
	case FormatJSONL:
		return writeJSONL(w, rep)
	default:
		return fmt.Errorf("unknown output format %q (want json or jsonl)", format)
	}
}

// writeJSONL emits one event per line: a "run" event (envelope and summary),
// then per collector a "collector" event followed by its "record" events and
// a "finding" event per finding (with the record's index), so a SIEM can
// alert on findings without unpacking nested arrays.
func writeJSONL(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	type runEvent struct {
		Type      string         `json:"type"`
		Schema    string         `json:"schema_version"`
		Tool      string         `json:"tool"`
		Version   string         `json:"tool_version"`
		Commit    string         `json:"tool_commit,omitempty"`
		RunID     string         `json:"run_id"`
		Host      string         `json:"host"`
		OS        string         `json:"os"`
		Arch      string         `json:"arch"`
		Collected time.Time      `json:"collected_at"`
		HostInfo  *hostinfo.Info `json:"host_info,omitempty"`
		Run       RunInfo        `json:"run"`
		Summary   Summary        `json:"summary"`
	}
	if err := enc.Encode(runEvent{"run", rep.Schema, rep.Tool, rep.Version, rep.Commit, rep.RunID, rep.Host,
		rep.OS, rep.Arch, rep.Collected, rep.HostInfo, rep.Run, rep.Summary}); err != nil {
		return err
	}
	for _, r := range rep.Results {
		if err := enc.Encode(map[string]any{
			"type": "collector", "run_id": rep.RunID, "host": rep.Host, "collector": r.Collector,
			"started_at": r.StartedAt, "duration_ns": r.Duration, "record_count": len(r.Records),
			"meta": r.Meta, "errors": r.Errors,
		}); err != nil {
			return err
		}
		for i, rec := range r.Records {
			if err := enc.Encode(map[string]any{
				"type": "record", "run_id": rep.RunID, "host": rep.Host, "collector": r.Collector,
				"record": i, "fields": rec.Fields, "findings": rec.Findings,
			}); err != nil {
				return err
			}
			for _, f := range rec.Findings {
				if err := enc.Encode(map[string]any{
					"type": "finding", "run_id": rep.RunID, "host": rep.Host, "collector": r.Collector,
					"record": i, "rule": f.Rule, "severity": f.Severity, "technique": f.Technique,
					"confidence": f.Confidence, "detail": f.Detail,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// WriteFile writes the report to path and returns its SHA-256, also written
// alongside as "<path>.sha256" in sha256sum format.
//
// It refuses to replace an existing file unless overwrite is set, so a typo
// can't clobber an earlier report. It also syncs and checks Close: on USB
// media or a network share, Close is where a failed write shows up.
func WriteFile(path string, rep Report, format string, pretty, overwrite bool) (string, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("%s already exists; refusing to overwrite (use -force)", path)
		}
		return "", err
	}

	h := sha256.New()
	werr := Write(io.MultiWriter(f, h), rep, format, pretty)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", werr
	}

	sum := hex.EncodeToString(h.Sum(nil))
	line := sum + "  " + filepath.Base(path) + "\n"
	if err := os.WriteFile(path+".sha256", []byte(line), 0o600); err != nil {
		return sum, fmt.Errorf("report written, but checksum file failed: %w", err)
	}
	return sum, nil
}

// FileSHA256 hashes a file, e.g. the running agent binary for the report.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
