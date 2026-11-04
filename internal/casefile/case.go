// Package casefile builds bounded, offline workspaces from existing LRNG JSON
// reports. Reports retain their own run, host and record indices. No imported
// field is ever used as a local path, and a hostname is not a machine identity.
package casefile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jp101216/liveresponse-ng/internal/output"
	"github.com/jp101216/liveresponse-ng/viewer"
)

const (
	SchemaVersion = "1.0"
	MaxSources    = 16
	MaxFileBytes  = 16 << 20
	MaxTotalBytes = 64 << 20
	MaxRecords    = 100000
	MaxFindings   = 200000
)

type Case struct {
	Schema     string      `json:"case_schema_version"`
	Kind       string      `json:"kind"`
	ID         string      `json:"case_id"`
	Name       string      `json:"name"`
	CreatedAt  time.Time   `json:"created_at"`
	Sources    []Source    `json:"sources"`
	Comparison *Comparison `json:"comparison,omitempty"`
}

type Source struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Bytes   int             `json:"bytes"`
	SHA256  string          `json:"sha256"` // original input bytes, not a re-serialization
	Report  json.RawMessage `json:"report"`
	Summary output.Summary  `json:"summary"` // recomputed; never trust an imported summary
	decoded output.Report
}

type Options struct {
	Name     string
	Compare  bool
	SameHost bool // explicit operator attestation, not an inferred identity
}

// Build reads only the explicitly named, existing regular JSON files. Invalid
// or excessive input fails the whole operation rather than producing an
// apparently complete case with silently missing sources.
func Build(ctx context.Context, paths []string, opts Options) (Case, error) {
	if len(paths) == 0 || len(paths) > MaxSources {
		return Case{}, fmt.Errorf("case needs 1-%d JSON reports", MaxSources)
	}
	if len(opts.Name) > 256 || !utf8.ValidString(opts.Name) {
		return Case{}, errors.New("case name must be valid UTF-8, at most 256 bytes")
	}
	if opts.Compare && (len(paths) != 2 || !opts.SameHost) {
		return Case{}, errors.New("-compare needs exactly two -case-report files (before, then after) and -same-host to attest they describe the same machine")
	}
	if opts.SameHost && !opts.Compare {
		return Case{}, errors.New("-same-host requires -compare")
	}
	c := Case{Schema: SchemaVersion, Kind: "lrng_case", ID: output.NewRunID(), Name: opts.Name, CreatedAt: time.Now().UTC(), Sources: []Source{}}
	if c.Name == "" {
		c.Name = "Investigation"
	}
	seenFiles, seenRuns := map[string]bool{}, map[string]bool{}
	total, records, findings := 0, 0, 0
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return Case{}, err
		}
		data, err := readReportFile(path, min(MaxFileBytes, MaxTotalBytes-total))
		if err != nil {
			return Case{}, fmt.Errorf("case report %q: %w", path, err)
		}
		total += len(data)
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if seenFiles[digest] {
			return Case{}, fmt.Errorf("case report %q duplicates an input file", path)
		}
		rep, err := decodeReport(data)
		if err != nil {
			return Case{}, fmt.Errorf("case report %q: %w", path, err)
		}
		if seenRuns[rep.RunID] {
			return Case{}, fmt.Errorf("case report %q repeats run_id %q; conflicting exports must be resolved before import", path, rep.RunID)
		}
		summary := output.Summarise(rep.Results)
		records += summary.Records
		findings += summary.Findings
		if records > MaxRecords || findings > MaxFindings {
			return Case{}, fmt.Errorf("case exceeds %d records or %d findings", MaxRecords, MaxFindings)
		}
		seenFiles[digest], seenRuns[rep.RunID] = true, true
		c.Sources = append(c.Sources, Source{ID: "sha256:" + digest, Name: filepath.Base(path), Bytes: len(data), SHA256: digest, Report: json.RawMessage(data), Summary: summary, decoded: rep})
	}
	if err := ctx.Err(); err != nil {
		return Case{}, err
	}
	if opts.Compare {
		comparison, err := compare(c.Sources[0], c.Sources[1])
		if err != nil {
			return Case{}, err
		}
		c.Comparison = &comparison
	}
	return c, nil
}

func readReportFile(path string, limit int) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > int64(limit) {
		return nil, fmt.Errorf("needs a regular file (no symlinks), at most %d bytes within the case budget", limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(st, opened) {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || len(data) > limit || int64(len(data)) != st.Size() || !after.ModTime().Equal(st.ModTime()) || after.Size() != st.Size() {
		return nil, errors.New("file is oversized or changed while reading")
	}
	return data, nil
}

func decodeReport(data []byte) (output.Report, error) {
	var rep output.Report
	if !utf8.Valid(data) {
		return rep, errors.New("report is not valid UTF-8")
	}
	// Ambiguous JSON member names can make Go and JavaScript disagree about
	// what was imported. Reject duplicates (including case variants) and deep
	// nesting before decoding; preserve the source envelope including extras.
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := checkJSON(d, 0); err != nil {
		return rep, fmt.Errorf("needs one unambiguous JSON report: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return rep, errors.New("needs one JSON envelope; JSONL and concatenated reports are not supported in a case")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil || root == nil {
		return rep, errors.New("report must be an object")
	}
	for _, key := range []string{"schema_version", "tool", "run_id", "host", "os", "arch", "collected_at", "run", "results"} {
		if _, ok := root[key]; !ok {
			return rep, fmt.Errorf("report has no %s", key)
		}
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber() // keep large numeric fields exact for comparisons
	if err := d.Decode(&rep); err != nil {
		return rep, err
	}
	if err := checkMemberNames(data, reflect.TypeOf(rep)); err != nil {
		return rep, err
	}
	if rep.Schema != output.SchemaVersion || rep.Tool != "liveresponse-ng" || rep.RunID == "" || len(rep.RunID) > 256 || rep.Host == "" || len(rep.Host) > 1024 || rep.OS == "" || rep.Arch == "" || rep.Collected.IsZero() || rep.Results == nil || len(rep.Results) > 256 || string(root["run"]) == "null" {
		return rep, errors.New("needs an LRNG schema 1.2 report with a run ID, host, platform, collection time, run object and results array")
	}
	// Require the exact structural member names the viewer uses. Fields and
	// metadata remain extensible; unknown envelope members are kept in Report.
	var results []struct {
		Collector json.RawMessage              `json:"collector"`
		Records   []map[string]json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(root["results"], &results); err != nil {
		return rep, err
	}
	var rawResults []map[string]json.RawMessage
	if err := json.Unmarshal(root["results"], &rawResults); err != nil {
		return rep, err
	}
	collectors := map[string]bool{}
	for ri, r := range rep.Results {
		if r.Collector == "" || len(r.Collector) > 256 || rawResults[ri]["collector"] == nil || rawResults[ri]["records"] == nil {
			return rep, errors.New("each result needs collector and records members")
		}
		if collectors[r.Collector] {
			return rep, errors.New("duplicate collector names would make source-record navigation ambiguous")
		}
		collectors[r.Collector] = true
		for _, rec := range results[ri].Records {
			if rec["fields"] == nil || bytes.Equal(rec["fields"], []byte("null")) {
				return rep, errors.New("each record needs a fields object")
			}
			for key := range rec {
				if key != "findings" && strings.EqualFold(key, "findings") {
					return rep, errors.New("record member names are case-sensitive")
				}
			}
			if raw, ok := rec["findings"]; ok {
				var findings []map[string]json.RawMessage
				if err := json.Unmarshal(raw, &findings); err != nil || findings == nil {
					return rep, errors.New("record findings must be an array of objects")
				}
				for _, f := range findings {
					if f == nil {
						return rep, errors.New("finding is not an object")
					}
				}
			}
		}
	}
	return rep, nil
}

// Go's struct decoder accepts case-insensitive member names; JavaScript does
// not. Reject aliases in the typed envelope while leaving artifact field maps
// extensible. Unknown members are retained in the raw source report.
func checkMemberNames(data json.RawMessage, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Struct {
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := checkMemberNames(item, typ.Elem()); err != nil {
				return err
			}
		}
	} else if typ.Kind() == reflect.Struct && typ != reflect.TypeOf(time.Time{}) {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			for key, value := range obj {
				if strings.EqualFold(key, name) {
					if key != name {
						return fmt.Errorf("report member %q is case-sensitive (want %q)", key, name)
					}
					if err := checkMemberNames(value, field.Type); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// checkJSON consumes exactly one value. The fixed depth bound also protects
// later field projection and browser rendering of deeply nested hostile data.
func checkJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch t {
	case json.Delim('{'):
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[strings.ToLower(name)] {
				return errors.New("duplicate JSON member")
			}
			keys[strings.ToLower(name)] = true
			if err := checkJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	case json.Delim('['):
		for d.More() {
			if err := checkJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
	}
	return err
}

func Write(w io.Writer, c Case, format string, pretty bool) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	if format == output.FormatHTML {
		data, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if err := viewer.Render(bw, data); err != nil {
			return err
		}
	} else if format == "" || format == output.FormatJSON {
		enc := json.NewEncoder(bw)
		if pretty {
			enc.SetIndent("", "  ")
		}
		if err := enc.Encode(c); err != nil {
			return err
		}
	} else {
		return errors.New("cases support -format json or html; JSONL still represents a single run")
	}
	return bw.Flush()
}
