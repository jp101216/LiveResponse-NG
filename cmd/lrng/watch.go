package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/hostinfo"
	"github.com/jp101216/liveresponse-ng/internal/intel"
	"github.com/jp101216/liveresponse-ng/internal/output"
	"github.com/jp101216/liveresponse-ng/internal/watch"
)

// watchOptions are the watch mode flags.
type watchOptions struct {
	Duration    time.Duration // -watch
	Only        bool          // -watch-only
	Raw         string        // -watch-raw
	From        string        // -watch-from
	MinEvents   int           // -watch-min-events
	AllowBeacon string        // -allow-beacon
}

func (w watchOptions) enabled() bool { return w.Duration > 0 }

const (
	minWatch      = time.Minute
	maxWatch      = 24 * time.Hour
	maxStreamFile = 2 << 30
)

// validateWatchOptions rejects watch flags that would be ignored, windows out
// of range, and modes that don't collect this host.
func validateWatchOptions(w watchOptions, explicit []string) error {
	given := map[string]bool{}
	for _, name := range explicit {
		given[name] = true
	}
	switch {
	case given["watch"] && (w.Duration < minWatch || w.Duration > maxWatch):
		return fmt.Errorf("-watch is a duration from %s to %s, such as 15m", minWatch, maxWatch)
	case w.enabled() && w.From != "":
		return errors.New("-watch records this host and -watch-from replays a saved stream; use one")
	case (given["watch-only"] || given["watch-raw"]) && !w.enabled():
		return errors.New("-watch-only and -watch-raw need -watch")
	case (given["watch-min-events"] || given["allow-beacon"]) && !w.enabled() && w.From == "":
		return errors.New("-watch-min-events and -allow-beacon need -watch or -watch-from")
	case given["watch-from"] && w.From == "":
		return errors.New("-watch-from needs a file path")
	case given["watch-raw"] && w.Raw == "":
		return errors.New("-watch-raw needs a file path")
	case w.MinEvents < 4 || w.MinEvents > 512:
		return errors.New("-watch-min-events is from 4 to 512")
	}
	if w.enabled() {
		for _, other := range []string{"evtx", "trace-only", "cloud-only", "case-report", "mem-scan", "prompt-scan", "ping-sidecar", "list", "version", "ui", "navigator-from"} {
			if given[other] {
				return fmt.Errorf("-%s cannot be combined with -watch", other)
			}
		}
	}
	if w.From != "" {
		allowed := map[string]bool{"watch-from": true, "watch-min-events": true, "allow-beacon": true, "out": true, "format": true,
			"pretty": true, "force": true, "quiet": true, "fail-on": true, "navigator": true, "navigator-min": true,
			"expect": true, "expect-min": true, "iocs": true, "intel": true, "intel-db": true, "timeline": true, "graph": true}
		for _, name := range explicit {
			if !allowed[name] {
				return fmt.Errorf("-%s cannot be combined with offline -watch-from", name)
			}
		}
	}
	return nil
}

// checkDistinctOutputs keeps one output (or its checksum) from replacing
// another, or the stream being replayed.
func checkDistinctOutputs(paths [][2]string) error {
	for i, a := range paths {
		for _, b := range paths[i+1:] {
			if a[1] == "" || b[1] == "" {
				continue
			}
			for _, x := range []string{a[1], a[1] + ".sha256"} {
				for _, y := range []string{b[1], b[1] + ".sha256"} {
					px, _ := filepath.Abs(x)
					py, _ := filepath.Abs(y)
					sx, ex := os.Stat(x)
					sy, ey := os.Stat(y)
					if px == py || ex == nil && ey == nil && os.SameFile(sx, sy) {
						return fmt.Errorf("-%s %s and -%s %s would write over each other; choose another path", a[0], a[1], b[0], b[1])
					}
				}
			}
		}
	}
	return nil
}

// watchRun is a recorded window waiting for the snapshot to score against.
type watchRun struct {
	rec       *watch.Recording
	runID     string
	only      bool
	minEvents int
	allow     []string
}

// recordWatch records this host for the -watch window, before the snapshot.
func recordWatch(ctx context.Context, cfg config.Config, w watchOptions) (*watchRun, error) {
	switch runtime.GOOS {
	case "windows", "linux":
	default:
		return nil, watch.ErrUnsupported
	}
	if elev, err := hostinfo.Elevated(); err != nil || !elev {
		if runtime.GOOS == "linux" {
			return nil, errors.New("watch mode needs root on Linux: the process connector, packet capture and other processes' sockets refuse anyone else")
		}
		return nil, errors.New("watch mode needs an elevated prompt (administrator or SYSTEM): the kernel's process and network providers refuse anyone else")
	}
	if w.Raw != "" && !cfg.Force {
		if _, err := os.Lstat(w.Raw); err == nil {
			return nil, fmt.Errorf("%s already exists; refusing to overwrite (use -force)", w.Raw)
		}
	}
	runID := output.NewRunID()
	host := cfg.Host
	if host == "" {
		host, _ = os.Hostname()
	}
	opts := watch.RecordOptions{Duration: w.Duration, RunID: runID, Host: host, SelfPID: uint32(os.Getpid())}

	// The raw stream is written as it's recorded, through a pipe into the
	// evidence writer, which adds the .sha256 when the window closes.
	type written struct {
		sum string
		err error
	}
	var rawDone chan written
	var pw *io.PipeWriter
	if w.Raw != "" {
		pr, p := io.Pipe()
		pw = p
		opts.Raw = pw
		rawDone = make(chan written, 1)
		go func() {
			sum, err := output.WriteArtifact(w.Raw, cfg.Force, func(out io.Writer) error {
				_, err := io.Copy(out, pr)
				return err
			})
			if err == nil {
				err = io.EOF
			}
			pr.CloseWithError(err)
			if errors.Is(err, io.EOF) {
				err = nil
			}
			rawDone <- written{sum, err}
		}()
	}
	if !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "lrng: watching this host for %s; Ctrl+C ends the window early\n", w.Duration)
	}
	rec, err := watch.Record(ctx, opts)
	if pw != nil {
		pw.Close()
		r := <-rawDone
		switch {
		case r.err != nil && rec != nil:
			rec.Window.Errors = append(rec.Window.Errors, "watch-raw: "+r.err.Error())
			fmt.Fprintln(os.Stderr, output.TerminalSafe("lrng: warning: -watch-raw: "+r.err.Error()))
		case r.err == nil:
			fmt.Fprintf(os.Stderr, "wrote %s\nsha256 %s\n", w.Raw, r.sum)
		}
	}
	if err != nil {
		return nil, err
	}
	return &watchRun{rec: rec, runID: runID, only: w.Only, minEvents: w.MinEvents, allow: splitCSV(w.AllowBeacon)}, nil
}

// analyzeWatch scores the window against the snapshot's results.
func analyzeWatch(wr *watchRun, snapshot []collector.Result, db *intel.DB) collector.Result {
	return watch.Analyze(wr.rec.Agg, wr.rec.Window, watch.Options{
		MinEvents: wr.minEvents, Allow: watch.NewAllowlist(wr.allow), Snapshot: snapshot, Intel: intelLookup(db),
	})
}

func intelLookup(db *intel.DB) func(netip.Addr) []string {
	if db == nil {
		return nil
	}
	return func(a netip.Addr) []string {
		if info, ok := db.Lookup(a); ok {
			return info.CategoryNames()
		}
		return nil
	}
}

// doWatchFrom rescores a saved stream and writes a report holding the watch
// result. It runs on any OS and collects nothing.
func doWatchFrom(ctx context.Context, cfg config.Config, w watchOptions) (output.Report, error) {
	started := time.Now().UTC()
	f, err := os.Open(w.From)
	if err != nil {
		return output.Report{}, fmt.Errorf("-watch-from: %w", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > maxStreamFile {
		return output.Report{}, fmt.Errorf("-watch-from %s: needs a regular file of at most %d bytes", w.From, int64(maxStreamFile))
	}
	h := sha256.New()
	st, err := watch.ReadStream(io.TeeReader(f, h))
	if err != nil {
		return output.Report{}, fmt.Errorf("-watch-from %s: %w", w.From, err)
	}
	_, _ = io.Copy(h, f) // hash the whole file even if the reader stopped early
	agg := watch.NewAggregator(st.Header.Started, watch.Limits{}, st.Header.SelfPID)
	for _, e := range st.Events {
		agg.Add(e)
	}
	win := watch.Window{Source: "replay", Meta: map[string]any{
		"replayed_from": w.From, "stream_sha256": hex.EncodeToString(h.Sum(nil)),
		"recorded_source": st.Header.Source, "recorded_run_id": st.Header.RunID,
	}}
	ended := st.Header.Started
	if d, err := time.ParseDuration(st.Header.Duration); err == nil {
		ended = st.Header.Started.Add(d)
	}
	if st.Trailer != nil {
		ended = st.Trailer.Ended
		win.Interrupted = st.Trailer.Interrupted
		if len(st.Trailer.Dropped) > 0 {
			win.Meta["recorded_dropped"] = st.Trailer.Dropped
		}
	} else {
		win.Interrupted = true
		win.Errors = append(win.Errors, "the stream has no end line: the recording didn't finish cleanly")
		if n := len(st.Events); n > 0 && st.Events[n-1].Time.Before(ended) {
			ended = st.Events[n-1].Time
		}
	}
	agg.Close(ended)

	var db *intel.DB
	var intelProv string
	if cfg.Intel {
		if db, err = loadIntelDB(cfg); err != nil {
			return output.Report{}, fmt.Errorf("intel dataset: %w", err)
		}
		intelProv = intelProvenance(db, cfg)
	}
	results := []collector.Result{watch.Analyze(agg, win, watch.Options{
		MinEvents: w.MinEvents, Allow: watch.NewAllowlist(splitCSV(w.AllowBeacon)), Intel: intelLookup(db),
	})}
	if cfg.Timeline {
		results = append(results, collector.BuildTimeline(results))
	}
	if cfg.IOCs {
		results = append(results, collector.ExtractIOCs(results))
	}
	if cfg.Intel {
		results = append(results, collector.AnnotateIntel(results, db))
	}
	host := st.Header.Host
	if host == "" {
		host = "(offline)"
	}
	if cfg.Graph {
		results = append(results, collector.BuildEvidenceGraph(results, host))
	}
	run := output.RunInfo{
		StartedAt: started, FinishedAt: time.Now().UTC(), PID: os.Getpid(), Args: os.Args[1:],
		Collectors: []string{"watch"}, Workers: 1, Timeout: "0s", Intel: cfg.Intel, IntelDataset: intelProv,
		Interrupted: ctx.Err() != nil, Graph: cfg.Graph,
	}
	if exe, err := os.Executable(); err == nil {
		run.ExePath = exe
		if sum, err := output.FileSHA256(exe); err == nil {
			run.ExeSHA256 = sum
		}
	}
	osName := st.Header.OS
	if osName == "" {
		osName = runtime.GOOS
	}
	rep := output.Report{
		Schema: output.SchemaVersion, Tool: "liveresponse-ng", Version: version, Commit: commit,
		RunID: output.NewRunID(), Host: host, OS: osName, Arch: runtime.GOARCH,
		Collected: st.Header.Started, Run: run, Results: results, Summary: output.Summarise(results),
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
