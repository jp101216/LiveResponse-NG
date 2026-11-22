package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jp101216/liveresponse-ng/internal/casefile"
	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/navigator"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

// navOptions are the ATT&CK Navigator export flags.
type navOptions struct {
	Out       string  // -navigator: layer path ("" = none; with -navigator-from, stdout)
	From      string  // -navigator-from: build from a saved report and exit
	Min       string  // -navigator-min
	Expect    string  // -expect
	ExpectMin float64 // -expect-min, percent
	ExpectSet bool    // -expect-min was given
}

func (n navOptions) enabled() bool { return n.Out != "" || n.From != "" }

// maxNavigatorReport bounds a report read by -navigator-from. Live reports
// are larger than case imports allow (casefile.MaxFileBytes) on busy hosts.
const maxNavigatorReport = 256 << 20

// validateNavigatorOptions rejects Navigator flags that would be silently
// ignored, and offline -navigator-from runs mixed with collection flags.
func validateNavigatorOptions(n navOptions, explicit []string) error {
	given := map[string]bool{}
	for _, name := range explicit {
		given[name] = true
	}
	switch {
	case !n.enabled() && (given["navigator-min"] || given["expect"] || given["expect-min"]):
		return errors.New("-navigator-min, -expect and -expect-min need -navigator or -navigator-from")
	case given["expect-min"] && n.Expect == "":
		return errors.New("-expect-min needs -expect")
	case n.ExpectSet && (n.ExpectMin < 0 || n.ExpectMin > 100):
		return errors.New("-expect-min is a percentage, 0 to 100")
	case n.Min != "" && collector.SeverityRank(collector.Severity(n.Min)) == 0:
		return errors.New("-navigator-min must be one of info, notable, suspect, critical")
	case given["navigator"] && n.Out == "":
		return errors.New("-navigator needs a file path")
	}
	for _, early := range []string{"mem-scan", "prompt-scan", "ping-sidecar", "list", "version"} {
		if n.enabled() && given[early] {
			return fmt.Errorf("-%s doesn't produce a report, so it can't be combined with -navigator", early)
		}
	}
	if n.From != "" {
		// Offline: nothing that would collect this host or change the run.
		allowed := map[string]bool{"navigator-from": true, "navigator": true, "navigator-min": true, "expect": true, "expect-min": true, "force": true, "quiet": true}
		for _, name := range explicit {
			if !allowed[name] {
				return fmt.Errorf("-%s cannot be combined with offline -navigator-from", name)
			}
		}
	}
	return nil
}

// checkLayerPath keeps the layer from replacing a report or its checksum.
func checkLayerPath(layer string, others ...string) error {
	if layer == "" {
		return nil
	}
	for _, other := range others {
		if other == "" {
			continue
		}
		for _, a := range []string{layer, layer + ".sha256"} {
			for _, b := range []string{other, other + ".sha256"} {
				pa, _ := filepath.Abs(a)
				pb, _ := filepath.Abs(b)
				x, xe := os.Stat(a)
				y, ye := os.Stat(b)
				if pa == pb || xe == nil && ye == nil && os.SameFile(x, y) {
					return fmt.Errorf("-navigator %s would overwrite %s; choose another path", layer, b)
				}
			}
		}
	}
	return nil
}

// writeNavigator builds the layer for rep and writes it. It reports whether
// an -expect-min threshold was missed (exit status 3, like -fail-on).
func writeNavigator(rep output.Report, n navOptions, reportSHA256 string, force, quiet bool) (bool, error) {
	opts := navigator.Options{MinSeverity: collector.Severity(n.Min), ReportSHA256: reportSHA256}
	var (
		layer   *navigator.Layer
		summary string
		below   bool
	)
	if n.Expect != "" {
		data, err := readExpected(n.Expect)
		if err != nil {
			return false, err
		}
		exp, err := navigator.ParseExpected(data, filepath.Base(n.Expect))
		if err != nil {
			return false, fmt.Errorf("-expect %s: %w", n.Expect, err)
		}
		l, cs, err := navigator.Coverage(rep, exp, opts)
		if err != nil {
			return false, err
		}
		layer = l
		summary = "coverage: " + cs.Line()
		if len(cs.ExpectedUnknown) > 0 {
			summary += fmt.Sprintf("; %d expected ID(s) unknown to ATT&CK v%s ignored", len(cs.ExpectedUnknown), layer.Versions.Attack)
		}
		below = n.ExpectSet && cs.Rate() < n.ExpectMin
		if below {
			summary += fmt.Sprintf("; below -expect-min %.0f%%", n.ExpectMin)
		}
		summary += noteStats(cs.Stats)
	} else {
		l, st, err := navigator.Build(rep, opts)
		if err != nil {
			return false, err
		}
		layer = l
		summary = fmt.Sprintf("%d techniques from %d findings", st.Techniques, st.Qualifying) + noteStats(st)
	}
	write := func(w io.Writer) error { return navigator.Encode(w, layer) }
	if n.Out == "" {
		if err := write(os.Stdout); err != nil {
			return below, fmt.Errorf("write layer: %w", err)
		}
	} else {
		sum, err := output.WriteArtifact(n.Out, force, write)
		if err != nil {
			return below, fmt.Errorf("write layer: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\nsha256 %s\n", n.Out, sum)
	}
	if !quiet || below {
		fmt.Fprintln(os.Stderr, output.TerminalSafe("lrng: ATT&CK Navigator layer: "+summary))
	}
	return below, nil
}

func noteStats(st navigator.Stats) string {
	s := ""
	if st.NoTechnique > 0 {
		s += fmt.Sprintf("; %d finding(s) name no technique", st.NoTechnique)
	}
	if n := len(st.Remapped); n > 0 {
		s += fmt.Sprintf("; %d retired ID(s) mapped to current ones", n)
	}
	if n := len(st.Unknown); n > 0 {
		s += fmt.Sprintf("; %d unknown ID(s) left out", n)
	}
	return s
}

func readExpected(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("-expect: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > navigator.MaxExpectedBytes {
		return nil, fmt.Errorf("-expect %s: needs a regular file of at most %d bytes", path, navigator.MaxExpectedBytes)
	}
	return os.ReadFile(path)
}

// doNavigatorFrom builds a layer from a saved report and exits.
func doNavigatorFrom(n navOptions, cfg config.Config) (bool, error) {
	if err := checkLayerPath(n.Out, n.From); err != nil {
		return false, err
	}
	rep, sum, err := casefile.ReadReport(n.From, maxNavigatorReport)
	if err != nil {
		return false, fmt.Errorf("-navigator-from %s: %w", n.From, err)
	}
	return writeNavigator(rep, n, sum, cfg.Force, cfg.Quiet)
}

// navigatorAfterRun writes the layer for a report a live or offline run just
// produced. The report's checksum is recorded when it went to a file.
func navigatorAfterRun(rep output.Report, n navOptions, cfg config.Config) (bool, error) {
	if n.Out == "" {
		return false, nil
	}
	sum := ""
	if cfg.Output != "" {
		sum, _ = output.FileSHA256(cfg.Output)
	}
	return writeNavigator(rep, n, sum, cfg.Force, cfg.Quiet)
}
