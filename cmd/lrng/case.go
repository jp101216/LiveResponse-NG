package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jp101216/liveresponse-ng/internal/casefile"
	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func validateCaseOptions(cfg config.Config, paths []string, name string, compare, sameHost bool, explicit []string) error {
	if len(paths) == 0 {
		if name != "" || compare || sameHost {
			return errors.New("-case-name, -compare and -same-host require -case-report")
		}
		return nil
	}
	if cfg.Format == output.FormatJSONL {
		return errors.New("cases support -format json or html; JSONL represents a single run")
	}
	if len(paths) > casefile.MaxSources {
		return fmt.Errorf("at most %d -case-report inputs are allowed", casefile.MaxSources)
	}
	if compare && (len(paths) != 2 || !sameHost) || sameHost && !compare {
		return errors.New("-compare needs exactly two -case-report inputs (before, after) and -same-host; -same-host requires -compare")
	}
	// An explicit allowlist prevents ignored live options from making an
	// offline case command unexpectedly collect this computer or contact a
	// provider. New live flags are rejected here automatically.
	allowed := map[string]bool{"case-report": true, "case-name": true, "compare": true, "same-host": true, "out": true, "format": true, "pretty": true, "force": true, "quiet": true, "fail-on": true}
	for _, name := range explicit {
		if !allowed[name] {
			return fmt.Errorf("-%s cannot be combined with offline -case-report", name)
		}
	}
	return nil
}

func doCase(ctx context.Context, cfg config.Config, paths []string, name string, compare, sameHost bool) (output.Summary, error) {
	if cfg.Output != "" {
		for _, path := range paths {
			for _, target := range []string{cfg.Output, cfg.Output + ".sha256"} {
				a, _ := filepath.Abs(path)
				b, _ := filepath.Abs(target)
				x, xe := os.Stat(path)
				y, ye := os.Stat(target)
				if a == b || xe == nil && ye == nil && os.SameFile(x, y) {
					return output.Summary{}, errors.New("case output or checksum would replace an input report; choose another -out path")
				}
			}
		}
	}
	c, err := casefile.Build(ctx, paths, casefile.Options{Name: name, Compare: compare, SameHost: sameHost})
	if err != nil {
		return output.Summary{}, err
	}
	summary := output.Summary{BySeverity: map[collector.Severity]int{}, ByRule: map[string]int{}}
	for _, source := range c.Sources {
		summary.Collectors += source.Summary.Collectors
		summary.Records += source.Summary.Records
		summary.Findings += source.Summary.Findings
		summary.Errors += source.Summary.Errors
		for sev, n := range source.Summary.BySeverity {
			summary.BySeverity[sev] += n
		}
		for rule, n := range source.Summary.ByRule {
			summary.ByRule[rule] += n
		}
	}
	write := func(w io.Writer) error { return casefile.Write(w, c, cfg.Format, cfg.Pretty) }
	if cfg.Output == "" {
		err = write(os.Stdout)
	} else {
		var sum string
		sum, err = output.WriteArtifact(cfg.Output, cfg.Force, write)
		if err == nil && !cfg.Quiet {
			fmt.Fprintf(os.Stderr, "lrng: case written to %s (sha256 %s)\n", cfg.Output, sum)
		}
	}
	if err == nil && !cfg.Quiet {
		fmt.Fprintf(os.Stderr, "lrng: case %q: %d source reports, %d records, %d findings; source coverage retained\n", c.Name, len(c.Sources), summary.Records, summary.Findings)
	}
	return summary, err
}
