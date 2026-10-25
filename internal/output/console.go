package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

// WriteConsoleSummary prints a short human summary of a run — totals and the
// most severe findings — for the analyst at the keyboard. It goes to stderr,
// so it never mixes with a report written to stdout.
func WriteConsoleSummary(w io.Writer, rep Report, max int) {
	s := rep.Summary
	var parts []string
	for _, sev := range []collector.Severity{collector.SevCritical, collector.SevSuspect, collector.SevNotable, collector.SevInfo} {
		if n := s.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	sevs := ""
	if len(parts) > 0 {
		sevs = " (" + strings.Join(parts, ", ") + ")"
	}
	fmt.Fprintf(w, "lrng: %d collector(s), %d record(s), %d finding(s)%s, %d error(s)\n",
		s.Collectors, s.Records, s.Findings, sevs, s.Errors)
	if len(s.CollectorsWithErrors) > 0 {
		fmt.Fprintf(w, "  incomplete coverage: %s (see results[].errors)\n", strings.Join(s.CollectorsWithErrors, ", "))
	}
	for i, f := range s.TopFindings {
		if i >= max {
			fmt.Fprintf(w, "  ... %d more in the report\n", s.Findings-max)
			break
		}
		if collector.SeverityRank(f.Severity) < collector.SeverityRank(collector.SevNotable) {
			break
		}
		fmt.Fprintf(w, "  [%-8s] %-14s %-38s %s\n", f.Severity, f.Collector, f.Rule, truncate(f.Detail, 160))
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
