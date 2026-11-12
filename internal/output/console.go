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
		fmt.Fprintf(w, "  [%-8s] %-14s %-38s %s\n", TerminalSafe(string(f.Severity)), TerminalSafe(f.Collector),
			TerminalSafe(f.Rule), TerminalSafe(truncate(f.Detail, 160)))
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// TerminalSafe renders text taken from the host (command lines, file names,
// event data, a case name) safe to print on the analyst's terminal. An
// attacker controls much of that text, and a raw escape sequence in it would
// be interpreted, not shown: it can retitle the window, move the cursor to
// overwrite or hide earlier lines, and on some terminals set the clipboard
// (OSC 52). Bidirectional-override characters can reorder what is shown
// ("exe.txt" displayed for "txt.exe"). Each such character is written as a
// visible \xNN or \uNNNN escape instead; everything else is unchanged.
func TerminalSafe(s string) string {
	clean := true
	for _, r := range s {
		if terminalUnsafe(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !terminalUnsafe(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// terminalUnsafe reports whether a character changes how a terminal shows
// text rather than being shown: C0 and C1 controls (ESC, BEL, CSI, OSC...),
// DEL, invalid UTF-8 (decoded as U+FFFD by range, so not here), and the
// bidirectional formatting characters.
func terminalUnsafe(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
