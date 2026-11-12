package collector

import (
	"fmt"
	"strings"
)

// modulerules_unix.go — judging a Linux process's executable mappings (the
// modules collector's analytics). No build tag: pure logic over parsed
// /proc/<pid>/maps entries, unit-tested on any OS; the collector that reads
// /proc lives in modules_linux.go.

// moduleJudgement sorts one process's executable mappings into what they say.
type moduleJudgement struct {
	memfd    []string // anonymous in-memory files (fileless code)
	deleted  []string // unlinked while mapped, with nothing replacing them
	replaced []string // unlinked, but a new file sits at the same system path
	high     []string // loaded from a high-risk location
	low      []string // loaded from a low-risk (but unusual) location
	reasons  []string // why, for high then low: the distinct location kinds, first-seen order
}

// judgeLinuxModules classifies the mappings. A deleted mapping's location is
// judged by its original path — the deletion itself is reported on its own, so
// it isn't counted twice — and a memfd is reported only as a memfd.
func judgeLinuxModules(mods []mapsFile, exists func(string) bool) moduleJudgement {
	var j moduleJudgement
	var highWhy, lowWhy []string
	for _, m := range mods {
		path := m.Path
		switch {
		case isMemfdPath(path):
			j.memfd = append(j.memfd, path)
			continue
		case m.Deleted && replacedSystemFile(path, exists):
			j.replaced = append(j.replaced, path)
			continue
		case m.Deleted:
			j.deleted = append(j.deleted, path)
			path = strings.TrimSuffix(path, deletedSuffix)
		}
		switch lvl, why := unixPathRisk(path); lvl {
		case riskHigh:
			j.high = append(j.high, m.Path)
			highWhy = appendDistinct(highWhy, why)
		case riskLow:
			j.low = append(j.low, m.Path)
			lowWhy = appendDistinct(lowWhy, why)
		}
	}
	for _, why := range append(highWhy, lowWhy...) {
		j.reasons = appendDistinct(j.reasons, why)
	}
	return j
}

func appendDistinct(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// annotate adds the judgement's fields to a modules record and returns the
// record's findings. label names the process ("bash (pid 42)").
func (j moduleJudgement) annotate(fields map[string]any, label string) (map[string]any, []Finding) {
	var findings []Finding
	if len(j.memfd) > 0 {
		fields["memfd_modules"] = j.memfd
		findings = append(findings, Finding{
			Rule: "modules.memfd_exec", Severity: SevSuspect, Technique: "T1620", Confidence: 75,
			Detail: fmt.Sprintf("%s has %d executable mapping(s) of an anonymous in-memory file (memfd) — fileless code with nothing on disk: %s",
				label, len(j.memfd), strings.Join(j.memfd, ", ")),
		})
	}
	if len(j.deleted) > 0 {
		fields["deleted_modules"] = j.deleted
		findings = append(findings, Finding{
			Rule: "modules.deleted_file", Severity: SevSuspect, Technique: "T1620", Confidence: 65,
			Detail: fmt.Sprintf("%s has %d mapped library file(s) deleted from disk while still loaded: %s",
				label, len(j.deleted), strings.Join(j.deleted, ", ")),
		})
	}
	if len(j.replaced) > 0 {
		fields["replaced_modules"] = j.replaced
		findings = append(findings, Finding{
			Rule: "modules.replaced_on_disk", Severity: SevInfo, Technique: "T1554", Confidence: 20,
			Detail: fmt.Sprintf("%s still maps %d system library file(s) that were replaced on disk (a new file sits at each path) — "+
				"usually a package upgrade the process hasn't been restarted after; a replaced system library is also how a "+
				"PAM or libc backdoor is installed, so verify with the package manager (dpkg -V / rpm -V): %s",
				label, len(j.replaced), strings.Join(j.replaced, ", ")),
		})
	}
	if susp := append(append([]string{}, j.high...), j.low...); len(susp) > 0 {
		fields["suspicious_modules"] = susp
		sev, conf := SevNotable, 30
		if len(j.high) > 0 {
			sev, conf = SevSuspect, 55
		}
		// Say where they really are: a hidden directory in a home folder is not
		// a world-writable temporary location, and the difference is the triage.
		where := strings.Join(j.reasons, "; ")
		if where == "" {
			where = "an unusual location"
		}
		findings = append(findings, Finding{
			Rule: "modules.unusual_path", Severity: sev, Technique: "T1574.006", Confidence: conf,
			Detail: fmt.Sprintf("%s has %d module(s) loaded from %s: %s",
				label, len(susp), where, strings.Join(susp, ", ")),
		})
	}
	return fields, findings
}
