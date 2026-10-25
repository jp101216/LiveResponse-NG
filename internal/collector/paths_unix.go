package collector

import "strings"

// Unix path heuristics — the Linux counterpart to paths.go. No build tag:
// pure string handling, unit-tested on any OS. The Windows pathRisk works on
// drive letters and %ENV%; this one grades POSIX paths. Both return the shared
// riskLevel so the finding builders read the same.

// unixHighRiskPrefixes are world-writable or ephemeral locations that installed
// software does not run from — where a dropper lands and a fileless payload
// executes. Matched as path prefixes (a whole path component).
var unixHighRiskPrefixes = []pathMarker{
	{"/tmp", "a world-writable temporary directory"},
	{"/var/tmp", "a world-writable temporary directory"},
	{"/dev/shm", "shared memory (world-writable, non-persistent)"},
	{"/run/shm", "shared memory (world-writable, non-persistent)"},
	{"/dev/mqueue", "a world-writable POSIX message-queue mount"},
	{"/run/user", "a per-user runtime tmpfs"},
}

// unixLowRiskPrefixes are writable spots that malware likes but legitimate use
// also touches, so they rate a lower severity.
var unixLowRiskPrefixes = []pathMarker{
	{"/var/www", "a web-server document root"},
	{"/srv/www", "a web-server document root"},
}

// unixPathRisk grades a single POSIX path and says why. memfd and deleted-image
// markers are checked first because they can decorate an exe link target
// anywhere (e.g. "/tmp/x (deleted)", "/memfd:foo (deleted)").
func unixPathRisk(p string) (riskLevel, string) {
	p = strings.TrimSpace(p)
	if p == "" {
		return riskNone, ""
	}
	if strings.Contains(p, "memfd:") {
		return riskHigh, "an anonymous in-memory file (memfd — no file on disk)"
	}
	if strings.HasSuffix(p, " (deleted)") {
		return riskHigh, "a deleted executable that is still running (self-deleting malware)"
	}
	for _, m := range unixHighRiskPrefixes {
		if hasPathPrefix(p, m.marker) {
			return riskHigh, m.reason
		}
	}
	if lvl, why := homePathRisk(p); lvl != riskNone {
		return lvl, why
	}
	for _, m := range unixLowRiskPrefixes {
		if hasPathPrefix(p, m.marker) {
			return riskLow, m.reason
		}
	}
	return riskNone, ""
}

// unixSuspiciousPath is the boolean form, for "suspicious_path" report fields.
func unixSuspiciousPath(p string) bool {
	lvl, _ := unixPathRisk(p)
	return lvl != riskNone
}

// homePathRisk flags a hidden directory or a Downloads folder inside a home
// directory — common spots for user-level persistence and dropped payloads.
func homePathRisk(p string) (riskLevel, string) {
	if !strings.HasPrefix(p, "/home/") && !strings.HasPrefix(p, "/root") && !strings.HasPrefix(p, "/Users/") {
		return riskNone, ""
	}
	// A hidden component (/.foo/) anywhere under the home dir.
	if strings.Contains(p, "/.") {
		return riskLow, "a hidden directory in a home folder"
	}
	lower := strings.ToLower(p)
	if strings.Contains(lower, "/downloads/") {
		return riskLow, "a Downloads folder"
	}
	return riskNone, ""
}

// hasPathPrefix reports whether path is dir itself or lies beneath it, matching
// whole components so "/tmpfoo" is not treated as being under "/tmp".
func hasPathPrefix(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// unixBaseName returns the final component of a POSIX path (what /proc/<pid>/comm
// or an ExecStart names), with no extension assumptions.
func unixBaseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p
}
