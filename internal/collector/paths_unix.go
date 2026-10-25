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
	if isMemfdPath(p) {
		return riskHigh, "an anonymous in-memory file (memfd — no file on disk)"
	}
	if strings.HasSuffix(p, deletedSuffix) {
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

// deletedSuffix is how the kernel marks an exe link or mapping whose file was
// unlinked while in use.
const deletedSuffix = " (deleted)"

// isMemfdPath reports whether an exe link or mapping names an anonymous
// in-memory file (memfd_create) rather than anything on disk.
func isMemfdPath(p string) bool { return strings.Contains(p, "memfd:") }

// systemPackagePrefixes are the root-owned trees distribution packages (and
// vendor installers) put programs and libraries in.
var systemPackagePrefixes = []string{
	"/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/opt",
	"/snap", "/nix/store", "/var/lib/flatpak", "/var/lib/snapd",
}

// replacedSystemFile reports whether p, an exe link target or mapping marked
// " (deleted)", is a file in a system package location that now has a new file
// at the same path. That is the footprint of a package upgrade the process
// hasn't been restarted after: dpkg/rpm install the new version by renaming it
// over the old one, so the running copy shows as deleted. It is not proof —
// a trojanized system binary dropped the same way looks identical — so callers
// report it at low severity rather than not at all. exists says whether a
// regular file is at a path, as the process itself would see it.
func replacedSystemFile(p string, exists func(string) bool) bool {
	orig, ok := strings.CutSuffix(p, deletedSuffix)
	if !ok || orig == "" || isMemfdPath(orig) || !strings.HasPrefix(orig, "/") {
		return false
	}
	for _, pre := range systemPackagePrefixes {
		if hasPathPrefix(orig, pre) {
			return exists(orig)
		}
	}
	return false
}

// homePathRisk flags a hidden directory or a Downloads folder inside a home
// directory — common spots for user-level persistence and dropped payloads.
func homePathRisk(p string) (riskLevel, string) {
	if !strings.HasPrefix(p, "/home/") && !hasPathPrefix(p, "/root") && !strings.HasPrefix(p, "/Users/") {
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
