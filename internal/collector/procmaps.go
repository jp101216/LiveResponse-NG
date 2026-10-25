package collector

import "strings"

// procmaps.go — parser for /proc/<pid>/maps. No build tag: pure text handling,
// unit-tested on any OS.

// mapsFile is one file-backed, executable mapping (a loaded library or the main
// image). Anonymous regions, pseudo-maps ([heap], [stack], [vdso]) and
// non-executable mappings are not returned — the modules collector is about
// loaded files, the way the Windows one lists DLLs.
type mapsFile struct {
	Path    string
	Deleted bool // the backing file was unlinked while still mapped
}

// parseExecMappedFiles returns the distinct executable, file-backed mappings in
// a /proc/<pid>/maps dump, in first-seen order. A mapping line is:
//
//	address           perms offset  dev   inode      pathname
//	7f...-7f...        r-xp  00000   fd:00 1234       /usr/lib/libc.so.6
func parseExecMappedFiles(data []byte) []mapsFile {
	var out []mapsFile
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue // no pathname (anonymous mapping)
		}
		perms := f[1]
		if !strings.Contains(perms, "x") {
			continue // only executable mappings are "modules"
		}
		// The pathname is everything from field 6 on (it may carry a trailing
		// " (deleted)"); join the rest to preserve that.
		path := strings.Join(f[5:], " ")
		if path == "" || !strings.HasPrefix(path, "/") {
			continue // [vdso], [heap], anon_inode:..., empty — not a file
		}
		deleted := strings.HasSuffix(path, " (deleted)")
		key := path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, mapsFile{Path: path, Deleted: deleted})
	}
	return out
}
