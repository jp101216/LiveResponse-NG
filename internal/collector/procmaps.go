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
		perms, path, ok := mapsPermsAndPath(line)
		if !ok {
			continue // no pathname (anonymous mapping)
		}
		if !strings.Contains(perms, "x") {
			continue // only executable mappings are "modules"
		}
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

// mapsPermsAndPath splits one maps line into its permissions and its pathname.
// The first five columns are separated by runs of blanks; the pathname is the
// rest of the line exactly as the kernel wrote it, so a name with consecutive
// or trailing spaces — one way to make two files look alike in a listing — is
// reported as it is rather than normalised (and keeps its " (deleted)" marker).
func mapsPermsAndPath(line string) (perms, path string, ok bool) {
	rest := line
	for col := 0; col < 5; col++ {
		rest = strings.TrimLeft(rest, " \t")
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			return "", "", false
		}
		if col == 1 {
			perms = rest[:end]
		}
		rest = rest[end:]
	}
	path = strings.TrimLeft(rest, " \t")
	return perms, strings.TrimRight(path, "\r"), path != ""
}
