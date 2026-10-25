package collector

import "strings"

// prefetchExecutable parses a prefetch filename of the form NAME-HASH.pf into
// the executable name and its 8-hex path hash (a hash of the full path and,
// on some versions, the command line). ok is false when the name doesn't fit
// the standard shape. No build tag: pure string handling, tested on any OS.
func prefetchExecutable(fname string) (exe, hash string, ok bool) {
	if len(fname) < 4 || !strings.EqualFold(fname[len(fname)-3:], ".pf") {
		return "", "", false
	}
	stem := fname[:len(fname)-3]
	dash := strings.LastIndexByte(stem, '-')
	if dash <= 0 || dash == len(stem)-1 {
		return stem, "", false
	}
	exe = stem[:dash]
	hash = stem[dash+1:]
	return exe, hash, isHex8(hash)
}

func isHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
