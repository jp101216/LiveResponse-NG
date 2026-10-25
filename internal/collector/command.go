package collector

import "strings"

// Command-line splitting for service ImagePaths, autorun values and task
// actions. No build tag: pure string handling, unit-tested on any OS.

// commandExts are the extensions recognised as the end of a program path
// when an unquoted command line contains spaces.
var commandExts = []string{
	".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".cpl", ".dll", ".sys",
	".ocx", ".msi", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
	".hta", ".lnk", ".jar", ".py",
}

func hasCommandExt(s string) bool {
	s = strings.ToLower(s)
	for _, e := range commandExts {
		if strings.HasSuffix(s, e) && len(s) > len(e) {
			return true
		}
	}
	return false
}

// splitCommand splits a Windows command line into the program it runs and
// the remaining arguments, following the shapes CreateProcess resolves:
//
//	"C:\Program Files\x\svc.exe" -k net      quoted path
//	C:\Windows\system32\svchost.exe -k net    unquoted, no spaces
//	C:\Program Files\x\svc.exe -k net         unquoted path with spaces
//
// The last shape can't be told from a path plus arguments without touching
// the filesystem, so the image is extended across spaces to the first
// executable extension only while the text still looks like one path (it
// starts like a path, and no word in between looks like a switch). quoted
// reports whether the program was quoted.
func splitCommand(cmd string) (image, args string, quoted bool) {
	s := strings.TrimSpace(cmd)
	s = strings.TrimPrefix(s, `\??\`)
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			return s[1 : 1+end], strings.TrimSpace(s[2+end:]), true
		}
		return strings.Trim(s, `"`), "", true // unterminated quote: best effort
	}
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		i = len(s)
	}
	first := s[:i]
	if hasCommandExt(first) {
		return first, strings.TrimSpace(s[i:]), false
	}
	end := pathEndByExt(s)
	switch {
	case end > 0 && end < len(first):
		// "userinit.exe,next.exe": the program ends at a comma inside the
		// first word (Winlogon values are comma-separated lists).
		return s[:end], strings.TrimSpace(s[end:]), false
	case end > len(first) && looksLikeSpacedPath(s[:end]):
		return s[:end], strings.TrimSpace(s[end:]), false
	}
	return first, strings.TrimSpace(s[i:]), false
}

// imageFromCommand returns just the program a command line runs.
func imageFromCommand(cmd string) string {
	img, _, _ := splitCommand(cmd)
	return img
}

// pathEndByExt returns the index just past the earliest executable extension
// that ends a word in s (followed by the end, whitespace, a quote or a
// comma), or -1.
func pathEndByExt(s string) int {
	lower := strings.ToLower(s)
	best := -1
	for _, e := range commandExts {
		from := 0
		for {
			j := strings.Index(lower[from:], e)
			if j < 0 {
				break
			}
			end := from + j + len(e)
			if end == len(lower) || strings.IndexByte(" \t\",", lower[end]) >= 0 {
				if best < 0 || end < best {
					best = end
				}
				break
			}
			from = end
		}
	}
	return best
}

// looksLikeSpacedPath reports whether an unquoted candidate containing spaces
// reads as a single path: it starts like an absolute path (drive, UNC or an
// environment reference) and no later word starts like a switch.
func looksLikeSpacedPath(cand string) bool {
	words := strings.Fields(cand)
	if len(words) < 2 {
		return false
	}
	w0 := words[0]
	if !(len(w0) >= 3 && w0[1] == ':' && (w0[2] == '\\' || w0[2] == '/')) &&
		!strings.HasPrefix(w0, `\\`) && !strings.HasPrefix(w0, "%") {
		return false
	}
	for _, w := range words[1:] {
		if w[0] == '-' || w[0] == '/' {
			return false
		}
	}
	return true
}

// unquotedSpacePath reports whether a command runs an unquoted program path
// that contains a space — "C:\Program Files\App\svc.exe". Windows tries
// C:\Program.exe first, so anyone who can write there hijacks the program
// (T1574.009, unquoted path interception).
func unquotedSpacePath(cmd string) bool {
	img, _, quoted := splitCommand(cmd)
	return !quoted && strings.ContainsAny(img, " \t")
}
