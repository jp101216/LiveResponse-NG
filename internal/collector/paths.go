package collector

import (
	"strings"
)

// Path heuristics shared by every collector that judges where a program runs
// from. No build tag: pure string handling, unit-tested on any OS.

// riskLevel grades how unusual a location is for a program to run from.
type riskLevel int

const (
	riskNone riskLevel = iota
	// riskLow: writable by every user but also used by some legitimate
	// software (ProgramData, a file directly in a drive root).
	riskLow
	// riskHigh: temporary, download or world-writable locations installed
	// software doesn't run from.
	riskHigh
)

func (l riskLevel) String() string {
	switch l {
	case riskHigh:
		return "high"
	case riskLow:
		return "low"
	}
	return "none"
}

type pathMarker struct{ marker, reason string }

// highRiskMarkers are user-writable or temporary locations where droppers
// commonly land and installed software doesn't run from. Matched against a
// lower-cased, normalised path.
var highRiskMarkers = []pathMarker{
	{`\temp\`, "a temporary directory"},
	{`\tmp\`, "a temporary directory"},
	{`\downloads\`, "a Downloads folder"},
	{`\users\public\`, "the Public profile"},
	{`\$recycle.bin\`, "the Recycle Bin"},
	{`\perflogs\`, "PerfLogs (writable by all users)"},
	{`\windows\tasks\`, "a world-writable Windows directory"},
	{`\windows\tracing\`, "a world-writable Windows directory"},
	{`\system32\spool\drivers\color\`, "a world-writable Windows directory"},
	{`\system32\tasks\`, "the task store (not a program location)"},
	{`\syswow64\tasks\`, "the task store (not a program location)"},
}

// lowRiskMarkers are writable by every user, so malware likes them, but some
// legitimate software runs from them too; they rate a lower severity.
var lowRiskMarkers = []pathMarker{
	{`\programdata\`, "ProgramData (writable by all users)"},
}

// trustedSubpaths sit under a marker but hold well-known protected software.
// Without these, Microsoft Defender (which runs and loads its engine from
// ProgramData) would be flagged on every Windows host.
var trustedSubpaths = []string{
	`\programdata\microsoft\windows defender\`,
	`\programdata\microsoft\windows defender advanced threat protection\platform\`,
}

// placeholderEnv resolves environment references to representative locations
// so a path such as %TEMP%\x.exe can be judged without the target user's
// actual environment. Only the directory shape matters here.
var placeholderEnv = map[string]string{
	"systemroot":              `C:\Windows`,
	"windir":                  `C:\Windows`,
	"systemdrive":             `C:`,
	"programfiles":            `C:\Program Files`,
	"programfiles(x86)":       `C:\Program Files (x86)`,
	"programw6432":            `C:\Program Files`,
	"commonprogramfiles":      `C:\Program Files\Common Files`,
	"commonprogramfiles(x86)": `C:\Program Files (x86)\Common Files`,
	"commonprogramw6432":      `C:\Program Files\Common Files`,
	"programdata":             `C:\ProgramData`,
	"allusersprofile":         `C:\ProgramData`,
	"public":                  `C:\Users\Public`,
	"userprofile":             `C:\Users\user`,
	"homedrive":               `C:`,
	"homepath":                `\Users\user`,
	"appdata":                 `C:\Users\user\AppData\Roaming`,
	"localappdata":            `C:\Users\user\AppData\Local`,
	"temp":                    `C:\Users\user\AppData\Local\Temp`,
	"tmp":                     `C:\Users\user\AppData\Local\Temp`,
	"comspec":                 `C:\Windows\System32\cmd.exe`,
}

// expandEnvRefs replaces each %NAME% for which lookup returns a value
// (lookup receives the lower-cased name). Unknown references are left as they
// are, matching how Windows treats them.
func expandEnvRefs(s string, lookup func(name string) (string, bool)) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			b.WriteString(s)
			break
		}
		name := s[i+1 : i+1+j]
		if v, ok := lookup(strings.ToLower(name)); ok && name != "" {
			b.WriteString(s[:i])
			b.WriteString(v)
			s = s[i+2+j:]
			continue
		}
		// Not a known reference: keep the text up to (not including) the
		// second '%', which may itself open a valid reference.
		b.WriteString(s[:i+1+j])
		s = s[i+1+j:]
	}
	return b.String()
}

func placeholderLookup(name string) (string, bool) {
	v, ok := placeholderEnv[name]
	return v, ok
}

// normalizeForMatch lower-cases a path, resolves environment references to
// placeholders and NT/relative prefixes to Win32 form, so the markers above
// match however the path was written.
func normalizeForMatch(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	if p == "" {
		return ""
	}
	p = expandEnvRefs(p, placeholderLookup)
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	switch {
	case strings.HasPrefix(p, `\\?\unc\`):
		p = `\\` + p[len(`\\?\unc\`):]
	case strings.HasPrefix(p, `\\?\`), strings.HasPrefix(p, `\??\`), strings.HasPrefix(p, `\\.\`):
		p = p[4:]
	}
	switch {
	case strings.HasPrefix(p, `\systemroot\`):
		p = `c:\windows\` + p[len(`\systemroot\`):]
	case strings.HasPrefix(p, `system32\`), strings.HasPrefix(p, `syswow64\`):
		// Driver ImagePaths are often relative to %SystemRoot%.
		p = `c:\windows\` + p
	}
	return p
}

// pathRisk grades a path and says why. A command line should be split first
// (see commandPathRisk); this looks at a single path.
func pathRisk(p string) (riskLevel, string) {
	n := normalizeForMatch(p)
	if n == "" {
		return riskNone, ""
	}
	for _, t := range trustedSubpaths {
		if strings.Contains(n, t) {
			return riskNone, ""
		}
	}
	for _, m := range highRiskMarkers {
		if strings.Contains(n, m.marker) {
			return riskHigh, m.reason
		}
	}
	for _, m := range lowRiskMarkers {
		if strings.Contains(n, m.marker) {
			return riskLow, m.reason
		}
	}
	if isDriveRootFile(n) {
		return riskLow, "the root of a drive"
	}
	return riskNone, ""
}

// suspiciousPath reports whether a single path is in an unusual location at
// any risk level. Kept for the boolean "suspicious_path" report fields.
func suspiciousPath(p string) bool {
	lvl, _ := pathRisk(p)
	return lvl != riskNone
}

// isDriveRootFile reports whether a normalised path names a program directly
// in a drive root, e.g. c:\update.exe.
func isDriveRootFile(n string) bool {
	if len(n) < 4 || n[1] != ':' || n[2] != '\\' || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	rest := n[3:]
	return rest != "" && !strings.ContainsRune(rest, '\\') && hasCommandExt(rest)
}

// baseName returns the lower-cased final path component of p (either
// separator), e.g. "c:\windows\system32\cmd.exe" -> "cmd.exe".
func baseName(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// progName is baseName with ".exe" assumed when no extension is given, as
// Windows does when it resolves a bare program name ("powershell -c ...").
func progName(p string) string {
	b := baseName(p)
	if b != "" && !strings.Contains(b, ".") {
		b += ".exe"
	}
	return b
}

// dirName returns the lower-cased directory of a Windows path, without a
// trailing separator.
func dirName(p string) string {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "/", `\`))
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		return p[:i]
	}
	return ""
}

// proxyHosts are programs that run other code named in their arguments (a
// DLL, a script, a project file). For these, a payload in an unusual path is
// in the arguments, not the image path.
var proxyHosts = map[string]bool{
	"rundll32.exe": true, "regsvr32.exe": true, "mshta.exe": true,
	"wscript.exe": true, "cscript.exe": true, "powershell.exe": true,
	"pwsh.exe": true, "cmd.exe": true, "msiexec.exe": true,
	"msbuild.exe": true, "installutil.exe": true, "regasm.exe": true,
	"regsvcs.exe": true, "cmstp.exe": true, "odbcconf.exe": true,
	"java.exe": true, "javaw.exe": true, "python.exe": true,
	"pythonw.exe": true, "node.exe": true, "wmic.exe": true,
	"forfiles.exe": true, "pcalua.exe": true, "explorer.exe": true,
	"conhost.exe": true, "control.exe": true, "hh.exe": true,
	"mmc.exe": true, "bash.exe": true, "wsl.exe": true,
}

// commandPathRisk grades a whole command line: the program it runs, and —
// when that program is a proxy host such as rundll32 or wscript — the paths
// in its arguments. Arguments of ordinary programs are ignored, so a log path
// like "--log C:\Windows\Temp\app.log" doesn't make a service look malicious.
// It returns the highest level found, why, and the path responsible.
func commandPathRisk(cmd string) (lvl riskLevel, reason, culprit string) {
	image, args, _ := splitCommand(cmd)
	lvl, reason = pathRisk(image)
	culprit = image
	if !proxyHosts[progName(image)] {
		return lvl, reason, culprit
	}
	for _, tok := range pathTokens(args) {
		if l, r := pathRisk(tok); l > lvl {
			lvl, reason, culprit = l, r, tok
		}
	}
	return lvl, reason, culprit
}

// proxyPayload returns the first file a proxy host is told to run — the DLL
// for rundll32/regsvr32, the script for wscript/powershell -File — or "" for
// an ordinary program. Paths still holding %VARIABLES% are returned as is.
func proxyPayload(cmd string) string {
	image, args, _ := splitCommand(cmd)
	if !proxyHosts[progName(image)] {
		return ""
	}
	for _, tok := range pathTokens(args) {
		if hasCommandExt(tok) || strings.HasSuffix(strings.ToLower(tok), ".sct") ||
			strings.HasSuffix(strings.ToLower(tok), ".inf") || strings.HasSuffix(strings.ToLower(tok), ".xml") {
			return tok
		}
	}
	return ""
}

// pathTokens extracts path-like tokens (containing a separator or an
// environment reference) from an argument string, splitting on whitespace
// outside quotes and on the ',' and '=' that rundll32 entry points and
// /switch=value arguments use.
func pathTokens(args string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		t := strings.Trim(cur.String(), `"' `)
		cur.Reset()
		if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "-") {
			// A switch: only its value can be a path (/i:C:\x.sct).
			i := strings.IndexByte(t, ':')
			if i < 0 || i+1 >= len(t) {
				return
			}
			t = strings.Trim(t[i+1:], `"'`)
		}
		if t != "" && (strings.ContainsAny(t, `\/`) || strings.Contains(t, "%")) &&
			!strings.Contains(t, "://") {
			out = append(out, t)
		}
	}
	for _, r := range args {
		switch {
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t' || r == ',' || r == '=' || r == ';'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}
