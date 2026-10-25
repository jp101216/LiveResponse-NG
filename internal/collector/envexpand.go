package collector

import (
	"strings"
)

// Environment expansion for registry values (REG_EXPAND_SZ) and task actions.
//
// Expanding with the agent's own environment is wrong for anything that runs
// as another user: a per-user Run value of %APPDATA%\x.exe must resolve under
// that user's profile, not the analyst's (or SYSTEM's). So expansion is split:
// machine-wide variables (%SystemRoot%, %ProgramFiles%, ...) expand from the
// host, per-user variables only from a known profile directory, and anything
// else is left as written — an unexpanded %TEMP% is honest, a wrong one isn't.
//
// No build tag: pure string handling, unit-tested on any OS.

// machineEnvNames are the variables whose value is the same for every user.
var machineEnvNames = []string{
	"systemroot", "windir", "systemdrive", "programfiles", "programfiles(x86)",
	"programw6432", "commonprogramfiles", "commonprogramfiles(x86)",
	"commonprogramw6432", "programdata", "allusersprofile", "public", "comspec",
	"driverdata",
}

// envLookup resolves a lower-cased variable name.
type envLookup func(name string) (string, bool)

// machineLookupFrom builds a machine-variable lookup from a getenv function,
// ignoring per-user variables even if getenv knows them.
func machineLookupFrom(getenv func(string) string) envLookup {
	vals := map[string]string{}
	for _, n := range machineEnvNames {
		if v := getenv(n); v != "" {
			vals[n] = v
		}
	}
	return func(name string) (string, bool) {
		v, ok := vals[name]
		return v, ok
	}
}

// userLookup resolves the per-user variables derivable from a profile
// directory such as C:\Users\alice.
func userLookup(profile string) envLookup {
	profile = strings.TrimRight(profile, `\`)
	if profile == "" {
		return func(string) (string, bool) { return "", false }
	}
	vals := map[string]string{
		"userprofile":  profile,
		"appdata":      profile + `\AppData\Roaming`,
		"localappdata": profile + `\AppData\Local`,
		"temp":         profile + `\AppData\Local\Temp`,
		"tmp":          profile + `\AppData\Local\Temp`,
	}
	if i := strings.LastIndexByte(profile, '\\'); i >= 0 && i+1 < len(profile) {
		vals["username"] = profile[i+1:]
	}
	if len(profile) >= 2 && profile[1] == ':' {
		vals["homedrive"] = profile[:2]
		vals["homepath"] = profile[2:]
	}
	return func(name string) (string, bool) {
		v, ok := vals[name]
		return v, ok
	}
}

// chain consults lookups in order.
func chain(ls ...envLookup) envLookup {
	return func(name string) (string, bool) {
		for _, l := range ls {
			if l == nil {
				continue
			}
			if v, ok := l(name); ok {
				return v, true
			}
		}
		return "", false
	}
}

// normalizeImageWith turns the forms Windows stores program paths in —
// \SystemRoot\..., system32\drivers\x.sys (relative to the Windows
// directory), \??\C:\..., %SystemRoot%\... — into an ordinary Win32 path.
func normalizeImageWith(p, sysRoot string, lookup envLookup) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if p == "" {
		return ""
	}
	p = expandEnvRefs(p, lookup)
	lower := strings.ToLower(p)
	switch {
	case strings.HasPrefix(lower, `\??\`),
		strings.HasPrefix(lower, `\\?\`) && !strings.HasPrefix(lower, `\\?\unc\`):
		p = p[4:]
	case strings.HasPrefix(lower, `\systemroot\`):
		p = sysRoot + p[len(`\systemroot`):]
	case strings.HasPrefix(lower, `system32\`), strings.HasPrefix(lower, `syswow64\`):
		p = sysRoot + `\` + p
	}
	return p
}
