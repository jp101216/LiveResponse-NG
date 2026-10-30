package collector

import (
	"fmt"
	"strings"
)

// Type-library registration heuristics, a second face of COM hijacking
// (T1546.015) that the CLSID-server walk in comrules.go does not see.
//
// A COM object can carry a type library, registered under
// TypeLib\{libid}\{version}\{lcid}\{platform} with the library's path as that
// key's default value. When an object is instantiated and its type library is
// loaded, Windows reads that path — so a registration that names a COM script
// moniker instead of a .tlb/.dll, or a library in a user-writable location,
// reaches code the same way a rewritten InprocServer32 would. The per-user
// class store is consulted before the machine one here too, so a per-user
// TypeLib entry silently overrides the machine copy for that LibID.
//
// Judging is behavioural, matching the CLSID walk: a script moniker where a
// library file belongs, a library in a user-writable/temporary path, and a
// per-user entry that shadows a machine one. No build tag: pure logic,
// unit-tested on any OS.

// typeLibEntry is one registered type-library location as the heuristics see
// it (one platform leaf under one LibID/version/LCID).
type typeLibEntry struct {
	LibID    string // "{guid}", lower-case
	Version  string // "major.minor"
	LCID     string // locale-id subkey ("0", "409", ...)
	Platform string // win32 / win64 / win16
	Name     string // the library's friendly (version-key default) name, if any
	Hive     string // where it was read: "HKLM" or "HKU\<sid>"
	User     bool   // a per-user registration (a user's own class store)
	View     string // "native" or "wow64"
	Path     string // the library path, expanded (or the moniker, kept verbatim)
	PathRaw  string // as stored, before expansion

	// Shadows is set for a per-user entry whose LibID is also registered in
	// HKLM: the per-user copy wins, the TypeLib analogue of the CLSID hijack.
	Shadows bool
}

// typeLibRef renders a short, stable location string for one entry.
func typeLibRef(e typeLibEntry) string {
	ref := e.Hive + ` TypeLib\` + e.LibID
	if e.Version != "" {
		ref += `\` + e.Version
	}
	if e.Platform != "" {
		ref += " (" + e.Platform + ")"
	}
	if e.Name != "" {
		ref += " " + excerpt(e.Name, 60)
	}
	return ref
}

// typeLibScriptMoniker reports whether a type-library value is a COM script
// moniker or scriptlet rather than an ordinary library file — the shape of a
// TypeLib-hijack payload, where loading the "type library" runs script. It
// returns a short description when so, else "".
func typeLibScriptMoniker(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.HasPrefix(s, "script:"), strings.HasPrefix(s, "scriptlet:"):
		return "a COM script moniker (script runs when the library is loaded), not a type-library file"
	case strings.HasSuffix(s, ".sct"):
		return "a COM scriptlet (.sct), not a type-library file"
	case baseName(s) == "scrobj.dll":
		return "scrobj.dll, the script-component runtime"
	}
	return ""
}

// judgeTypeLib returns the findings for one type-library registration.
func judgeTypeLib(e typeLibEntry) []Finding {
	if strings.TrimSpace(e.Path) == "" && strings.TrimSpace(e.PathRaw) == "" {
		return nil
	}
	var out []Finding
	loc := typeLibRef(e)

	moniker := typeLibScriptMoniker(firstNonEmpty(e.PathRaw, e.Path))
	lvl, why := pathRisk(e.Path)

	// The classic hijack shape: a per-user registration overriding a machine
	// one. Critical when that override is itself a moniker or an odd path.
	if e.Shadows {
		sev, conf := SevSuspect, 70
		detail := fmt.Sprintf("a per-user type library at %s overrides the machine-wide one for this LibID (a user's class store is consulted first)", loc)
		if p := firstNonEmpty(e.Path, e.PathRaw); p != "" {
			detail += ": " + excerpt(p, 160)
		}
		if moniker != "" || lvl == riskHigh {
			sev, conf = SevCritical, 85
		}
		out = append(out, Finding{Rule: "persistence.typelib_user_shadow", Severity: sev, Technique: "T1546.015", Confidence: conf, Detail: detail})
	}

	// A script moniker / scriptlet where a library file belongs.
	if moniker != "" {
		out = append(out, Finding{Rule: "persistence.typelib_script_moniker", Severity: SevSuspect, Technique: "T1546.015", Confidence: 75,
			Detail: fmt.Sprintf("%s names %s: %s", loc, moniker, excerpt(firstNonEmpty(e.PathRaw, e.Path), 200))})
	}

	// A library loaded from a user-writable / temporary / unusual location.
	if lvl != riskNone {
		sev, conf := SevSuspect, 55
		if lvl == riskLow {
			sev, conf = SevNotable, 35
		}
		out = append(out, Finding{Rule: "persistence.typelib_unusual_path", Severity: sev, Technique: "T1546.015", Confidence: conf,
			Detail: fmt.Sprintf("type library for %s loads from %s: %s", loc, why, excerpt(e.Path, 160))})
	}

	return out
}
