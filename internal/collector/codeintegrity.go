package collector

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/vulndrivers"
)

// Code Integrity's own log (Microsoft-Windows-CodeIntegrity/Operational)
// records every image it refused to load, and, under a policy in audit mode,
// every one it would have refused. Each event carries the file's hashes,
// flat and Authenticode, so a driver it names is matched against the
// vulnerable-driver list by hash, the same way as a driver on disk:
//
//   - a listed driver that was blocked is an attempt to bring a vulnerable
//     driver that Microsoft's blocklist (or HVCI, or an App Control policy)
//     stopped. It never shows in the kernel's module list;
//   - a listed driver under an audit-mode policy was loaded;
//   - any other driver that was blocked is reported as such (an unknown
//     vulnerable driver, or an unsigned one from a hardware vendor);
//   - a module LSA protection kept out of LSASS is a security package or
//     authentication plugin that isn't signed the way LSA protection requires
//     (mimilib, an SSP or password-filter backdoor).
//
// Other user-mode blocks are an App Control policy doing its job, not
// findings.

// codeIntegrityBlocks are the events for an image refused, and the audit
// events for one a policy would have refused.
var (
	codeIntegrityBlocks = map[int]string{
		3004: "its signature or page hashes are invalid",
		3023: "it doesn't meet the requirements of the policy",
		3033: "it doesn't meet the signing level required",
		3077: "it violates a code integrity policy",
	}
	codeIntegrityAudits = map[int]bool{3034: true, 3076: true}
)

// isCodeIntegrity reports whether an event comes from Code Integrity.
func isCodeIntegrity(ev winEvent) bool {
	return strings.Contains(strings.ToLower(ev.Provider+" "+ev.Channel), "codeintegrity")
}

// ciHashes are the event's hash fields: flat (the file) and Authenticode.
var ciHashes = []struct {
	name string
	auth bool
}{
	{"SHA256 Flat Hash", false}, {"SHA1 Flat Hash", false}, {"SHA256 Hash", true}, {"SHA1 Hash", true},
}

// ciKnownDriver looks the event's file up in the vulnerable-driver list by
// each of its hashes.
func ciKnownDriver(set *vulndrivers.Set, ev winEvent) (vulndrivers.Match, bool) {
	for _, h := range ciHashes {
		v := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(evData(ev, h.name)), " ", ""))
		b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err != nil || len(b) == 0 {
			continue
		}
		var m vulndrivers.Match
		var ok bool
		switch {
		case !h.auth:
			m, ok = set.FileHex(hex.EncodeToString(b))
		case len(b) == 32:
			m, ok = set.AuthentihashSHA256([32]byte(b))
		case len(b) == 20:
			m, ok = set.AuthentihashSHA1([20]byte(b))
		}
		if ok {
			return m, true
		}
	}
	return vulndrivers.Match{}, false
}

// codeIntegrityFindings judges one Code Integrity event.
func codeIntegrityFindings(ev winEvent) []Finding {
	why, blocked := codeIntegrityBlocks[ev.EventID]
	if !blocked && !codeIntegrityAudits[ev.EventID] {
		return nil
	}
	file := firstNonEmpty(evData(ev, "File Name"), evData(ev, "FileName"), "an image")
	proc := firstNonEmpty(evData(ev, "Process Name"), evData(ev, "ProcessName"), "a process")
	policy := evData(ev, "PolicyName")
	when := ""
	if !ev.TimeCreated.IsZero() {
		when = " at " + ev.TimeCreated.UTC().Format(time.RFC3339)
	}
	by := fmt.Sprintf("Code Integrity event %d", ev.EventID)
	if policy != "" {
		by += ", policy " + policy
	}
	driver := strings.HasSuffix(strings.ToLower(file), ".sys") || strings.TrimSpace(evData(ev, "SI Signing Scenario")) == "0"

	if set, err := vulndrivers.Default(); err == nil && driver {
		if m, ok := ciKnownDriver(set, ev); ok {
			switch {
			case !blocked: // an audit-mode policy let it load
				return []Finding{knownDriverFinding(m, file, fmt.Sprintf("was loaded%s: the code integrity policy was only auditing and "+
					"would have blocked it (%s)", when, by), false)}
			case m.Driver.Category == vulndrivers.Malicious:
				return []Finding{knownDriverFinding(m, file, fmt.Sprintf("was blocked from loading%s (%s)", when, by), false)}
			default:
				d := m.Driver
				tech := d.Technique
				if tech == "" {
					tech = "T1068"
				}
				return []Finding{{
					Rule: "privesc.vulnerable_driver_blocked", Severity: SevSuspect, Technique: tech, Confidence: 70,
					Detail: fmt.Sprintf("Windows kept the known vulnerable driver %s (LOLDrivers: %s, matched by %s) from loading%s (%s): "+
						"someone tried to bring a vulnerable driver into the kernel, and the blocklist or policy stopped it. See %s",
						file, d.Label(), m.By, when, by, d.URL()),
				}}
			}
		}
	}
	if !blocked {
		return nil
	}
	if driver {
		return []Finding{{
			Rule: "defense.driver_load_blocked", Severity: SevNotable, Technique: "T1068", Confidence: 45,
			Detail: fmt.Sprintf("Code Integrity refused to load the driver %s for %s%s: %s (%s). A driver Windows refuses is an "+
				"unlisted vulnerable driver someone tried, or an unsigned one from a hardware vendor", file, proc, when, why, by),
		}}
	}
	if baseName(proc) == "lsass.exe" {
		return []Finding{{
			Rule: "cred.lsa_plugin_blocked", Severity: SevSuspect, Technique: "T1547.005", Confidence: 65,
			Detail: fmt.Sprintf("Code Integrity kept %s out of LSASS%s: %s (%s). LSA protection only admits modules signed for it, "+
				"so this was a security package, authentication package or password filter that isn't: mimilib, or an SSP or "+
				"password-filter backdoor, unless it is an old third-party plugin", file, when, why, by),
		}}
	}
	return nil
}
