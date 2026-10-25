package collector

import (
	"fmt"
	"strings"
)

// Service heuristics. No build tag: pure logic, unit-tested on any OS.

// serviceConfig is what the heuristics need to know about one service.
type serviceConfig struct {
	Name           string
	Command        string // ImagePath with machine-wide variables expanded
	CommandRaw     string
	Image          string // the program, normalised to a Win32 path
	ServiceDLL     string
	FailureCommand string
	Type           uint32
	HasType        bool
}

// judgeService returns the findings for one service.
func judgeService(s serviceConfig, sysRoot string) []Finding {
	var out []Finding
	driver := s.HasType && isDriverType(s.Type)
	kind := "service"
	if driver {
		kind = "driver"
	}
	label := kind + " " + s.Name

	// Where the code lives: the image, a proxy host's payload, or the DLL.
	lvl, why, culprit := commandPathRisk(s.Command)
	for _, p := range []string{s.Image, s.ServiceDLL} {
		if l, w := pathRisk(p); l > lvl {
			lvl, why, culprit = l, w, p
		}
	}
	if lvl != riskNone {
		sev, conf := SevSuspect, 60
		if lvl == riskLow {
			sev, conf = SevNotable, 35
		}
		out = append(out, Finding{
			Rule: "persistence.service_unusual_path", Severity: sev, Technique: "T1543.003", Confidence: conf,
			Detail: fmt.Sprintf("%s runs code from %s: %s", label, why, culprit),
		})
	}

	// A service binary directly in the Windows directory is how PsExec
	// (PSEXESVC.exe) and Impacket's psexec run commands remotely: they copy
	// a binary to ADMIN$ and start it as a service.
	if !driver && s.Image != "" && sysRoot != "" &&
		dirName(s.Image) == strings.ToLower(strings.TrimRight(sysRoot, `\`)) {
		out = append(out, Finding{
			Rule: "lateral.service_in_windows_dir", Severity: SevSuspect, Technique: "T1569.002", Confidence: 65,
			Detail: fmt.Sprintf("%s runs %s directly from the Windows directory — PsExec and Impacket copy their service binary to ADMIN$ and start it this way",
				label, s.Image),
		})
	}

	// A shell as the service binary: smbexec and many droppers run commands
	// as SYSTEM through "%COMSPEC% /c ..." services.
	if !driver && scriptHosts[progName(s.Image)] {
		out = append(out, Finding{
			Rule: "persistence.service_script_host", Severity: SevSuspect, Technique: "T1569.002", Confidence: 70,
			Detail: fmt.Sprintf("%s runs a script host directly: %s", label, excerpt(s.Command, 240)),
		})
	}

	if !driver && unquotedSpacePath(s.Command) {
		out = append(out, Finding{
			Rule: "persistence.service_unquoted_path", Severity: SevNotable, Technique: "T1574.009", Confidence: 40,
			Detail: fmt.Sprintf("%s has an unquoted image path containing spaces (%s): Windows tries each space-separated prefix first, "+
				"so a writable parent directory lets anyone hijack the service", label, s.Command),
		})
	}

	out = mergeFindings(out, analyzeCommandLine(label+" ImagePath", s.Image, s.Command)...)

	if s.FailureCommand != "" {
		out = append(out, Finding{
			Rule: "persistence.service_failure_command", Severity: SevNotable, Technique: "T1543.003", Confidence: 40,
			Detail: fmt.Sprintf("%s runs a command whenever it fails (recovery action): %s", label, excerpt(s.FailureCommand, 240)),
		})
		out = mergeFindings(out, analyzeCommandLine(label+" FailureCommand", "", s.FailureCommand)...)
	}
	return out
}
