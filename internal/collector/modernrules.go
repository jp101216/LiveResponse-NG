package collector

import (
	"fmt"
	"regexp"
	"strings"
)

// These rules describe observable behavior, not attribution to a campaign.
// The CLI rule is deliberately informational unless other evidence agrees.
var ideTunnelCommand = regexp.MustCompile(`(?i)(?:^|\s)tunnel(?:\s|$)`)
var ideTunnelArgs = regexp.MustCompile(`(?i)^\s*(?:(?:--cli-data-dir|--log|--extensions-dir)\s+(?:"[^"]*"|\S+)\s+)*tunnel(?:\s|$)`)
var clickFixMarker = regexp.MustCompile(`(?i)cloudflare.{0,40}verif|verif.{0,40}cloudflare|captcha|verify you are human|i am not a robot|browser.{0,20}(?:repair|fix)`)

// modernCommandFindings applies the rules above to a command line. c is the
// command as analyzeCommandLine already prepared it (lower-cased,
// an encoded payload decoded), so it isn't decoded twice.
func modernCommandFindings(source, image, cmd string, c *cmdInput) []Finding {
	var fs []Finding
	if c.ps && clickFixMarker.MatchString(c.text()) && cradle(c) && executes(c) {
		fs = append(fs, Finding{"exec.clickfix_lure", SevSuspect, "T1204.004", 75,
			source + " combines verification/repair lure text with downloading and executing code; consistent with ClickFix-family delivery, but the lure's origin is unverified"})
	}
	if isIDETunnel(image, cmd) {
		fs = append(fs, Finding{"remote.ide_tunnel", SevNotable, "T1219.001", 40,
			source + " starts or configures a VS Code-style remote tunnel; legitimate development uses the same feature, so investigate its launch context and persistence"})
	}
	return fs
}

func isIDETunnel(image, cmd string) bool {
	program, args, _ := splitCommand(cmd)
	if !ideTunnelArgs.MatchString(args) {
		return false
	}
	n := strings.TrimSuffix(baseName(image), ".exe")
	if n == "" {
		n = strings.TrimSuffix(baseName(program), ".exe")
	}
	s := strings.ToLower(cmd)
	if n == "code" || n == "code-insiders" || n == "code-tunnel" {
		return true
	}
	if shellLike[n+".exe"] || n == "echo" || n == "printf" {
		return false
	}
	return strings.Contains(s, "--accept-server-license-terms") || strings.Contains(s, "--cli-data-dir")
}

// A matching system-DLL name is context, not a signature. Real applications
// also ship these DLLs. Higher severity requires separate corroboration.
var sideLoadDLLs = set("dui70.dll", "cryptbase.dll", "version.dll", "winmm.dll", "winhttp.dll",
	"dbghelp.dll", "dwmapi.dll", "wtsapi32.dll", "msimg32.dll", "secur32.dll", "uxtheme.dll")

func sideLoadCandidate(image, module string) bool {
	return image != "" && module != "" && sideLoadDLLs[baseName(module)] &&
		dirName(image) == dirName(module) && pathRiskLevel(image) != riskNone
}

func pathRiskLevel(path string) riskLevel { l, _ := pathRisk(path); return l }

func sideLoadFinding(image, module string, host, dll SignatureResult) []Finding {
	if !sideLoadCandidate(image, module) || host.State != SigTrusted ||
		(dll.State != SigUnsigned && dll.State != SigUntrusted) {
		return nil
	}
	return []Finding{{"modules.side_load_candidate", SevNotable, "T1574.001", 55,
		fmt.Sprintf("trusted executable %s has loaded adjacent %s (%s signature) from an unusual location; a sideloading candidate requiring context, not proof of maliciousness", image, module, dll.State)}}
}

// A small, explicit list makes targeting visible without trusting a filter's
// attacker-controlled display name. It is a hint; file identity is unverified.
var securityAgentNames = set("mssense.exe", "msmpeng.exe", "senseir.exe", "sensece.exe", "sensecncproxy.exe",
	"csfalconservice.exe", "csfalconcontainer.exe", "sentinelagent.exe", "sentinelservicehost.exe",
	"sophoshealth.exe", "sophosfilescanner.exe", "sophosendpoint.exe", "sophosinterceptx.exe",
	"cyserver.exe", "cortex-xdr.exe", "repux.exe", "cb.exe", "ekrn.exe", "fortiedrcollector.exe")

func wfpFilterFindings(app, layer, match string) []Finding {
	if match != "equal" || (layer != "ale_auth_connect_v4" && layer != "ale_auth_connect_v6") || !securityAgentNames[baseName(app)] {
		return nil
	}
	return []Finding{{"defense.wfp_security_agent_block", SevSuspect, "T1562.001", 65,
		"an outbound authorization BLOCK filter matches security-agent-named executable " + app + "; filter precedence, other conditions and legitimate policy can affect the outcome; this does not establish actual telemetry loss"}}
}
