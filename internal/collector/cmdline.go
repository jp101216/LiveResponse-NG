package collector

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
)

// Command-line analytics: behavioural rules over a command line, applied to
// running processes, service ImagePaths, autorun values and scheduled-task
// actions. Each rule names one well-documented attacker technique (encoded
// PowerShell, download cradles, LOLBin proxy execution, credential dumping,
// recovery inhibition...) so a finding says what was seen, not just that
// something looked odd.
//
// The rules are deliberately specific: they match the technique's mechanics
// (a switch plus the thing it acts on), not a bare program name, because
// administrators use the same programs every day. Matching uses Go's RE2
// engine, which runs in linear time — command lines are attacker-controlled.
//
// No build tag: pure string handling, unit-tested on any OS.

// cmdInput is one command line prepared for the rules.
type cmdInput struct {
	lower   string // the command line, lower-cased
	image   string // lower-cased base name of the program
	ps      bool   // runs (or launches) PowerShell
	encoded bool   // has an -EncodedCommand argument (decodable or not)
	decoded string // lower-cased -EncodedCommand payload, if it decodes
	shown   string // printable excerpt of the decoded payload for details
}

func (c *cmdInput) has(s string) bool { return strings.Contains(c.lower, s) }

// text is the command line plus any decoded payload, for rules that apply to
// both.
func (c *cmdInput) text() string {
	if c.decoded == "" {
		return c.lower
	}
	return c.lower + "\n" + c.decoded
}

// tok reports whether name appears as a program token (start of the line,
// or after whitespace, a quote, a path separator or a shell operator),
// optionally with ".exe". Names must be listed in cmdTokens.
func (c *cmdInput) tok(name string) bool {
	re := tokenRes[name]
	if re == nil {
		panic("cmdline: token not registered in cmdTokens: " + name)
	}
	return re.MatchString(c.lower)
}

// cmdTokens are the program names the rules look for. Their matchers are
// compiled once at start-up (collectors run concurrently, so nothing here is
// built lazily).
var cmdTokens = []string{
	"bcdedit", "bitsadmin", "certutil", "cmstp", "copy", "esentutl", "installutil",
	"msiexec", "mshta", "netsh", "ntdsutil", "odbcconf", "procdump", "procdump64",
	"reg", "regasm", "regsvcs", "regsvr32", "rundll32", "sc", "schtasks",
	"sqldumper", "vssadmin", "wbadmin", "wmic",
}

var tokenRes = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(cmdTokens))
	for _, name := range cmdTokens {
		m[name] = regexp.MustCompile(`(?:^|[\s"'\\/&|;(=])` + regexp.QuoteMeta(name) + `(?:\.exe)?(?:$|[\s"'&|;),])`)
	}
	return m
}()

var (
	// -EncodedCommand and every prefix PowerShell accepts for it (-e, -ec,
	// -en, -enc, ...), introduced by '-', '/' or the Unicode dashes PowerShell
	// also accepts (en dash, em dash, horizontal bar) that attackers use to
	// dodge naive matching.
	rePSEncoded = regexp.MustCompile(`(?i)(?:^|[\s"'])[-/\x{2013}\x{2014}\x{2015}]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+["']?([A-Za-z0-9+/]{16,}={0,2})`)
	rePSHidden  = regexp.MustCompile(`[-/\x{2013}\x{2014}\x{2015}]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\s+["']?(?:hidden|1)\b`)
	rePSNoProf  = regexp.MustCompile(`[-/\x{2013}\x{2014}\x{2015}]nop(?:r(?:o(?:f(?:i(?:l(?:e)?)?)?)?)?)?\b`)
	rePSBypass  = regexp.MustCompile(`[-/\x{2013}\x{2014}\x{2015}](?:ep|ex\w*)\s+["']?(?:bypass|unrestricted)\b`)
	reIEX       = regexp.MustCompile(`\biex\b|invoke-expression|\bi` + "`" + `?e` + "`" + `?x\b`)
	reURL       = regexp.MustCompile(`\b(?:https?|ftp)://|\\\\[a-z0-9.-]+@(?:ssl|\d+)\\|\\davwwwroot\\`)
	reNetAPI    = regexp.MustCompile(`downloadstring|downloadfile|downloaddata|openread\s*\(|net\.webclient|system\.net\.http\.httpclient|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|\.uploadstring\(`)
	reWebCmdlet = regexp.MustCompile(`invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|start-bitstransfer|\bwget(?:\.exe)?\b|\bcurl(?:\.exe)?\b`)
	rePipeShell = regexp.MustCompile(`\|\s*(?:iex|invoke-expression|powershell|pwsh|cmd|sh|bash)\b`)
	reReflLoad  = regexp.MustCompile(`(?:reflection\.assembly\]::load|\[system\.reflection\.assembly\]::load|assembly\]::load\w*\()`)
	reB64Blob   = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)
	reNetUser   = regexp.MustCompile(`(?:^|[\s"\\/&|;(])net1?(?:\.exe)?\s+user\b.*\s/add\b`)
	reNetGroup  = regexp.MustCompile(`(?:^|[\s"\\/&|;(])net1?(?:\.exe)?\s+localgroup\s+"?(?:administrators|remote desktop users|administrateurs|administratoren|administradores)"?(?:\s.*)?\s/add\b`)
	reBcdRecov  = regexp.MustCompile(`recoveryenabled\s+(?:no|off|false|0)\b`)
	reMpDisable = regexp.MustCompile(`disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|blockatfirstseen|intrusionpreventionsystem)`)
	reWevtClear = regexp.MustCompile(`(?:^|[\s"\\/&|;(])wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b`)
	reRegSave   = regexp.MustCompile(`(?:^|[\s"\\/&|;(])reg(?:\.exe)?\s+(?:save|export)\s+["']?(?:hklm|hkey_local_machine)\\(?:sam|system|security)\b`)
)

// cmdRule is one analytic. match returns a short description of what was
// seen ("" means no match).
type cmdRule struct {
	id         string
	severity   Severity
	technique  string
	confidence int
	match      func(c *cmdInput) string
}

func any2(c *cmdInput, subs ...string) bool {
	for _, s := range subs {
		if c.has(s) {
			return true
		}
	}
	return false
}

func all2(c *cmdInput, subs ...string) bool {
	for _, s := range subs {
		if !c.has(s) {
			return false
		}
	}
	return true
}

// cradle reports a download primitive in the command line or decoded payload.
func cradle(c *cmdInput) bool {
	t := c.text()
	if reNetAPI.MatchString(t) {
		return true
	}
	if reWebCmdlet.MatchString(t) && reURL.MatchString(t) {
		return true
	}
	if (c.tok("certutil") && any2(c, "urlcache", "-verifyctl")) && reURL.MatchString(c.lower) {
		return true
	}
	return c.tok("bitsadmin") && any2(c, "/transfer", "/addfile") && reURL.MatchString(c.lower)
}

func executes(c *cmdInput) bool {
	t := c.text()
	return reIEX.MatchString(t) || rePipeShell.MatchString(t)
}

// cmdRules is evaluated in order; see analyzeCommandLine for how overlapping
// PowerShell rules are reduced to the most specific one.
var cmdRules = []cmdRule{
	{"exec.download_execute", SevCritical, "T1059.001", 90, func(c *cmdInput) string {
		if cradle(c) && executes(c) {
			return "downloads content and executes it in memory (download cradle + Invoke-Expression/pipe to a shell)"
		}
		return ""
	}},
	{"exec.powershell_reflective_load", SevCritical, "T1620", 85, func(c *cmdInput) string {
		if reReflLoad.MatchString(c.text()) {
			return "loads a .NET assembly from memory ([Reflection.Assembly]::Load) — reflective code loading"
		}
		return ""
	}},
	{"exec.powershell_encoded", SevSuspect, "T1059.001", 70, func(c *cmdInput) string {
		switch {
		case !c.ps || !c.encoded:
			return ""
		case c.decoded == "":
			return "PowerShell runs an -EncodedCommand payload (T1027 obfuscation) that does not decode as UTF-16 text"
		}
		return "PowerShell runs an -EncodedCommand payload (T1027 obfuscation); decoded: " + c.shown
	}},
	{"exec.download_cradle", SevSuspect, "T1105", 65, func(c *cmdInput) string {
		if cradle(c) {
			return "downloads a file or script from a remote location (ingress tool transfer)"
		}
		return ""
	}},
	{"exec.mshta_script", SevSuspect, "T1218.005", 80, func(c *cmdInput) string {
		if c.tok("mshta") && (reURL.MatchString(c.lower) || any2(c, "javascript:", "vbscript:", "about:")) {
			return "mshta runs remote or inline script (signed binary proxy execution)"
		}
		return ""
	}},
	{"exec.rundll32_script", SevCritical, "T1218.011", 85, func(c *cmdInput) string {
		if c.tok("rundll32") && any2(c, "javascript:", "vbscript:", "runhtmlapplication") {
			return "rundll32 executes script through mshtml (signed binary proxy execution)"
		}
		return ""
	}},
	{"exec.regsvr32_scriptlet", SevCritical, "T1218.010", 90, func(c *cmdInput) string {
		if c.tok("regsvr32") && (c.has("scrobj") || ((c.has("/i:") || c.has("-i:")) && reURL.MatchString(c.lower))) {
			return "regsvr32 runs a COM scriptlet (Squiblydoo)"
		}
		return ""
	}},
	{"exec.certutil_decode", SevSuspect, "T1140", 70, func(c *cmdInput) string {
		if c.tok("certutil") && any2(c, "-decode", "/decode", "-decodehex", "/decodehex") {
			return "certutil decodes an encoded file (deobfuscation)"
		}
		return ""
	}},
	{"exec.lolbin_proxy", SevSuspect, "T1218", 65, func(c *cmdInput) string {
		switch {
		case c.tok("msiexec") && any2(c, "/i", "-i", "/package", "-package", "/y", "-y") && reURL.MatchString(c.lower):
			return "msiexec installs a package straight from a URL (T1218.007)"
		case c.tok("odbcconf") && any2(c, "regsvr", " -a ", " /a ", "-f ", "/f "):
			return "odbcconf loads a DLL or response file (T1218.008)"
		case c.tok("cmstp") && any2(c, "/s", "/au", "/ni") && c.has(".inf"):
			return "cmstp installs a connection-manager profile from an INF (T1218.003)"
		case c.tok("installutil") && any2(c, "/u", "-u", "/logfile=", "/logtoconsole"):
			return "installutil runs an assembly's installer code (T1218.004)"
		case (c.tok("regasm") || c.tok("regsvcs")) && any2(c, "/u", "-u"):
			return "regasm/regsvcs runs an assembly's registration code (T1218.009)"
		}
		return ""
	}},
	{"cred.lsass_dump", SevCritical, "T1003.001", 95, func(c *cmdInput) string {
		switch {
		case c.has("comsvcs") && c.has("minidump"):
			return "dumps process memory with comsvcs.dll MiniDump (classic LSASS credential theft)"
		case c.has("comsvcs") && c.tok("rundll32") && c.has("#24"):
			return "calls comsvcs.dll ordinal #24 (MiniDump) via rundll32 (LSASS credential theft)"
		case (c.tok("procdump") || c.tok("procdump64") || c.tok("sqldumper")) && c.has("lsass"):
			return "dumps LSASS memory with a debugging tool"
		case c.has("lsass") && (c.has("-ma ") || c.has("/ma ") || c.has("out-minidump") || c.has("minidumpwritedump")):
			return "creates a full memory dump of LSASS"
		}
		return ""
	}},
	{"cred.hive_or_ntds_dump", SevCritical, "T1003", 90, func(c *cmdInput) string {
		switch {
		case reRegSave.MatchString(c.lower):
			return "saves the SAM/SYSTEM/SECURITY hive (offline credential extraction, T1003.002)"
		case c.tok("ntdsutil") && (c.has("ifm") || c.has("create full")):
			return "creates an NTDS.dit copy with ntdsutil (T1003.003)"
		case c.has("ntds.dit") && (c.tok("esentutl") || c.tok("copy") || c.has("copy-item") || c.has("shadowcopy")):
			return "copies NTDS.dit (T1003.003)"
		}
		return ""
	}},
	{"impact.inhibit_recovery", SevCritical, "T1490", 95, func(c *cmdInput) string {
		switch {
		case c.tok("vssadmin") && c.has("delete") && c.has("shadows"):
			return "deletes Volume Shadow Copies (ransomware precursor)"
		case c.tok("vssadmin") && c.has("resize") && c.has("shadowstorage"):
			return "shrinks shadow storage to purge shadow copies (ransomware precursor)"
		case c.tok("wmic") && c.has("shadowcopy") && c.has("delete"):
			return "deletes shadow copies through WMI (ransomware precursor)"
		case c.has("win32_shadowcopy") && any2(c, ".delete(", "remove-wmiobject", "remove-ciminstance", "| rwmi", "|rwmi"):
			return "deletes shadow copies through WMI/CIM (ransomware precursor)"
		case c.tok("wbadmin") && c.has("delete") && any2(c, "catalog", "systemstatebackup", "backup"):
			return "deletes the Windows backup catalog or backups"
		case c.tok("bcdedit") && (reBcdRecov.MatchString(c.lower) || c.has("ignoreallfailures")):
			return "disables Windows recovery / boot repair with bcdedit"
		}
		return ""
	}},
	{"defense.clear_event_logs", SevCritical, "T1070.001", 85, func(c *cmdInput) string {
		if reWevtClear.MatchString(c.lower) || strings.Contains(c.text(), "clear-eventlog") {
			return "clears Windows event logs"
		}
		return ""
	}},
	{"defense.disable_defender", SevSuspect, "T1562.001", 80, func(c *cmdInput) string {
		t := c.text()
		switch {
		case strings.Contains(t, "set-mppreference") && reMpDisable.MatchString(t):
			return "turns off Microsoft Defender protection with Set-MpPreference"
		case strings.Contains(t, "add-mppreference") && strings.Contains(t, "exclusion"):
			return "adds a Microsoft Defender exclusion"
		case c.tok("sc") && c.has("windefend") && any2(c, " stop", " config", " delete"):
			return "stops or reconfigures the Microsoft Defender service"
		case c.tok("reg") && c.has("windows defender") && any2(c, "disableantispyware", "disablerealtimemonitoring"):
			return "disables Microsoft Defender through the registry"
		}
		return ""
	}},
	{"defense.firewall_disabled", SevSuspect, "T1562.004", 75, func(c *cmdInput) string {
		t := c.text()
		switch {
		case c.tok("netsh") && c.has("advfirewall") && c.has("state") && c.has("off"):
			return "turns the Windows Firewall off (netsh advfirewall)"
		case c.tok("netsh") && c.has("firewall") && c.has("opmode") && c.has("disable"):
			return "turns the Windows Firewall off (netsh firewall)"
		case strings.Contains(t, "set-netfirewallprofile") && strings.Contains(t, "-enabled") && strings.Contains(t, "false"):
			return "turns the Windows Firewall off (Set-NetFirewallProfile)"
		}
		return ""
	}},
	{"persistence.account_created", SevSuspect, "T1136.001", 70, func(c *cmdInput) string {
		if reNetUser.MatchString(c.lower) || strings.Contains(c.text(), "new-localuser") {
			return "creates a local user account"
		}
		return ""
	}},
	{"persistence.admin_group_add", SevSuspect, "T1098", 75, func(c *cmdInput) string {
		t := c.text()
		if reNetGroup.MatchString(c.lower) ||
			(strings.Contains(t, "add-localgroupmember") && (strings.Contains(t, "administrators") || strings.Contains(t, "remote desktop users"))) {
			return "adds an account to a privileged local group"
		}
		return ""
	}},
	{"exec.wmic_process_create", SevSuspect, "T1047", 65, func(c *cmdInput) string {
		if c.tok("wmic") && c.has("process") && c.has("call") && c.has("create") {
			if c.has("/node:") {
				return "starts a process on a remote host through WMI (lateral movement)"
			}
			return "starts a process through WMI"
		}
		return ""
	}},
	{"exec.scheduled_task_create", SevNotable, "T1053.005", 35, func(c *cmdInput) string {
		if c.tok("schtasks") && c.has("/create") {
			return "creates a scheduled task"
		}
		return ""
	}},
	{"exec.service_create", SevNotable, "T1543.003", 40, func(c *cmdInput) string {
		if c.tok("sc") && any2(c, " create ", " config ") && c.has("binpath") {
			return "creates or reconfigures a service binary (sc create/config binPath=)"
		}
		return ""
	}},
	{"exec.powershell_hidden", SevNotable, "T1059.001", 40, func(c *cmdInput) string {
		if c.ps && rePSHidden.MatchString(c.lower) && (rePSNoProf.MatchString(c.lower) || rePSBypass.MatchString(c.lower)) {
			return "PowerShell started hidden, without a profile or execution policy (common in malicious launchers, also in some admin tooling)"
		}
		return ""
	}},
	{"exec.frombase64", SevNotable, "T1140", 45, func(c *cmdInput) string {
		if c.ps && !c.encoded && c.has("frombase64string") {
			return "PowerShell decodes base64 at runtime (FromBase64String)"
		}
		return ""
	}},
	{"exec.obfuscated_blob", SevNotable, "T1027", 40, func(c *cmdInput) string {
		if !c.encoded && scriptHosts[c.image] && reB64Blob.MatchString(c.lower) {
			return "script host command line carries a long base64-like blob"
		}
		return ""
	}},
}

// scriptHosts are interpreters whose command lines carry code.
var scriptHosts = map[string]bool{
	"powershell.exe": true, "pwsh.exe": true, "powershell_ise.exe": true,
	"cmd.exe": true, "mshta.exe": true, "wscript.exe": true, "cscript.exe": true,
}

// psSuperseded lists rules made redundant by a stronger one on the same line,
// so one encoded download cradle yields one critical finding, not four.
var psSuperseded = map[string][]string{
	"exec.download_execute":           {"exec.download_cradle", "exec.powershell_hidden", "exec.frombase64", "exec.obfuscated_blob"},
	"exec.powershell_reflective_load": {"exec.powershell_hidden", "exec.frombase64", "exec.obfuscated_blob"},
	"exec.powershell_encoded":         {"exec.powershell_hidden", "exec.obfuscated_blob"},
	"exec.download_cradle":            {"exec.powershell_hidden"},
}

// analyzeCommandLine runs every rule over one command line. image is the
// program it runs (a path or a name; may be empty), used to recognise
// PowerShell and script hosts launched directly. Findings come back with
// detail text naming the source ("process command line", "service", ...).
func analyzeCommandLine(source, image, cmd string) []Finding {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	c := prepareCommand(image, cmd)
	matched := map[string]string{}
	for _, r := range cmdRules {
		if d := r.match(c); d != "" {
			matched[r.id] = d
		}
	}
	for id := range matched {
		for _, weaker := range psSuperseded[id] {
			delete(matched, weaker)
		}
	}
	var out []Finding
	for _, r := range cmdRules {
		d, ok := matched[r.id]
		if !ok {
			continue
		}
		sev, conf := r.severity, r.confidence
		if r.id == "exec.powershell_encoded" && (cradle(c) || executes(c) || reReflLoad.MatchString(c.decoded)) {
			sev, conf = SevCritical, 90 // the payload itself is malicious-looking
		}
		out = append(out, Finding{
			Rule:       r.id,
			Severity:   sev,
			Technique:  r.technique,
			Confidence: conf,
			Detail:     source + " " + d + ": " + excerpt(cmd, 240),
		})
	}
	return out
}

// prepareCommand lower-cases a command line, recognises PowerShell and
// decodes an -EncodedCommand payload.
func prepareCommand(image, cmd string) *cmdInput {
	c := &cmdInput{lower: strings.ToLower(cmd), image: baseName(image)}
	if c.image == "" {
		c.image = baseName(imageFromCommand(cmd))
	}
	if c.image != "" && !strings.Contains(c.image, ".") {
		c.image += ".exe"
	}
	c.ps = c.image == "powershell.exe" || c.image == "pwsh.exe" || c.image == "powershell_ise.exe" ||
		strings.Contains(c.lower, "powershell") || strings.Contains(c.lower, "pwsh")
	if c.ps {
		if m := rePSEncoded.FindStringSubmatch(cmd); m != nil {
			c.encoded = true
			if text, ok := decodePSPayload(m[1]); ok {
				c.decoded = strings.ToLower(text)
				c.shown = excerpt(text, 160)
			}
		}
	}
	return c
}

// decodePSPayload decodes a PowerShell -EncodedCommand argument: base64 of
// UTF-16LE text. Payloads that aren't valid base64 or don't decode to mostly
// printable text are rejected (a long random token after -e is not a script).
func decodePSPayload(b64 string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(padBase64(b64))
	if err != nil || len(raw) < 4 {
		return "", false
	}
	var s string
	if len(raw)%2 == 0 && looksUTF16LE(raw) {
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
		}
		s = string(utf16.Decode(u))
	} else {
		s = string(raw)
	}
	printable := 0
	for _, r := range s {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	n := len([]rune(s))
	if n == 0 || printable*10 < n*9 {
		return "", false
	}
	return s, true
}

func padBase64(s string) string {
	s = strings.TrimRight(s, "=")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

// looksUTF16LE reports whether most odd bytes are zero, as in ASCII-range
// UTF-16LE text.
func looksUTF16LE(b []byte) bool {
	zeros := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	return zeros*10 >= (len(b)/2)*7
}

// excerpt returns a single-line, printable, length-capped version of s for
// finding details: control characters become spaces, runs of whitespace
// collapse (attackers pad command lines to push the payload out of view).
func excerpt(s string, max int) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				n++
			}
			space = true
			continue
		}
		space = false
		if n >= max {
			b.WriteString("…")
			return strings.TrimSpace(b.String())
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// mergeFindings appends findings whose rule isn't already present.
func mergeFindings(dst []Finding, add ...Finding) []Finding {
	for _, f := range add {
		dup := false
		for _, g := range dst {
			if g.Rule == f.Rule {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, f)
		}
	}
	return dst
}

// sevRank orders severities for sorting and roll-ups.
func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevSuspect:
		return 3
	case SevNotable:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}
