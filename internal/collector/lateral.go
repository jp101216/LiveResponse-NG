package collector

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// lateral (Windows) looks for what remote-execution and C2 tooling leaves
// on a host:
//
//   - Named pipes. SMB beacons, post-exploitation jobs and remote-execution
//     tools talk over pipes, and most keep a default name: Cobalt Strike's
//     msagent_##, postex_####, MSSE-####-server; PsExec's PSEXESVC; RemCom's
//     (Impacket psexec); the pipes potato exploits plant to catch a SYSTEM
//     service's connection. Every pipe on the host is listed (\\.\pipe\);
//     the same names are judged in Sysmon pipe events (17 and 18), which
//     also say which program made the pipe.
//   - Output files. Impacket's wmiexec and dcomexec write each command's
//     output to \\127.0.0.1\ADMIN$\__<time>, smbexec to C$\__output_<8
//     letters>, and delete it once read. A session that died leaves the file
//     behind, and with it the output of the attacker's last command.
//
// Names are matched exactly as the tools build them (their source, and
// Sigma's pipe rules); a bare system pipe name (spoolss, ntsvcs, wkssvc)
// never matches, only the suffixed forms C2 profiles use.
//
// No build tag: the rules are pure string handling, unit-tested on any OS;
// lateral_windows.go lists the pipes and files.

type lateralCollector struct{}

func (*lateralCollector) Name() string        { return "lateral" }
func (*lateralCollector) Platforms() []string { return []string{"windows"} }

func (*lateralCollector) Timeout() time.Duration { return time.Minute }

func (*lateralCollector) Collect(ctx context.Context) (Result, error) {
	return collectLateral(ctx)
}

func init() { Register(&lateralCollector{}) }

// pipeRule is one known pipe name and who uses it.
type pipeRule struct {
	re         *regexp.Regexp
	rule       string
	severity   Severity
	technique  string
	confidence int
	who        string
}

func pipe(re, rule string, sev Severity, technique string, conf int, who string) pipeRule {
	return pipeRule{regexp.MustCompile(`(?i)` + re), rule, sev, technique, conf, who}
}

// pipeRules are checked in order; the first match names a pipe.
var pipeRules = []pipeRule{
	// Cobalt Strike's own defaults.
	pipe(`^msse-\d+-server$`, "network.c2_named_pipe", SevCritical, "T1071", 85, "Cobalt Strike's default stager pipe (MSSE-<n>-server)"),
	pipe(`^msagent_[0-9a-f]{2,4}$`, "network.c2_named_pipe", SevCritical, "T1071", 85, "Cobalt Strike's default SMB beacon pipe (msagent_##)"),
	pipe(`^postex_(?:ssh_)?[0-9a-f]{4}$`, "network.c2_named_pipe", SevCritical, "T1071", 85, "Cobalt Strike's default post-exploitation job pipe (postex_####)"),
	pipe(`^status_[0-9a-f]{2}$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "Cobalt Strike's default status pipe (status_##)"),
	pipe(`^mojo\.5688\.8052\.(?:183894939787088877|35780273329370473)[0-9a-f]{2}$`, "network.c2_named_pipe", SevCritical, "T1071", 85,
		"Cobalt Strike's default pipe since 4.2, named to pass for one of Chrome's"),
	// Names published Cobalt Strike malleable C2 profiles set.
	pipe(`^(?:interprocess|samr|netlogon|srvsvc|lsarpc|wkssvc)_[0-9a-f]{2,}$`, "network.c2_named_pipe", SevSuspect, "T1071", 70,
		"a pipe name published Cobalt Strike malleable C2 profiles set"),
	pipe(`^(?:dsernamepipe|searchtextharvester|pgmessagepipe|msftewds|f4c3|f53f|ntsvcs_?|scerpc_?|spoolss_|rpc_|fullduplex_|mypipe-[fh])[0-9a-f]{2}$`,
		"network.c2_named_pipe", SevSuspect, "T1071", 65, "a pipe name published Cobalt Strike malleable C2 profiles set"),
	pipe(`^(?:win\\)?msrpc_[0-9a-f]{2,4}$|^windows\.update\.manager[0-9a-f]{2,3}$|^demoagent_(?:11|22)$`,
		"network.c2_named_pipe", SevSuspect, "T1071", 65, "a pipe name published Cobalt Strike malleable C2 profiles set"),
	// Other frameworks' defaults.
	pipe(`^gruntsvc$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "Covenant's default pipe"),
	pipe(`^jaccdpqnvbrrxlaf$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "PoshC2's default pipe"),
	// Malware families' pipes (Sigma's list of known malicious pipe names).
	pipe(`^583da945-62af-10e8-4902-a8f205c72b2e$`, "network.c2_named_pipe", SevCritical, "T1071", 90, "SUNBURST's pipe (the SolarWinds backdoor)"),
	pipe(`^(?:46a676ab7f179e511e30dd2dc41bd388|9f81f59bc58452127884ce513865ed20|e710f28d59aa529d6792ca6ff0ca1b34|rpchlp_3)$`,
		"network.c2_named_pipe", SevCritical, "T1071", 85, "ProjectSauron's pipes"),
	pipe(`^(?:isapi_dg2?|isapi_http|sdlrpc|adschemerpc)$`, "network.c2_named_pipe", SevCritical, "T1071", 85, "Turla's pipes (Uroburos, Cobra, HyperStack)"),
	pipe(`^(?:lsassw|winsession)$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "Wild Neutron's pipes"),
	pipe(`^namepipe_morewindows$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "RedLeaves' pipe (APT10)"),
	pipe(`^6e7645c4-32c5-4fe3-aabf-e94c2f4370e7$`, "network.c2_named_pipe", SevCritical, "T1071", 80, "LiquidSnake's pipe"),
	pipe(`^(?:ahexec|bizkaz|dce_3d|pcheap_reuse|bc31a7|bc367|anonymouspipe)$`, "network.c2_named_pipe", SevCritical, "T1071", 75,
		"a pipe a known malware family uses (Sofacy, Snatch, Qbot, Equation, Pacifier, Hoplight)"),
	// Credential theft.
	pipe(`(?:^|\\)(?:cachedump|lsadump|wceservicepipe)`, "cred.dump_tool_pipe", SevCritical, "T1003", 80,
		"a credential-dumping tool's pipe (cachedump, lsadump, Windows Credentials Editor)"),
	pipe(`(?:^|\\)(?:imposecost|imposingcost)$`, "cred.dump_tool_pipe", SevCritical, "T1134.001", 80,
		"Koh's default pipe: it captures the tokens of users who log on, to impersonate them"),
	// Potato privilege escalation: a pipe whose name ends in a path to
	// another pipe catches a SYSTEM service that was coerced into opening it.
	pipe(`^[^\\].*\\pipe\\`, "privesc.potato_pipe", SevCritical, "T1134.001", 75,
		"a pipe named after a path to another pipe (<name>\\pipe\\spoolss): PrintSpoofer, EfsPotato and their kin coerce a SYSTEM service into opening it, then impersonate the service"),
	pipe(`(?:^|\\)coerced\\`, "privesc.potato_pipe", SevCritical, "T1134.001", 75, "CoercedPotato's pipe"),
	// Remote execution tools, which administrators use as well.
	pipe(`^remcom_`, "lateral.remote_exec_pipe", SevSuspect, "T1569.002", 70, "RemCom's pipe, which Impacket's psexec uses: a program run on this host from another"),
	pipe(`^psexesvc(?:-.*)?$`, "lateral.remote_exec_pipe", SevNotable, "T1569.002", 45, "PsExec's service pipe: a program run on this host from another"),
	pipe(`^paexec`, "lateral.remote_exec_pipe", SevNotable, "T1569.002", 45, "PAExec's pipe: a program run on this host from another"),
	pipe(`^csexecsvc`, "lateral.remote_exec_pipe", SevNotable, "T1569.002", 45, "CSExec's pipe: a program run on this host from another"),
}

// judgePipe names a pipe a known tool uses. name is as listed under
// \\.\pipe\ (a leading backslash, as Sysmon gives it, is ignored).
func judgePipe(name string) (pipeRule, bool) {
	name = strings.TrimPrefix(strings.TrimSpace(name), `\`)
	if name == "" || strings.Contains(strings.ToLower(name), "ctxshare") {
		return pipeRule{}, false
	}
	for _, r := range pipeRules {
		if r.re.MatchString(name) {
			return r, true
		}
	}
	return pipeRule{}, false
}

func pipeFinding(r pipeRule, what string) Finding {
	return Finding{Rule: r.rule, Severity: r.severity, Technique: r.technique, Confidence: r.confidence, Detail: what + ": " + r.who}
}

// pipeEventFindings judges the pipe in a Sysmon pipe event (17 created, 18
// connected), naming the program.
func pipeEventFindings(ev winEvent) []Finding {
	name := strings.TrimPrefix(evData(ev, "PipeName"), `\`)
	r, ok := judgePipe(name)
	if !ok {
		return nil
	}
	verb := "created"
	if ev.EventID == 18 {
		verb = "connected to"
	}
	when := ""
	if !ev.TimeCreated.IsZero() {
		when = " at " + ev.TimeCreated.UTC().Format(time.RFC3339)
	}
	return []Finding{pipeFinding(r, fmt.Sprintf("%s %s the pipe \\\\.\\pipe\\%s%s (Sysmon event %d)",
		firstNonEmpty(evData(ev, "Image"), "a process"), verb, name, when, ev.EventID))}
}

// Impacket's output files: wmiexec's "__" + time.time(), dcomexec's
// "__" + its first five digits (both in ADMIN$, the Windows folder), and
// smbexec's "__output_" + 8 letters ("__output" before 0.10, in C$, the
// system drive's root).
var (
	reWmiexecOutput = regexp.MustCompile(`^__\d{9,10}\.\d+$|^__\d{5}$`)
	reSmbexecOutput = regexp.MustCompile(`^__output(?:_[A-Za-z]{8})?$`)
)

// leftoverFinding judges a file in the Windows folder or the system drive's
// root by its name.
func leftoverFinding(path, name string) (Finding, bool) {
	switch {
	case reWmiexecOutput.MatchString(name):
		return Finding{Rule: "lateral.impacket_output_file", Severity: SevSuspect, Technique: "T1047", Confidence: 75,
			Detail: path + " is named the way Impacket's wmiexec and dcomexec name a command's output (__<time>), which they read over SMB " +
				"and then delete: one left behind is from a session that ended before it could"}, true
	case reSmbexecOutput.MatchString(name):
		return Finding{Rule: "lateral.impacket_output_file", Severity: SevSuspect, Technique: "T1569.002", Confidence: 75,
			Detail: path + " is named the way Impacket's smbexec names a command's output (__output_<8 letters>), which it reads over SMB " +
				"and then deletes: one left behind is from a session that ended before it could"}, true
	}
	return Finding{}, false
}

// printable keeps the printable text of a command's output, for the record.
func printable(b []byte, max int) string {
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() >= max {
			sb.WriteString("…")
			break
		}
		switch {
		case c == '\n' || c == '\t':
			sb.WriteByte(c)
		case c == '\r':
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	return strings.TrimSpace(sb.String())
}

// lateralReport turns the host's pipes and leftover files into records:
// one summary (every pipe's name), one per pipe a known tool uses, one per
// leftover file.
func lateralReport(res *Result, pipes []string, files []leftoverFile) {
	flagged := 0
	for _, name := range pipes {
		if r, ok := judgePipe(name); ok {
			flagged++
			res.Add(map[string]any{"kind": "pipe", "name": name},
				pipeFinding(r, fmt.Sprintf("the named pipe \\\\.\\pipe\\%s is open on this host", name)))
		}
	}
	listed := pipes
	if len(listed) > maxPipesListed {
		listed = listed[:maxPipesListed]
	}
	res.Add(map[string]any{"kind": "summary", "pipes": len(pipes), "pipes_flagged": flagged, "pipe_names": listed,
		"pipe_names_truncated": len(pipes) > maxPipesListed, "leftover_files": len(files)})
	for _, f := range files {
		finding, ok := leftoverFinding(f.Path, f.Name)
		if !ok {
			continue
		}
		res.Add(map[string]any{"kind": "file", "path": f.Path, "size": f.Size, "modified": f.Modified.UTC().Format(time.RFC3339),
			"content": f.Content}, finding)
	}
}

// maxPipesListed caps the pipe names kept in the summary record.
const maxPipesListed = 2000

// leftoverFile is a file whose name matched one of Impacket's output files.
type leftoverFile struct {
	Path, Name string
	Size       int64
	Modified   time.Time
	Content    string // the start of it, printable
}
