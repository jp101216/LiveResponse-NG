package collector

import (
	"strings"
	"testing"
	"time"
)

func TestJudgePipe(t *testing.T) {
	hits := map[string]string{
		"MSSE-1234-server":                     "network.c2_named_pipe",
		"msagent_1a":                           "network.c2_named_pipe",
		`\postex_ab12`:                         "network.c2_named_pipe", // as Sysmon gives it
		"postex_ssh_0f3c":                      "network.c2_named_pipe",
		"status_4f":                            "network.c2_named_pipe",
		"mojo.5688.8052.18389493978708887731":  "network.c2_named_pipe",
		"mojo.5688.8052.3578027332937047391":   "network.c2_named_pipe",
		"ntsvcs_3f":                            "network.c2_named_pipe",
		"spoolss_ab":                           "network.c2_named_pipe",
		"win\\msrpc_9e":                        "network.c2_named_pipe",
		"wkssvc_1c0":                           "network.c2_named_pipe",
		"gruntsvc":                             "network.c2_named_pipe",
		"583da945-62af-10e8-4902-a8f205c72b2e": "network.c2_named_pipe",
		"lsadump":                              "cred.dump_tool_pipe",
		"imposecost":                           "cred.dump_tool_pipe",
		`x5Ka9\pipe\spoolss`:                   "privesc.potato_pipe",
		`coerced\pipe\srvsvc`:                  "privesc.potato_pipe",
		"RemCom_communicaton":                  "lateral.remote_exec_pipe",
		"PSEXESVC":                             "lateral.remote_exec_pipe",
		"PSEXESVC-WS01-4242-stdin":             "lateral.remote_exec_pipe",
		"PAExec-1234-WS01":                     "lateral.remote_exec_pipe",
	}
	for name, rule := range hits {
		r, ok := judgePipe(name)
		if !ok || r.rule != rule || r.who == "" || r.technique == "" {
			t.Errorf("%s: got %+v, want %s", name, r, rule)
		}
	}
	// Windows' own pipes and other programs' look-alikes.
	for _, name := range []string{
		"spoolss", "ntsvcs", "wkssvc", "srvsvc", "scerpc", "lsass", "epmapper", "atsvc", "eventlog", "InitShutdown",
		"MsFteWds", "SearchTextHarvester", "PGMessagePipe", "DserNamePipe", "status", "postex", "msagent",
		`Winsock2\CatalogChangeListener-3a8-0`, "mojo.5688.8052.1234567890123456789", "chrome.sync.1234.5678.1",
		`LOCAL\mojo.4242.4343.2103`, "PSHost.133746287654.4242.DefaultAppDomain.powershell", `pipe\LOCAL\Monitorian`,
		`CtxShare\pipe\x`, "", "   ",
	} {
		if r, ok := judgePipe(name); ok {
			t.Errorf("%q flagged as %s (%s)", name, r.rule, r.who)
		}
	}
}

func TestLeftoverFinding(t *testing.T) {
	for name, technique := range map[string]string{
		"__1698765432.1234567": "T1047", "__1698765432.12": "T1047", "__16987": "T1047",
		"__output": "T1569.002", "__output_AbCdEfGh": "T1569.002",
	} {
		f, ok := leftoverFinding(`C:\Windows\`+name, name)
		if !ok || f.Rule != "lateral.impacket_output_file" || f.Technique != technique || !strings.Contains(f.Detail, name) {
			t.Errorf("%s: %+v", name, f)
		}
	}
	for _, name := range []string{"__init__.py", "__16987a", "__output_abc", "__output.txt", "__PSScriptPolicyTest_x.ps1", "_16987", "__123"} {
		if f, ok := leftoverFinding(`C:\`+name, name); ok {
			t.Errorf("%s flagged: %+v", name, f)
		}
	}
	if got := printable([]byte("nt authority\\system\r\n\x00\x01ok"), 512); got != "nt authority\\system\n..ok" {
		t.Errorf("printable: %q", got)
	}
	if got := printable([]byte(strings.Repeat("a", 20)), 8); got != "aaaaaaaa…" {
		t.Errorf("printable cap: %q", got)
	}
}

func TestLateralReport(t *testing.T) {
	res := NewResult("lateral")
	mod := time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC)
	lateralReport(res, []string{"spoolss", "msagent_7c", "PSEXESVC", "lsass"},
		[]leftoverFile{{Path: `C:\Windows\__1698765432.123`, Name: "__1698765432.123", Size: 19, Modified: mod, Content: "nt authority\\system"}})
	got := res.Finish()
	if len(got.Records) != 4 {
		t.Fatalf("want 2 pipes, a summary and a file: %+v", got.Records)
	}
	sum := got.Records[2].Fields
	if sum["kind"] != "summary" || sum["pipes"] != 4 || sum["pipes_flagged"] != 2 || len(sum["pipe_names"].([]string)) != 4 {
		t.Errorf("summary: %+v", sum)
	}
	if f := got.Records[0].Findings[0]; f.Rule != "network.c2_named_pipe" || f.Severity != SevCritical ||
		!strings.Contains(f.Detail, `\\.\pipe\msagent_7c is open`) {
		t.Errorf("beacon pipe: %+v", f)
	}
	file := got.Records[3]
	if file.Fields["content"] != "nt authority\\system" || file.Fields["modified"] != "2026-10-30T01:02:03Z" ||
		file.Findings[0].Rule != "lateral.impacket_output_file" {
		t.Errorf("leftover file: %+v", file)
	}
}

func TestLateralEvents(t *testing.T) {
	when := time.Date(2026, 10, 31, 4, 5, 6, 0, time.UTC)
	// atexec's task, as the Security log keeps it (4698), though the task
	// itself was deleted seconds later.
	taskXML := `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
		`<Actions Context="LocalSystem"><Exec><Command>cmd.exe</Command><Arguments>/C whoami &gt; %windir%\Temp\AbCdEfGh.tmp 2&gt;&amp;1</Arguments></Exec></Actions></Task>`
	task := winEvent{EventID: 4698, Channel: "Security", TimeCreated: when, UserData: map[string]string{},
		Data: map[string]string{"TaskName": `\AbCdEfGh`, "TaskContent": taskXML}}
	fs := eventFindings(task)
	if len(fs) != 1 || fs[0].Rule != "lateral.atexec" || !strings.HasPrefix(fs[0].Detail, `scheduled task \AbCdEfGh (event 4698) `) {
		t.Errorf("atexec task event: %+v", fs)
	}
	task.Data["TaskContent"] = strings.Replace(taskXML, `/C whoami &gt; %windir%\Temp\AbCdEfGh.tmp 2&gt;&amp;1`, `/c C:\Tools\backup.cmd`, 1)
	if fs := eventFindings(task); len(fs) != 0 {
		t.Errorf("an ordinary task: %+v", fs)
	}

	logon := func(typ, proc string) winEvent {
		return winEvent{EventID: 4624, Channel: "Security", TimeCreated: when, UserData: map[string]string{},
			Data: map[string]string{"LogonType": typ, "LogonProcessName": proc, "TargetUserName": "alice", "TargetDomainName": "CORP",
				"TargetOutboundUserName": "Administrator", "TargetOutboundDomainName": "CORP", "ProcessName": `C:\Windows\System32\svchost.exe`}}
	}
	fs = eventFindings(logon("9", "seclogo     "))
	if len(fs) != 1 || fs[0].Rule != "cred.pass_the_hash" || fs[0].Technique != "T1550.002" ||
		!strings.Contains(fs[0].Detail, `by CORP\alice with the network credentials of CORP\Administrator`) {
		t.Errorf("type 9 via seclogo: %+v", fs)
	}
	for _, ev := range []winEvent{logon("9", "Advapi"), logon("2", "User32")} {
		if fs := eventFindings(ev); len(fs) != 0 {
			t.Errorf("logon type %s via %s: %+v", ev.Data["LogonType"], ev.Data["LogonProcessName"], fs)
		}
	}

	pipeEv := func(id int, name string) winEvent {
		return winEvent{EventID: id, Provider: "Microsoft-Windows-Sysmon", Channel: "Microsoft-Windows-Sysmon/Operational",
			TimeCreated: when, UserData: map[string]string{}, Data: map[string]string{"PipeName": name, "Image": `C:\Windows\System32\rundll32.exe`}}
	}
	fs = eventFindings(pipeEv(17, `\postex_3f2a`))
	if len(fs) != 1 || fs[0].Rule != "network.c2_named_pipe" ||
		!strings.Contains(fs[0].Detail, `rundll32.exe created the pipe \\.\pipe\postex_3f2a at 2026-10-31T04:05:06Z (Sysmon event 17)`) {
		t.Errorf("Sysmon pipe created: %+v", fs)
	}
	if fs := eventFindings(pipeEv(18, `\RemCom_communicaton`)); len(fs) != 1 || !strings.Contains(fs[0].Detail, "connected to") {
		t.Errorf("Sysmon pipe connected: %+v", fs)
	}
	if fs := eventFindings(pipeEv(17, `\spoolss`)); len(fs) != 0 {
		t.Errorf("an ordinary pipe: %+v", fs)
	}
	other := pipeEv(17, `\msagent_12`)
	other.Provider, other.Channel = "Microsoft-Windows-Kernel-General", "System"
	if fs := eventFindings(other); len(fs) != 0 {
		t.Errorf("event 17 from another provider: %+v", fs)
	}
}
