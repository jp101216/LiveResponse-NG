package collector

import (
	"strings"
	"testing"
	"time"
)

// A 7045 service-install event record, as the eventlog collector would emit it.
func svcInstallRecord(name, imagePath string, existing ...Finding) Record {
	return Record{
		Fields: map[string]any{
			"event_id":   7045,
			"channel":    "System",
			"event_data": map[string]string{"ServiceName": name, "ImagePath": imagePath},
		},
		Findings: existing,
	}
}

func TestCorrelateServiceInstalledAbsent(t *testing.T) {
	el := Result{Collector: "eventlog", Records: []Record{
		svcInstallRecord("Updater", `C:\Users\Public\x.exe`,
			Finding{Rule: "eventlog.service_installed", Severity: SevSuspect, Technique: "T1543.003", Confidence: 70, Detail: "..."}),
	}}
	svc := Result{Collector: "services", Records: []Record{
		{Fields: map[string]any{"name": "W32Time"}},
		{Fields: map[string]any{"name": "Spooler"}},
	}}
	results := []Result{el, svc}

	Correlate(results)

	rec := results[0].Records[0]
	if rec.Fields["service_still_present"] != false {
		t.Errorf("service_still_present = %v, want false", rec.Fields["service_still_present"])
	}
	f := hasFinding(rec.Findings, "correlate.service_installed_absent")
	if f == nil {
		t.Fatalf("want correlate.service_installed_absent, got %+v", rec.Findings)
	}
	if f.Severity != SevSuspect || f.Technique != "T1070.009" {
		t.Errorf("finding = %+v, want suspect T1070.009", *f)
	}
	if !strings.Contains(f.Detail, "Updater") {
		t.Errorf("detail should name the service: %q", f.Detail)
	}
}

func TestCorrelateServiceInstalledPresent(t *testing.T) {
	el := Result{Collector: "eventlog", Records: []Record{
		svcInstallRecord("Updater", `C:\Program Files\App\upd.exe`),
	}}
	svc := Result{Collector: "services", Records: []Record{
		{Fields: map[string]any{"name": "Updater"}},
	}}
	results := []Result{el, svc}

	Correlate(results)

	rec := results[0].Records[0]
	if rec.Fields["service_still_present"] != true {
		t.Errorf("service_still_present = %v, want true", rec.Fields["service_still_present"])
	}
	if hasFinding(rec.Findings, "correlate.service_installed_absent") != nil {
		t.Errorf("a present service should raise no absent finding: %+v", rec.Findings)
	}
}

func TestCorrelateServiceNoLiveSide(t *testing.T) {
	// Only the event log was collected (e.g. -collectors eventlog, or offline):
	// with no services result there is nothing to compare against, so no finding
	// and no annotation — absence of data must not read as an absent service.
	el := Result{Collector: "eventlog", Records: []Record{
		svcInstallRecord("Updater", `C:\Users\Public\x.exe`),
	}}
	results := []Result{el}

	Correlate(results)

	rec := results[0].Records[0]
	if _, set := rec.Fields["service_still_present"]; set {
		t.Errorf("service_still_present must not be set without a services result: %v", rec.Fields["service_still_present"])
	}
	if hasFinding(rec.Findings, "correlate.service_installed_absent") != nil {
		t.Error("no absent finding should be raised without a services result")
	}
}

func taskRegisterRecord(eventID int, taskName string) Record {
	return Record{Fields: map[string]any{
		"event_id":   eventID,
		"channel":    "Security",
		"event_data": map[string]string{"TaskName": taskName},
	}}
}

func TestCorrelateTaskRegisteredAbsent(t *testing.T) {
	el := Result{Collector: "eventlog", Records: []Record{
		taskRegisterRecord(4698, `\EvilUpdater`),                                // registered per log, gone now
		taskRegisterRecord(106, `\Microsoft\Windows\UpdateOrchestrator\Reboot`), // still present
	}}
	st := Result{Collector: "scheduledtasks", Records: []Record{
		{Fields: map[string]any{"task_path": `\Microsoft\Windows\UpdateOrchestrator\Reboot`}},
		{Fields: map[string]any{"task_path": `\GoogleUpdateTaskMachineCore`}},
	}}
	results := []Result{el, st}

	Correlate(results)

	gone := results[0].Records[0]
	if gone.Fields["task_still_present"] != false {
		t.Errorf("task_still_present = %v, want false", gone.Fields["task_still_present"])
	}
	f := hasFinding(gone.Findings, "correlate.task_registered_absent")
	if f == nil || f.Severity != SevNotable || f.Technique != "T1070.009" {
		t.Fatalf("want notable task_registered_absent (T1070.009), got %+v", gone.Findings)
	}
	if !strings.Contains(f.Detail, "EvilUpdater") {
		t.Errorf("detail should name the task: %q", f.Detail)
	}

	present := results[0].Records[1]
	if present.Fields["task_still_present"] != true {
		t.Errorf("a still-present task should be annotated true, got %v", present.Fields["task_still_present"])
	}
	if hasFinding(present.Findings, "correlate.task_registered_absent") != nil {
		t.Error("a present task must not raise the absent finding")
	}
}

func TestCorrelateTaskNoLiveSide(t *testing.T) {
	// Only the event log (offline / -collectors eventlog): no scheduledtasks
	// result, so nothing is asserted about the registered task.
	el := Result{Collector: "eventlog", Records: []Record{taskRegisterRecord(4698, `\EvilUpdater`)}}
	results := []Result{el}

	Correlate(results)

	rec := results[0].Records[0]
	if _, set := rec.Fields["task_still_present"]; set {
		t.Error("task_still_present must not be set without a scheduledtasks result")
	}
	if hasFinding(rec.Findings, "correlate.task_registered_absent") != nil {
		t.Error("no absent finding without the live Task Scheduler store")
	}
}

func TestCorrelateLogClearRange(t *testing.T) {
	earliest := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 10, 21, 18, 0, 0, 0, time.UTC)
	el := Result{
		Collector: "eventlog",
		Meta: map[string]any{
			"channel_ranges": map[string]*channelRange{
				"Security": {MinRecordID: 500, MaxRecordID: 20500, Scanned: 20001, Earliest: earliest, Latest: latest},
			},
		},
		Records: []Record{{
			Fields: map[string]any{"event_id": 1102, "channel": "Security"},
			Findings: []Finding{{
				Rule: "defense.clear_event_logs", Severity: SevCritical, Technique: "T1070.001",
				Confidence: 85, Detail: "the Security audit log was cleared by evil",
			}},
		}},
	}
	results := []Result{el}

	Correlate(results)

	rec := results[0].Records[0]
	if rec.Fields["surviving_record_min"] != uint64(500) || rec.Fields["surviving_record_max"] != uint64(20500) {
		t.Errorf("surviving range = %v–%v, want 500–20500", rec.Fields["surviving_record_min"], rec.Fields["surviving_record_max"])
	}
	if rec.Fields["surviving_records"] != 20001 {
		t.Errorf("surviving_records = %v, want 20001", rec.Fields["surviving_records"])
	}
	f := hasFinding(rec.Findings, "defense.clear_event_logs")
	if f == nil {
		t.Fatal("clear finding vanished")
	}
	if !strings.Contains(f.Detail, "ids 500–20500") {
		t.Errorf("clear finding detail not enriched with the surviving range: %q", f.Detail)
	}
}

// TestCorrelatePartialInventoryIsNotAbsence: a services walk that ran out of
// time lists only some services; one it never reached must not be reported as
// "installed, then removed".
func TestCorrelatePartialInventoryIsNotAbsence(t *testing.T) {
	el := Result{Collector: "eventlog", Records: []Record{
		svcInstallRecord("Updater", `C:\Users\Public\x.exe`),
		svcInstallRecord("Spooler", `C:\Windows\System32\spoolsv.exe`),
	}}
	svc := Result{Collector: "services",
		Records: []Record{{Fields: map[string]any{"name": "Spooler"}}},
		Errors:  []string{"cancelled: context deadline exceeded"},
	}
	tasks := Result{Collector: "scheduledtasks",
		Records: []Record{{Fields: map[string]any{"task_path": `\Other`}}},
		Errors:  []string{"cancelled: context deadline exceeded"},
	}
	el.Records = append(el.Records, Record{Fields: map[string]any{
		"event_id": 4698, "channel": "Security", "event_data": map[string]string{"TaskName": `\Updater`},
	}})
	results := []Result{el, svc, tasks}
	Correlate(results)

	for _, rec := range results[0].Records {
		for _, f := range rec.Findings {
			if strings.HasPrefix(f.Rule, "correlate.") {
				t.Errorf("a partial inventory produced %s: %s", f.Rule, f.Detail)
			}
		}
	}
	if results[0].Records[1].Fields["service_still_present"] != true {
		t.Error("a service the partial walk did list is still annotated present")
	}
	m, _ := results[0].Meta["service_install_correlation"].(map[string]any)
	if m["unverified"] != 1 || m["absent"] != 0 {
		t.Errorf("service correlation meta = %v, want 1 unverified, 0 absent", m)
	}
	if tm, _ := results[0].Meta["task_register_correlation"].(map[string]any); tm["unverified"] != 1 {
		t.Errorf("task correlation meta = %v, want 1 unverified", tm)
	}
}

func TestCorrelateTaskComHandlerHijack(t *testing.T) {
	com := NewResult("comhijack")
	// A flagged per-user COM hijack (critical).
	com.Add(map[string]any{"clsid": "{11111111-0000-0000-0000-000000000001}"},
		Finding{Rule: "persistence.com_hijack_user_shadow", Severity: SevCritical, Technique: "T1546.015", Confidence: 85, Detail: "a per-user COM registration overrides the machine one"})
	// A TypeLib record (no "clsid" field) must be ignored by the cross-check.
	com.Add(map[string]any{"artifact": "typelib", "libid": "{22222222-0000-0000-0000-000000000002}"},
		Finding{Rule: "persistence.typelib_script_moniker", Severity: SevSuspect})
	comRes := com.Finish()

	st := NewResult("scheduledtasks")
	// A task whose ComHandler fires the hijacked CLSID (brace/case differ).
	st.Add(map[string]any{"task_path": `\Evil`, "com_handlers": []string{"{11111111-0000-0000-0000-000000000001}"}})
	// A task with an unrelated ComHandler.
	st.Add(map[string]any{"task_path": `\Good`, "com_handlers": []string{"{99999999-0000-0000-0000-000000000009}"}})
	stRes := st.Finish()

	results := []Result{comRes, stRes}
	Correlate(results)

	got := rulesOf(results[1].Records[0].Findings)
	f, ok := got["correlate.task_comhandler_hijacked"]
	if !ok {
		t.Fatalf("correlate.task_comhandler_hijacked missing on the evil task (got %v)", keys(got))
	}
	if f.Severity != SevCritical {
		t.Errorf("a task firing a critical COM hijack should be critical, got %s", f.Severity)
	}
	if len(results[1].Records[1].Findings) != 0 {
		t.Errorf("the unrelated task should carry no correlation finding, got %v", keys(rulesOf(results[1].Records[1].Findings)))
	}
	if results[0].Meta["task_comhandler_matches"] != 1 {
		t.Errorf("expected 1 recorded match in comhijack meta, got %v", results[0].Meta["task_comhandler_matches"])
	}
}
