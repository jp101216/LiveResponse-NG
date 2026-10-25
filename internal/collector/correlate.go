package collector

import (
	"fmt"
	"strings"
	"time"
)

// correlate.go — cross-reference the event log against the live host state
// gathered in the same run. Each collector sees only its own slice of the host;
// correlation is where the slices line up into one story: a service logged as
// installed that is no longer present (installed, run, then removed), and a
// cleared Security log measured against the records that survived it.
//
// No build tag: it works on the structured results, so it is portable and
// unit-tested on any OS. It is a no-op for any cross-check whose inputs weren't
// collected — a run without the services collector, or offline mode with only
// the event log — so it never invents an "absent" finding from data that was
// simply never gathered.

// Correlate enriches results in place with cross-collector findings and
// annotations. Safe to call on any result set; callers run it after collection
// and before summarising, so the findings it adds roll up like any other.
func Correlate(results []Result) {
	el := findResult(results, "eventlog")
	if el == nil {
		return
	}
	correlateServiceInstalls(results, el)
	correlateScheduledTasks(results, el)
	correlateLogClears(el)
}

// findResult returns a pointer to the named collector's result (so edits
// persist), or nil.
func findResult(results []Result, name string) *Result {
	for i := range results {
		if results[i].Collector == name {
			return &results[i]
		}
	}
	return nil
}

// correlateServiceInstalls checks every 7045 "service installed" event against
// the services present now. One still present is annotated (no finding); one
// that is gone is raised as correlate.service_installed_absent — the clean-up
// half of install-run-delete, and stronger when the install already looked bad.
func correlateServiceInstalls(results []Result, el *Result) {
	svc := findResult(results, "services")
	if svc == nil || len(svc.Records) == 0 {
		return // the live side wasn't collected: assert nothing
	}
	live := make(map[string]bool, len(svc.Records))
	for _, r := range svc.Records {
		if n := stringField(r.Fields, "name"); n != "" {
			live[strings.ToLower(n)] = true
		}
	}

	partial := inventoryPartial(svc)
	present, absent, unverified := 0, 0, 0
	for i := range el.Records {
		rec := &el.Records[i]
		if intField(rec.Fields, "event_id") != 7045 {
			continue
		}
		name := eventDataField(rec, "ServiceName")
		if name == "" {
			continue
		}
		if live[strings.ToLower(name)] {
			rec.Fields["service_still_present"] = true
			present++
			continue
		}
		if partial {
			unverified++ // the services walk stopped early: it may just not have got there
			continue
		}
		rec.Fields["service_still_present"] = false
		absent++
		sev, conf := SevNotable, 45
		if recordHasSeverity(rec, SevSuspect) || imagePathRisky(rec) {
			sev, conf = SevSuspect, 70
		}
		rec.Findings = append(rec.Findings, Finding{
			Rule:       "correlate.service_installed_absent",
			Severity:   sev,
			Technique:  "T1070.009",
			Confidence: conf,
			Detail: fmt.Sprintf("service %q was installed (event 7045) but is not among the %d services present now — installed and then removed",
				name, len(svc.Records)),
		})
	}
	if present+absent+unverified > 0 {
		m := map[string]any{"still_present": present, "absent": absent}
		if unverified > 0 {
			m["unverified"] = unverified
			m["note"] = "the services collector was cancelled before it finished, so installs it didn't list weren't judged absent"
		}
		el.SetMeta("service_install_correlation", m)
	}
}

// correlateScheduledTasks checks every "scheduled task registered" event (4698
// Security, 106 TaskScheduler/Operational) against the tasks present in the live
// Task Scheduler store. One still present is annotated; one that is gone is
// raised as correlate.task_registered_absent — registered, then deleted or
// hidden (the Tarrask-style technique the scheduledtasks collector flags from
// the other direction).
func correlateScheduledTasks(results []Result, el *Result) {
	st := findResult(results, "scheduledtasks")
	if st == nil || len(st.Records) == 0 {
		return // the live side wasn't collected: assert nothing
	}
	live := make(map[string]bool, len(st.Records))
	for _, r := range st.Records {
		if p := stringField(r.Fields, "task_path"); p != "" {
			live[normTaskName(p)] = true
		}
	}

	partial := inventoryPartial(st)
	present, absent, unverified := 0, 0, 0
	for i := range el.Records {
		rec := &el.Records[i]
		if id := intField(rec.Fields, "event_id"); id != 4698 && id != 106 {
			continue
		}
		name := eventDataField(rec, "TaskName")
		if name == "" {
			continue
		}
		if live[normTaskName(name)] {
			rec.Fields["task_still_present"] = true
			present++
			continue
		}
		if partial {
			unverified++
			continue
		}
		rec.Fields["task_still_present"] = false
		absent++
		rec.Findings = append(rec.Findings, Finding{
			Rule:       "correlate.task_registered_absent",
			Severity:   SevNotable,
			Technique:  "T1070.009",
			Confidence: 50,
			Detail: fmt.Sprintf("scheduled task %q was registered (event-log record) but is not in the Task Scheduler store now — deleted, or hidden (cross-check the scheduledtasks collector)",
				name),
		})
	}
	if present+absent+unverified > 0 {
		m := map[string]any{"still_present": present, "absent": absent}
		if unverified > 0 {
			m["unverified"] = unverified
			m["note"] = "the scheduledtasks collector was cancelled before it finished, so registrations it didn't list weren't judged absent"
		}
		el.SetMeta("task_register_correlation", m)
	}
}

// inventoryPartial reports whether a live collector stopped before it had
// listed everything (its time budget ran out, or the run was interrupted), so
// something missing from its records may simply not have been reached. Such a
// gap must not become an "installed, then removed" finding.
func inventoryPartial(r *Result) bool {
	for _, e := range r.Errors {
		if strings.HasPrefix(e, "cancelled") {
			return true
		}
	}
	return false
}

// normTaskName normalizes a task path for comparison: drop the leading "\" and
// lower-case, so "\Updater" from an event and "Updater" from the store match.
func normTaskName(s string) string {
	return strings.ToLower(strings.TrimLeft(strings.TrimSpace(s), `\`))
}

// correlateLogClears measures a log-clear event against the records that
// survived it: for a Security clear (1102) or an event-log clear (104), the
// surviving channel's record-id and time span quantify the gap left behind, and
// are folded into the clear finding's detail.
func correlateLogClears(el *Result) {
	ranges, _ := el.Meta["channel_ranges"].(map[string]*channelRange)
	if ranges == nil {
		return
	}
	for i := range el.Records {
		rec := &el.Records[i]
		id := intField(rec.Fields, "event_id")
		if id != 1102 && id != 104 {
			continue
		}
		cleared := "Security"
		if id == 104 {
			cleared = firstNonEmpty(eventDataField(rec, "Channel"), stringField(rec.Fields, "channel"))
		}
		cr := ranges[cleared]
		if cr == nil {
			continue // the cleared channel isn't one we parsed
		}
		rec.Fields["surviving_record_min"] = cr.MinRecordID
		rec.Fields["surviving_record_max"] = cr.MaxRecordID
		rec.Fields["surviving_records"] = cr.Scanned
		if !cr.Earliest.IsZero() {
			rec.Fields["surviving_earliest"] = cr.Earliest
			rec.Fields["surviving_latest"] = cr.Latest
		}
		span := fmt.Sprintf("; the surviving %s log holds %d record(s), ids %d–%d",
			cleared, cr.Scanned, cr.MinRecordID, cr.MaxRecordID)
		if !cr.Earliest.IsZero() {
			span += fmt.Sprintf(" (%s – %s)", cr.Earliest.Format(time.RFC3339), cr.Latest.Format(time.RFC3339))
		}
		for j := range rec.Findings {
			if rec.Findings[j].Rule == "defense.clear_event_logs" {
				rec.Findings[j].Detail += span
			}
		}
	}
}

// imagePathRisky reports whether a 7045 record's ImagePath runs from a
// high-risk location.
func imagePathRisky(rec *Record) bool {
	img := eventDataField(rec, "ImagePath")
	if img == "" {
		return false
	}
	lvl, _ := pathRisk(imageFromCommand(img))
	return lvl == riskHigh
}

// recordHasSeverity reports whether any of a record's findings is at least min.
func recordHasSeverity(rec *Record, min Severity) bool {
	want := sevRank(min)
	for _, f := range rec.Findings {
		if sevRank(f.Severity) >= want {
			return true
		}
	}
	return false
}

// stringField, intField and eventDataField read typed values from a record's
// field map while it still holds Go types (correlation runs before the report
// is serialised).
func stringField(f map[string]any, key string) string {
	s, _ := f[key].(string)
	return s
}

func intField(f map[string]any, key string) int {
	n, _ := f[key].(int)
	return n
}

func eventDataField(rec *Record, key string) string {
	if ed, ok := rec.Fields["event_data"].(map[string]string); ok {
		if v := ed[key]; v != "" {
			return v
		}
	}
	if ud, ok := rec.Fields["user_data"].(map[string]string); ok {
		return ud[key]
	}
	return ""
}
