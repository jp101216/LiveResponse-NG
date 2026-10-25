package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// eventLogCollector reads the host's Windows event logs, parses the
// DFIR-relevant channels, and raises findings over them. It gets a larger time
// budget than the dispatcher default because reading and parsing the logs can
// take longer than live-state enumeration; it honours cancellation between
// files. When configured with a Sigma ruleset it evaluates it against every
// event alongside the built-in detections.
type eventLogCollector struct{ sigma *SigmaRuleset }

func (*eventLogCollector) Name() string             { return "eventlog" }
func (*eventLogCollector) Platforms() []string      { return []string{"windows"} }
func (*eventLogCollector) Timeout() time.Duration   { return 3 * time.Minute }
func (c *eventLogCollector) Configure(o RunOptions) { c.sigma = o.Sigma }

func (c *eventLogCollector) Collect(ctx context.Context) (Result, error) {
	return collectEventLog(ctx, c.sigma)
}

func init() { Register(&eventLogCollector{}) }

const (
	// evtxReadCap skips a single log larger than this; copy it off-host and
	// parse it offline instead of reading a gigabyte into memory on a live box.
	evtxReadCap = 512 << 20
	// evtxMaxPerFile bounds the most-recent kept records retained per log.
	evtxMaxPerFile = 50000
	// evtxMaxKept bounds the kept records across the whole run.
	evtxMaxKept = 100000
)

// eventLogSource is one log to triage.
type eventLogSource struct {
	path    string // file to read
	channel string // channel for records that omit System/Channel
	label   string // short name for meta and each record's source_log field
}

// ParseEventLogFiles triages supplied .evtx files offline into a Result: an
// exported log, a Volume Shadow Copy, or a file pulled from a disk image. It is
// portable — it runs on any OS, since only the live collector needs Windows —
// and applies exactly the same classification and findings as the live sweep.
// The channel for each record defaults to the one inferred from the file name.
func ParseEventLogFiles(ctx context.Context, files []string, sigma *SigmaRuleset) Result {
	res := NewResult("eventlog")
	res.SetMeta("mode", "offline")
	res.SetMeta("note", "offline triage of supplied .evtx files; same classification as the live collector")
	sources := make([]eventLogSource, 0, len(files))
	labels := make([]string, 0, len(files))
	for _, p := range files {
		base := filepath.Base(p)
		sources = append(sources, eventLogSource{path: p, channel: channelName(base), label: base})
		labels = append(labels, base)
	}
	res.SetMeta("sources", labels)
	collectEventLogSources(ctx, res, sources, false, sigma)
	return res.Finish()
}

// collectEventLogSources reads and triages a set of .evtx files into res.
// Portable: the live Windows collector points it at winevt\Logs, offline mode
// points it at supplied files. quietMissing reports a missing file as a count
// rather than an error (a targeted channel a host simply doesn't have is
// normal; a path the analyst named is not).
func collectEventLogSources(ctx context.Context, res *Result, sources []eventLogSource, quietMissing bool, sigma *SigmaRuleset) {
	logsRead, logsMissing, scanned, kept, totalWarn := 0, 0, 0, 0, 0
	truncated := false
	ranges := map[string]*channelRange{}
	agg := sigma.newAggregator() // nil unless a Sigma rule has an aggregation or a "near"

	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		if kept >= evtxMaxKept {
			truncated = true
			break
		}
		info, err := os.Stat(src.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				logsMissing++
				if !quietMissing {
					res.Fail(src.label + ": file not found")
				}
			} else {
				res.Fail(src.label + ": " + err.Error())
			}
			continue
		}
		if info.IsDir() {
			res.Fail(src.label + ": is a directory, not an .evtx file")
			continue
		}
		if info.Size() > evtxReadCap {
			res.Fail(fmt.Sprintf("%s: %d bytes exceeds the %d-byte read cap; copy it off-host and parse offline",
				src.label, info.Size(), evtxReadCap))
			continue
		}
		data, err := os.ReadFile(src.path)
		if err != nil {
			// A live log held open by the EventLog service can refuse a read;
			// point the analyst at a shadow-copy or image instead of failing.
			res.Fail(fmt.Sprintf("%s: %v (read it from a shadow copy or image)", src.label, err))
			continue
		}
		logsRead++

		var fileKept []Record
		warns, perr := parseEvtxStream(data, func(rec evtxRecord) bool {
			scanned++
			ev := newWinEvent(rec)
			if ev.Channel == "" {
				ev.Channel = src.channel
			}
			trackChannelRange(ranges, ev) // every scanned record, for log-clear correlation
			agg.observe(ev)               // feed Sigma aggregations and "near" rules (no-op if none)
			fields, findings, keepIt := classifyWinEvent(ev, sigma)
			if keepIt {
				fields["source_log"] = src.label
				fileKept = append(fileKept, Record{Fields: fields, Findings: findings})
				if len(fileKept) > evtxMaxPerFile { // retain the most recent
					fileKept = fileKept[len(fileKept)-evtxMaxPerFile:]
				}
			}
			return kept+len(fileKept) < evtxMaxKept
		})
		if perr != nil {
			res.Fail(src.label + ": " + perr.Error())
			continue
		}
		totalWarn += len(warns)
		for i, w := range warns {
			if i >= 20 {
				res.Fail(fmt.Sprintf("%s: … and %d more parse warnings", src.label, len(warns)-20))
				break
			}
			res.Fail(w)
		}
		for _, r := range fileKept {
			res.Add(r.Fields, r.Findings...)
			kept++
		}
	}

	// Flush the Sigma aggregations and "near" rules: one synthetic record per
	// group that crossed its threshold (or co-occurrence found) over the run.
	for _, r := range agg.flush() {
		if kept >= evtxMaxKept {
			truncated = true
			break
		}
		r.Fields["source_log"] = "sigma:aggregation"
		res.Add(r.Fields, r.Findings...)
		kept++
	}

	res.SetMeta("logs_read", logsRead)
	res.SetMeta("logs_missing", logsMissing)
	res.SetMeta("records_scanned", scanned)
	res.SetMeta("records_kept", kept)
	if len(ranges) > 0 {
		res.SetMeta("channel_ranges", ranges)
	}
	if sigma != nil {
		res.SetMeta("sigma", sigmaMeta(sigma))
	}
	if totalWarn > 0 {
		res.SetMeta("parse_warnings", totalWarn)
	}
	if truncated {
		res.SetMeta("records_truncated", true)
	}
}

// sigmaMetaListMax bounds the skipped/failed lists in meta.sigma; loading a
// large public rule repository can skip hundreds of rules.
const sigmaMetaListMax = 200

// sigmaMeta reports what the Sigma engine could and couldn't run: counts, plus
// which rules were skipped and why ("title (file): reason") and which files
// failed to parse, so "no Sigma findings" can be told apart from "the rule
// never ran" — the same way YARA compile failures are listed.
func sigmaMeta(rs *SigmaRuleset) map[string]any {
	m := map[string]any{"rules_loaded": rs.Loaded}
	if len(rs.Skipped) > 0 {
		m["rules_skipped"] = len(rs.Skipped)
		m["skipped"] = boundedList(rs.Skipped, sigmaMetaListMax)
	}
	if len(rs.Failed) > 0 {
		m["rules_failed"] = len(rs.Failed)
		m["failed"] = boundedList(rs.Failed, sigmaMetaListMax)
	}
	return m
}

// boundedList returns at most max entries of list, ending with an
// "… and N more" marker when it had to cut.
func boundedList(list []string, max int) []string {
	if len(list) <= max {
		return append([]string(nil), list...)
	}
	out := append([]string(nil), list[:max]...)
	return append(out, fmt.Sprintf("… and %d more", len(list)-max))
}

// channelName turns a log file name into its channel: drop .evtx and decode the
// "%4" that stands in for "/" in the on-disk file name.
func channelName(fname string) string {
	return strings.ReplaceAll(strings.TrimSuffix(fname, ".evtx"), "%4", "/")
}

// eventlog.go — turn parsed EVTX records (evtx.go) into normalized Windows
// events and raise DFIR findings over them. No build tag: it works on the
// in-memory bxml tree and the shared command-line analytics, and is unit-tested
// on any OS. The Windows-only collector that reads the on-disk logs lives in
// eventlog_windows.go.
//
// Event logs are the half of live response the live-state collectors can't see:
// what happened before the analyst arrived. Rather than dump whole logs (a
// Security log can hold millions of records), lrng targets the DFIR-relevant
// events, records those in full, and — for the high-volume command-bearing
// events (process creation, PowerShell script blocks) — keeps only the ones a
// rule fires on. Command lines inside events go through the same analytics as
// processes, services and task actions, so one encoded-PowerShell rule covers a
// running process and a logged one alike.

// winEvent is one event, normalized out of the <System>/<EventData> shape.
type winEvent struct {
	Channel      string
	Provider     string
	ProviderGUID string
	EventID      int
	Level        int
	Task         int
	Opcode       int
	Keywords     string
	RecordID     uint64
	TimeCreated  time.Time
	Computer     string
	SecurityUser string // the SID in System/Security/@UserID
	ProcessID    int
	ThreadID     int
	Data         map[string]string // EventData <Data Name="x">v</Data>
	DataList     []string          // positional EventData <Data>v</Data>
	UserData     map[string]string // flattened UserData (e.g. 1102's LogFileCleared)
}

// textOf returns an element's trimmed text, nil-safe.
func (e *bxmlElement) textOf() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Text)
}

// newWinEvent normalizes a parsed record. A missing field is simply empty/zero.
func newWinEvent(rec evtxRecord) winEvent {
	ev := winEvent{
		RecordID:    rec.RecordID,
		TimeCreated: rec.Written,
		Data:        map[string]string{},
		UserData:    map[string]string{},
	}
	root := rec.Root
	if root == nil {
		return ev
	}

	if sys := root.child("System"); sys != nil {
		if p := sys.child("Provider"); p != nil {
			ev.Provider = firstNonEmpty(p.attr("Name"), p.attr("EventSourceName"))
			ev.ProviderGUID = p.attr("Guid")
		}
		ev.EventID = atoiSafe(sys.child("EventID").textOf())
		ev.Level = atoiSafe(sys.child("Level").textOf())
		ev.Task = atoiSafe(sys.child("Task").textOf())
		ev.Opcode = atoiSafe(sys.child("Opcode").textOf())
		ev.Keywords = sys.child("Keywords").textOf()
		ev.Channel = sys.child("Channel").textOf()
		ev.Computer = sys.child("Computer").textOf()
		if tc := sys.child("TimeCreated"); tc != nil {
			if t, ok := parseEvtxTime(tc.attr("SystemTime")); ok {
				ev.TimeCreated = t
			}
		}
		if rid := sys.child("EventRecordID").textOf(); rid != "" {
			if v, err := strconv.ParseUint(rid, 10, 64); err == nil {
				ev.RecordID = v
			}
		}
		if ex := sys.child("Execution"); ex != nil {
			ev.ProcessID = atoiSafe(ex.attr("ProcessID"))
			ev.ThreadID = atoiSafe(ex.attr("ThreadID"))
		}
		if sec := sys.child("Security"); sec != nil {
			ev.SecurityUser = sec.attr("UserID")
		}
	}

	if ed := root.child("EventData"); ed != nil {
		for _, d := range ed.Children {
			if d.Name != "Data" {
				continue
			}
			if name := d.attr("Name"); name != "" {
				ev.Data[name] = strings.TrimSpace(d.Text)
			} else if t := strings.TrimSpace(d.Text); t != "" {
				ev.DataList = append(ev.DataList, t)
			}
		}
	}
	if ud := root.child("UserData"); ud != nil {
		flattenUserData(ud, ev.UserData, 0)
	}
	return ev
}

// flattenUserData collects leaf name/value pairs from a UserData subtree. The
// UserData shape is provider-defined; one level of nesting (as in 1102's
// <LogFileCleared>) covers the events lrng targets.
func flattenUserData(el *bxmlElement, into map[string]string, depth int) {
	if el == nil || depth > 4 {
		return
	}
	for _, c := range el.Children {
		if len(c.Children) == 0 {
			if t := strings.TrimSpace(c.Text); t != "" {
				into[c.Name] = t
			}
			continue
		}
		flattenUserData(c, into, depth+1)
	}
}

// classifyEvent normalizes a record and classifies it. channel is the log the
// record came from, used when the record omits System/Channel.
func classifyEvent(channel string, rec evtxRecord) (fields map[string]any, findings []Finding, keep bool) {
	ev := newWinEvent(rec)
	if ev.Channel == "" {
		ev.Channel = channel
	}
	return classifyWinEvent(ev, nil)
}

// classifyWinEvent raises findings for a normalized event (built-in rules plus
// any Sigma rules) and reports whether it is worth recording: targeted
// (security-relevant, low-volume) events are always kept; high-volume events
// are kept only when a rule — built-in or Sigma — fired.
func classifyWinEvent(ev winEvent, sigma *SigmaRuleset) (fields map[string]any, findings []Finding, keep bool) {
	findings = eventFindings(ev)
	if sigma != nil {
		findings = append(findings, sigma.match(ev)...)
	}
	if !alwaysRecord(ev.EventID) && len(findings) == 0 {
		return nil, nil, false
	}
	return ev.fields(), findings, true
}

// channelRange is the record-id and time span of every record seen in one
// channel — the whole log, not just the kept subset — so a log clear can be
// measured against the records that survived it (see correlate.go).
type channelRange struct {
	MinRecordID uint64    `json:"min_record_id"`
	MaxRecordID uint64    `json:"max_record_id"`
	Earliest    time.Time `json:"earliest,omitempty"`
	Latest      time.Time `json:"latest,omitempty"`
	Scanned     int       `json:"scanned"`
}

// trackChannelRange folds one event into its channel's running range.
func trackChannelRange(ranges map[string]*channelRange, ev winEvent) {
	if ev.Channel == "" {
		return
	}
	cr := ranges[ev.Channel]
	if cr == nil {
		cr = &channelRange{MinRecordID: ev.RecordID, MaxRecordID: ev.RecordID}
		ranges[ev.Channel] = cr
	}
	cr.Scanned++
	if ev.RecordID < cr.MinRecordID {
		cr.MinRecordID = ev.RecordID
	}
	if ev.RecordID > cr.MaxRecordID {
		cr.MaxRecordID = ev.RecordID
	}
	if !ev.TimeCreated.IsZero() {
		t := ev.TimeCreated.UTC()
		if cr.Earliest.IsZero() || t.Before(cr.Earliest) {
			cr.Earliest = t
		}
		if cr.Latest.IsZero() || t.After(cr.Latest) {
			cr.Latest = t
		}
	}
}

// eventFindings raises findings for one normalized event.
func eventFindings(ev winEvent) []Finding {
	var out []Finding
	switch ev.EventID {
	case 1102: // Security audit log cleared
		out = append(out, Finding{
			Rule: "defense.clear_event_logs", Severity: SevCritical, Technique: "T1070.001", Confidence: 85,
			Detail: "the Security audit log was cleared" + whoBy(ev),
		})
	case 104: // an event log file was cleared
		logName := firstNonEmpty(evData(ev, "Channel"), "an event")
		out = append(out, Finding{
			Rule: "defense.clear_event_logs", Severity: SevCritical, Technique: "T1070.001", Confidence: 80,
			Detail: fmt.Sprintf("the %s log was cleared", logName) + whoBy(ev),
		})
	case 7045: // a service was installed
		out = append(out, serviceInstallFindings(ev)...)
	case 4720: // a user account was created
		out = append(out, Finding{
			Rule: "persistence.account_created", Severity: SevSuspect, Technique: "T1136.001", Confidence: 70,
			Detail: "a local user account was created: " + firstNonEmpty(evData(ev, "TargetUserName"), "(unknown)") + whoBy(ev),
		})
	case 4728, 4732, 4756: // a member was added to a security-enabled group
		if f := groupAddFinding(ev); f != nil {
			out = append(out, *f)
		}
	case 4104: // PowerShell script-block logging
		out = append(out, scriptBlockFindings(ev)...)
	case 4688: // a new process was created
		out = append(out, processCreateFindings(ev)...)
	case 1116, 1117: // Microsoft Defender detected / acted on malware
		out = append(out, defenderFindings(ev)...)
	case 4624: // an account was successfully logged on
		out = append(out, logonFindings(ev)...)
	case 4625: // an account failed to log on
		out = append(out, failedLogonFindings(ev)...)
	}
	return out
}

// logonFindings surfaces remote logons from the surviving 4624 records. A
// remote-interactive (RDP, type 10) logon is always worth keeping; from a
// public source address it rises to suspect (RDP exposed to the internet, or an
// attacker arriving over one). A network logon (type 3) is only raised when it
// comes from an external address and isn't a machine account.
func logonFindings(ev winEvent) []Finding {
	ip := evData(ev, "IpAddress")
	switch evData(ev, "LogonType") {
	case "10": // RemoteInteractive (RDP / RemoteApp)
		sev, conf := SevNotable, 35
		detail := fmt.Sprintf("remote-interactive (RDP) logon as %s from %s",
			logonUser(ev), firstNonEmpty(ip, "(no source address)"))
		if publicIP(ip) {
			sev, conf = SevSuspect, 70
			detail += " — external source address (RDP exposed to the internet, or arrived via a jump host)"
		}
		return []Finding{{Rule: "logon.remote_interactive", Severity: sev, Technique: "T1021.001", Confidence: conf, Detail: detail}}
	case "3": // Network
		if publicIP(ip) && !strings.HasSuffix(evData(ev, "TargetUserName"), "$") {
			return []Finding{{
				Rule: "logon.network_external", Severity: SevNotable, Technique: "T1021", Confidence: 40,
				Detail: fmt.Sprintf("network logon as %s from external address %s", logonUser(ev), ip),
			}}
		}
	}
	return nil
}

// failedLogonFindings raises a 4625 failed logon that came from an external
// address (a single data point for brute force / password spray; an analyst
// correlates volume).
func failedLogonFindings(ev winEvent) []Finding {
	ip := evData(ev, "IpAddress")
	if !publicIP(ip) {
		return nil
	}
	return []Finding{{
		Rule: "logon.failed_external", Severity: SevNotable, Technique: "T1110", Confidence: 40,
		Detail: fmt.Sprintf("failed logon as %s from external address %s (possible brute force / password spray)", logonUser(ev), ip),
	}}
}

// logonUser renders the target account of a logon event as DOMAIN\user.
func logonUser(ev winEvent) string {
	u := evData(ev, "TargetUserName")
	if d := evData(ev, "TargetDomainName"); d != "" && u != "" {
		return d + "\\" + u
	}
	return firstNonEmpty(u, "(unknown)")
}

// publicIP reports whether s is a routable public address, using the same test
// as module A and the sessions collector (so "external" means one thing
// everywhere). A blank or "-" address (a local logon) is not public.
func publicIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return aidetect.PublicAddr(addr)
}

// alwaysRecord lists the low-volume, security-relevant event ids lrng records
// in full even without a finding. High-volume ids (4688, 4104, logons) are
// recorded only when a rule fires.
func alwaysRecord(id int) bool {
	switch id {
	case 104, // event log cleared (System)
		1100,             // event logging service shut down
		1102,             // Security audit log cleared
		7045,             // service installed
		7030,             // service marked interactive
		4697,             // a service was installed (Security)
		4720,             // user account created
		4722,             // user account enabled
		4725,             // user account disabled
		4726,             // user account deleted
		4728, 4732, 4756, // member added to a group
		4672,             // special privileges assigned (admin logon)
		4698, 4699, 4702, // scheduled task created / deleted / updated (Security)
		1116, 1117, // Defender detection / action
		106, 140, 200, 201: // Task Scheduler register/update/run
		return true
	}
	return false
}

func serviceInstallFindings(ev winEvent) []Finding {
	name := firstNonEmpty(evData(ev, "ServiceName"), "(unnamed)")
	img := evData(ev, "ImagePath")
	program := imageFromCommand(img)

	sev, conf := SevNotable, 45
	detail := fmt.Sprintf("a service %q was installed: %s", name, excerpt(img, 200))
	if img != "" {
		if lvl, why := pathRisk(program); lvl == riskHigh {
			sev, conf = SevSuspect, 70
			detail = fmt.Sprintf("a service %q was installed from %s: %s", name, why, excerpt(img, 200))
		}
	}
	out := []Finding{{Rule: "eventlog.service_installed", Severity: sev, Technique: "T1543.003", Confidence: conf, Detail: detail}}
	// The ImagePath is a command line: reuse the shared analytics (PsExec/
	// Impacket service hosts, encoded PowerShell, LOLBin proxies, ...).
	out = append(out, analyzeCommandLine("installed service", program, img)...)
	return out
}

func groupAddFinding(ev winEvent) *Finding {
	group := evData(ev, "TargetUserName")
	groupSID := evData(ev, "TargetSid")
	if !privilegedGroup(group, groupSID) {
		return nil
	}
	member := firstNonEmpty(evData(ev, "MemberName"), evData(ev, "MemberSid"), "an account")
	return &Finding{
		Rule: "persistence.admin_group_add", Severity: SevSuspect, Technique: "T1098", Confidence: 70,
		Detail: fmt.Sprintf("%s was added to the privileged group %q", member, group) + whoBy(ev),
	}
}

// privilegedGroup matches the well-known privileged local groups by RID
// (language-independent) and by a few localized names as a fallback.
func privilegedGroup(name, sid string) bool {
	switch {
	case strings.HasSuffix(sid, "-544"), // Administrators
		strings.HasSuffix(sid, "-555"), // Remote Desktop Users
		strings.HasSuffix(sid, "-551"), // Backup Operators
		strings.HasSuffix(sid, "-580"): // Remote Management Users
		return true
	}
	switch strings.ToLower(name) {
	case "administrators", "administrateurs", "administratoren", "administradores",
		"remote desktop users", "backup operators", "remote management users":
		return true
	}
	return false
}

func scriptBlockFindings(ev winEvent) []Finding {
	text := evData(ev, "ScriptBlockText")
	if text == "" {
		return nil
	}
	out := analyzeCommandLine("powershell script block", "powershell.exe", text)
	// PowerShell auto-logs script blocks it deems suspicious at Warning level
	// even when full script-block logging is off; surface those at notable.
	if len(out) == 0 && ev.Level == 3 {
		out = append(out, Finding{
			Rule: "eventlog.powershell_suspicious_block", Severity: SevNotable, Technique: "T1059.001", Confidence: 40,
			Detail: "PowerShell flagged a script block as suspicious: " + excerpt(text, 200),
		})
	}
	return out
}

func processCreateFindings(ev winEvent) []Finding {
	cmd := evData(ev, "CommandLine")
	if cmd == "" {
		return nil // 4688 without command-line auditing: nothing to analyze
	}
	img := firstNonEmpty(evData(ev, "NewProcessName"), evData(ev, "ProcessName"))
	return analyzeCommandLine("process creation", img, cmd)
}

func defenderFindings(ev winEvent) []Finding {
	threat := firstNonEmpty(evData(ev, "Threat Name"), evData(ev, "ThreatName"))
	path := firstNonEmpty(evData(ev, "Path"), evData(ev, "Process Name"), evData(ev, "ProcessName"))
	detail := "Microsoft Defender reported a threat"
	if threat != "" {
		detail += ": " + threat
	}
	if path != "" {
		detail += " (" + excerpt(path, 160) + ")"
	}
	return []Finding{{
		Rule: "eventlog.defender_detection", Severity: SevSuspect, Confidence: 75,
		Detail: detail,
	}}
}

// fields renders the normalized event as a record field map.
func (ev winEvent) fields() map[string]any {
	f := map[string]any{
		"event_id":  ev.EventID,
		"record_id": ev.RecordID,
	}
	if ev.Channel != "" {
		f["channel"] = ev.Channel
	}
	if ev.Provider != "" {
		f["provider"] = ev.Provider
	}
	if ev.ProviderGUID != "" {
		f["provider_guid"] = ev.ProviderGUID
	}
	if !ev.TimeCreated.IsZero() {
		f["time_created"] = ev.TimeCreated.UTC()
	}
	if ev.Level != 0 {
		f["level"] = ev.Level
		if n := levelName(ev.Level); n != "" {
			f["level_name"] = n
		}
	}
	if ev.Task != 0 {
		f["task"] = ev.Task
	}
	if ev.Computer != "" {
		f["computer"] = ev.Computer
	}
	if ev.SecurityUser != "" {
		f["user_sid"] = ev.SecurityUser
	}
	if ev.ProcessID != 0 {
		f["process_id"] = ev.ProcessID
	}
	if ev.ThreadID != 0 {
		f["thread_id"] = ev.ThreadID
	}
	if len(ev.Data) > 0 {
		f["event_data"] = ev.Data
	}
	if len(ev.DataList) > 0 {
		f["event_data_list"] = ev.DataList
	}
	if len(ev.UserData) > 0 {
		f["user_data"] = ev.UserData
	}
	return f
}

func levelName(l int) string {
	switch l {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Information"
	case 5:
		return "Verbose"
	}
	return ""
}

// evData reads a value from EventData, falling back to flattened UserData.
func evData(ev winEvent, key string) string {
	if v, ok := ev.Data[key]; ok {
		return v
	}
	if v, ok := ev.UserData[key]; ok {
		return v
	}
	return ""
}

// whoBy names the actor of a security event: the subject account when present,
// otherwise the Security/@UserID SID.
func whoBy(ev winEvent) string {
	if u := evData(ev, "SubjectUserName"); u != "" {
		if dom := evData(ev, "SubjectDomainName"); dom != "" {
			return " by " + dom + "\\" + u
		}
		return " by " + u
	}
	if ev.SecurityUser != "" {
		return " by " + ev.SecurityUser
	}
	return ""
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

// parseEvtxTime parses an EVTX ISO-8601 timestamp (System/TimeCreated or a
// FILETIME/SysTime rendered by the parser).
func parseEvtxTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
