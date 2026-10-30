package collector

import (
	"fmt"
	"strings"
)

// WMI event-subscription (permanent consumer) heuristics. WMI persistence
// (T1546.003) stores three objects in the CIM repository, almost always in
// root\subscription: an __EventFilter (a WQL query that is the trigger), an
// __EventConsumer (the action) and a __FilterToConsumerBinding joining the
// two. The subscription survives reboots, runs as SYSTEM, and for the two
// script-bearing consumer classes leaves nothing on disk. A default Windows
// install carries essentially no permanent subscriptions, so each object is
// worth surfacing; the two fileless consumer classes are the ones attackers
// reach for. No build tag: pure logic, unit-tested on any OS.

// Consumer class names (the concrete __EventConsumer subclasses).
const (
	wmiActiveScript = "ActiveScriptEventConsumer" // runs VBScript/JScript in-process (fileless)
	wmiCommandLine  = "CommandLineEventConsumer"  // runs a command line
	wmiNTEventLog   = "NTEventLogEventConsumer"   // writes the event log
)

// wmiFilter is an __EventFilter.
type wmiFilter struct {
	Namespace      string
	Name           string
	Query          string
	QueryLang      string
	EventNamespace string
}

// wmiConsumer is an __EventConsumer of any concrete class.
type wmiConsumer struct {
	Namespace string
	Class     string // the concrete __CLASS: ActiveScriptEventConsumer, ...
	Name      string
	// CommandLineEventConsumer
	CommandLineTemplate string
	ExecutablePath      string
	WorkingDirectory    string
	// ActiveScriptEventConsumer
	ScriptingEngine string
	ScriptText      string
	ScriptFileName  string
	// A short description of the destination/target for the other classes.
	Extra string
}

// wmiBinding is a __FilterToConsumerBinding (reference strings to a filter and
// a consumer).
type wmiBinding struct {
	Namespace string
	Filter    string
	Consumer  string
}

// knownBenignConsumer recognises the consumers Windows itself ships in
// root\subscription, so a clean host raises nothing. "SCM Event Log Consumer"
// (an NTEventLogEventConsumer) is present on stock installs.
func knownBenignConsumer(c wmiConsumer) bool {
	return strings.EqualFold(c.Class, wmiNTEventLog) &&
		strings.EqualFold(strings.TrimSpace(c.Name), "SCM Event Log Consumer")
}

// judgeWMIConsumer returns the findings for one event consumer.
func judgeWMIConsumer(c wmiConsumer) []Finding {
	if knownBenignConsumer(c) {
		return nil
	}
	loc := "WMI consumer " + wmiRef(c.Namespace, c.Class, c.Name)

	switch {
	case strings.EqualFold(c.Class, wmiActiveScript):
		shown := firstNonEmpty(c.ScriptText, c.ScriptFileName)
		out := []Finding{{
			Rule: "persistence.wmi_script_consumer", Severity: SevSuspect, Technique: "T1546.003", Confidence: 75,
			Detail: fmt.Sprintf("%s runs %s script on an event — fileless WMI persistence, nothing on disk: %s",
				loc, engineOr(c.ScriptingEngine), excerpt(shown, 240)),
		}}
		return mergeFindings(out, analyzeCommandLine(loc+" ScriptText", "", c.ScriptText)...)

	case strings.EqualFold(c.Class, wmiCommandLine):
		cmd := firstNonEmpty(c.CommandLineTemplate, c.ExecutablePath)
		out := []Finding{{
			Rule: "persistence.wmi_commandline_consumer", Severity: SevNotable, Technique: "T1546.003", Confidence: 45,
			Detail: fmt.Sprintf("%s runs a command on an event (WMI persistence): %s", loc, excerpt(cmd, 240)),
		}}
		if lvl, why, culprit := commandPathRisk(cmd); lvl != riskNone {
			sev, conf := SevSuspect, 65
			if lvl == riskLow {
				sev, conf = SevNotable, 40
			}
			out = append(out, Finding{
				Rule: "persistence.wmi_consumer_unusual_path", Severity: sev, Technique: "T1546.003", Confidence: conf,
				Detail: fmt.Sprintf("%s runs code from %s: %s", loc, why, culprit),
			})
		}
		return mergeFindings(out, analyzeCommandLine(loc+" CommandLineTemplate", c.ExecutablePath, cmd)...)

	default:
		// LogFile / SMTP / NTEventLog and anything else: less abused, but on a
		// clean host there are none, so note that it exists.
		return []Finding{{
			Rule: "persistence.wmi_consumer", Severity: SevNotable, Technique: "T1546.003", Confidence: 35,
			Detail: fmt.Sprintf("%s is registered (%s)", loc, firstNonEmpty(c.Extra, c.Class)),
		}}
	}
}

// judgeWMIFilter returns the findings for one event filter. Every filter in
// root\subscription is worth a glance; the WQL often reveals the trigger (a
// logon, a process start, an interval timer). A filter that triggers on a WMI
// timer is called out separately: timer triggers fire on a schedule rather
// than on a system event, which legitimate software almost never relies on.
func judgeWMIFilter(f wmiFilter) []Finding {
	out := []Finding{{
		Rule: "persistence.wmi_filter", Severity: SevNotable, Technique: "T1546.003", Confidence: 40,
		Detail: fmt.Sprintf("WMI event filter %s watches: %s", wmiRef(f.Namespace, "__EventFilter", f.Name), excerpt(f.Query, 240)),
	}}
	if id := wmiFilterTimerID(f.Query); id != "" {
		out = append(out, Finding{
			Rule: "persistence.wmi_timer_filter", Severity: SevSuspect, Technique: "T1546.003", Confidence: 60,
			Detail: fmt.Sprintf("WMI event filter %s triggers on a timer (TimerID %s) — a schedule-based trigger that fires independently of any system event",
				wmiRef(f.Namespace, "__EventFilter", f.Name), id),
		})
	}
	return out
}

// Timer-instruction classes: the scheduling half of timer-based subscriptions.
const (
	wmiIntervalTimer = "__IntervalTimerInstruction" // fires every IntervalBetweenEvents ms
	wmiAbsoluteTimer = "__AbsoluteTimerInstruction" // fires once at EventDateTime
)

// wmiTimer is an __IntervalTimerInstruction or __AbsoluteTimerInstruction.
type wmiTimer struct {
	Namespace    string
	Class        string // the concrete __CLASS
	TimerID      string // the TimerId a __TimerEvent filter subscribes to
	Interval     string // IntervalBetweenEvents (ms), for interval timers
	When         string // EventDateTime, for absolute timers
	SkipIfPassed string
}

// wmiFilterTimerID reports the TimerID an __EventFilter subscribes to when its
// WQL is a __TimerEvent subscription, else "". A __TimerEvent query with no
// readable TimerID still returns a non-empty marker, since the timer trigger
// itself is the point.
func wmiFilterTimerID(query string) string {
	if !strings.Contains(strings.ToLower(query), "__timerevent") {
		return ""
	}
	i := strings.Index(strings.ToLower(query), "timerid")
	if i < 0 {
		return `"(unnamed)"`
	}
	rest := query[i+len("timerid"):]
	if eq := strings.IndexByte(rest, '='); eq >= 0 {
		rest = rest[eq+1:]
	}
	rest = strings.TrimSpace(rest)
	quoted := strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, `'`)
	rest = strings.Trim(rest, `"'`)
	// Cut at the first quote, whitespace or clause terminator.
	for _, sep := range []string{`"`, `'`, " ", "\t", ")"} {
		if k := strings.Index(rest, sep); k >= 0 {
			rest = rest[:k]
		}
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return `"(unnamed)"`
	}
	if quoted {
		return `"` + rest + `"`
	}
	return rest
}

// judgeWMITimer returns the finding for one timer instruction. A default
// Windows install carries no timer instructions, so each is surfaced; paired
// with a __TimerEvent filter and a binding, a timer makes a subscription fire
// on a schedule with no system-event trigger at all.
func judgeWMITimer(tm wmiTimer) []Finding {
	ref := tm.Class
	if tm.TimerID != "" {
		ref += ` (TimerID "` + tm.TimerID + `")`
	}
	detail := fmt.Sprintf("WMI timer instruction %s in %s", ref, tm.Namespace)
	switch {
	case tm.Interval != "":
		detail += " fires every " + tm.Interval + " ms"
	case tm.When != "":
		detail += " fires at " + tm.When
	}
	detail += " — the schedule for a timer-triggered subscription"
	return []Finding{{
		Rule: "persistence.wmi_timer", Severity: SevNotable, Technique: "T1546.003", Confidence: 45, Detail: detail,
	}}
}

// judgeWMIBinding returns the finding for one filter-to-consumer binding. A
// binding is the live link: once it exists, the consumer fires when the filter
// matches. c is the consumer the binding resolves to (nil if it couldn't be
// matched), used to rank the binding by what it will run.
func judgeWMIBinding(b wmiBinding, c *wmiConsumer) []Finding {
	if c != nil && knownBenignConsumer(*c) {
		return nil
	}
	sev, conf, kind := SevSuspect, 70, "a consumer"
	if c != nil {
		switch {
		case strings.EqualFold(c.Class, wmiActiveScript):
			sev, conf, kind = SevCritical, 85, "a fileless script consumer"
		case strings.EqualFold(c.Class, wmiCommandLine):
			sev, conf, kind = SevSuspect, 75, "a command-line consumer"
		}
	}
	return []Finding{{
		Rule: "persistence.wmi_subscription_active", Severity: sev, Technique: "T1546.003", Confidence: conf,
		Detail: fmt.Sprintf("an active WMI subscription binds filter %s to %s %s — it fires when the filter matches",
			bindingRefName(b.Filter), kind, bindingRefName(b.Consumer)),
	}}
}

// wmiRef renders a readable object reference.
func wmiRef(namespace, class, name string) string {
	ref := class
	if name != "" {
		ref += ` "` + name + `"`
	}
	if namespace != "" {
		ref += " in " + namespace
	}
	return ref
}

// parseWMIRef extracts the class and Name= of a WMI object reference string
// such as `\\.\root\subscription:ActiveScriptEventConsumer.Name="evil"` or the
// relative `CommandLineEventConsumer.Name="x"`. Either may be absent.
func parseWMIRef(ref string) (class, name string) {
	ref = strings.TrimSpace(ref)
	if i := strings.LastIndex(ref, ":"); i >= 0 && i+1 < len(ref) {
		// Keep only the object path after a namespace prefix, but not the ':'
		// inside a drive-less path (there is none); the last ':' is the sep.
		ref = ref[i+1:]
	}
	dot := strings.IndexByte(ref, '.')
	if dot < 0 {
		return strings.TrimSpace(ref), ""
	}
	class = strings.TrimSpace(ref[:dot])
	rest := ref[dot+1:]
	if j := strings.Index(strings.ToLower(rest), "name="); j >= 0 {
		v := strings.TrimSpace(rest[j+len("name="):])
		v = strings.Trim(v, `"`)
		// Drop any trailing key=value pairs.
		if k := strings.IndexByte(v, '"'); k >= 0 {
			v = v[:k]
		}
		name = v
	}
	return class, name
}

// bindingRefName renders a binding's reference as class "name" when it parses,
// else the raw reference.
func bindingRefName(ref string) string {
	class, name := parseWMIRef(ref)
	if class == "" {
		return excerpt(ref, 120)
	}
	if name == "" {
		return class
	}
	return class + ` "` + name + `"`
}

// consumerKey is the class|name identity used to match a binding to a consumer.
func consumerKey(class, name string) string {
	return strings.ToLower(strings.TrimSpace(class)) + "|" + strings.ToLower(strings.TrimSpace(name))
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func engineOr(engine string) string {
	if e := strings.TrimSpace(engine); e != "" {
		return "a " + e
	}
	return "a"
}
