package collector

import (
	"fmt"
	"regexp"
	"strings"
)

// uacbypass.go — per-user registry keys that make an auto-elevating Windows
// program run a command of the user's choosing, elevated and without a UAC
// prompt. Windows reads these keys from the user's own hive before the
// machine's, so any user can plant one; none has a legitimate use. NIK C2
// (Cisco Talos, October 2026) uses fodhelper's, deleting the key two seconds
// later, which Sysmon's registry events (12, 13) still record.

// uacBypassKey is one key an auto-elevating program reads.
type uacBypassKey struct {
	classes bool   // under the user's Classes (HKCU\Software\Classes)
	key     string // lower-case, relative to Classes or to the user's hive
	value   string // the value holding the command ("" is the default value)
	// needDelegate: only a bypass with an empty DelegateExecute value beside
	// the command (file managers replace Explorer through the same key).
	needDelegate bool
	via          string
}

var uacBypassKeys = []uacBypassKey{
	{true, `ms-settings\shell\open\command`, "", false, "fodhelper.exe and computerdefaults.exe"},
	{true, `mscfile\shell\open\command`, "", false, "eventvwr.exe and CompMgmtLauncher.exe"},
	{true, `exefile\shell\runas\command`, "isolatedcommand", false, "sdclt.exe /kickoffelev"},
	{true, `folder\shell\open\command`, "", true, "sdclt.exe"},
	{true, `appx82a6gwre4fdg3bt635tn5ctqjf8msdd2\shell\open\command`, "", false, "wsreset.exe"},
	{false, `software\microsoft\windows\currentversion\app paths\control.exe`, "", false, "sdclt.exe"},
	{false, `environment`, "windir", false, "the SilentCleanup scheduled task"},
}

// uacBypassFinding judges a planted key: the command found in it (possibly
// empty) and where.
func uacBypassFinding(k uacBypassKey, where, command, when string) Finding {
	what := "holds the command " + excerpt(command, 240)
	if k.key == "environment" {
		what = "overrides %windir% with " + excerpt(command, 240)
	}
	f := Finding{Rule: "privesc.uac_bypass_key", Severity: SevCritical, Technique: "T1548.002", Confidence: 85,
		Detail: fmt.Sprintf("%s %s%s: %s then run it elevated, without a UAC prompt (a UAC bypass; NIK C2 plants "+
			"fodhelper's and deletes it two seconds later)", where, what, when, k.via)}
	if strings.TrimSpace(command) == "" {
		f.Severity, f.Confidence = SevSuspect, 60
		f.Detail = fmt.Sprintf("%s exists%s, with no command yet: the key %s reads to run a command elevated without a "+
			"UAC prompt (a UAC bypass being set up, or one cleaned up badly)", where, when, k.via)
	}
	return f
}

// reUserHivePrefix strips the hive a registry path starts in: Sysmon's
// HKU\<sid>\ and HKU\<sid>_Classes\, HKCU\, and the kernel's \REGISTRY\USER\.
var reUserHivePrefix = regexp.MustCompile(`^(?:hku|hkey_users|\\registry\\user)\\(s-1-[0-9-]+)(_classes)?\\|^(?:hkcu|hkey_current_user)\\`)

// matchUACBypassPath matches a registry path (key, or key plus value for a
// value event) against the keys above. It returns the key, and the value name
// when the path ends in one.
func matchUACBypassPath(path string) (k uacBypassKey, value string, ok bool) {
	p := strings.ToLower(strings.TrimSpace(path))
	m := reUserHivePrefix.FindStringSubmatchIndex(p)
	if m == nil {
		return k, "", false
	}
	classes := m[4] >= 0 // a ..._Classes hive
	rest := p[m[1]:]
	if !classes {
		if r, found := strings.CutPrefix(rest, `software\classes\`); found {
			rest, classes = r, true
		}
	}
	for _, c := range uacBypassKeys {
		if c.classes != classes {
			continue
		}
		switch {
		case rest == c.key:
			return c, "", true
		case strings.HasPrefix(rest, c.key+`\`) && !strings.Contains(rest[len(c.key)+1:], `\`):
			v := rest[len(c.key)+1:]
			if v == "(default)" {
				v = ""
			}
			return c, v, true
		}
	}
	return k, "", false
}

// registryEventFindings judges Sysmon's registry events: a key created (12)
// or a value set (13) where a UAC bypass lives. A planted command is set as a
// value, so key creation alone counts only for the keys with no other use.
func registryEventFindings(ev winEvent) []Finding {
	target := evData(ev, "TargetObject")
	k, value, ok := matchUACBypassPath(target)
	if !ok {
		return nil
	}
	who := firstNonEmpty(evData(ev, "Image"), "a process")
	when := eventTime(ev)
	switch ev.EventID {
	case 12:
		if !strings.EqualFold(strings.TrimSpace(evData(ev, "EventType")), "CreateKey") || k.needDelegate || k.key == "environment" {
			return nil
		}
		f := uacBypassFinding(k, fmt.Sprintf("%s created %s", who, target), "", when)
		return []Finding{f}
	case 13:
		if k.needDelegate {
			if value != "delegateexecute" {
				return nil
			}
			return []Finding{uacBypassFinding(k, fmt.Sprintf("%s set %s (an empty DelegateExecute, which makes the command "+
				"beside it run)", who, target), "(the key's default value)", when)}
		}
		if value != k.value {
			return nil
		}
		return []Finding{uacBypassFinding(k, fmt.Sprintf("%s set %s", who, target), strings.TrimSpace(evData(ev, "Details")), when)}
	}
	return nil
}
