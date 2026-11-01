//go:build windows

package collector

import (
	"fmt"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// uacBypass records the UAC-bypass keys planted in one user's hive (see
// uacbypass.go). A user's Classes live in their own hive, HKU\<sid>_Classes,
// which older systems also show under HKU\<sid>\Software\Classes.
func (a *asepWalker) uacBypass(sid, profile string) {
	for _, k := range uacBypassKeys {
		if a.done() {
			return
		}
		paths := []string{sid + `\` + k.key}
		if k.classes {
			paths = []string{sid + `_Classes\` + k.key, sid + `\Software\Classes\` + k.key}
		}
		for _, p := range paths {
			label := `HKU\` + p
			vals, _, lw, ok := a.readKey(winreg.Users, p, label)
			if !ok {
				continue
			}
			v, has := vals[k.value]
			if k.key == "environment" && !has {
				break // the user's environment, without a windir of its own
			}
			if _, delegate := vals["delegateexecute"]; k.needDelegate && !delegate {
				break
			}
			cmd := ""
			if has {
				_, cmd = regString(v, profile) // as written: what the elevated program will run
			}
			when := ""
			if !lw.IsZero() {
				when = fmt.Sprintf(" (key last written %s)", lw.UTC().Format(time.RFC3339))
			}
			fields := map[string]any{"kind": "uac_bypass_key", "location": label, "command": cmd, "user_sid": sid}
			if !lw.IsZero() {
				fields["key_last_write"] = lw
			}
			findings := []Finding{uacBypassFinding(k, label, cmd, when)}
			if strings.TrimSpace(cmd) != "" {
				findings = mergeFindings(findings, analyzeCommandLine("UAC bypass key "+label, "", cmd)...)
			}
			a.res.Add(fields, findings...)
			a.count++
			break // found under one of the two paths
		}
	}
}
