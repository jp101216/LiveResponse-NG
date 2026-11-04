//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

type runHistoryCollector struct{}

func (*runHistoryCollector) Name() string        { return "runhistory" }
func (*runHistoryCollector) Platforms() []string { return []string{"windows"} }
func (*runHistoryCollector) Collect(ctx context.Context) (Result, error) {
	r := NewResult("runhistory")
	sids, err := loadedUserHives()
	if err != nil {
		return r.Finish(), err
	}
	const rel = `Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`
	for _, sid := range sids {
		if ctx.Err() != nil {
			r.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		key, err := winreg.Open(winreg.Users, sid+`\`+rel)
		if err != nil {
			if !winreg.IsNotExist(err) {
				r.Fail(fmt.Sprintf("RunMRU %s: %v", sid, err))
			}
			continue
		}
		// RunMRU uses single-letter entries: reject surprising registry shapes
		// before Values allocates a buffer based on registry-controlled lengths.
		info, err := key.Info()
		if err != nil || info.Values > 64 || info.MaxValueLen > 128<<10 || info.MaxValueNameLen > 64 {
			key.Close()
			r.Fail("RunMRU key unreadable or exceeds value limits: " + sid)
			continue
		}
		values, err := key.Values()
		key.Close()
		if err != nil {
			r.Fail(fmt.Sprintf("RunMRU %s: %v", sid, err))
		}
		for _, v := range values {
			if len(v.Name) != 1 || v.Name[0] < 'a' || v.Name[0] > 'z' || v.Type != winreg.TypeSZ {
				continue
			}
			cmd := strings.TrimSuffix(v.String(), `\1`)
			fs := analyzeCommandLine("Run-dialog history", imageFromCommand(cmd), cmd)
			for i := range fs {
				fs[i].Detail = redactSecrets(fs[i].Detail)
			}
			if len(fs) > 0 {
				fs = mergeFindings(fs, Finding{"execution.run_dialog_payload", SevNotable, "T1204.004", 45,
					"a command in Run-dialog history matches execution heuristics; history records an entered command, not successful execution or the source of a lure"})
			}
			r.Add(map[string]any{"user_sid": sid, "registry_key": `HKU\` + sid + `\` + rel, "value_name": v.Name,
				"command": redactSecrets(cmd), "command_sha256": commandDigest(cmd), "key_last_write": info.LastWrite}, fs...)
		}
	}
	r.SetMeta("loaded_user_hives", len(sids))
	r.SetMeta("coverage", "loaded user hives only; key_last_write is shared by the entire key and is not an individual command execution time; no clipboard contents collected")
	return r.Finish(), nil
}

func init() { Register(&runHistoryCollector{}) }
