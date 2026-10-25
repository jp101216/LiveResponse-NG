package collector

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Scheduled-task heuristics: what each action runs, and whether the task
// store and the Task Scheduler's registry cache agree. No build tag: pure
// logic, unit-tested on any OS.

// taskCacheEntry is one task registered under
// HKLM\...\Schedule\TaskCache\Tree.
type taskCacheEntry struct {
	Path      string // \Folder\TaskName, as Task Scheduler names it
	ID        string // {GUID} of the TaskCache\Tasks entry
	HasSD     bool   // the "SD" security descriptor value is present
	Index     uint32
	HasIndex  bool
	LastWrite time.Time
}

// taskCommand renders an Exec action as one command line.
func taskCommand(e taskExec) string {
	cmd := strings.TrimSpace(e.Command)
	if strings.ContainsAny(cmd, " \t") && !strings.HasPrefix(cmd, `"`) {
		cmd = `"` + cmd + `"`
	}
	return strings.TrimSpace(cmd + " " + e.Arguments)
}

// judgeTask returns the findings for one task definition.
func judgeTask(taskPath string, def taskDef) []Finding {
	var out []Finding
	for i, e := range def.Execs {
		cmd := taskCommand(e)
		lvl, why, culprit := commandPathRisk(cmd)
		// A bare program name runs from the working directory if it's there.
		if !strings.ContainsAny(e.Command, `\/%`) && e.WorkingDirectory != "" {
			if l, w := pathRisk(e.WorkingDirectory + `\` + e.Command); l > lvl {
				lvl, why, culprit = l, w, e.WorkingDirectory+`\`+e.Command
			}
		}
		if lvl != riskNone {
			sev, conf := SevSuspect, 60
			if lvl == riskLow {
				sev, conf = SevNotable, 35
			}
			if def.Hidden {
				conf += 15
			}
			out = mergeFindings(out, Finding{
				Rule: "persistence.scheduled_task_unusual_path", Severity: sev, Technique: "T1053.005", Confidence: conf,
				Detail: fmt.Sprintf("scheduled task %s action %d runs code from %s: %s", taskPath, i+1, why, culprit),
			})
		}
		out = mergeFindings(out, analyzeCommandLine(fmt.Sprintf("scheduled task %s action %d", taskPath, i+1), e.Command, cmd)...)
	}
	return out
}

// taskCacheFindings cross-checks the task files against the registry cache:
//
//   - a registered task with no "SD" value is hidden from schtasks and the
//     Task Scheduler UI while it keeps running (the HAFNIUM "Tarrask"
//     technique) — critical;
//   - a registered task whose definition file is gone keeps running from the
//     registry with no file to inspect;
//   - a task file with no registration was dropped or orphaned outside the
//     Task Scheduler.
//
// It returns findings keyed by lower-case task path, and the registered tasks
// that have no file (so they can be reported as records of their own). A file
// is only called unregistered when the cache was read completely.
func taskCacheFindings(filePaths []string, cache []taskCacheEntry, complete bool) (map[string][]Finding, []taskCacheEntry) {
	out := map[string][]Finding{}
	files := map[string]bool{}
	for _, p := range filePaths {
		files[strings.ToLower(p)] = true
	}
	registered := map[string]bool{}
	var registryOnly []taskCacheEntry
	for _, c := range cache {
		key := strings.ToLower(c.Path)
		registered[key] = true
		if !c.HasSD {
			out[key] = append(out[key], Finding{
				Rule: "persistence.scheduled_task_hidden", Severity: SevCritical, Technique: "T1053.005", Confidence: 85,
				Detail: fmt.Sprintf("scheduled task %s has no security descriptor (SD) in TaskCache\\Tree: it is hidden from schtasks "+
					"and the Task Scheduler UI but still runs (Tarrask technique, T1564)", c.Path),
			})
		}
		if !files[key] {
			registryOnly = append(registryOnly, c)
			out[key] = append(out[key], Finding{
				Rule: "persistence.scheduled_task_no_file", Severity: SevNotable, Technique: "T1053.005", Confidence: 45,
				Detail: fmt.Sprintf("scheduled task %s is registered in TaskCache but its definition file is missing from the task store", c.Path),
			})
		}
	}
	if complete && len(cache) > 0 {
		for _, p := range filePaths {
			key := strings.ToLower(p)
			if !registered[key] {
				out[key] = append(out[key], Finding{
					Rule: "persistence.scheduled_task_unregistered", Severity: SevNotable, Technique: "T1053.005", Confidence: 35,
					Detail: fmt.Sprintf("task file %s is in the task store but not registered in TaskCache (dropped or orphaned outside the Task Scheduler)", p),
				})
			}
		}
	}
	sort.Slice(registryOnly, func(i, j int) bool { return registryOnly[i].Path < registryOnly[j].Path })
	return out, registryOnly
}

// taskPathFromFile maps a file under the task store to its task path:
// C:\Windows\System32\Tasks\Microsoft\X -> \Microsoft\X.
func taskPathFromFile(tasksDir, file string) string {
	rel, err := filepath.Rel(tasksDir, file)
	if err != nil {
		return file
	}
	return `\` + strings.ReplaceAll(filepath.ToSlash(rel), "/", `\`)
}
