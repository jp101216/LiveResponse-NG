//go:build windows

package collector

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const (
	// maxTaskFileBytes caps a single task-definition read. Task XML is small;
	// a much larger file is suspect in itself and is recorded, not read.
	maxTaskFileBytes = 1 << 20
	taskCacheTreeKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
	maxTaskCacheKeys = 50000
)

type taskFile struct {
	path, taskPath string
	info           fs.FileInfo
	def            taskDef
	err            string
}

func collectScheduledTasks(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("scheduledtasks")
	tasksDir := filepath.Join(systemRoot(), `System32`, `Tasks`)
	res.SetMeta("tasks_dir", tasksDir)

	var files []taskFile
	walkErr := filepath.WalkDir(tasksDir, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			res.Fail(path + ": " + err.Error())
			return nil // keep walking siblings
		}
		if d.IsDir() {
			return nil
		}
		tf := taskFile{path: path, taskPath: taskPathFromFile(tasksDir, path)}
		info, err := d.Info()
		if err != nil {
			res.Fail(path + ": " + err.Error())
			return nil
		}
		tf.info = info
		switch {
		case info.Size() > maxTaskFileBytes:
			tf.err = "task file too large to parse"
		default:
			raw, err := os.ReadFile(path)
			if err != nil {
				tf.err = err.Error()
				break
			}
			if tf.def, err = parseTaskXML(raw); err != nil {
				tf.err = "parse: " + err.Error()
			}
		}
		files = append(files, tf)
		return nil
	})
	if walkErr != nil && ctx.Err() != nil {
		res.Fail("cancelled: " + ctx.Err().Error())
	} else if walkErr != nil {
		res.Fail(walkErr.Error())
	}

	cache, cacheErr := readTaskCache()
	if cacheErr != nil {
		res.Fail("TaskCache: " + cacheErr.Error())
	}
	res.SetMeta("task_files", len(files))
	res.SetMeta("taskcache_tasks", len(cache))
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.taskPath
	}
	cacheFindings, registryOnly := taskCacheFindings(paths, cache, cacheErr == nil)
	byPath := map[string]taskCacheEntry{}
	for _, c := range cache {
		byPath[strings.ToLower(c.Path)] = c
	}

	sysRoot := systemRoot()
	for _, tf := range files {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		fields := taskFields(tf)
		if c, ok := byPath[strings.ToLower(tf.taskPath)]; ok {
			addTaskCacheFields(fields, c)
		} else if cacheErr == nil && len(cache) > 0 {
			fields["registered"] = false
		}
		var findings []Finding
		if tf.err == "" {
			findings = judgeTask(tf.taskPath, tf.def)
			if opts.Hasher != nil {
				for i, e := range tf.def.Execs {
					img := normalizeImage(imageFromCommand(taskCommand(e)))
					if strings.ContainsAny(img, `\/`) && (len(findings) > 0 || !underDir(img, sysRoot)) {
						opts.Hasher.Fields(ctx, fields["actions"].([]map[string]any)[i], "image", img)
					}
				}
			}
		} else {
			fields["parse_error"] = tf.err
		}
		findings = mergeFindings(findings, cacheFindings[strings.ToLower(tf.taskPath)]...)
		fields["suspicious_path"] = hasRule(findings, "persistence.scheduled_task_unusual_path")
		res.Add(fields, findings...)
	}

	// Tasks the Task Scheduler runs from its registry cache with no file.
	for _, c := range registryOnly {
		fields := map[string]any{"task_path": c.Path, "source": "taskcache_only"}
		addTaskCacheFields(fields, c)
		res.Add(fields, cacheFindings[strings.ToLower(c.Path)]...)
	}
	return res.Finish(), nil
}

func addTaskCacheFields(fields map[string]any, c taskCacheEntry) {
	fields["registered"] = true
	if c.ID != "" {
		fields["task_id"] = c.ID
	}
	fields["has_security_descriptor"] = c.HasSD
	if c.HasIndex {
		fields["taskcache_index"] = c.Index
	}
	if !c.LastWrite.IsZero() {
		fields["taskcache_last_write"] = c.LastWrite
	}
}

// taskFields turns a parsed definition into a record.
func taskFields(tf taskFile) map[string]any {
	def := tf.def
	fields := map[string]any{"task_path": tf.taskPath, "file": tf.path}
	if tf.info != nil {
		addFileTimes(fields, "file_", tf.info)
	}
	if tf.err != "" {
		return fields
	}
	fields["enabled"] = def.Enabled
	if def.Hidden {
		fields["hidden"] = true
	}
	for k, v := range map[string]string{
		"author": def.Author, "description": def.Description, "registered_date": def.Date,
		"run_as": def.RunAs, "logon_type": def.LogonType, "run_level": def.RunLevel,
	} {
		if v != "" {
			fields[k] = v
		}
	}
	if len(def.Triggers) > 0 {
		fields["triggers"] = def.Triggers
	}
	if len(def.ComHandlers) > 0 {
		fields["com_handlers"] = def.ComHandlers
	}
	actions := make([]map[string]any, 0, len(def.Execs))
	for _, e := range def.Execs {
		a := map[string]any{"command": e.Command}
		if e.Arguments != "" {
			a["arguments"] = e.Arguments
		}
		if e.WorkingDirectory != "" {
			a["working_directory"] = e.WorkingDirectory
		}
		if img := imageFromCommand(taskCommand(e)); img != "" {
			a["image"] = normalizeImage(img)
		}
		actions = append(actions, a)
	}
	fields["actions"] = actions
	return fields
}

// readTaskCache walks TaskCache\Tree. Folders and tasks are both keys; a task
// is a key with an "Id" value.
func readTaskCache() ([]taskCacheEntry, error) {
	var out []taskCacheEntry
	visited := 0
	var walk func(path, rel string, depth int) error
	walk = func(path, rel string, depth int) error {
		if depth > 32 || visited > maxTaskCacheKeys {
			return nil
		}
		visited++
		k, err := winreg.Open(winreg.LocalMachine, path)
		if err != nil {
			return err
		}
		vals, verr := k.Values()
		subs, serr := k.SubKeys()
		lw := k.LastWrite()
		k.Close()
		if verr == nil && rel != "" {
			e := taskCacheEntry{Path: rel, LastWrite: lw}
			isTask := false
			for _, v := range vals {
				switch strings.ToLower(v.Name) {
				case "id":
					e.ID, isTask = v.String(), true
				case "sd":
					e.HasSD = len(v.Data) > 0
				case "index":
					e.Index, e.HasIndex = v.Uint32()
				}
			}
			if isTask {
				out = append(out, e)
			}
		}
		if serr != nil {
			return serr
		}
		for _, s := range subs {
			if err := walk(path+`\`+s, rel+`\`+s, depth+1); err != nil && !winreg.IsNotExist(err) {
				return err
			}
		}
		return nil
	}
	err := walk(taskCacheTreeKey, "", 0)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}
