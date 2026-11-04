package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// AdaptiveOptions bounds a single deterministic follow-up pass. Imported
// telemetry never supplies file-read targets. No command or payload executes.
type AdaptiveOptions struct {
	MaxFiles int
	Budget   time.Duration
	NoHash   bool
	NoSign   bool
}

type adaptiveTask struct {
	path     string
	severity Severity
	rules    []string
	refs     []EvidenceRef
}

// RunAdaptive collects metadata and bounded hashes of suspect/critical local
// executable paths already named by live collectors. It makes one pass, never
// recursively expands its findings, and leaves original observations intact.
func RunAdaptive(ctx context.Context, results []Result, opts AdaptiveOptions) Result {
	tasks := planAdaptive(results)
	if opts.MaxFiles < 1 {
		opts.MaxFiles = 20
	}
	opts.MaxFiles = min(opts.MaxFiles, 200)
	if opts.Budget <= 0 {
		opts.Budget = 15 * time.Second
	}
	c := &adaptiveCollector{tasks: tasks, opts: opts}
	d := Dispatcher{Workers: 1, Timeout: opts.Budget}
	return d.Run(ctx, []Collector{c})[0]
}

type adaptiveCollector struct {
	tasks []adaptiveTask
	opts  AdaptiveOptions
}

func (*adaptiveCollector) Name() string        { return "adaptive" }
func (*adaptiveCollector) Platforms() []string { return []string{"windows", "linux"} }

func (c *adaptiveCollector) Collect(ctx context.Context) (Result, error) {
	r := NewResult("adaptive")
	remaining := int64(64 << 20)
	var signer *SignatureVerifier
	if !c.opts.NoSign && runtime.GOOS == "windows" {
		signer = NewSignatureVerifier()
	}
	for i, t := range c.tasks {
		if i >= c.opts.MaxFiles {
			break
		}
		f := map[string]any{"action": "file_metadata", "path": t.path, "trigger_rules": t.rules, "trigger_severity": t.severity, "source_refs": t.refs}
		if ctx.Err() != nil {
			f["status"] = "skipped"
			f["reason"] = "time budget exhausted or run interrupted"
			r.Add(f)
			continue
		}
		info, err := os.Lstat(t.path)
		if err != nil {
			f["status"] = "error"
			f["reason"] = err.Error()
			r.Add(f)
			continue
		}
		if !info.Mode().IsRegular() {
			f["status"] = "skipped"
			f["reason"] = "target is not a regular file (symlinks and devices excluded)"
			r.Add(f)
			continue
		}
		f["size"] = info.Size()
		f["modified_at"] = info.ModTime().UTC()
		f["status"] = "collected"
		if c.opts.NoHash {
			f["hash_status"] = "disabled"
		} else {
			limit := min(int64(8<<20), remaining)
			if info.Size() > limit {
				f["hash_status"] = "skipped: byte budget"
			} else {
				// Reserve before reading, so failed reads cannot evade the cap.
				remaining -= info.Size()
				h := adaptiveHash(ctx, t.path, info, info.Size())
				if h.Err != "" {
					f["hash_status"] = h.Err
				} else {
					f["sha256"] = h.SHA256
				}
			}
		}
		if signer != nil && ctx.Err() == nil && info.Size() <= 8<<20 {
			s := signer.Verify(ctx, t.path)
			f["signature_state"] = s.State.String()
			if s.Signer != "" {
				f["signer"] = s.Signer
			}
		}
		r.Add(f)
	}
	r.SetMeta("strategy", "one deterministic pass over executable paths on suspect/critical live records; no commands, memory scans, or remediation")
	r.SetMeta("planned_files", len(c.tasks))
	r.SetMeta("file_limit", c.opts.MaxFiles)
	r.SetMeta("uncollected_files", max(0, len(c.tasks)-len(r.Records)))
	r.SetMeta("budget", c.opts.Budget.String())
	r.SetMeta("hash_byte_limit", 64<<20)
	r.SetMeta("hash_bytes_reserved", (64<<20)-remaining)
	r.SetMeta("note", "A follow-up is a later file observation; paths may have changed since the triggering record. Source findings are not duplicated.")
	if ctx.Err() != nil {
		r.Fail("adaptive collection interrupted: " + ctx.Err().Error())
	}
	return r.Finish(), nil
}

// Hash a regular file through a strict byte limiter and reject a file that
// changed after the metadata check. A changing file is not a complete image.
func adaptiveHash(ctx context.Context, path string, expected os.FileInfo, limit int64) HashResult {
	f, err := os.Open(path)
	if err != nil {
		return HashResult{Err: err.Error()}
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(expected, before) || before.Size() != expected.Size() || !before.ModTime().Equal(expected.ModTime()) {
		return HashResult{Err: "file identity changed before hashing"}
	}
	if before.Size() > limit {
		return HashResult{Err: "file exceeds remaining hash byte budget"}
	}
	h := sha256.New()
	reader := io.LimitReader(f, limit)
	buf := make([]byte, 32<<10)
	var size int64
	for {
		if ctx.Err() != nil {
			return HashResult{Err: "hash interrupted"}
		}
		n, err := reader.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			size += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return HashResult{Err: err.Error()}
		}
	}
	after, err := f.Stat()
	if err != nil || after.Size() != size || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return HashResult{Err: "file changed while hashing; digest omitted"}
	}
	return HashResult{SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}
}

func planAdaptive(results []Result) []adaptiveTask {
	byPath := map[string]*adaptiveTask{}
	for ri, r := range results {
		// Only known live inventories can cause extra file reads. In
		// particular, events and imported traces cannot name arbitrary targets.
		switch r.Collector {
		case "processes", "services", "autoruns", "scheduledtasks", "modules", "drivers":
		default:
			continue
		}
		for i, rec := range r.Records {
			_, sev := topFinding(rec)
			if SeverityRank(sev) < SeverityRank(SevSuspect) {
				continue
			}
			// Do not treat a configuration's own path or event data as an
			// executable target merely because the graph can display it.
			executableFields := map[string]any{}
			for _, k := range []string{"image_path", "image", "executable", "actions"} {
				executableFields[k] = rec.Fields[k]
			}
			if r.Collector == "drivers" {
				executableFields["image"] = rec.Fields["path"]
			}
			if r.Collector == "modules" {
				executableFields["image"] = rec.Fields["path"]
				// Linux emits one process record with nested module paths.
				executableFields["actions"] = rec.Fields["modules"]
			}
			for _, p := range graphPaths(executableFields) {
				if !adaptiveLocalPath(p) {
					continue
				}
				k := pathKey(p)
				task := byPath[k]
				if task == nil {
					task = &adaptiveTask{path: p}
					byPath[k] = task
				}
				if SeverityRank(sev) > SeverityRank(task.severity) {
					task.severity = sev
				}
				if len(task.refs) < 20 {
					task.refs = append(task.refs, EvidenceRef{ri, i})
				}
				for _, finding := range rec.Findings {
					if SeverityRank(finding.Severity) < SeverityRank(SevSuspect) {
						continue
					}
					found := false
					for _, rule := range task.rules {
						found = found || rule == finding.Rule
					}
					if !found && len(task.rules) < 20 {
						task.rules = append(task.rules, finding.Rule)
					}
				}
			}
		}
	}
	tasks := make([]adaptiveTask, 0, len(byPath))
	for _, task := range byPath {
		sort.Strings(task.rules)
		tasks = append(tasks, *task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		if a, b := SeverityRank(tasks[i].severity), SeverityRank(tasks[j].severity); a != b {
			return a > b
		}
		return tasks[i].path < tasks[j].path
	})
	return tasks
}

func adaptiveLocalPath(path string) bool {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00%") {
		return false
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
		return false
	}
	if runtime.GOOS == "windows" {
		// Reject device namespaces, ADS and non-drive paths.
		return len(path) > 3 && path[1] == ':' && !strings.Contains(path[2:], ":")
	}
	p := filepath.Clean(path)
	for _, root := range []string{"/dev", "/proc", "/sys"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return false
		}
	}
	return true
}
