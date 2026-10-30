package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/sidecar"
)

const (
	defaultMemBudget  = 60 * time.Second
	defaultMemTimeout = 15 * time.Minute
	defaultMemWorkers = 2
)

// memoryCollector scans live process memory with YARA rules and the module-B
// prompt scanner, via the Rust sidecar. It's opt-in (expensive and intrusive)
// and has its own timeout, since a full scan takes minutes, not seconds.
//
// PIDs are split across a few sidecar processes; each compiles the rules once
// and streams back one result per PID, so whatever finished before a timeout
// is kept.
type memoryCollector struct {
	opts RunOptions
}

func (*memoryCollector) Name() string        { return "memory" }
func (*memoryCollector) Platforms() []string { return []string{"windows", "linux"} }
func (*memoryCollector) OptIn() bool         { return true }

func (c *memoryCollector) Configure(o RunOptions) { c.opts = o }

func (c *memoryCollector) Timeout() time.Duration {
	if c.opts.Memory.Timeout > 0 {
		return c.opts.Memory.Timeout
	}
	return defaultMemTimeout
}

func init() { Register(&memoryCollector{}) }

// procInfo is one process as seen by the platform process lister.
type procInfo struct {
	PID    int
	Name   string
	Path   string
	Kernel bool // no user-mode memory to scan (Windows Idle/System, Linux kernel threads)
	Zombie bool // exited but not yet reaped (Linux): no memory left to scan
}

type memSkip struct {
	proc   procInfo
	reason string
}

func (c *memoryCollector) Collect(ctx context.Context) (Result, error) {
	res := NewResult("memory")
	mo := c.opts.Memory
	budget := mo.Budget
	if budget <= 0 {
		budget = defaultMemBudget
	}
	workers := mo.Workers
	if workers < 1 {
		workers = defaultMemWorkers
	}

	client, err := sidecar.New(c.opts.SidecarPath)
	if err != nil {
		return res.Finish(), err
	}
	procs, err := listProcesses()
	if err != nil {
		return res.Finish(), fmt.Errorf("list processes: %w", err)
	}

	exe, _ := os.Executable()
	targets, skipped := selectMemoryTargets(procs, mo.PIDs, os.Getpid(), []string{exe, client.Path})

	// Spread targets round-robin so big processes don't all land on one worker.
	if workers > len(targets) {
		workers = len(targets)
	}
	batches := make([][]int, workers)
	for i, t := range targets {
		batches[i%workers] = append(batches[i%workers], t.PID)
	}

	prompts := !mo.NoPrompts
	var (
		mu         sync.Mutex
		responses  = map[int]*sidecar.Response{}
		streamErrs []string
		wg         sync.WaitGroup
	)
	for _, b := range batches {
		wg.Add(1)
		go func(pids []int) {
			defer wg.Done()
			err := client.Stream(ctx, sidecar.Request{
				Op:               sidecar.OpScanMemory,
				PIDs:             pids,
				RulesPath:        mo.YaraRules,
				Prompts:          &prompts,
				BudgetMS:         budget.Milliseconds(),
				IncludeSensitive: mo.IncludeSensitive,
			}, func(r *sidecar.Response) {
				mu.Lock()
				responses[int(r.MetaInt("pid"))] = r
				mu.Unlock()
			})
			if err != nil {
				mu.Lock()
				streamErrs = append(streamErrs, err.Error())
				mu.Unlock()
			}
		}(b)
	}
	wg.Wait()

	for _, e := range dedupe(streamErrs) {
		res.Fail(e)
	}
	recs, counts, rulesMeta := memoryRecords(targets, skipped, responses)
	for _, r := range recs {
		res.Add(r.Fields, r.Findings...)
	}
	// A rules problem fails every PID identically; surface it once. Rule
	// files that didn't compile are a coverage gap, so they count as errors
	// too (details in meta.yara.rules_failed).
	if msg, ok := commonRulesError(responses); ok {
		res.Fail(msg)
	}
	if m, ok := rulesMeta.(map[string]any); ok {
		if failed, _ := m["rules_failed"].([]any); len(failed) > 0 {
			res.Fail(fmt.Sprintf("%d YARA rule file(s) failed to compile and were not used; see meta.yara.rules_failed", len(failed)))
		}
	}

	res.SetMeta("targets", len(targets))
	res.SetMeta("status_counts", counts)
	res.SetMeta("yara_rules", mo.YaraRules)
	if rulesMeta != nil {
		res.SetMeta("yara", rulesMeta)
	}
	res.SetMeta("prompt_scan", prompts)
	res.SetMeta("budget_per_process", budget.String())
	res.SetMeta("workers", workers)
	res.SetMeta("include_sensitive", mo.IncludeSensitive)
	res.SetMeta("sidecar", client.Path)
	return res.Finish(), nil
}

// selectMemoryTargets picks which processes to scan and records why the
// others aren't scanned. lrng itself, its sidecar, and kernel-only processes
// are always skipped (lrng's own memory holds the strings its rules look for).
func selectMemoryTargets(procs []procInfo, want []int, self int, exclude []string) ([]procInfo, []memSkip) {
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	wantSet := map[int]bool{}
	for _, p := range want {
		wantSet[p] = true
	}
	exclude = resolvePaths(exclude) // once, not once per process

	var (
		targets []procInfo
		skipped []memSkip
		seen    = map[int]bool{}
	)
	for _, p := range procs {
		if len(wantSet) > 0 && !wantSet[p.PID] {
			continue
		}
		seen[p.PID] = true
		switch {
		case p.PID == self:
			skipped = append(skipped, memSkip{p, "lrng itself"})
		case p.Kernel:
			skipped = append(skipped, memSkip{p, "kernel process: no user-mode memory"})
		case p.Zombie:
			skipped = append(skipped, memSkip{p, "zombie process: it has exited and holds no memory"})
		case samePath(p.Path, exclude):
			skipped = append(skipped, memSkip{p, "lrng component"})
		default:
			targets = append(targets, p)
		}
	}
	for _, pid := range want {
		if !seen[pid] {
			seen[pid] = true
			skipped = append(skipped, memSkip{procInfo{PID: pid}, "no such process"})
		}
	}
	return targets, skipped
}

// resolvePaths adds the symlink-resolved form of each path, so a process
// started through a link still matches.
func resolvePaths(paths []string) []string {
	out := make([]string, 0, 2*len(paths))
	for _, q := range paths {
		if q == "" {
			continue
		}
		out = append(out, q)
		if r, err := filepath.EvalSymlinks(q); err == nil && r != q {
			out = append(out, r)
		}
	}
	return out
}

func samePath(p string, list []string) bool {
	if p == "" {
		return false
	}
	for _, q := range list {
		if p == q || (runtime.GOOS == "windows" && strings.EqualFold(p, q)) {
			return true
		}
	}
	return false
}

// memoryRecordKeys are the per-process sidecar meta values copied into each
// memory record.
var memoryRecordKeys = []string{
	"regions_total", "regions_scanned", "bytes_total", "bytes_scanned", "coverage_pct",
	"read_failures", "elapsed_ms", "stopped_early", "hits_truncated",
	"prompt_verdict", "prompt_score",
	"unbacked_exec_regions", "unbacked_rwx_regions", "memory_heuristic_hits", "memory_heuristics_truncated",
	// The image-integrity pass: images and code compared, rewrites, patches,
	// header mismatches, unreadable backing files, and why anything was skipped.
	"image_integrity",
}

// memoryRecords turns sidecar responses into one record per process (every
// target and every skip, so coverage gaps are visible) in PID order.
func memoryRecords(targets []procInfo, skipped []memSkip, responses map[int]*sidecar.Response) ([]Record, map[string]int, any) {
	counts := map[string]int{}
	var rulesMeta any
	type row struct {
		pid int
		rec Record
	}
	var rows []row

	for _, s := range skipped {
		f := map[string]any{"pid": s.proc.PID, "status": "skipped", "reason": s.reason}
		if s.proc.Name != "" {
			f["name"] = s.proc.Name
		}
		if s.proc.Path != "" {
			f["image_path"] = s.proc.Path
		}
		counts["skipped"]++
		rows = append(rows, row{s.proc.PID, Record{Fields: f}})
	}

	for _, t := range targets {
		f := map[string]any{"pid": t.PID, "name": t.Name}
		if t.Path != "" {
			f["image_path"] = t.Path
		}
		r, ok := responses[t.PID]
		if !ok {
			f["status"] = "not_reached"
			f["error"] = "not scanned: the memory collector timed out or its sidecar stopped first"
			counts["not_reached"]++
			rows = append(rows, row{t.PID, Record{Fields: f}})
			continue
		}
		status := r.MetaString("status")
		if status == "" {
			status = "error"
		}
		f["status"] = status
		counts[status]++
		if r.Error != "" {
			f["error"] = r.Error
		}
		if img := r.MetaString("image"); img != "" {
			f["image_path"] = img
		}
		for _, k := range memoryRecordKeys {
			if v, ok := r.Meta[k]; ok && v != nil {
				f[k] = v
			}
		}
		if y, ok := r.Meta["yara"]; ok && y != nil && rulesMeta == nil {
			rulesMeta = summarizeRulesMeta(y)
		}
		var findings []Finding
		for _, h := range r.Hits {
			findings = append(findings, hitToFinding(h))
		}
		rows = append(rows, row{t.PID, Record{Fields: f, Findings: findings}})
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].pid < rows[j].pid })
	out := make([]Record, len(rows))
	for i, r := range rows {
		out[i] = r.rec
	}
	return out, counts, rulesMeta
}

// summarizeRulesMeta keeps the run-wide part of a response's YARA metadata
// (rule counts, failures) and drops the per-process match count.
func summarizeRulesMeta(y any) any {
	m, ok := y.(map[string]any)
	if !ok {
		return y
	}
	out := map[string]any{}
	for k, v := range m {
		if k != "matched_rules" && k != "error" {
			out[k] = v
		}
	}
	return out
}

func commonRulesError(responses map[int]*sidecar.Response) (string, bool) {
	for _, r := range responses {
		if strings.HasPrefix(r.Error, "rules:") {
			return r.Error, true
		}
	}
	return "", false
}

var validSeverity = map[Severity]bool{SevInfo: true, SevNotable: true, SevSuspect: true, SevCritical: true}

// hitToFinding maps a sidecar hit onto a Finding, describing where in memory
// it was found. It carries no raw memory bytes.
func hitToFinding(h sidecar.Hit) Finding {
	sev := Severity(h.Severity)
	if !validSeverity[sev] {
		sev = SevSuspect
	}
	conf := h.Confidence
	if conf < 0 {
		conf = 0
	} else if conf > 100 {
		conf = 100
	}

	where := fmt.Sprintf("at 0x%x", uint64(h.Offset))
	if h.Region == nil && h.Offset == 0 {
		where = "(condition-only rule, no pattern match address)"
	}
	if r := h.Region; r != nil {
		where += fmt.Sprintf(" in %s %s region 0x%x (%s)", r.Kind, r.Protect, r.Base, humanBytes(r.Size))
		if r.File != "" {
			where += " " + r.File
		}
	}
	if h.Encoding != "" {
		where += " [" + h.Encoding + "]"
	}
	return Finding{
		Rule:       h.Rule,
		Severity:   sev,
		Technique:  h.Technique,
		Confidence: conf,
		Detail:     where + ": " + h.Context,
	}
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
