//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Linux process collector: reads /proc. Each process contributes its PID/PPID,
// parent name, image path (with deleted/memfd markers), command line, owning
// user, state and start time, and is judged by the Linux path and command-line
// heuristics. Access to another user's process files is denied without root, so
// those gaps are recorded per record rather than failing the run — the same
// posture as the Windows collector with protected processes.

// linuxClockTick is the near-universal USER_HZ. Reading the real value needs
// sysconf (cgo); start time is advisory, so the standard 100 Hz is assumed and
// the field is best-effort.
const linuxClockTick = 100

func collectProcesses(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("processes")

	pids, err := readProcPIDs()
	if err != nil && len(pids) == 0 {
		return res.Finish(), err
	}
	if err != nil {
		res.Fail(err.Error())
	}

	uidNames := uidNameMap(parsePasswd(readFileSafe("/etc/passwd")))
	btime, haveBtime := parseBtime(readFileSafe("/proc/stat"))

	rows := make([]linuxProcRow, 0, len(pids))
	nameByPID := make(map[int]string, len(pids))

	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		base := "/proc/" + strconv.Itoa(pid)
		st := parseProcStatus(readFileSafe(base + "/status"))
		name := st.Name
		if name == "" {
			name = strings.TrimSpace(string(readFileSafe(base + "/comm")))
		}
		nameByPID[pid] = name

		exe, exeErr := os.Readlink(base + "/exe")
		cmd := parseCmdline(readFileSafe(base + "/cmdline"))

		fields := map[string]any{"pid": pid, "name": name}
		if st.PPID >= 0 {
			fields["ppid"] = st.PPID
		}
		if st.State != "" {
			fields["state"] = st.State
		}
		kernel := false
		if exeErr == nil && exe != "" {
			fields["image_path"] = exe
			fields["suspicious_path"] = unixSuspiciousPath(exe)
		} else if os.IsNotExist(exeErr) {
			kernel = true // no exe target: a kernel thread (or it just exited)
			fields["kernel"] = true
		} else if exeErr != nil {
			fields["query_errors"] = []string{"exe: " + exeErr.Error()}
		}
		if cmd != "" {
			fields["command_line"] = cmd
		}
		if st.UID >= 0 {
			fields["uid"] = st.UID
			if u, ok := uidNames[st.UID]; ok {
				fields["user"] = u
			}
		}
		if ticks, ok := parseStarttimeTicks(readFileSafe(base + "/stat")); ok && haveBtime {
			fields["created_at"] = time.Unix(btime+int64(ticks)/linuxClockTick, 0).UTC()
		}
		self := opts.isSelf(uint32(pid), exe)
		if self {
			fields["lrng_component"] = true
		}
		rows = append(rows, linuxProcRow{pid: pid, st: st, exe: exe, cmd: cmd, kernel: kernel, self: self, fields: fields})
	}

	// Parent names from the PID->name map gathered above.
	for i := range rows {
		if ppid := rows[i].st.PPID; ppid > 0 {
			if pn, ok := nameByPID[ppid]; ok {
				rows[i].fields["parent_name"] = pn
			}
		}
	}

	hashed := 0
	for i := range rows {
		r := rows[i]
		var findings []Finding
		if !r.self {
			findings = linuxProcessFindings(r)
		}
		if opts.Hasher != nil && hashableImage(r.exe) && ctx.Err() == nil {
			opts.Hasher.Fields(ctx, r.fields, "image", r.exe)
			if _, ok := r.fields["image_sha256"]; ok {
				hashed++
			}
		}
		res.Add(r.fields, findings...)
	}

	res.SetMeta("platform", "linux")
	res.SetMeta("processes", len(rows))
	res.SetMeta("images_hashed", hashed)
	res.SetMeta("hashing", opts.Hasher != nil)
	if opts.Hasher != nil && ctx.Err() != nil {
		res.Fail("time budget ran out while hashing images; later records have no image_sha256")
	}
	return res.Finish(), nil
}

// hashableImage reports whether an exe path points at a real on-disk file worth
// hashing (not a deleted image or an anonymous memfd, which have no file).
func hashableImage(exe string) bool {
	return exe != "" && !strings.HasSuffix(exe, " (deleted)") && !strings.Contains(exe, "memfd:")
}

// linuxProcRow is one process as gathered from /proc, before findings.
type linuxProcRow struct {
	pid    int
	st     procStatus
	exe    string
	cmd    string
	kernel bool
	self   bool
	fields map[string]any
}

// linuxProcessFindings judges one process by its image location, its fileless
// markers, a masqueraded kernel-thread name, and its command line.
func linuxProcessFindings(r linuxProcRow) []Finding {
	label := fmt.Sprintf("process %s (pid %d)", r.st.Name, r.pid)
	var out []Finding

	switch {
	case strings.Contains(r.exe, "memfd:"):
		out = append(out, Finding{
			Rule: "process.memfd_exec", Severity: SevSuspect, Technique: "T1620", Confidence: 80,
			Detail: fmt.Sprintf("%s runs from an anonymous in-memory file (%s) — fileless execution, nothing on disk to inspect", label, r.exe),
		})
	case strings.HasSuffix(r.exe, " (deleted)"):
		out = append(out, Finding{
			Rule: "process.deleted_binary", Severity: SevSuspect, Technique: "T1070.004", Confidence: 70,
			Detail: fmt.Sprintf("%s is running from a deleted executable (%s) — self-deleting malware removes the file but keeps running", label, r.exe),
		})
	case r.exe != "":
		if lvl, why := unixPathRisk(r.exe); lvl == riskHigh {
			out = append(out, Finding{
				Rule: "process.unusual_exec_path", Severity: SevSuspect, Technique: "T1036", Confidence: 60,
				Detail: fmt.Sprintf("%s runs from %s (%s)", label, why, r.exe),
			})
		} else if lvl == riskLow {
			out = append(out, Finding{
				Rule: "process.unusual_exec_path", Severity: SevNotable, Technique: "T1036", Confidence: 35,
				Detail: fmt.Sprintf("%s runs from %s (%s)", label, why, r.exe),
			})
		}
	}

	// A userland process wearing a kernel-thread name is masquerading: real
	// kernel threads have no executable, so anything with an exe whose name looks
	// like "kworker/…" (bare, or the bracketed form ps prints) is suspect.
	if !r.kernel && r.exe != "" && looksLikeKernelThreadName(r.st.Name) {
		out = append(out, Finding{
			Rule: "process.kthread_masquerade", Severity: SevSuspect, Technique: "T1036.004", Confidence: 70,
			Detail: fmt.Sprintf("%s has a kernel-thread name but a real executable (%s) — real kernel threads have none", label, r.exe),
		})
	}

	if r.cmd != "" {
		out = mergeFindings(out, analyzeUnixCommandLine(label+" command line", r.exe, r.cmd)...)
	}
	return out
}

// readProcPIDs returns the numeric PID entries under /proc, sorted ascending.
// os.ReadDir sorts by name, which is lexicographic ("10" before "2"), so the
// numeric sort is applied explicitly to give a natural, stable record order.
func readProcPIDs() ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids, nil
}

// kernelThreadNamePrefixes are comm prefixes that real (exe-less) kernel threads
// use. A process that has an executable but whose comm matches one is
// masquerading as a kernel thread (T1036.004). The list is intentionally limited
// to distinctly-kernel names to avoid flagging ordinary processes.
var kernelThreadNamePrefixes = []string{
	"kworker/", "ksoftirqd/", "migration/", "rcu_", "rcuc/", "rcub/", "rcuop/", "rcuog/",
	"watchdog/", "kthreadd", "kswapd", "kcompactd", "khugepaged", "kintegrityd", "kblockd",
	"kdevtmpfs", "kauditd", "khungtaskd", "ksmd", "kcryptd", "kthrotld", "oom_reaper",
	"cpuhp/", "idle_inject/", "irq/", "jbd2/", "scsi_eh_", "scsi_tmf_",
}

// looksLikeKernelThreadName reports whether comm matches a kernel-thread naming
// pattern — the bare name, or the bracketed form ps prints (which malware may
// bake into its comm to blend into ps output).
func looksLikeKernelThreadName(comm string) bool {
	comm = strings.TrimPrefix(comm, "[")
	for _, p := range kernelThreadNamePrefixes {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// readFileSafe reads a file, returning nil (not an error) when it can't be read:
// /proc entries vanish and permission is denied for other users' files, and in
// both cases a missing field is better than a failed run.
func readFileSafe(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}
