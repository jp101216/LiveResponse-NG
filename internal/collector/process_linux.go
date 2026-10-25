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
		pst, havePst := parseProcStat(readFileSafe(base + "/stat"))

		fields := map[string]any{"pid": pid, "name": name}
		if st.PPID >= 0 {
			fields["ppid"] = st.PPID
		}
		if st.State != "" {
			fields["state"] = st.State
		}
		// A kernel thread is told by the kernel's PF_KTHREAD flag. Without
		// /proc/<pid>/stat, fall back to "no exe target and no argv" — which a
		// zombie also matches, so the flag is preferred whenever it can be read.
		kernel := false
		switch {
		case havePst:
			kernel = pst.kernelThread()
		case os.IsNotExist(exeErr) && cmd == "":
			kernel = true
		}
		replaced := false
		switch {
		case exeErr == nil && exe != "":
			fields["image_path"] = exe
			fields["suspicious_path"] = unixSuspiciousPath(exe)
			if replacedSystemFile(exe, procRootExists(pid)) {
				replaced = true
				fields["image_replaced"] = true
			}
		case kernel:
			fields["kernel"] = true
		case os.IsNotExist(exeErr):
			// A zombie has lost its exe link, and a process that exited after
			// /proc was listed has no entry left: neither is a read failure.
		case exeErr != nil:
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
		if havePst && haveBtime {
			fields["created_at"] = time.Unix(btime+int64(pst.StartTicks)/linuxClockTick, 0).UTC()
		}
		self := opts.isSelf(uint32(pid), exe)
		if self {
			fields["lrng_component"] = true
		}
		rows = append(rows, linuxProcRow{pid: pid, st: st, exe: exe, cmd: cmd, kernel: kernel,
			kernelKnown: havePst, replaced: replaced, self: self, fields: fields})
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
		// Hash the executable through /proc/<pid>/exe, not the path text: that
		// reaches the file the process really runs — a deleted or memfd payload
		// included, and the right file for a process in a container.
		if opts.Hasher != nil && r.exe != "" && !r.kernel && ctx.Err() == nil {
			if hashProcessImage(ctx, opts.Hasher, r.pid, r.fields) {
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

// linuxProcRow is one process as gathered from /proc, before findings.
type linuxProcRow struct {
	pid         int
	st          procStatus
	exe         string
	cmd         string
	kernel      bool
	kernelKnown bool // kernel came from the PF_KTHREAD flag, not a guess
	replaced    bool // exe is deleted, but a new file sits at its system path
	self        bool
	fields      map[string]any
}

// linuxProcessFindings judges one process by its image location, its fileless
// markers, a masqueraded kernel-thread name, and its command line.
func linuxProcessFindings(r linuxProcRow) []Finding {
	label := fmt.Sprintf("process %s (pid %d)", r.st.Name, r.pid)
	var out []Finding

	switch {
	case isMemfdPath(r.exe):
		out = append(out, Finding{
			Rule: "process.memfd_exec", Severity: SevSuspect, Technique: "T1620", Confidence: 80,
			Detail: fmt.Sprintf("%s runs from an anonymous in-memory file (%s) — fileless execution, nothing on disk to inspect", label, r.exe),
		})
	case r.replaced:
		out = append(out, Finding{
			Rule: "process.binary_replaced", Severity: SevNotable, Technique: "T1554", Confidence: 30,
			Detail: fmt.Sprintf("%s still runs an executable that has since been replaced on disk (%s; a new file now sits at that path) — "+
				"usually a package upgrade the process hasn't been restarted after, but a trojanized system binary is installed "+
				"the same way: verify the file with the package manager (dpkg -V / rpm -V)", label, r.exe),
		})
	case strings.HasSuffix(r.exe, deletedSuffix):
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

	// A userland process wearing a kernel-thread name is masquerading. The
	// PF_KTHREAD flag settles it without root (another user's exe link can't be
	// read unprivileged); without the flag, an executable is the giveaway, since
	// real kernel threads have none. The name may be bare ("kworker/0:1") or the
	// bracketed form ps prints.
	if !r.kernel && looksLikeKernelThreadName(r.st.Name) && (r.kernelKnown || r.exe != "") {
		what := "its executable couldn't be read"
		if r.exe != "" {
			what = "it runs " + r.exe
		}
		out = append(out, Finding{
			Rule: "process.kthread_masquerade", Severity: SevSuspect, Technique: "T1036.004", Confidence: 70,
			Detail: fmt.Sprintf("%s has a kernel-thread name but is a userland process (%s) — real kernel threads have no executable", label, what),
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
