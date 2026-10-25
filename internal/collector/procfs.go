package collector

import (
	"strconv"
	"strings"
)

// procfs.go — parsers for the /proc text files the Linux collectors read. No
// build tag on purpose: they work on plain byte slices (like tcptable.go), so
// they are unit-tested on any OS even though only Linux produces the files.
// Parsing is tolerant — a malformed line is skipped, never fatal — because a
// triage must survive an odd row in a kernel interface.

// procStatus is the subset of /proc/<pid>/status the process collector uses.
type procStatus struct {
	Name  string // comm, truncated by the kernel to 15 bytes
	State string // single-letter state (R, S, D, Z, T, ...)
	PPID  int    // parent PID, -1 if unknown
	UID   int    // real UID, -1 if unknown
}

// parseProcStatus reads the handful of fields we need out of /proc/<pid>/status.
func parseProcStatus(data []byte) procStatus {
	s := procStatus{PPID: -1, UID: -1}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Name":
			s.Name = val
		case "State":
			if val != "" {
				s.State = val[:1]
			}
		case "PPid":
			if n, err := strconv.Atoi(val); err == nil {
				s.PPID = n
			}
		case "Uid":
			if f := strings.Fields(val); len(f) > 0 {
				if n, err := strconv.Atoi(f[0]); err == nil {
					s.UID = n
				}
			}
		}
	}
	return s
}

// pfKthread is the PF_KTHREAD bit in /proc/<pid>/stat's flags field: set for
// kernel threads and nothing else.
const pfKthread = 0x00200000

// procStat is the subset of /proc/<pid>/stat the collectors use.
type procStat struct {
	State      string // single-letter state, as in /proc/<pid>/status
	Flags      uint64 // the kernel's per-task PF_* flags (field 9)
	StartTicks uint64 // start time in clock ticks since boot (field 22)
}

// kernelThread reports whether the task is a kernel thread. This is the
// kernel's own flag, so unlike "no /proc/<pid>/exe target" it doesn't mistake a
// zombie (which has lost its exe link) for a kernel thread, and it can be read
// for every process without root.
func (s procStat) kernelThread() bool { return s.Flags&pfKthread != 0 }

// parseProcStat reads state, flags and starttime from /proc/<pid>/stat. The
// comm field (field 2) is wrapped in parentheses and may itself contain spaces
// or ')', so parsing starts after the last ')'.
func parseProcStat(stat []byte) (procStat, bool) {
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+1 >= len(s) {
		return procStat{}, false
	}
	fields := strings.Fields(s[i+1:])
	// After ')': [0]=state [1]=ppid ... [6]=flags (field 9) ... [19]=starttime
	// (field 22).
	if len(fields) < 20 {
		return procStat{}, false
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return procStat{}, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procStat{}, false
	}
	return procStat{State: fields[0], Flags: flags, StartTicks: start}, true
}

// parseStarttimeTicks returns field 22 (starttime, in clock ticks since boot)
// from /proc/<pid>/stat.
func parseStarttimeTicks(stat []byte) (uint64, bool) {
	st, ok := parseProcStat(stat)
	return st.StartTicks, ok
}

// parseBtime returns the boot time (seconds since the epoch) from /proc/stat.
func parseBtime(data []byte) (int64, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// parseCmdline turns the NUL-separated /proc/<pid>/cmdline into a display
// string. An empty result means a kernel thread (no argv).
func parseCmdline(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

// passwdEntry is one /etc/passwd row.
type passwdEntry struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// parsePasswd parses /etc/passwd into entries, skipping malformed lines.
func parsePasswd(data []byte) []passwdEntry {
	var out []passwdEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(f[3])
		out = append(out, passwdEntry{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out
}

// uidNameMap builds a UID->name lookup from parsed passwd entries.
func uidNameMap(entries []passwdEntry) map[int]string {
	m := make(map[int]string, len(entries))
	for _, e := range entries {
		if _, seen := m[e.UID]; !seen { // first name wins (the primary account for a UID)
			m[e.UID] = e.Name
		}
	}
	return m
}

// parseShadow maps each account in an /etc/shadow dump to its raw password-hash
// field (the second column). Comments, blank and malformed lines are skipped.
func parseShadow(data []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) >= 2 && f[0] != "" {
			m[f[0]] = f[1]
		}
	}
	return m
}

// Password states, as reported in the localaccounts records.
const (
	pwUsable = "usable" // a real hash: password login works
	pwEmpty  = "empty"  // no password at all: login with an empty password
	pwLocked = "locked" // "!", "*", "!!", "!$6$…" (passwd -l): password login disabled
	pwNone   = "none"   // the account has no /etc/shadow entry
)

// passwordState classifies a shadow hash field. A leading "!" (passwd -l) or "*"
// disables password login whatever follows; an empty field means no password.
func passwordState(hash string) string {
	switch {
	case hash == "":
		return pwEmpty
	case strings.HasPrefix(hash, "!"), strings.HasPrefix(hash, "*"):
		return pwLocked
	default:
		return pwUsable
	}
}

// groupEntry is one /etc/group row.
type groupEntry struct {
	Name    string
	GID     int
	Members []string
}

// parseGroup parses /etc/group, skipping malformed lines.
func parseGroup(data []byte) []groupEntry {
	var out []groupEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		var members []string
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		out = append(out, groupEntry{Name: f[0], GID: gid, Members: members})
	}
	return out
}
