package collector

// Helpers watch mode (internal/watch) shares with the collectors, so its
// judgements match theirs.

// RunningProcess is a process watch mode seeds its table with when the
// window opens, so connections from programs already running are named.
type RunningProcess struct {
	PID  uint32
	Path string
}

// RunningProcesses lists this host's processes with their image paths where
// readable.
func RunningProcesses() ([]RunningProcess, error) {
	ps, err := listProcesses()
	out := make([]RunningProcess, 0, len(ps))
	for _, p := range ps {
		if p.PID < 0 || p.Kernel {
			continue
		}
		out = append(out, RunningProcess{PID: uint32(p.PID), Path: p.Path})
	}
	return out, err
}

// SuspiciousPath reports whether an image lives where installed programs
// don't: temporary, download or public folders and the like.
func SuspiciousPath(p string) bool { return suspiciousPath(p) }

// RedactSecrets masks tokens, keys and passwords in a command line the way
// the process collector does.
func RedactSecrets(s string) string { return redactSecrets(s) }
