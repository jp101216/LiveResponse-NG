//go:build linux

package collector

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// listProcesses reads /proc. Kernel threads (the PF_KTHREAD flag in
// /proc/<pid>/stat) have no user-mode memory, so they're marked Kernel; a zombie
// has exited and holds no memory either, so it's marked Zombie.
func listProcesses() ([]procInfo, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []procInfo
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		base := "/proc/" + e.Name()
		p := procInfo{PID: pid}
		if b, err := os.ReadFile(base + "/comm"); err == nil {
			p.Name = strings.TrimSpace(string(b))
		}
		st, haveSt := parseProcStat(readFileSafe(base + "/stat"))
		path, err := os.Readlink(base + "/exe")
		switch {
		case err == nil:
			p.Path = path
		case haveSt:
			// The flags say what an exe-less entry is.
		case errors.Is(err, fs.ErrNotExist):
			p.Kernel = true // no stat to tell: no exe target most likely means a kernel thread
		}
		if haveSt {
			p.Kernel = st.kernelThread()
			p.Zombie = st.State == "Z"
		}
		out = append(out, p)
	}
	return out, nil
}
