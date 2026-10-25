//go:build linux

package collector

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// listProcesses reads /proc. Kernel threads have no /proc/<pid>/exe target
// and no user-mode memory, so they're marked Kernel.
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
		p := procInfo{PID: pid}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil {
			p.Name = strings.TrimSpace(string(b))
		}
		path, err := os.Readlink("/proc/" + e.Name() + "/exe")
		switch {
		case err == nil:
			p.Path = path
		case errors.Is(err, fs.ErrNotExist):
			p.Kernel = true // kernel thread (or exited since ReadDir)
		}
		out = append(out, p)
	}
	return out, nil
}
