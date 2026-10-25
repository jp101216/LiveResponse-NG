//go:build windows

package collector

// listProcesses returns every process with its image path where readable.
// PID 0 (Idle) and 4 (System) have no user-mode memory to scan.
func listProcesses() ([]procInfo, error) {
	entries, err := snapshotProcesses()
	if err != nil && len(entries) == 0 {
		return nil, err
	}
	out := make([]procInfo, 0, len(entries))
	for _, e := range entries {
		p := procInfo{PID: int(e.pid), Name: e.name}
		if e.pid == 0 || e.pid == 4 {
			p.Kernel = true
		} else if path, err := imagePath(e.pid); err == nil {
			p.Path = path
		}
		out = append(out, p)
	}
	return out, nil
}
