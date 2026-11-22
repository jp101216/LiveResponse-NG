//go:build !windows

package collector

// ProcessCommandLine is only needed by watch mode's Windows source.
func ProcessCommandLine(pid uint32) string { return "" }
