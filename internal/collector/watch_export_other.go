//go:build !windows && !linux

package collector

// ProcessCommandLine is only needed by watch mode's Windows and Linux sources.
func ProcessCommandLine(pid uint32) string { return "" }
