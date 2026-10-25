//go:build !windows

// Package hostinfo answers questions about the agent's own execution context
// that belong in the report (for example, whether it ran elevated).
package hostinfo

import "os"

// Elevated reports whether this process runs as root.
func Elevated() (bool, error) { return os.Geteuid() == 0, nil }
