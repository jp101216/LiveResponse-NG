//go:build unix

package collector

import (
	"os"
	"syscall"
)

// openNoBlock opens read-only with O_NONBLOCK, so a FIFO returns at once
// instead of waiting for a writer, and O_NOCTTY, so a terminal never becomes
// this process's controlling terminal. For regular files neither flag changes
// how reads behave.
func openNoBlock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

// remotePath is false on Unix: mounted network filesystems are the host's own.
func remotePath(string) bool { return false }
