//go:build !windows

package collector

import (
	"os"
	"time"
)

// statTimes returns a file's modification time; Unix file systems don't
// expose a creation time through stat.
func statTimes(path string) (created, modified time.Time, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	return time.Time{}, fi.ModTime().UTC(), true
}
