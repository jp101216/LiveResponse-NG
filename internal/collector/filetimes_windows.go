//go:build windows

package collector

import (
	"os"
	"syscall"
	"time"
)

// statTimes returns a file's creation and last-write times (zero when the
// file can't be read).
func statTimes(path string) (created, modified time.Time, ok bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	if d, isW := fi.Sys().(*syscall.Win32FileAttributeData); isW {
		return filetimeToTime(d.CreationTime), filetimeToTime(d.LastWriteTime), true
	}
	return time.Time{}, fi.ModTime().UTC(), true
}

// filetimeToTime converts a FILETIME (100 ns ticks since 1601) without
// overflowing on early dates, which syscall.Filetime.Nanoseconds does before
// 1678 — and a stomped time can be anything. A zero FILETIME is "not set".
func filetimeToTime(ft syscall.Filetime) time.Time {
	ticks := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	if ticks == 0 {
		return time.Time{}
	}
	const epochDiff = 11644473600 // seconds from 1601 to 1970
	return time.Unix(int64(ticks/1e7)-epochDiff, int64(ticks%1e7)*100).UTC()
}
