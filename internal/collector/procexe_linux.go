//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// procexe_linux.go — reading a process's executable and files the way the
// process itself sees them. /proc/<pid>/exe and /proc/<pid>/root are "magic"
// links: opening or stat-ing through them reaches the file the process really
// has, even when it has been deleted, is an anonymous memfd, or lives in a
// container whose mount namespace maps the same path to a different file. The
// path text readlink returns is only a label in the process's own namespace, so
// hashing or stat-ing that text from lrng's namespace can reach the wrong file,
// or none at all.

// procExePath is the magic link to a process's executable.
func procExePath(pid int) string { return "/proc/" + strconv.Itoa(pid) + "/exe" }

// exeIdentity names the file behind /proc/<pid>/exe by device, inode, size and
// modification time, so processes running the same binary share one cache entry
// in the hasher (and a binary rewritten in place gets a fresh one).
func exeIdentity(pid int) (string, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(procExePath(pid), &st); err != nil {
		return "", false
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return "", false
	}
	return fmt.Sprintf("dev=%d,ino=%d,size=%d,mtime=%d.%d",
		st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec), true
}

// hashProcessImage adds image_sha256 (or image_hash_error) for a process by
// hashing its /proc/<pid>/exe. It reports whether a hash was recorded. Unlike
// FileHasher.Fields it never writes image_exists=false: a failure here means the
// process exited or can't be read, not that its binary is gone from disk.
func hashProcessImage(ctx context.Context, h *FileHasher, pid int, fields map[string]any) bool {
	if h == nil {
		return false
	}
	key, ok := exeIdentity(pid)
	if !ok {
		return false
	}
	r := h.HashAs(ctx, key, procExePath(pid))
	switch {
	case r.SHA256 != "":
		fields["image_sha256"] = r.SHA256
		return true
	case r.Err != "":
		fields["image_hash_error"] = r.Err
	}
	return false
}

// procRootExists returns an "exists" test that resolves paths inside a
// process's own root (/proc/<pid>/root), for replacedSystemFile.
func procRootExists(pid int) func(string) bool {
	root := "/proc/" + strconv.Itoa(pid) + "/root"
	return func(p string) bool {
		st, err := os.Stat(root + p)
		return err == nil && st.Mode().IsRegular()
	}
}
