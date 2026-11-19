//go:build windows

package collector

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// makeLink creates a symbolic link without Go's os.Symlink, which stats the
// target first and so would itself reach out to a UNC target.
func makeLink(t *testing.T, link, target string, dir bool) {
	t.Helper()
	l, _ := syscall.UTF16PtrFromString(link)
	tg, _ := syscall.UTF16PtrFromString(target)
	flags := uint32(2) // SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	if dir {
		flags |= 1 // SYMBOLIC_LINK_FLAG_DIRECTORY
	}
	if err := syscall.CreateSymbolicLink(l, tg, flags); err != nil {
		t.Skipf("can't create symbolic links here: %v", err)
	}
}

// A link planted where a file or folder is expected must not lead the
// collector to a network share: opening it would authenticate to that host.
func TestRemotePathFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	const share = `\\127.0.0.1\lrng-test-no-such-share`

	fileLink := filepath.Join(dir, "settings.json")
	makeLink(t, fileLink, share+`\settings.json`, false)
	dirLink := filepath.Join(dir, ".claude")
	makeLink(t, dirLink, share, true)
	nested := filepath.Join(dir, "nested")
	makeLink(t, nested, dirLink, true) // a local link to the link above

	local := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(local, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	localLink := filepath.Join(dir, "alias.txt")
	makeLink(t, localLink, local, false)

	start := time.Now()
	for _, p := range []string{fileLink, filepath.Join(dirLink, "settings.json"), filepath.Join(nested, "x", "y.json")} {
		if !remotePath(p) {
			t.Errorf("%s: a link to %s was not refused", p, share)
		}
		if _, _, err := openRegular(p); !errors.Is(err, errRemotePath) {
			t.Errorf("openRegular(%s) = %v, want errRemotePath", p, err)
		}
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("refusing the links took %v: something reached out to the share", took)
	}
	for _, p := range []string{local, localLink, filepath.Join(dir, "missing", "file")} {
		if remotePath(p) {
			t.Errorf("%s: a local path was refused", p)
		}
	}
	if b, _, err := readRegular(localLink, 16); err != nil || string(b) != "ok" {
		t.Errorf("a link to a local file must still read: %q, %v", b, err)
	}
}
