//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

func openNoBlock(path string) (*os.File, error) { return os.Open(path) }

var procGetDriveTypeW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDriveTypeW")

const driveRemote = 4 // DRIVE_REMOTE

var remoteDrives sync.Map // drive letter (upper case) -> bool

// remotePath reports whether opening path would reach another host or a
// device: by its name (remotePathName), or through a symbolic link or
// junction on the way to it whose target is such a path. Windows follows a
// local link to a remote target by default, and Stat, open and
// WinVerifyTrust all would, so a link planted where a file is expected
// (C:\Users\x\.claude -> \\attacker\share) would otherwise make this process
// authenticate to the attacker's host.
func remotePath(p string) bool {
	return remotePathName(p) || remoteViaLink(p)
}

// remotePathName reports whether a path names another host or a device: a
// UNC path (\\host\share, \\host@SSL\dav, \\?\UNC\...), the \\.\ device
// namespace (named pipes, raw disks), an NT \??\UNC\ path, or a drive letter
// mapped to a network share. \\?\C:\..., \\?\Volume{...}\ and
// \\?\GLOBALROOT\Device\HarddiskVolumeN\ are local volumes and stay allowed.
func remotePathName(p string) bool {
	sep := func(c byte) bool { return c == '\\' || c == '/' }
	letter := func(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, `\??\unc\`) {
		return true
	}
	if strings.HasPrefix(lower, `\??\`) && len(p) >= 6 && letter(p[4]) && p[5] == ':' {
		return remoteDrive(p[4])
	}
	if len(p) >= 2 && sep(p[0]) && sep(p[1]) {
		if len(p) >= 4 && p[2] == '?' && sep(p[3]) {
			r, lr := p[4:], lower[4:]
			switch {
			case len(r) >= 2 && letter(r[0]) && r[1] == ':':
				return remoteDrive(r[0])
			case strings.HasPrefix(lr, "volume{"), strings.HasPrefix(lr, `globalroot\device\harddiskvolume`):
				return false
			}
		}
		return true
	}
	if len(p) >= 2 && letter(p[0]) && p[1] == ':' {
		return remoteDrive(p[0])
	}
	return false
}

// remoteDrive reports whether a drive letter is mapped to a network share.
// The answer is cached: GetDriveTypeW itself doesn't touch the network.
func remoteDrive(d byte) bool {
	d &^= 0x20 // upper case
	if v, ok := remoteDrives.Load(d); ok {
		return v.(bool)
	}
	root, _ := syscall.UTF16PtrFromString(string([]byte{d, ':', '\\'}))
	r, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(root)))
	remote := r == driveRemote
	remoteDrives.Store(d, remote)
	return remote
}

// linkFreeDirs caches directories already walked whose path holds no link to
// a remote target (lower-cased): most reads share a handful of folders.
var linkFreeDirs sync.Map

// maxLinkHops bounds how many links one path may pass through; a longer chain
// (or a loop) is refused rather than followed.
const maxLinkHops = 32

// remoteViaLink walks path from its volume root one component at a time,
// examining each with Lstat (which doesn't follow the component itself) before
// anything beneath it is touched, and reports whether a symbolic link or
// junction on the way points at a network or device path. A missing
// component ends the walk: there is nothing left to follow.
func remoteViaLink(p string) bool {
	if p == "" {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	return walkLinks(abs, 0)
}

func walkLinks(p string, hops int) bool {
	if hops > maxLinkHops {
		return true
	}
	vol := filepath.VolumeName(p)
	if remotePathName(vol + `\`) {
		return true
	}
	parts := strings.FieldsFunc(p[len(vol):], func(r rune) bool { return r == '\\' || r == '/' })
	cur := vol + `\`
	for i, part := range parts {
		next := filepath.Join(cur, part)
		last := i == len(parts)-1
		if !last {
			if _, ok := linkFreeDirs.Load(strings.ToLower(next)); ok {
				cur = next
				continue
			}
		}
		fi, err := os.Lstat(next)
		if err != nil {
			return false
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			if target, err := os.Readlink(next); err == nil {
				if remotePathName(target) {
					return true
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(cur, target)
				}
				return walkLinks(filepath.Join(append([]string{target}, parts[i+1:]...)...), hops+1)
			}
		}
		if !last && fi.IsDir() {
			linkFreeDirs.Store(strings.ToLower(next), struct{}{})
		}
		cur = next
	}
	return false
}
