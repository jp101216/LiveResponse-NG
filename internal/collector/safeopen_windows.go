//go:build windows

package collector

import (
	"os"
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
// device: a UNC path (\\host\share, \\host@SSL\dav, \\?\UNC\...), the \\.\
// device namespace (named pipes, raw disks), an NT \??\UNC\ path, or a drive
// letter mapped to a network share. \\?\C:\..., \\?\Volume{...}\ and
// \\?\GLOBALROOT\Device\HarddiskVolumeN\ are local volumes and stay allowed.
func remotePath(p string) bool {
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
