//go:build windows

package analyst

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var procGetSystemDirectoryW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")

// browserCommand launches the default browser through rundll32 by its full
// path in the system directory. The console is typically opened elevated on a
// host under investigation, where PATH is attacker-influenced: a bare
// "rundll32.exe" would be whichever one a PATH search finds first.
func browserCommand(url string) *exec.Cmd {
	return exec.Command(filepath.Join(systemDirectory(), "rundll32.exe"), "url.dll,FileProtocolHandler", url)
}

// systemDirectory asks the OS for System32 rather than trusting %SystemRoot%,
// which a launcher can change; the environment is only the fallback.
func systemDirectory() string {
	buf := make([]uint16, syscall.MAX_PATH)
	n, _, _ := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n > 0 && int(n) < len(buf) {
		return syscall.UTF16ToString(buf[:n])
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32")
}
