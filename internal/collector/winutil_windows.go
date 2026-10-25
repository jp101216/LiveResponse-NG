//go:build windows

package collector

import (
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

var (
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procGetSystemWindowsDirectoryW = modkernel32.NewProc("GetSystemWindowsDirectoryW")
	procQueryFullProcessImageName  = modkernel32.NewProc("QueryFullProcessImageNameW")
	procProcessIdToSessionId       = modkernel32.NewProc("ProcessIdToSessionId")
	procModule32FirstW             = modkernel32.NewProc("Module32FirstW")
	procModule32NextW              = modkernel32.NewProc("Module32NextW")
	modntdll                       = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess  = modntdll.NewProc("NtQueryInformationProcess")
	systemRootOnce                 sync.Once
	systemRootPath                 string
	machineEnvOnce                 sync.Once
	machineEnv                     envLookup
)

// utf16PtrToString reads a NUL-terminated UTF-16 string from a pointer handed
// back by a Win32 API (WTS session info, NetApi buffers). The pointer is only
// walked up to a sane bound so a missing terminator can't run away.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	const maxChars = 32768
	base := unsafe.Pointer(p)
	var u []uint16
	for i := 0; i < maxChars; i++ {
		c := *(*uint16)(unsafe.Add(base, uintptr(i)*2))
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// systemRoot returns the host's Windows directory (e.g. C:\Windows). It asks
// the OS rather than trusting %SystemRoot%, which a launcher can change.
func systemRoot() string {
	systemRootOnce.Do(func() {
		buf := make([]uint16, 512)
		n, _, _ := procGetSystemWindowsDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n > 0 && int(n) < len(buf) {
			systemRootPath = syscall.UTF16ToString(buf[:n])
		}
		if systemRootPath == "" {
			systemRootPath = os.Getenv("SystemRoot")
		}
		if systemRootPath == "" {
			systemRootPath = `C:\Windows`
		}
	})
	return systemRootPath
}

// machineLookup resolves machine-wide environment variables from the agent's
// environment, with the Windows directory taken from the OS.
func machineLookup() envLookup {
	machineEnvOnce.Do(func() {
		root := systemRoot()
		getenv := func(name string) string {
			switch name {
			case "systemroot", "windir":
				return root
			case "systemdrive":
				if len(root) >= 2 && root[1] == ':' {
					return root[:2]
				}
			}
			return os.Getenv(name)
		}
		machineEnv = machineLookupFrom(getenv)
	})
	return machineEnv
}

// expandMachine expands machine-wide variables only (see envexpand.go).
func expandMachine(s string) string { return expandEnvRefs(s, machineLookup()) }

// expandForProfile expands per-user variables from a profile directory, then
// machine-wide ones.
func expandForProfile(s, profile string) string {
	return expandEnvRefs(s, chain(userLookup(profile), machineLookup()))
}

// regString decodes a registry string value and expands machine-wide
// variables in a REG_EXPAND_SZ. It returns the expanded and raw forms.
func regString(v winreg.Value, profile string) (expanded, raw string) {
	raw = v.String()
	if v.Type != winreg.TypeExpandSZ {
		return raw, raw
	}
	if profile != "" {
		return expandForProfile(raw, profile), raw
	}
	return expandMachine(raw), raw
}

// win32Error renders a Win32/NetApi status code as text.
func win32Error(code uintptr) string {
	return fmt.Sprintf("%s (%d)", syscall.Errno(code).Error(), code)
}

// fileTimes returns a file's creation, modification and access times.
func fileTimes(info fs.FileInfo) (created, modified, accessed time.Time) {
	modified = info.ModTime().UTC()
	if ad, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		created = time.Unix(0, ad.CreationTime.Nanoseconds()).UTC()
		accessed = time.Unix(0, ad.LastAccessTime.Nanoseconds()).UTC()
	}
	return
}

// addFileTimes records a file's timestamps on a record.
func addFileTimes(fields map[string]any, prefix string, info fs.FileInfo) {
	c, m, a := fileTimes(info)
	if !c.IsZero() {
		fields[prefix+"created_at"] = c
	}
	fields[prefix+"modified_at"] = m
	if !a.IsZero() {
		fields[prefix+"accessed_at"] = a
	}
}

// normalizeImage turns the forms Windows stores program paths in into an
// ordinary Win32 path, for display and hashing (see normalizeImageWith).
func normalizeImage(p string) string { return normalizeImageWith(p, systemRoot(), machineLookup()) }
