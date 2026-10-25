//go:build windows

package hostinfo

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

var (
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount64        = modkernel32.NewProc("GetTickCount64")
	modnetapi32               = syscall.NewLazyDLL("netapi32.dll")
	procNetGetJoinInformation = modnetapi32.NewProc("NetGetJoinInformation")
	procNetApiBufferFree      = modnetapi32.NewProc("NetApiBufferFree")
)

const currentVersionKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// Gather reads the OS identity from the registry, boot time from the tick
// count, and domain membership from NetGetJoinInformation. Read-only.
func Gather() Info {
	var in Info
	if k, err := winreg.Open(winreg.LocalMachine, currentVersionKey); err == nil {
		str := func(name string) string {
			v, err := k.Value(name)
			if err != nil {
				return ""
			}
			return strings.TrimSpace(v.String())
		}
		build := str("CurrentBuildNumber")
		if build == "" {
			build = str("CurrentBuild")
		}
		if v, err := k.Value("UBR"); err == nil {
			if ubr, ok := v.Uint32(); ok && build != "" {
				build = fmt.Sprintf("%s.%d", build, ubr)
			}
		}
		in.OSBuild = build
		in.OSName = windowsProductName(str("ProductName"), build)
		in.OSVersion = str("DisplayVersion")
		if in.OSVersion == "" {
			in.OSVersion = str("ReleaseId")
		}
		in.Edition = str("EditionID")
		in.InstallationType = str("InstallationType")
		if v, err := k.Value("InstallDate"); err == nil {
			if secs, ok := v.Uint32(); ok && secs > 0 {
				in.InstalledAt = timePtr(time.Unix(int64(secs), 0))
			}
		}
		k.Close()
	} else {
		in.Errors = append(in.Errors, "os version: "+err.Error())
	}

	if err := procGetTickCount64.Find(); err == nil {
		ms, _, _ := procGetTickCount64.Call()
		in.BootTime = timePtr(time.Now().Add(-time.Duration(ms) * time.Millisecond).Truncate(time.Second))
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, "TimeZoneKeyName"); err == nil {
		in.TimeZone = v.String()
	}

	var name *uint16
	var status uint32
	if r, _, _ := procNetGetJoinInformation.Call(0, uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&status))); r == 0 {
		switch status {
		case 1:
			in.JoinType = "unjoined"
		case 2:
			in.JoinType = "workgroup"
		case 3:
			in.JoinType = "domain"
		}
		if name != nil {
			in.Domain = syscall.UTF16ToString(unsafe.Slice(name, 256)[:strlen16(name, 256)])
			procNetApiBufferFree.Call(uintptr(unsafe.Pointer(name)))
		}
	}
	const tcpip = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	for _, valueName := range []string{"Domain", "NV Domain"} {
		if v, err := winreg.ReadValue(winreg.LocalMachine, tcpip, valueName); err == nil && v.String() != "" {
			in.DNSDomain = v.String()
			break
		}
	}
	if host, err := os.Hostname(); err == nil && in.DNSDomain != "" {
		in.FQDN = strings.ToLower(host + "." + in.DNSDomain)
	}
	return in
}

// strlen16 counts UTF-16 units up to a NUL, at most max.
func strlen16(p *uint16, max int) int {
	s := unsafe.Slice(p, max)
	for i, c := range s {
		if c == 0 {
			return i
		}
	}
	return max
}
