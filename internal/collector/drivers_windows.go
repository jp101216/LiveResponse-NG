//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// The Windows half of the drivers collector: the kernel's loaded-module list
// and code-integrity options (NtQuerySystemInformation), the driver services
// in the registry, and the blocklist and HVCI settings. Everything is read;
// nothing is loaded, started or changed.

var (
	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
	procQueryDosDeviceW          = modkernel32.NewProc("QueryDosDeviceW")
	procMultiByteToWideChar      = modkernel32.NewProc("MultiByteToWideChar")
)

const (
	systemModuleInformation        = 11
	systemCodeIntegrityInformation = 103
	// statusInfoLengthMismatch is shared with process_windows.go.
)

func collectDrivers(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("drivers")
	sysRoot := systemRoot()

	mods, err := loadedKernelModules()
	if err != nil {
		res.Fail("loaded drivers: " + err.Error())
	}
	for i := range mods {
		mods[i].Path = kernelModulePath(mods[i].KernelPath, sysRoot, dosDevicePath)
	}
	svcs, err := driverServices(sysRoot)
	if err != nil {
		res.Fail("driver services: " + err.Error())
	}
	if len(mods) == 0 && len(svcs) == 0 {
		return res.Finish(), fmt.Errorf("no loaded drivers and no driver services could be read")
	}
	driversReport(ctx, res, opts, mergeDrivers(mods, svcs, sysRoot), readCodeIntegrity())
	return res.Finish(), nil
}

// ntQuerySystemInformation fills a buffer for one information class, growing
// it while the kernel says it is too small (the module list can change size
// between calls).
func ntQuerySystemInformation(class uint32, size int) ([]byte, error) {
	for attempt := 0; attempt < 6; attempt++ {
		buf := make([]byte, size)
		var ret uint32
		st, _, _ := procNtQuerySystemInformation.Call(uintptr(class), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
		switch uint32(st) {
		case 0:
			return buf[:min(int(ret), len(buf))], nil
		case statusInfoLengthMismatch:
			size = max(int(ret), size*2) + 16<<10
			if size > 64<<20 {
				return nil, fmt.Errorf("NtQuerySystemInformation(%d): wants %d bytes", class, ret)
			}
		default:
			return nil, fmt.Errorf("NtQuerySystemInformation(%d): NTSTATUS 0x%08X", class, uint32(st))
		}
	}
	return nil, fmt.Errorf("NtQuerySystemInformation(%d): the buffer kept growing", class)
}

func loadedKernelModules() ([]kernelModule, error) {
	if err := procNtQuerySystemInformation.Find(); err != nil {
		return nil, err
	}
	buf, err := ntQuerySystemInformation(systemModuleInformation, 256<<10)
	if err != nil {
		return nil, err
	}
	return parseModuleList(buf, int(unsafe.Sizeof(uintptr(0))), ansiToString)
}

// ansiToString converts a string in the system ANSI code page; plain ASCII
// (nearly every driver path) needs no call.
func ansiToString(b []byte) string {
	ascii := true
	for _, c := range b {
		if c >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii || procMultiByteToWideChar.Find() != nil {
		return string(b)
	}
	const cpACP = 0
	w := make([]uint16, len(b)+1)
	n, _, _ := procMultiByteToWideChar.Call(cpACP, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&w[0])), uintptr(len(w)))
	if n == 0 {
		return string(b)
	}
	return syscall.UTF16ToString(w[:n])
}

var (
	dosDevicesOnce sync.Once
	dosDevices     [][2]string // NT device name, drive ("C:")
)

// dosDevicePath maps \Device\HarddiskVolume3\x to C:\x, or returns "".
func dosDevicePath(nt string) string {
	dosDevicesOnce.Do(func() {
		if procQueryDosDeviceW.Find() != nil {
			return
		}
		for c := 'A'; c <= 'Z'; c++ {
			drive := string(c) + ":"
			name, _ := syscall.UTF16PtrFromString(drive)
			buf := make([]uint16, 1024)
			n, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if n == 0 {
				continue
			}
			if target := syscall.UTF16ToString(buf); target != "" {
				dosDevices = append(dosDevices, [2]string{target, drive})
			}
		}
	})
	for _, d := range dosDevices {
		if len(nt) >= len(d[0]) && strings.EqualFold(nt[:len(d[0])], d[0]) &&
			(len(nt) == len(d[0]) || nt[len(d[0])] == '\\') {
			return d[1] + nt[len(d[0]):]
		}
	}
	return ""
}

// driverServices lists the services of a driver type (kernel or file-system
// driver) and the file each loads.
func driverServices(sysRoot string) ([]driverService, error) {
	root, err := winreg.Open(winreg.LocalMachine, servicesKey)
	if err != nil {
		return nil, err
	}
	names, err := root.SubKeys()
	root.Close()
	if err != nil && len(names) == 0 {
		return nil, err
	}
	var out []driverService
	for _, name := range names {
		k, err := winreg.Open(winreg.LocalMachine, servicesKey+`\`+name)
		if err != nil {
			continue
		}
		vals := map[string]winreg.Value{}
		if vs, err := k.Values(); err == nil {
			for _, v := range vs {
				vals[strings.ToLower(v.Name)] = v
			}
		}
		lastWrite := k.LastWrite()
		k.Close()
		typ, ok := vals["type"].Uint32()
		if !ok || !isDriverType(typ) {
			continue
		}
		s := driverService{Name: name, Type: serviceType(typ), LastWrite: lastWrite}
		if st, ok := vals["start"].Uint32(); ok {
			s.Start = serviceStart(st)
		}
		// A driver's ImagePath is a path, never a command line: the kernel
		// opens it as given, spaces and all.
		s.ImagePath, _ = regString(vals["imagepath"], "")
		if s.ImagePath == "" {
			s.Path = defaultDriverPath(name, sysRoot)
		} else {
			s.Path = kernelModulePath(s.ImagePath, sysRoot, dosDevicePath)
		}
		out = append(out, s)
	}
	return out, err
}

// readCodeIntegrity reads the code-integrity options and the blocklist and
// HVCI settings.
func readCodeIntegrity() codeIntegrity {
	var ci codeIntegrity
	if err := procNtQuerySystemInformation.Find(); err == nil {
		info := struct {
			Length  uint32
			Options uint32
		}{Length: 8}
		var ret uint32
		st, _, _ := procNtQuerySystemInformation.Call(systemCodeIntegrityInformation, uintptr(unsafe.Pointer(&info)),
			unsafe.Sizeof(info), uintptr(unsafe.Pointer(&ret)))
		if st == 0 {
			ci.Known, ci.Options = true, info.Options
		} else {
			ci.Error = fmt.Sprintf("NtQuerySystemInformation(SystemCodeIntegrityInformation): NTSTATUS 0x%08X", uint32(st))
		}
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine, `SYSTEM\CurrentControlSet\Control\CI\Config`, "VulnerableDriverBlocklistEnable"); err == nil {
		if n, ok := v.Uint32(); ok {
			ci.Blocklist = &n
		}
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, "Enabled"); err == nil {
		if n, ok := v.Uint32(); ok {
			ci.HVCIConfig = &n
		}
	}
	return ci
}
