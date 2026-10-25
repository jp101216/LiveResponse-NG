//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	th32csSnapModule     = 0x00000008
	th32csSnapModule32   = 0x00000010
	maxModulesPerProcess = 4096 // guard against a runaway module list
	errorBadLength       = syscall.Errno(24)
)

// moduleEntry32 mirrors MODULEENTRY32W. The uintptr fields give it the same
// alignment and size as the C struct (which dwSize must be set to) on both
// 32- and 64-bit.
type moduleEntry32 struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	HModule      uintptr
	Module       [256]uint16
	ExePath      [260]uint16
}

type moduleInfo struct {
	Name string
	Path string
	Base uintptr
	Size uint32
}

func collectModules(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("modules")

	procs, err := snapshotProcesses()
	if err != nil && len(procs) == 0 {
		return res.Finish(), err
	}
	if err != nil {
		res.Fail(err.Error())
	}

	scanned, inaccessible := 0, 0
	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		if p.pid == 0 || p.pid == 4 { // Idle / System have no user-mode modules
			continue
		}
		mods, err := processModules(p.pid)
		if err != nil {
			inaccessible++ // access denied, protected, or a 64-bit target from a 32-bit lrng
			continue
		}
		scanned++

		self := len(mods) > 0 && opts.isSelf(p.pid, mods[0].Path)
		type flagged struct{ path, why string }
		var high, low []flagged
		list := make([]map[string]any, 0, len(mods))
		for _, m := range mods {
			list = append(list, map[string]any{
				"name": m.Name,
				"path": m.Path,
				"base": fmt.Sprintf("0x%x", m.Base),
				"size": m.Size,
			})
			switch lvl, why := pathRisk(m.Path); {
			case self:
			case lvl == riskHigh:
				high = append(high, flagged{m.Path, why})
			case lvl == riskLow:
				low = append(low, flagged{m.Path, why})
			}
		}
		fields := map[string]any{
			"pid":          p.pid,
			"process":      p.name,
			"module_count": len(list),
			"modules":      list,
		}
		if self {
			fields["lrng_component"] = true
		}
		var findings []Finding
		for _, set := range []struct {
			mods []flagged
			sev  Severity
			conf int
		}{{high, SevSuspect, 55}, {low, SevNotable, 30}} {
			if len(set.mods) == 0 {
				continue
			}
			paths := make([]string, len(set.mods))
			for i, f := range set.mods {
				paths[i] = f.path
			}
			fields["suspicious_modules"] = append(asStrings(fields["suspicious_modules"]), paths...)
			findings = append(findings, Finding{
				Rule:       "modules.unusual_path",
				Severity:   set.sev,
				Technique:  "T1574.002",
				Confidence: set.conf,
				Detail: fmt.Sprintf("%s (pid %d) has %d module(s) loaded from %s: %s",
					p.name, p.pid, len(set.mods), set.mods[0].why, strings.Join(paths, ", ")),
			})
			break // one finding per process, at the highest level present
		}
		res.Add(fields, findings...)
	}
	res.SetMeta("processes_scanned", scanned)
	res.SetMeta("processes_inaccessible", inaccessible)
	return res.Finish(), nil
}

func asStrings(v any) []string {
	s, _ := v.([]string)
	return s
}

// processModules returns the modules loaded in one process via a Toolhelp
// module snapshot. CreateToolhelp32Snapshot fails with ERROR_BAD_LENGTH while
// the target is loading or unloading modules; the documented remedy is to
// retry.
func processModules(pid uint32) ([]moduleInfo, error) {
	var snap syscall.Handle
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		snap, err = syscall.CreateToolhelp32Snapshot(th32csSnapModule|th32csSnapModule32, pid)
		if !errors.Is(err, errorBadLength) {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 5 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snap)

	var me moduleEntry32
	me.Size = uint32(unsafe.Sizeof(me))
	r, _, e := procModule32FirstW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	if r == 0 {
		return nil, e
	}
	var out []moduleInfo
	for {
		out = append(out, moduleInfo{
			Name: syscall.UTF16ToString(me.Module[:]),
			Path: syscall.UTF16ToString(me.ExePath[:]),
			Base: me.ModBaseAddr,
			Size: me.ModBaseSize,
		})
		if len(out) >= maxModulesPerProcess {
			break
		}
		r, _, _ := procModule32NextW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
		if r == 0 {
			break // ERROR_NO_MORE_FILES
		}
	}
	return out, nil
}
