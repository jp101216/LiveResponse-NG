//go:build windows

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// A process's parameters, read out of its memory: PEB → ProcessParameters →
// the environment block and the desktop it started on. Only the .NET runtime
// variables in runtimeEnvNames are kept (an environment also holds secrets).
// This needs PROCESS_VM_READ, which the rest of the process collector does
// without, so it opens its own handle and leaves LSASS alone (its environment
// holds nothing of interest, and reading its memory is what credential theft
// looks like).

const (
	processVMRead = 0x0010 // PROCESS_VM_READ

	pebProcessParameters = 0x20  // PEB.ProcessParameters (64-bit)
	paramsFlags          = 0x08  // RTL_USER_PROCESS_PARAMETERS.Flags
	paramsEnvironment    = 0x80  // RTL_USER_PROCESS_PARAMETERS.Environment (64-bit)
	paramsDesktopInfo    = 0xC0  // RTL_USER_PROCESS_PARAMETERS.DesktopInfo (64-bit UNICODE_STRING)
	paramsEnvironmentLen = 0x3F0 // RTL_USER_PROCESS_PARAMETERS.EnvironmentSize (64-bit)
	paramsNormalized     = 0x01  // RTL_USER_PROC_PARAMS_NORMALIZED: pointers, not offsets

	envBlockMax   = 1 << 20 // the largest environment block read
	envPage       = 4096
	desktopMaxLen = 1024 // bytes of DesktopInfo read at most
)

var procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")

// readMem reads n bytes at addr of another process.
func readMem(h syscall.Handle, addr uintptr, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	var got uintptr
	ok, _, err := procReadProcessMemory.Call(uintptr(h), addr, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&got)))
	if ok == 0 {
		return buf[:got], err
	}
	return buf[:got], nil
}

func readPtr(h syscall.Handle, addr uintptr) (uintptr, error) {
	b, err := readMem(h, addr, 8)
	if len(b) < 8 {
		if err == nil {
			err = errors.New("short read")
		}
		return 0, err
	}
	return uintptr(binary.LittleEndian.Uint64(b)), nil
}

// pebParams is what is read from a process's parameters.
type pebParams struct {
	Env     map[string]string // the runtimeEnvNames set (empty when none are)
	Desktop string            // DesktopInfo: "WinSta0\Default" for an ordinary program
}

// processRuntimeEnv returns the runtimeEnvNames set in a process's
// environment (an empty map when none are).
func processRuntimeEnv(pid uint32) (map[string]string, error) {
	p, err := processParams(pid)
	return p.Env, err
}

// processParams reads a process's environment (keeping only runtimeEnvNames)
// and the desktop it started on.
func processParams(pid uint32) (pebParams, error) {
	var out pebParams
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return out, errors.New("process parameters are read by 64-bit builds only")
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation|processVMRead, false, pid)
	if err != nil {
		return out, err
	}
	defer syscall.CloseHandle(h)

	var pbi [6]uintptr // PROCESS_BASIC_INFORMATION; PebBaseAddress is the second field
	var ret uint32
	st, _, _ := procNtQueryInformationProcess.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&pbi[0])),
		unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&ret)))
	if st != 0 {
		return out, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%08X", uint32(st))
	}
	if pbi[1] == 0 {
		return out, errors.New("no PEB (a minimal or system process)")
	}
	params, err := readPtr(h, pbi[1]+pebProcessParameters)
	if err != nil || params == 0 {
		return out, fmt.Errorf("process parameters: %v", err)
	}
	// A running process's parameters are normalized (absolute pointers);
	// before that, string buffers are offsets from the parameters block.
	normalized := true
	if fb, _ := readMem(h, params+paramsFlags, 4); len(fb) == 4 {
		normalized = binary.LittleEndian.Uint32(fb)&paramsNormalized != 0
	}
	out.Desktop, _ = readUnicodeString(h, params+paramsDesktopInfo, params, normalized, desktopMaxLen)
	env, err := readPtr(h, params+paramsEnvironment)
	if err != nil || env == 0 {
		return out, fmt.Errorf("environment pointer: %v", err)
	}
	size, _ := readPtr(h, params+paramsEnvironmentLen)
	var block []byte
	if size > 0 && size <= envBlockMax {
		block, _ = readMem(h, env, int(size))
	}
	if len(block) == 0 {
		// No usable size: read a page at a time until the block's double NUL.
		for addr := env; len(block) < envBlockMax; {
			chunk := envPage - int(addr%envPage)
			b, _ := readMem(h, addr, chunk)
			block = append(block, b...)
			if len(b) < chunk || envBlockEnds(block) {
				break
			}
			addr += uintptr(chunk)
		}
	}
	out.Env = parseEnvBlock(envStrings(block))
	return out, nil
}

// readUnicodeString reads a 64-bit UNICODE_STRING at addr in another process
// (base is the block its buffer is an offset into when not normalized).
func readUnicodeString(h syscall.Handle, addr, base uintptr, normalized bool, max int) (string, error) {
	hdr, err := readMem(h, addr, 16)
	if len(hdr) < 16 {
		if err == nil {
			err = errors.New("short read")
		}
		return "", err
	}
	n := int(binary.LittleEndian.Uint16(hdr[0:2]))
	buf := uintptr(binary.LittleEndian.Uint64(hdr[8:16]))
	if n == 0 || buf == 0 {
		return "", nil
	}
	if n > max || n%2 != 0 {
		return "", fmt.Errorf("implausible string length %d", n)
	}
	if !normalized {
		buf += base
	}
	b, err := readMem(h, buf, n)
	if len(b) < n {
		if err == nil {
			err = errors.New("short read")
		}
		return "", err
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u)), nil
}
