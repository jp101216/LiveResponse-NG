//go:build windows

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// A process's environment, read out of its memory: PEB → ProcessParameters
// → Environment. Only the .NET runtime variables in runtimeEnvNames are kept
// (an environment also holds secrets). This needs PROCESS_VM_READ, which the
// rest of the process collector does without, so it opens its own handle and
// leaves LSASS alone (its environment holds nothing of interest, and reading
// its memory is what credential theft looks like).

const (
	processVMRead = 0x0010 // PROCESS_VM_READ

	pebProcessParameters = 0x20  // PEB.ProcessParameters (64-bit)
	paramsEnvironment    = 0x80  // RTL_USER_PROCESS_PARAMETERS.Environment (64-bit)
	paramsEnvironmentLen = 0x3F0 // RTL_USER_PROCESS_PARAMETERS.EnvironmentSize (64-bit)

	envBlockMax = 1 << 20 // the largest environment block read
	envPage     = 4096
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

// processRuntimeEnv returns the runtimeEnvNames set in a process's
// environment (an empty map when none are).
func processRuntimeEnv(pid uint32) (map[string]string, error) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return nil, errors.New("environment reading is implemented for 64-bit builds only")
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation|processVMRead, false, pid)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)

	var pbi [6]uintptr // PROCESS_BASIC_INFORMATION; PebBaseAddress is the second field
	var ret uint32
	st, _, _ := procNtQueryInformationProcess.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&pbi[0])),
		unsafe.Sizeof(pbi), uintptr(unsafe.Pointer(&ret)))
	if st != 0 {
		return nil, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%08X", uint32(st))
	}
	if pbi[1] == 0 {
		return nil, errors.New("no PEB (a minimal or system process)")
	}
	params, err := readPtr(h, pbi[1]+pebProcessParameters)
	if err != nil || params == 0 {
		return nil, fmt.Errorf("process parameters: %v", err)
	}
	env, err := readPtr(h, params+paramsEnvironment)
	if err != nil || env == 0 {
		return nil, fmt.Errorf("environment pointer: %v", err)
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
	return parseEnvBlock(envStrings(block)), nil
}
