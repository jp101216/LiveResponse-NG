//go:build windows

// Package hostinfo answers questions about the agent's own execution context
// that belong in the report (for example, whether it ran elevated).
package hostinfo

import (
	"syscall"
	"unsafe"
)

const tokenElevation = 20 // TOKEN_INFORMATION_CLASS TokenElevation

// Elevated reports whether this process runs with an elevated (admin) token.
// A non-elevated run can't open many processes, so the report needs to say so.
func Elevated() (bool, error) {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false, err
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return false, err
	}
	defer tok.Close()

	var elevation, n uint32
	if err := syscall.GetTokenInformation(tok, tokenElevation,
		(*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &n); err != nil {
		return false, err
	}
	return elevation != 0, nil
}
