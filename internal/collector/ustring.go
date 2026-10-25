package collector

import (
	"errors"
	"unicode/utf16"
	"unsafe"
)

// decodeUnicodeString decodes the UNICODE_STRING that NtQueryInformationProcess
// writes at the start of buf for ProcessCommandLineInformation. Its Buffer
// field points back into buf; base is the address of buf[0].
//
// The pointer is only ever compared against buf's bounds, never dereferenced,
// so a bad length or pointer yields an error rather than a stray read. No
// build tag: it's pure arithmetic and is unit-tested on any OS.
func decodeUnicodeString(buf []byte, base uintptr) (string, error) {
	// UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
	// The pointer sits at offset 8 on 64-bit and 4 on 32-bit.
	const ptrSize = unsafe.Sizeof(uintptr(0))
	if uintptr(len(buf)) < 2*ptrSize {
		return "", errors.New("UNICODE_STRING: buffer shorter than header")
	}
	length := uintptr(le.Uint16(buf[0:2]))
	if length == 0 {
		return "", nil
	}
	var ptr uintptr
	if ptrSize == 8 {
		ptr = uintptr(le.Uint64(buf[8:16]))
	} else {
		ptr = uintptr(le.Uint32(buf[4:8]))
	}
	if ptr < base || length%2 != 0 {
		return "", errors.New("UNICODE_STRING: buffer pointer or length invalid")
	}
	off := ptr - base
	if off > uintptr(len(buf)) || length > uintptr(len(buf))-off {
		return "", errors.New("UNICODE_STRING: string runs past the buffer")
	}
	u := make([]uint16, length/2)
	for i := range u {
		u[i] = le.Uint16(buf[off+uintptr(2*i):])
	}
	return string(utf16.Decode(u)), nil
}
