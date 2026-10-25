// Package winreg is a small, read-only Windows registry reader built directly
// on advapi32, so lrng needs no third-party dependency. Keys are always opened
// read-only and in the 64-bit view (KEY_WOW64_64KEY), so a 32-bit agent on
// 64-bit Windows still reads the real hive rather than its WOW64 reflection;
// Wow6432Node paths are read explicitly where they matter.
//
// This file has no build tag: value decoding works on plain bytes and is
// unit-tested on any OS. The key-access half lives in winreg_windows.go.
package winreg

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// Registry value types (REG_*).
const (
	TypeNone          = 0
	TypeSZ            = 1
	TypeExpandSZ      = 2
	TypeBinary        = 3
	TypeDWORD         = 4
	TypeDWORDBigEndan = 5
	TypeLink          = 6
	TypeMultiSZ       = 7
	TypeQWORD         = 11
)

// Value is one registry value: its name, raw type tag and raw bytes. Decoding
// is explicit (String, Strings, Uint32, ...) so callers never get a silently
// converted value of the wrong type.
type Value struct {
	Name string
	Type uint32
	Data []byte
}

// String decodes a REG_SZ or REG_EXPAND_SZ value. Environment references in
// REG_EXPAND_SZ are NOT expanded: whose environment applies depends on the
// caller (a per-user Run key must not be expanded with the agent's %TEMP%).
// Other types return "".
func (v Value) String() string {
	switch v.Type {
	case TypeSZ, TypeExpandSZ, TypeLink:
		return UTF16Bytes(v.Data)
	default:
		return ""
	}
}

// Strings decodes a REG_MULTI_SZ value. A REG_SZ / REG_EXPAND_SZ value is
// returned as a one-element slice (some writers use the wrong type), and an
// empty value as nil.
func (v Value) Strings() []string {
	switch v.Type {
	case TypeMultiSZ:
		return SplitMultiSZ(v.Data)
	case TypeSZ, TypeExpandSZ:
		if s := v.String(); s != "" {
			return []string{s}
		}
	}
	return nil
}

// Uint32 decodes a REG_DWORD (little- or big-endian) value.
func (v Value) Uint32() (uint32, bool) {
	if len(v.Data) < 4 {
		return 0, false
	}
	switch v.Type {
	case TypeDWORD:
		return binary.LittleEndian.Uint32(v.Data), true
	case TypeDWORDBigEndan:
		return binary.BigEndian.Uint32(v.Data), true
	}
	return 0, false
}

// Uint64 decodes a REG_QWORD value, or widens a REG_DWORD.
func (v Value) Uint64() (uint64, bool) {
	if v.Type == TypeQWORD && len(v.Data) >= 8 {
		return binary.LittleEndian.Uint64(v.Data), true
	}
	if d, ok := v.Uint32(); ok {
		return uint64(d), true
	}
	return 0, false
}

// TypeName gives a human label for a raw registry type tag.
func TypeName(t uint32) string {
	switch t {
	case TypeNone:
		return "none"
	case TypeSZ:
		return "sz"
	case TypeExpandSZ:
		return "expand_sz"
	case TypeBinary:
		return "binary"
	case TypeDWORD:
		return "dword"
	case TypeDWORDBigEndan:
		return "dword_be"
	case TypeLink:
		return "link"
	case TypeMultiSZ:
		return "multi_sz"
	case TypeQWORD:
		return "qword"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

// UTF16Bytes decodes a little-endian UTF-16 byte slice (as the registry
// stores REG_SZ) up to the first NUL. An odd trailing byte is ignored.
func UTF16Bytes(b []byte) string {
	u := toUTF16(b)
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
}

// SplitMultiSZ splits a REG_MULTI_SZ blob (NUL-separated, double-NUL
// terminated) into its strings. Empty strings are dropped.
func SplitMultiSZ(b []byte) []string {
	u := toUTF16(b)
	var out []string
	start := 0
	for i, c := range u {
		if c == 0 {
			if i > start {
				out = append(out, string(utf16.Decode(u[start:i])))
			}
			start = i + 1
		}
	}
	if start < len(u) { // unterminated final string
		out = append(out, string(utf16.Decode(u[start:])))
	}
	return out
}

func toUTF16(b []byte) []uint16 {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return u
}

// FiletimeToTime converts a Windows FILETIME (100 ns ticks since 1601-01-01
// UTC) to a time.Time. Zero yields the zero time.
func FiletimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiffSeconds = 11644473600 // 1601-01-01 .. 1970-01-01
	sec := int64(ft/ticksPerSecond) - epochDiffSeconds
	nsec := int64(ft%ticksPerSecond) * 100
	return time.Unix(sec, nsec).UTC()
}
