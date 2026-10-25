//go:build windows

package winreg

import (
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Root is a predefined registry root key.
type Root syscall.Handle

// Predefined roots.
const (
	CurrentUser  Root = 0x80000001 // HKEY_CURRENT_USER
	LocalMachine Root = 0x80000002 // HKEY_LOCAL_MACHINE
	Users        Root = 0x80000003 // HKEY_USERS
)

const (
	keyRead       = 0x20019 // KEY_READ: STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
	keyWOW6464Key = 0x0100  // KEY_WOW64_64KEY

	errMoreData   = syscall.Errno(234) // ERROR_MORE_DATA
	errNoMoreItem = syscall.Errno(259) // ERROR_NO_MORE_ITEMS
)

var (
	modadvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyExW    = modadvapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey      = modadvapi32.NewProc("RegCloseKey")
	procRegEnumKeyExW    = modadvapi32.NewProc("RegEnumKeyExW")
	procRegEnumValueW    = modadvapi32.NewProc("RegEnumValueW")
	procRegQueryValueExW = modadvapi32.NewProc("RegQueryValueExW")
	procRegQueryInfoKeyW = modadvapi32.NewProc("RegQueryInfoKeyW")
)

// Key is an open, read-only registry key. Close it when done.
type Key struct{ h syscall.Handle }

// Open opens root\path read-only in the 64-bit registry view. An empty path
// opens a new handle to root itself.
func Open(root Root, path string) (Key, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return Key{}, err
	}
	var h syscall.Handle
	r, _, _ := procRegOpenKeyExW.Call(
		uintptr(root), uintptr(unsafe.Pointer(p)), 0,
		uintptr(keyRead|keyWOW6464Key), uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return Key{}, fmt.Errorf("RegOpenKeyEx(%s): %w", path, syscall.Errno(r))
	}
	return Key{h}, nil
}

// IsNotExist reports whether err means the key or value is absent — normal
// for optional autostart locations — rather than access denied or another
// failure that belongs in the report.
func IsNotExist(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND)
}

// Close releases the key handle.
func (k Key) Close() {
	if k.h != 0 {
		procRegCloseKey.Call(uintptr(k.h))
	}
}

// KeyInfo is what RegQueryInfoKey reports about a key.
type KeyInfo struct {
	SubKeys         uint32
	MaxSubKeyLen    uint32 // in UTF-16 units, without the terminator
	Values          uint32
	MaxValueNameLen uint32 // in UTF-16 units, without the terminator
	MaxValueLen     uint32 // in bytes
	// LastWrite is when the key or one of its values last changed.
	LastWrite time.Time
}

// Info returns the key's counts, buffer sizes and last-write time. The
// last-write time is forensic gold for persistence keys: it's roughly when
// the entry was added or last changed.
func (k Key) Info() (KeyInfo, error) {
	var (
		ki KeyInfo
		ft syscall.Filetime
	)
	r, _, _ := procRegQueryInfoKeyW.Call(
		uintptr(k.h),
		0, 0, 0, // class, class length, reserved
		uintptr(unsafe.Pointer(&ki.SubKeys)),
		uintptr(unsafe.Pointer(&ki.MaxSubKeyLen)),
		0, // max class length
		uintptr(unsafe.Pointer(&ki.Values)),
		uintptr(unsafe.Pointer(&ki.MaxValueNameLen)),
		uintptr(unsafe.Pointer(&ki.MaxValueLen)),
		0, // security descriptor size
		uintptr(unsafe.Pointer(&ft)),
	)
	if r != 0 {
		return KeyInfo{}, fmt.Errorf("RegQueryInfoKey: %w", syscall.Errno(r))
	}
	ki.LastWrite = FiletimeToTime(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
	return ki, nil
}

// LastWrite returns the key's last-write time (zero if it can't be read).
func (k Key) LastWrite() time.Time {
	ki, err := k.Info()
	if err != nil {
		return time.Time{}
	}
	return ki.LastWrite
}

// SubKeys returns the names of the key's immediate subkeys.
func (k Key) SubKeys() ([]string, error) {
	ki, err := k.Info()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, ki.SubKeys)
	name := make([]uint16, ki.MaxSubKeyLen+1)
	for i, retries := uint32(0), 0; ; {
		cch := uint32(len(name))
		r, _, _ := procRegEnumKeyExW.Call(
			uintptr(k.h), uintptr(i),
			uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&cch)),
			0, 0, 0, 0,
		)
		switch e := syscall.Errno(r); e {
		case 0:
			out = append(out, syscall.UTF16ToString(name[:cch]))
			i++
			retries = 0
		case errNoMoreItem:
			return out, nil
		case errMoreData:
			// A longer subkey appeared since Info(); grow and retry this index.
			if retries++; retries > 4 {
				return out, fmt.Errorf("RegEnumKeyEx: %w", e)
			}
			name = make([]uint16, len(name)*2+1)
		default:
			return out, fmt.Errorf("RegEnumKeyEx: %w", e)
		}
	}
}

// Values returns every value under the key with its raw type and bytes.
func (k Key) Values() ([]Value, error) {
	ki, err := k.Info()
	if err != nil {
		return nil, err
	}
	out := make([]Value, 0, ki.Values)
	name := make([]uint16, ki.MaxValueNameLen+1)
	data := make([]byte, ki.MaxValueLen+2) // +2: room for a REG_SZ terminator
	for i, retries := uint32(0), 0; ; {
		cchName := uint32(len(name))
		cbData := uint32(len(data))
		var typ uint32
		r, _, _ := procRegEnumValueW.Call(
			uintptr(k.h), uintptr(i),
			uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&cchName)),
			0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&cbData)),
		)
		switch e := syscall.Errno(r); e {
		case 0:
			v := Value{Name: syscall.UTF16ToString(name[:cchName]), Type: typ}
			if cbData > 0 {
				v.Data = append([]byte(nil), data[:min(int(cbData), len(data))]...)
			}
			out = append(out, v)
			i++
			retries = 0
		case errNoMoreItem:
			return out, nil
		case errMoreData:
			// A value grew since Info(); enlarge both buffers and retry.
			if retries++; retries > 4 {
				return out, fmt.Errorf("RegEnumValue: %w", e)
			}
			name = make([]uint16, len(name)*2+1)
			data = make([]byte, len(data)*2+2)
		default:
			return out, fmt.Errorf("RegEnumValue: %w", e)
		}
	}
}

// Value reads one named value ("" is the key's default value).
func (k Key) Value(name string) (Value, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return Value{}, err
	}
	var typ, size uint32
	r, _, _ := procRegQueryValueExW.Call(
		uintptr(k.h), uintptr(unsafe.Pointer(p)), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)),
	)
	if e := syscall.Errno(r); e != 0 && e != errMoreData {
		return Value{}, fmt.Errorf("RegQueryValueEx(%s): %w", name, e)
	}
	v := Value{Name: name, Type: typ}
	if size == 0 {
		return v, nil
	}
	// The value can grow between the probe and the read; retry a few times.
	for attempt := 0; attempt < 4; attempt++ {
		data := make([]byte, size+2)
		got := uint32(len(data))
		r, _, _ = procRegQueryValueExW.Call(
			uintptr(k.h), uintptr(unsafe.Pointer(p)), 0,
			uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&got)),
		)
		switch e := syscall.Errno(r); e {
		case 0:
			v.Type = typ
			v.Data = data[:min(int(got), len(data))]
			return v, nil
		case errMoreData:
			size = got + 64
		default:
			return Value{}, fmt.Errorf("RegQueryValueEx(%s): %w", name, e)
		}
	}
	return Value{}, fmt.Errorf("RegQueryValueEx(%s): value kept growing", name)
}

// ReadValue opens root\path, reads one value and closes the key.
func ReadValue(root Root, path, name string) (Value, error) {
	k, err := Open(root, path)
	if err != nil {
		return Value{}, err
	}
	defer k.Close()
	return k.Value(name)
}
