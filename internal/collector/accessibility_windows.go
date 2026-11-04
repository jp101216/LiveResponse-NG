//go:build windows

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	modversion                    = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSizeExW = modversion.NewProc("GetFileVersionInfoSizeExW")
	procGetFileVersionInfoExW     = modversion.NewProc("GetFileVersionInfoExW")
	procVerQueryValueW            = modversion.NewProc("VerQueryValueW")
)

// fileVerGetNeutral asks for the version resource of the file itself rather
// than of its language (.mui) resources.
const fileVerGetNeutral = 0x2

// accessibilityShellsToCompare are the programs an accessibility program is
// most often replaced with, compared byte for byte (relative to SystemRoot).
var accessibilityShellsToCompare = []string{
	`System32\cmd.exe`, `System32\WindowsPowerShell\v1.0\powershell.exe`, `explorer.exe`, `System32\taskmgr.exe`,
}

// accessibility checks the programs the logon screen runs before anyone logs
// on: a copy of a shell, or a program whose version resource names another
// program, in their place is a SYSTEM backdoor at the logon screen.
func (a *asepWalker) accessibility() {
	shells := map[string]string{}
	for _, rel := range accessibilityShellsToCompare {
		if r := hashFile(a.ctx, filepath.Join(a.sysRoot, rel), 0); r.SHA256 != "" {
			shells[r.SHA256] = filepath.Base(rel)
		}
	}
	sys32 := filepath.Join(a.sysRoot, "System32")
	checked := 0
	names := map[string]string{}
	for _, name := range accessibilityBinaries {
		if a.done() {
			return
		}
		path := filepath.Join(sys32, name)
		if _, err := os.Stat(path); err != nil {
			continue // Server Core lacks some of them
		}
		checked++
		orig, err := originalFileName(path)
		if err != nil {
			names[name] = "(unreadable: " + err.Error() + ")"
		} else {
			names[name] = orig
		}
		r := hashFile(a.ctx, path, 0)
		if f, ok := accessibilityFinding(path, orig, shells[r.SHA256]); ok {
			fields := map[string]any{"kind": "accessibility_binary", "location": sys32, "name": name, "command": path,
				"original_file_name": orig}
			if r.SHA256 != "" {
				fields["image_sha256"] = r.SHA256
			}
			a.res.Add(fields, f)
			a.count++
		}
	}
	a.res.SetMeta("accessibility_binaries_checked", checked)
	a.res.SetMeta("accessibility_original_names", names)
}

// originalFileName reads OriginalFilename from a file's language-neutral
// version resource, trying each translation it lists, then US English.
func originalFileName(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var zero uint32
	n, _, e := procGetFileVersionInfoSizeExW.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&zero)))
	if n == 0 {
		return "", fmt.Errorf("no version resource: %v", e)
	}
	if n > 4<<20 {
		return "", errors.New("version resource exceeds 4 MiB limit")
	}
	buf := make([]byte, n)
	if ok, _, e := procGetFileVersionInfoExW.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), 0, n,
		uintptr(unsafe.Pointer(&buf[0]))); ok == 0 {
		return "", fmt.Errorf("version resource: %v", e)
	}
	// query returns the bytes a sub-block points at (always inside buf).
	query := func(sub string) ([]byte, uint32) {
		s, err := syscall.UTF16PtrFromString(sub)
		if err != nil {
			return nil, 0
		}
		var ptr uintptr
		var length uint32
		if ok, _, _ := procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(s)),
			uintptr(unsafe.Pointer(&ptr)), uintptr(unsafe.Pointer(&length))); ok == 0 || ptr == 0 {
			return nil, 0
		}
		off := ptr - uintptr(unsafe.Pointer(&buf[0]))
		if off >= uintptr(len(buf)) {
			return nil, 0
		}
		return buf[off:], length
	}
	var langs []string
	if b, l := query(`\VarFileInfo\Translation`); b != nil {
		for i := 0; i+4 <= int(l) && i+4 <= len(b); i += 4 {
			langs = append(langs, fmt.Sprintf("%04x%04x", binary.LittleEndian.Uint16(b[i:]), binary.LittleEndian.Uint16(b[i+2:])))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "04090000")
	for _, lang := range langs {
		b, chars := query(`\StringFileInfo\` + lang + `\OriginalFilename`)
		if b == nil || chars == 0 {
			continue
		}
		u := make([]uint16, 0, chars)
		for i := 0; i < int(chars) && 2*i+1 < len(b); i++ {
			c := binary.LittleEndian.Uint16(b[2*i:])
			if c == 0 {
				break
			}
			u = append(u, c)
		}
		if len(u) > 0 {
			return string(utf16.Decode(u)), nil
		}
	}
	return "", errors.New("the version resource has no OriginalFilename")
}
