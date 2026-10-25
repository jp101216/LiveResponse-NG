package collector

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Parsing for Windows shortcut (.lnk, MS-SHLLINK) files, so a shortcut in a
// Startup folder is judged by what it runs — its target and arguments — and
// not by where the shortcut file itself sits.
//
// No build tag: it decodes plain bytes, bounds-checked everywhere (shortcuts
// are attacker-supplied), and is unit-tested on any OS against fixtures built
// by an independent implementation.

// lnkInfo is what a shortcut runs.
type lnkInfo struct {
	Target       string // resolved target path, "" if it couldn't be resolved
	TargetSource string // linkinfo | environment | idlist | relative
	Arguments    string
	WorkingDir   string
	RelativePath string
	IconLocation string
	Description  string
	ShowCommand  uint32 // 1 normal, 3 maximized, 7 minimized
}

// Command renders the shortcut as the command line it launches.
func (l lnkInfo) Command() string {
	t := l.Target
	if t == "" {
		t = l.RelativePath
	}
	if strings.ContainsAny(t, " \t") {
		t = `"` + t + `"`
	}
	return strings.TrimSpace(t + " " + l.Arguments)
}

const (
	lnkHasIDList     = 0x0001
	lnkHasLinkInfo   = 0x0002
	lnkHasName       = 0x0004
	lnkHasRelPath    = 0x0008
	lnkHasWorkingDir = 0x0010
	lnkHasArguments  = 0x0020
	lnkHasIconLoc    = 0x0040
	lnkIsUnicode     = 0x0080
	lnkHeaderSize    = 0x4C
	lnkEnvBlockSig   = 0xA0000001
	lnkMaxStringData = 32768 // characters; the format's own field is 16-bit
)

var lnkCLSID = []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// parseLNK decodes a shortcut file.
func parseLNK(b []byte) (lnkInfo, error) {
	var l lnkInfo
	if len(b) < lnkHeaderSize || le.Uint32(b) != lnkHeaderSize || !bytes.Equal(b[4:20], lnkCLSID) {
		return l, errors.New("lnk: not a shell link (bad header)")
	}
	flags := le.Uint32(b[20:])
	l.ShowCommand = le.Uint32(b[60:])
	pos := lnkHeaderSize

	var idPath string
	if flags&lnkHasIDList != 0 {
		if pos+2 > len(b) {
			return l, errors.New("lnk: truncated ID list")
		}
		n := int(le.Uint16(b[pos:]))
		if pos+2+n > len(b) {
			return l, errors.New("lnk: ID list runs past the file")
		}
		idPath = idListPath(b[pos+2 : pos+2+n])
		pos += 2 + n
	}
	var infoPath string
	if flags&lnkHasLinkInfo != 0 {
		if pos+4 > len(b) {
			return l, errors.New("lnk: truncated LinkInfo")
		}
		n := int(le.Uint32(b[pos:]))
		if n < 4 || pos+n > len(b) {
			return l, fmt.Errorf("lnk: LinkInfo size %d runs past the file", n)
		}
		infoPath = linkInfoPath(b[pos : pos+n])
		pos += n
	}

	unicode := flags&lnkIsUnicode != 0
	readString := func(present bool) (string, error) {
		if !present {
			return "", nil
		}
		if pos+2 > len(b) {
			return "", errors.New("lnk: truncated string data")
		}
		count := int(le.Uint16(b[pos:]))
		pos += 2
		size := count
		if unicode {
			size *= 2
		}
		if count > lnkMaxStringData || pos+size > len(b) {
			return "", errors.New("lnk: string data runs past the file")
		}
		var s string
		if unicode {
			s = utf16LE(b[pos : pos+size])
		} else {
			s = ansi(b[pos : pos+size])
		}
		pos += size
		return s, nil
	}
	var err error
	if l.Description, err = readString(flags&lnkHasName != 0); err != nil {
		return l, err
	}
	if l.RelativePath, err = readString(flags&lnkHasRelPath != 0); err != nil {
		return l, err
	}
	if l.WorkingDir, err = readString(flags&lnkHasWorkingDir != 0); err != nil {
		return l, err
	}
	if l.Arguments, err = readString(flags&lnkHasArguments != 0); err != nil {
		return l, err
	}
	if l.IconLocation, err = readString(flags&lnkHasIconLoc != 0); err != nil {
		return l, err
	}
	envPath := lnkEnvironmentTarget(b[pos:])

	switch {
	case infoPath != "":
		l.Target, l.TargetSource = infoPath, "linkinfo"
	case envPath != "":
		l.Target, l.TargetSource = envPath, "environment"
	case idPath != "":
		l.Target, l.TargetSource = idPath, "idlist"
	case l.RelativePath != "":
		l.Target, l.TargetSource = l.RelativePath, "relative"
	}
	return l, nil
}

// linkInfoPath resolves the target from a LinkInfo structure: a local base
// path, or a network share name, plus the common path suffix.
func linkInfoPath(li []byte) string {
	if len(li) < 0x1C {
		return ""
	}
	header := le.Uint32(li[4:])
	liFlags := le.Uint32(li[8:])
	localOff := le.Uint32(li[16:])
	cnrlOff := le.Uint32(li[20:])
	suffixOff := le.Uint32(li[24:])
	var localU, suffixU uint32
	if header >= 0x24 && len(li) >= 0x24 {
		localU, suffixU = le.Uint32(li[28:]), le.Uint32(li[32:])
	}
	suffix := ""
	if suffixU != 0 {
		suffix = utf16Z(li, int(suffixU))
	} else if suffixOff != 0 {
		suffix = ansiZ(li, int(suffixOff))
	}
	if liFlags&0x1 != 0 { // VolumeIDAndLocalBasePath
		base := ""
		if localU != 0 {
			base = utf16Z(li, int(localU))
		} else {
			base = ansiZ(li, int(localOff))
		}
		if base != "" {
			return joinLnkPath(base, suffix)
		}
	}
	if liFlags&0x2 != 0 && int(cnrlOff)+0x14 <= len(li) { // CommonNetworkRelativeLink
		cnrl := li[cnrlOff:]
		netOff := le.Uint32(cnrl[8:])
		net := ""
		if netOff > 0x14 && len(cnrl) >= 0x1C {
			net = utf16Z(cnrl, int(le.Uint32(cnrl[20:])))
		}
		if net == "" {
			net = ansiZ(cnrl, int(netOff))
		}
		if net != "" {
			return joinLnkPath(net, suffix)
		}
	}
	return ""
}

func joinLnkPath(base, suffix string) string {
	if suffix == "" {
		return base
	}
	if strings.HasSuffix(base, `\`) {
		return base + suffix
	}
	return base + `\` + suffix
}

// lnkEnvironmentTarget finds an EnvironmentVariableDataBlock among the extra
// data blocks and returns its target (e.g. %windir%\system32\cmd.exe).
func lnkEnvironmentTarget(extra []byte) string {
	for pos, n := 0, 0; pos+8 <= len(extra) && n < 64; n++ {
		size := int(le.Uint32(extra[pos:]))
		if size < 8 || pos+size > len(extra) {
			return ""
		}
		if le.Uint32(extra[pos+4:]) == lnkEnvBlockSig && size >= 8+260+520 {
			blk := extra[pos : pos+size]
			if s := utf16Z(blk, 8+260); s != "" {
				return s
			}
			return ansiZ(blk, 8)
		}
		pos += size
	}
	return ""
}

// idListPath rebuilds a file-system path from a link target ID list: a
// volume ("C:\") or network item followed by file-entry items. Anything else
// (control panel items, URIs, ...) is not guessed at: "" is returned.
func idListPath(b []byte) string {
	var parts []string
	for pos, n := 0, 0; pos+2 <= len(b) && n < 256; n++ {
		size := int(le.Uint16(b[pos:]))
		if size == 0 {
			break // terminal ID
		}
		if size < 3 || pos+size > len(b) {
			return ""
		}
		item := b[pos : pos+size]
		typ := item[2]
		switch {
		case typ == 0x1F: // root folder (a CLSID such as My Computer)
		case typ&0x70 == 0x20: // volume
			s := ansiZ(item, 3)
			if len(s) < 2 || s[1] != ':' {
				return ""
			}
			parts = []string{strings.TrimRight(s, `\`)}
		case typ&0x70 == 0x40: // network location
			s := ansiZ(item, 5)
			if !strings.HasPrefix(s, `\\`) {
				return ""
			}
			parts = []string{strings.TrimRight(s, `\`)}
		case typ&0x70 == 0x30: // file or directory entry
			name := fileEntryName(item)
			if name == "" || len(parts) == 0 {
				return ""
			}
			parts = append(parts, name)
		default:
			return ""
		}
		pos += size
	}
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts, `\`)
}

// fileEntryName returns a file-entry shell item's long name (from its
// 0xBEEF0004 extension block) or, failing that, its primary name.
func fileEntryName(item []byte) string {
	const nameOff = 14 // size(2) type(1) pad(1) size(4) mtime(4) attributes(2)
	if len(item) <= nameOff {
		return ""
	}
	var primary string
	var end int
	if item[2]&0x04 != 0 { // primary name stored as UTF-16
		primary, end = utf16ZEnd(item, nameOff)
	} else {
		primary, end = ansiZEnd(item, nameOff)
	}
	if long := beef0004Name(item[end:]); long != "" {
		return long
	}
	if strings.ContainsAny(primary, `\/`) {
		return ""
	}
	return primary
}

// beef0004Name extracts the long name from a file-entry extension block. Its
// position depends on the block version (XP 3, Vista 7, Windows 7 8,
// Windows 8+ 9).
func beef0004Name(rest []byte) string {
	sig := []byte{0x04, 0x00, 0xEF, 0xBE}
	i := bytes.Index(rest, sig)
	if i < 4 {
		return ""
	}
	ext := rest[i-4:]
	size := int(le.Uint16(ext))
	if size > len(ext) || size < 20 {
		return ""
	}
	ext = ext[:size]
	var off int
	switch v := le.Uint16(ext[2:]); {
	case v >= 9:
		off = 46
	case v == 8:
		off = 42
	case v == 7:
		off = 38
	case v >= 3:
		off = 20
	default:
		return ""
	}
	name := utf16Z(ext, off)
	if name == "" || strings.ContainsAny(name, "\\/\x00") {
		return ""
	}
	return name
}

// ---- bounded string readers -------------------------------------------

func utf16LE(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
}

// ansi decodes single-byte text. Code-page details aside, ASCII is exact and
// other bytes map to the Latin-1 code points (never invalid UTF-8).
func ansi(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func ansiZ(b []byte, off int) string  { s, _ := ansiZEnd(b, off); return s }
func utf16Z(b []byte, off int) string { s, _ := utf16ZEnd(b, off); return s }

// ansiZEnd reads a NUL-terminated single-byte string at off and returns it
// and the offset just past the terminator.
func ansiZEnd(b []byte, off int) (string, int) {
	if off <= 0 || off >= len(b) {
		return "", len(b)
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 {
		return ansi(b[off:]), len(b)
	}
	return ansi(b[off : off+end]), off + end + 1
}

// utf16ZEnd reads a NUL-terminated UTF-16LE string at off.
func utf16ZEnd(b []byte, off int) (string, int) {
	if off <= 0 || off >= len(b) {
		return "", len(b)
	}
	i := off
	for i+1 < len(b) && (b[i] != 0 || b[i+1] != 0) {
		i += 2
	}
	end := min(i+2, len(b))
	return utf16LE(b[off:i]), end
}
