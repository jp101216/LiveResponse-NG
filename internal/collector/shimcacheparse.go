package collector

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf16"
)

// Parsing for the Application Compatibility Cache ("ShimCache") binary value.
// This targets the Windows 10 / 11 "10ts" entry format, which is what the
// supported hosts (Windows 10 / Server 2016 and later) use. Older layouts
// (Windows 7/8, the 128-byte header) are detected and reported rather than
// mis-parsed.
//
// No build tag: it decodes a plain byte slice, bounds-checked, and is
// unit-tested on any OS. ShimCache records that a binary was present and its
// file last-modified time; it is strong execution/existence evidence but the
// timestamp is the file's, not a run time.

// shimEntry is one AppCompatCache record.
type shimEntry struct {
	Index        int       // position in the cache (lower is more recent)
	Path         string    // full path as recorded
	LastModified time.Time // the binary's file last-modified time (zero if unset)
}

var shim10ts = [4]byte{'1', '0', 't', 's'}

// parseAppCompatCache decodes a Windows 10/11 AppCompatCache value.
func parseAppCompatCache(b []byte) ([]shimEntry, error) {
	if len(b) < 4 {
		return nil, errors.New("appcompatcache: buffer shorter than header")
	}
	headerLen := le.Uint32(b[0:4])
	// Windows 10 1507-1607 use a 0x30 header; 1703+ use 0x34.
	if headerLen != 0x30 && headerLen != 0x34 {
		return nil, fmt.Errorf("appcompatcache: header 0x%x is not the Windows 10/11 format "+
			"(older Windows 7/8 layouts are not parsed)", headerLen)
	}
	pos := int(headerLen)
	var out []shimEntry
	for i := 0; pos+16 <= len(b); i++ {
		if [4]byte{b[pos], b[pos+1], b[pos+2], b[pos+3]} != shim10ts {
			break // padding or end of the valid entries
		}
		// b[pos+4:pos+8]  unknown
		entrySize := int(le.Uint32(b[pos+8 : pos+12]))
		entryEnd := pos + 12 + entrySize
		if entrySize < 2 || entryEnd > len(b) {
			return out, fmt.Errorf("appcompatcache: entry %d size %d runs past the buffer", i, entrySize)
		}
		pathLen := int(le.Uint16(b[pos+12 : pos+14]))
		pathStart := pos + 14
		pathEnd := pathStart + pathLen
		if pathLen%2 != 0 || pathEnd > entryEnd {
			return out, fmt.Errorf("appcompatcache: entry %d path length %d invalid", i, pathLen)
		}
		e := shimEntry{Index: i, Path: decodeUTF16LE(b[pathStart:pathEnd])}
		// An 8-byte FILETIME follows the path when the entry has room for it.
		if pathEnd+8 <= entryEnd {
			e.LastModified = fileTimeToTime(le.Uint64(b[pathEnd : pathEnd+8]))
		}
		out = append(out, e)
		pos = entryEnd
	}
	return out, nil
}

// decodeUTF16LE decodes a little-endian UTF-16 byte slice to a string.
func decodeUTF16LE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// fileTimeToTime converts a Windows FILETIME (100ns ticks since 1601-01-01) to
// a UTC time. Zero means unset and yields the zero time.
func fileTimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const ticksPerSecond = 10_000_000
	const epochDiffSeconds = 11644473600 // 1601-01-01 .. 1970-01-01
	sec := int64(ft/ticksPerSecond) - epochDiffSeconds
	nsec := int64(ft%ticksPerSecond) * 100
	return time.Unix(sec, nsec).UTC()
}
