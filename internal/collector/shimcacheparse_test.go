package collector

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// shim10tsEntry builds one Windows 10 "10ts" cache entry for a path.
func shim10tsEntry(path string, filetime uint64) []byte {
	u := utf16.Encode([]rune(path))
	pathBytes := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(pathBytes[2*i:], c)
	}
	// entry body after the CacheEntrySize DWORD: pathLen(2) + path + filetime(8) + dataLen(4)
	body := make([]byte, 0, 2+len(pathBytes)+8+4)
	var w [8]byte
	binary.LittleEndian.PutUint16(w[:2], uint16(len(pathBytes)))
	body = append(body, w[:2]...)
	body = append(body, pathBytes...)
	binary.LittleEndian.PutUint64(w[:8], filetime)
	body = append(body, w[:8]...)
	body = append(body, 0, 0, 0, 0) // data length 0

	e := make([]byte, 0, 12+len(body))
	e = append(e, '1', '0', 't', 's')
	e = append(e, 0, 0, 0, 0) // unknown
	binary.LittleEndian.PutUint32(w[:4], uint32(len(body)))
	e = append(e, w[:4]...)
	e = append(e, body...)
	return e
}

func TestParseAppCompatCache(t *testing.T) {
	// A known FILETIME: 2021-01-01T00:00:00Z == 132539328000000000.
	const ft = 132539328000000000
	buf := make([]byte, 0x34)
	binary.LittleEndian.PutUint32(buf[0:], 0x34) // 1703+ header
	buf = append(buf, shim10tsEntry(`C:\Users\Public\update.exe`, ft)...)
	buf = append(buf, shim10tsEntry(`C:\Windows\system32\cmd.exe`, 0)...)

	entries, err := parseAppCompatCache(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Path != `C:\Users\Public\update.exe` || entries[0].Index != 0 {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if got := entries[0].LastModified.UTC().Format("2006-01-02"); got != "2021-01-01" {
		t.Errorf("entry 0 last modified = %s", got)
	}
	if entries[1].Path != `C:\Windows\system32\cmd.exe` || !entries[1].LastModified.IsZero() {
		t.Errorf("entry 1 = %+v", entries[1])
	}
}

func TestParseAppCompatCacheRejectsOldFormat(t *testing.T) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:], 0xbadc0de)
	if _, err := parseAppCompatCache(buf); err == nil {
		t.Fatal("expected an error for an unrecognised header")
	}
}

func TestParseAppCompatCacheRejectsTruncatedEntry(t *testing.T) {
	buf := make([]byte, 0x34)
	binary.LittleEndian.PutUint32(buf[0:], 0x34)
	e := shim10tsEntry(`C:\x.exe`, 0)
	binary.LittleEndian.PutUint32(e[8:], 0xffffff) // oversized entry size
	buf = append(buf, e...)
	if _, err := parseAppCompatCache(buf); err == nil {
		t.Fatal("expected an error for an entry that overruns the buffer")
	}
}
