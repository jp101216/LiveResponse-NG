package collector

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

func sz(s string) winreg.Value {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return winreg.Value{Type: winreg.TypeSZ, Data: b}
}

func dword(n uint32) winreg.Value {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return winreg.Value{Type: winreg.TypeDWORD, Data: b}
}

func TestIAFEntry(t *testing.T) {
	sha := strings.Repeat("ab", 20) // 40 hex
	vm := map[string]winreg.Value{
		"lowercaselongpath": sz(`c:\users\public\evil.exe`),
		"name":              sz("evil.exe"),
		"publisher":         sz("Acme Corp"),
		"version":           sz("1.2.3.4"),
		"binarytype":        sz("pe64_amd64"),
		"linkdate":          sz("01/02/2021 03:04:05"),
		"programid":         sz("0000abcd"),
		"fileid":            sz("0000" + sha),
		"size":              dword(12345),
	}
	e := iafEntry("0001", time.Unix(1609459200, 0).UTC(), vm)
	if e.Path != `c:\users\public\evil.exe` || e.Name != "evil.exe" {
		t.Fatalf("entry = %+v", e)
	}
	if e.SHA1 != sha {
		t.Errorf("sha1 = %q, want %q", e.SHA1, sha)
	}
	if e.Publisher != "Acme Corp" || e.Version != "1.2.3.4" || e.BinaryType != "pe64_amd64" {
		t.Errorf("metadata = %+v", e)
	}
	if !e.HasSize || e.Size != 12345 {
		t.Errorf("size = %d (has %v)", e.Size, e.HasSize)
	}
	if e.Source != "InventoryApplicationFile" {
		t.Errorf("source = %q", e.Source)
	}
}

func TestIAFEntryStringSize(t *testing.T) {
	// Some builds store Size as a string; it should still parse.
	e := iafEntry("x", time.Time{}, map[string]winreg.Value{
		"lowercaselongpath": sz(`c:\windows\system32\cmd.exe`),
		"size":              sz("4096"),
	})
	if !e.HasSize || e.Size != 4096 {
		t.Errorf("string size = %d (has %v)", e.Size, e.HasSize)
	}
}

func TestLegacyFileEntry(t *testing.T) {
	sha := strings.Repeat("cd", 20)
	e := legacyFileEntry(`fileref`, time.Time{}, map[string]winreg.Value{
		"15":  sz(`c:\temp\dropper.exe`),
		"101": sz("0000" + sha),
	})
	if e.Path != `c:\temp\dropper.exe` || e.SHA1 != sha || e.Source != "File" {
		t.Fatalf("legacy entry = %+v", e)
	}
}

func TestAmcacheSHA1(t *testing.T) {
	sha := strings.Repeat("a", 40)
	cases := map[string]string{
		"0000" + sha:                sha, // 44-char "0000"+hash
		sha:                         sha, // bare 40-hex
		strings.ToUpper(sha):        sha, // upper-cased
		"0000" + "nothex" + sha[6:]: "",  // non-hex body
		"short":                     "",
		"":                          "",
	}
	for in, want := range cases {
		if got := amcacheSHA1(in); got != want {
			t.Errorf("amcacheSHA1(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAmcacheFindings(t *testing.T) {
	hot := amcacheEntry{Path: `c:\users\public\x.exe`, SHA1: strings.Repeat("a", 40)}
	f := amcacheFindings(hot)
	if len(f) != 1 || f[0].Rule != "execution.amcache_unusual_path" || f[0].Severity != SevNotable {
		t.Fatalf("findings = %+v", f)
	}
	if !strings.Contains(f[0].Detail, "sha1") {
		t.Errorf("detail should mention the sha1: %q", f[0].Detail)
	}

	for _, p := range []string{`c:\program files\app\app.exe`, `c:\windows\system32\svchost.exe`, ""} {
		if f := amcacheFindings(amcacheEntry{Path: p}); len(f) != 0 {
			t.Errorf("path %q unexpectedly flagged: %+v", p, f)
		}
	}
}

func TestAmcacheFields(t *testing.T) {
	f := amcacheFields(amcacheEntry{
		Key: "0001", Source: "InventoryApplicationFile",
		Path: `c:\temp\x.exe`, Name: "x.exe", SHA1: "deadbeef",
		HasSize: true, Size: 99,
	})
	if f["suspicious_path"] != true {
		t.Errorf("temp path should be suspicious: %v", f["suspicious_path"])
	}
	if f["path"] != `c:\temp\x.exe` || f["sha1"] != "deadbeef" || f["size"].(int64) != 99 {
		t.Errorf("fields = %+v", f)
	}
}
