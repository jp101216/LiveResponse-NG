package winreg

import (
	"encoding/binary"
	"reflect"
	"testing"
	"time"
	"unicode/utf16"
)

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

func TestStringStopsAtNULAndNeverExpands(t *testing.T) {
	v := Value{Type: TypeExpandSZ, Data: append(utf16le(`%SystemRoot%\x.exe`), 0, 0, 'j', 0)}
	if got := v.String(); got != `%SystemRoot%\x.exe` {
		t.Fatalf("got %q", got)
	}
	if got := (Value{Type: TypeDWORD, Data: []byte{1, 0, 0, 0}}).String(); got != "" {
		t.Fatalf("DWORD decoded as string: %q", got)
	}
	// An odd trailing byte is ignored, not read past.
	if got := (Value{Type: TypeSZ, Data: append(utf16le("ab"), 'c')}).String(); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestStrings(t *testing.T) {
	multi := append(append(append(utf16le("msv1_0"), 0, 0), utf16le("kerberos")...), 0, 0, 0, 0)
	if got := (Value{Type: TypeMultiSZ, Data: multi}).Strings(); !reflect.DeepEqual(got, []string{"msv1_0", "kerberos"}) {
		t.Fatalf("got %q", got)
	}
	// Unterminated final string (seen from sloppy writers) must not be lost.
	if got := (Value{Type: TypeMultiSZ, Data: utf16le("scecli")}).Strings(); !reflect.DeepEqual(got, []string{"scecli"}) {
		t.Fatalf("got %q", got)
	}
	if got := (Value{Type: TypeSZ, Data: utf16le("one")}).Strings(); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatalf("got %q", got)
	}
	if got := (Value{Type: TypeMultiSZ}).Strings(); got != nil {
		t.Fatalf("got %q", got)
	}
}

func TestIntegers(t *testing.T) {
	if d, ok := (Value{Type: TypeDWORD, Data: []byte{0x34, 0x12, 0, 0}}).Uint32(); !ok || d != 0x1234 {
		t.Fatalf("dword %x %v", d, ok)
	}
	if d, ok := (Value{Type: TypeDWORDBigEndan, Data: []byte{0, 0, 0x12, 0x34}}).Uint32(); !ok || d != 0x1234 {
		t.Fatalf("dword_be %x %v", d, ok)
	}
	if _, ok := (Value{Type: TypeDWORD, Data: []byte{1, 2}}).Uint32(); ok {
		t.Fatal("short DWORD accepted")
	}
	q := make([]byte, 8)
	binary.LittleEndian.PutUint64(q, 1<<40)
	if v, ok := (Value{Type: TypeQWORD, Data: q}).Uint64(); !ok || v != 1<<40 {
		t.Fatalf("qword %d %v", v, ok)
	}
	if v, ok := (Value{Type: TypeDWORD, Data: []byte{7, 0, 0, 0}}).Uint64(); !ok || v != 7 {
		t.Fatalf("widened dword %d %v", v, ok)
	}
}

func TestFiletimeToTime(t *testing.T) {
	if got := FiletimeToTime(132539328000000000); !got.Equal(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %s", got)
	}
	if !FiletimeToTime(0).IsZero() {
		t.Fatal("zero FILETIME must be the zero time")
	}
}

func TestTypeName(t *testing.T) {
	if TypeName(TypeMultiSZ) != "multi_sz" || TypeName(99) != "type_99" {
		t.Fatal("type names")
	}
}
