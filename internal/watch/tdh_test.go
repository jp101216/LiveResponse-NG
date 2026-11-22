package watch

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unicode/utf16"
)

func u16le(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return append(b, 0, 0)
}

// The Kernel-Network TCP connect layout: PID, size, daddr, saddr, dport,
// sport, then options and a connection pointer.
func TestTDHDecodeNetwork(t *testing.T) {
	s := tdhSchema{top: 8, props: []tdhProp{
		{name: "PID", inType: inUint32},
		{name: "size", inType: inUint32},
		{name: "daddr", inType: inUint32, outType: 23},
		{name: "saddr", inType: inUint32, outType: 23},
		{name: "dport", inType: inUint16, outType: outPort},
		{name: "sport", inType: inUint16, outType: outPort},
		{name: "mss", inType: inUint16},
		{name: "connid", inType: inPointer},
	}}
	var d []byte
	d = binary.LittleEndian.AppendUint32(d, 4242)
	d = binary.LittleEndian.AppendUint32(d, 0)
	d = append(d, 203, 0, 113, 7)
	d = append(d, 10, 0, 0, 5)
	d = append(d, 0x01, 0xbb) // 443, network order
	d = append(d, 0xc3, 0x50) // 50000
	d = binary.LittleEndian.AppendUint16(d, 1460)
	d = binary.LittleEndian.AppendUint64(d, 0xdeadbeef)
	f, err := s.decode(d, 8, map[string]bool{"PID": true, "daddr": true, "dport": true, "sport": true, "connid": true})
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := f["PID"].uint()
	dp, _ := f["dport"].uint()
	sp, _ := f["sport"].uint()
	if pid != 4242 || dp != 443 || sp != 50000 || f["daddr"].addr() != netip.MustParseAddr("203.0.113.7") || len(f["connid"].raw) != 8 {
		t.Fatalf("decoded %d %d %d %v", pid, dp, sp, f["daddr"].addr())
	}
	// A 32-bit producer's pointer is 4 bytes.
	if _, err := s.decode(d[:len(d)-4], 4, nil); err != nil {
		t.Fatal(err)
	}
	// Truncated payloads stop with an error but keep what came before.
	f, err = s.decode(d[:10], 8, map[string]bool{"PID": true, "dport": true})
	if err == nil || len(f) != 1 {
		t.Fatalf("truncated: %v %v", f, err)
	}
}

// Kernel-Process start: integers, then a null-terminated image path, then
// more fields; plus a parameter-counted array and a struct.
func TestTDHDecodeStringsArraysStructs(t *testing.T) {
	s := tdhSchema{top: 6, props: []tdhProp{
		{name: "ProcessID", inType: inUint32},
		{name: "ImageName", inType: inUnicodeString},
		{name: "N", inType: inUint16},
		{name: "Items", inType: inUint32, flags: propParamCount, count: 2},
		{name: "Pair", flags: propStruct, structStart: 6, structMembers: 2},
		{name: "Tail", inType: inAnsiString},
		{name: "A", inType: inUint8},
		{name: "B", inType: inCountedString},
	}}
	var d []byte
	d = binary.LittleEndian.AppendUint32(d, 77)
	d = append(d, u16le(`\Device\HarddiskVolume3\Windows\notepad.exe`)...)
	d = binary.LittleEndian.AppendUint16(d, 3)
	for i := 0; i < 3; i++ {
		d = binary.LittleEndian.AppendUint32(d, uint32(i))
	}
	d = append(d, 9)
	d = binary.LittleEndian.AppendUint16(d, 4)
	d = append(d, 'a', 0, 'b', 0)
	d = append(d, "tail\x00"...)
	f, err := s.decode(d, 8, map[string]bool{"ProcessID": true, "ImageName": true, "Items": true, "Tail": true})
	if err != nil {
		t.Fatal(err)
	}
	if f["ImageName"].str() != `\Device\HarddiskVolume3\Windows\notepad.exe` || len(f["Items"].raw) != 12 || f["Tail"].str() != "tail" {
		t.Fatalf("decoded %q %d %q", f["ImageName"].str(), len(f["Items"].raw), f["Tail"].str())
	}
	// Unknown types and absurd counts stop the walk instead of misreading.
	bad := tdhSchema{top: 2, props: []tdhProp{{name: "X", inType: 999}, {name: "Y", inType: inUint32}}}
	if _, err := bad.decode(make([]byte, 8), 8, map[string]bool{"Y": true}); err == nil {
		t.Error("an unknown in-type was sized")
	}
	huge := tdhSchema{top: 1, props: []tdhProp{{name: "X", inType: inUint8, count: 60000}}}
	if _, err := huge.decode(make([]byte, 8), 8, nil); err == nil {
		t.Error("an oversized array was accepted")
	}
	loop := tdhSchema{top: 1, props: []tdhProp{{name: "S", flags: propStruct, structStart: 0, structMembers: 1}}}
	if _, err := loop.decode(make([]byte, 8), 8, nil); err == nil {
		t.Error("a self-referencing struct was walked")
	}
}
