package winreg

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// A minimal regf hive builder, used only to exercise the offline hive reader.
// It lays cells into a single hive bin and wires up the offsets the parser
// follows: a root key -> InventoryApplicationFile -> one file entry with a mix
// of string (data-cell) and DWORD (resident) values.

const ftJan2021 = 132539328000000000 // 2021-01-01T00:00:00Z

type hiveBuilder struct{ bins []byte }

func newHiveBuilder() *hiveBuilder {
	hb := make([]byte, 32) // hive-bin header; the parser indexes by offset and ignores it
	copy(hb[0:4], "hbin")
	return &hiveBuilder{bins: hb}
}

// add writes a cell (negative size = allocated) 8-byte aligned, returning its
// offset relative to the hive bins data.
func (b *hiveBuilder) add(payload []byte) uint32 {
	off := uint32(len(b.bins))
	size := 4 + len(payload)
	if size%8 != 0 {
		size += 8 - size%8
	}
	cell := make([]byte, size)
	binary.LittleEndian.PutUint32(cell, uint32(int32(-size)))
	copy(cell[4:], payload)
	b.bins = append(b.bins, cell...)
	return off
}

func u16z(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2+2)
	var w [2]byte
	for _, c := range u {
		binary.LittleEndian.PutUint16(w[:], c)
		out = append(out, w[:]...)
	}
	return append(out, 0, 0) // NUL terminator
}

func makeVK(name string, typ, dataOff, dataSize uint32, resident bool) []byte {
	p := make([]byte, 20+len(name))
	copy(p[0:2], "vk")
	binary.LittleEndian.PutUint16(p[2:4], uint16(len(name)))
	if resident {
		dataSize |= 0x80000000
	}
	binary.LittleEndian.PutUint32(p[4:8], dataSize)
	binary.LittleEndian.PutUint32(p[8:12], dataOff)
	binary.LittleEndian.PutUint32(p[12:16], typ)
	binary.LittleEndian.PutUint16(p[16:18], 0x0001) // compressed (Latin-1) name
	copy(p[20:], name)
	return p
}

func (b *hiveBuilder) strVK(name, s string) uint32 {
	d := u16z(s)
	return b.add(makeVK(name, TypeSZ, b.add(d), uint32(len(d)), false))
}

func (b *hiveBuilder) dwordVK(name string, val uint32) uint32 {
	return b.add(makeVK(name, TypeDWORD, val, 4, true))
}

func (b *hiveBuilder) valueList(offs ...uint32) uint32 {
	p := make([]byte, 4*len(offs))
	for i, o := range offs {
		binary.LittleEndian.PutUint32(p[i*4:], o)
	}
	return b.add(p)
}

func (b *hiveBuilder) subkeyList(offs ...uint32) uint32 {
	p := make([]byte, 4+8*len(offs))
	copy(p[0:2], "lh")
	binary.LittleEndian.PutUint16(p[2:4], uint16(len(offs)))
	for i, o := range offs {
		binary.LittleEndian.PutUint32(p[4+i*8:], o) // offset; the 4-byte hash is left zero
	}
	return b.add(p)
}

func makeNK(name string, nSub, subOff, nVal, valOff uint32, ft uint64) []byte {
	p := make([]byte, 76+len(name))
	copy(p[0:2], "nk")
	binary.LittleEndian.PutUint16(p[2:4], 0x0020) // KEY_COMP_NAME
	binary.LittleEndian.PutUint64(p[4:12], ft)
	binary.LittleEndian.PutUint32(p[16:20], 0xffffffff) // parent
	binary.LittleEndian.PutUint32(p[20:24], nSub)
	binary.LittleEndian.PutUint32(p[28:32], subOff)
	binary.LittleEndian.PutUint32(p[32:36], 0xffffffff) // volatile subkeys
	binary.LittleEndian.PutUint32(p[36:40], nVal)
	binary.LittleEndian.PutUint32(p[40:44], valOff)
	binary.LittleEndian.PutUint32(p[44:48], 0xffffffff) // security
	binary.LittleEndian.PutUint32(p[48:52], 0xffffffff) // class
	binary.LittleEndian.PutUint16(p[72:74], uint16(len(name)))
	copy(p[76:], name)
	return p
}

func (b *hiveBuilder) finish(rootOff uint32) []byte {
	for len(b.bins)%4096 != 0 {
		b.bins = append(b.bins, 0)
	}
	file := make([]byte, hiveBaseBlock+len(b.bins))
	copy(file[0:4], "regf")
	binary.LittleEndian.PutUint64(file[12:20], ftJan2021)
	binary.LittleEndian.PutUint32(file[36:40], rootOff)
	binary.LittleEndian.PutUint32(file[40:44], uint32(len(b.bins)))
	copy(file[hiveBaseBlock:], b.bins)
	return file
}

func buildAmcacheHive() []byte {
	b := newHiveBuilder()
	entryVals := b.valueList(
		b.strVK("LowerCaseLongPath", `c:\users\public\evil.exe`),
		b.strVK("Name", "evil.exe"),
		b.strVK("FileId", "0000"+strings.Repeat("a", 40)),
		b.strVK("Publisher", "Acme Corp"),
		b.strVK("LinkDate", "01/02/2021 03:04:05"),
		b.dwordVK("Size", 12345),
	)
	entry := b.add(makeNK("0001a2b3c4", 0, 0xffffffff, 6, entryVals, ftJan2021))
	iaf := b.add(makeNK("InventoryApplicationFile", 1, b.subkeyList(entry), 0, 0xffffffff, ftJan2021))
	root := b.add(makeNK("ROOT", 1, b.subkeyList(iaf), 0, 0xffffffff, ftJan2021))
	return b.finish(root)
}

func TestParseHive(t *testing.T) {
	h, err := ParseHive(buildAmcacheHive())
	if err != nil {
		t.Fatal(err)
	}
	root, err := h.Root()
	if err != nil || root.Name != "ROOT" {
		t.Fatalf("root = %+v, err %v", root, err)
	}

	iaf, err := h.KeyAt("InventoryApplicationFile")
	if err != nil {
		t.Fatal(err)
	}
	subs, err := iaf.SubKeys()
	if err != nil || len(subs) != 1 {
		t.Fatalf("subkeys = %d, err %v", len(subs), err)
	}
	if subs[0].Name != "0001a2b3c4" {
		t.Fatalf("entry name = %q", subs[0].Name)
	}
	if subs[0].LastWrite.UTC().Format("2006-01-02") != "2021-01-01" {
		t.Errorf("entry last write = %v", subs[0].LastWrite)
	}

	vm := subs[0].ValueMap()
	if got := vm["lowercaselongpath"].String(); got != `c:\users\public\evil.exe` {
		t.Errorf("path = %q", got)
	}
	if got := vm["fileid"].String(); got != "0000"+strings.Repeat("a", 40) {
		t.Errorf("fileid = %q", got)
	}
	if got := vm["publisher"].String(); got != "Acme Corp" {
		t.Errorf("publisher = %q", got)
	}
	if n, ok := vm["size"].Uint32(); !ok || n != 12345 {
		t.Errorf("size = %d, ok %v", n, ok)
	}
}

func TestKeyAtViaChild(t *testing.T) {
	h, err := ParseHive(buildAmcacheHive())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.KeyAt(`InventoryApplicationFile\0001a2b3c4`); err != nil {
		t.Errorf("navigating to the entry: %v", err)
	}
	if _, err := h.KeyAt(`InventoryApplicationFile\nope`); err == nil {
		t.Error("expected an error for a missing subkey")
	}
}

func TestParseHiveRejects(t *testing.T) {
	if _, err := ParseHive(make([]byte, 100)); err == nil {
		t.Error("expected an error for a short hive")
	}
	bad := make([]byte, hiveBaseBlock+64)
	copy(bad[0:4], "xxxx")
	if _, err := ParseHive(bad); err == nil {
		t.Error("expected an error for a bad signature")
	}
}

// TestValuesHugeCountNoOOB guards the value-count clamp against integer
// overflow. The key claims ~1 billion values but its value-list cell holds room
// for only two offsets. numValues is attacker-controlled, so on a 32-bit build
// the old `numValues*4` clamp overflowed int, slipped past the bounds check and
// caused an out-of-bounds read plus an absurd allocation. The reader must clamp
// to what the cell holds and never panic, on every architecture.
func TestValuesHugeCountNoOOB(t *testing.T) {
	b := newHiveBuilder()
	vl := b.valueList(b.strVK("a", "x"), b.strVK("b", "y"))
	key := b.add(makeNK("K", 0, 0xffffffff, 0x40000001, vl, ftJan2021))
	root := b.add(makeNK("ROOT", 1, b.subkeyList(key), 0, 0xffffffff, ftJan2021))
	h, err := ParseHive(b.finish(root))
	if err != nil {
		t.Fatal(err)
	}
	k, err := h.KeyAt("K")
	if err != nil {
		t.Fatal(err)
	}
	vs, err := k.Values() // must not panic
	if err != nil {
		t.Fatalf("Values: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("got %d values, want 2 (clamped to the value-list cell)", len(vs))
	}
}
