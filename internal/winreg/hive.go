package winreg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Offline registry-hive (regf) reader. Unlike the rest of this package, which
// reads the live registry through advapi32, this parses a hive *file* — the
// format on disk — so collectors can read hives the live API doesn't expose,
// such as Amcache.hve. It is strictly read-only and decodes plain bytes, so it
// has no build tag and is unit-tested on any OS.
//
// The parser is deliberately defensive: a hive file can be attacker-influenced
// and is often "dirty" (the in-memory copy hadn't been flushed), so every
// offset, count and length is bounds-checked against the buffer, bad records
// are skipped rather than fatal, and recursion and totals are capped. It reads
// the primary file only; replaying the .LOG transaction logs is out of scope.
//
// References: the regf base block, hive bins, and the nk / vk / lf / lh / li /
// ri / db cell types, as documented by the registry-format reverse-engineering
// community (Morgan, Metz).

const (
	hiveBaseBlock  = 4096       // the base block, then hive bins data
	hiveCellNil    = 0xffffffff // a "none" cell offset
	hiveBigDataMax = 16344      // bytes per big-data segment
	hiveMaxList    = 1 << 20    // cap on subkeys gathered from one list tree
	hiveMaxDepth   = 32         // cap on ri-list nesting
)

// Hive is a parsed, read-only registry hive.
type Hive struct {
	data    []byte
	rootOff uint32
	ModTime time.Time // the base block's last-written time
}

// ParseHive validates the base block and returns a reader over the hive.
func ParseHive(data []byte) (*Hive, error) {
	if len(data) < hiveBaseBlock {
		return nil, errors.New("hive: shorter than the 4096-byte base block")
	}
	if string(data[0:4]) != "regf" {
		return nil, errors.New("hive: missing regf signature")
	}
	h := &Hive{
		data:    data,
		rootOff: binary.LittleEndian.Uint32(data[36:40]),
		ModTime: FiletimeToTime(binary.LittleEndian.Uint64(data[12:20])),
	}
	if _, err := h.cell(h.rootOff); err != nil {
		return nil, fmt.Errorf("hive: root cell: %w", err)
	}
	return h, nil
}

// cell returns the payload of the cell at off (an offset relative to the hive
// bins data, which starts at byte 4096), i.e. the bytes after the 4-byte cell
// size, bounds-checked.
func (h *Hive) cell(off uint32) ([]byte, error) {
	if off == hiveCellNil {
		return nil, errors.New("hive: nil cell offset")
	}
	start := hiveBaseBlock + int(off)
	if start < hiveBaseBlock || start+4 > len(h.data) {
		return nil, fmt.Errorf("hive: cell offset 0x%x out of range", off)
	}
	size := int32(binary.LittleEndian.Uint32(h.data[start : start+4]))
	if size < 0 {
		size = -size // negative size marks an allocated (in-use) cell
	}
	if size < 4 {
		return nil, fmt.Errorf("hive: cell 0x%x has bad size %d", off, size)
	}
	end := start + int(size)
	if end > len(h.data) {
		return nil, fmt.Errorf("hive: cell 0x%x runs past the file", off)
	}
	return h.data[start+4 : end], nil
}

// HiveKey is a key node (nk) within a hive.
type HiveKey struct {
	h             *Hive
	Name          string
	LastWrite     time.Time
	numSubkeys    uint32
	subkeyListOff uint32
	numValues     uint32
	valueListOff  uint32
}

func (h *Hive) keyAt(off uint32) (*HiveKey, error) {
	c, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(c) < 76 || c[0] != 'n' || c[1] != 'k' {
		return nil, fmt.Errorf("hive: cell 0x%x is not a key node", off)
	}
	flags := binary.LittleEndian.Uint16(c[2:4])
	k := &HiveKey{
		h:             h,
		LastWrite:     FiletimeToTime(binary.LittleEndian.Uint64(c[4:12])),
		numSubkeys:    binary.LittleEndian.Uint32(c[20:24]),
		subkeyListOff: binary.LittleEndian.Uint32(c[28:32]),
		numValues:     binary.LittleEndian.Uint32(c[36:40]),
		valueListOff:  binary.LittleEndian.Uint32(c[40:44]),
	}
	nameLen := int(binary.LittleEndian.Uint16(c[72:74]))
	if nameLen < 0 || 76+nameLen > len(c) {
		nameLen = len(c) - 76
	}
	nb := c[76 : 76+nameLen]
	if flags&0x0020 != 0 { // KEY_COMP_NAME: a Latin-1 name, one byte per char
		k.Name = latin1(nb)
	} else {
		k.Name = UTF16Bytes(nb)
	}
	return k, nil
}

// Root returns the hive's root key.
func (h *Hive) Root() (*HiveKey, error) { return h.keyAt(h.rootOff) }

// KeyAt navigates a backslash-separated path from the root (case-insensitive).
func (h *Hive) KeyAt(path string) (*HiveKey, error) {
	k, err := h.Root()
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		if k, err = k.Child(part); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// SubKeys returns the key's immediate subkeys. A malformed entry is skipped,
// not fatal.
func (k *HiveKey) SubKeys() ([]*HiveKey, error) {
	if k.numSubkeys == 0 || k.subkeyListOff == hiveCellNil {
		return nil, nil
	}
	var offs []uint32
	if err := k.h.subkeyOffsets(k.subkeyListOff, &offs, 0); err != nil {
		return nil, err
	}
	out := make([]*HiveKey, 0, len(offs))
	for _, o := range offs {
		if sk, err := k.h.keyAt(o); err == nil {
			out = append(out, sk)
		}
	}
	return out, nil
}

func (h *Hive) subkeyOffsets(listOff uint32, out *[]uint32, depth int) error {
	if depth > hiveMaxDepth {
		return errors.New("hive: subkey list nested too deep")
	}
	c, err := h.cell(listOff)
	if err != nil {
		return err
	}
	if len(c) < 4 {
		return errors.New("hive: short subkey list")
	}
	sig := string(c[0:2])
	count := int(binary.LittleEndian.Uint16(c[2:4]))
	switch sig {
	case "lf", "lh": // offset(4) + name hint/hash(4) per entry
		if 4+count*8 > len(c) {
			count = (len(c) - 4) / 8
		}
		for i := 0; i < count; i++ {
			*out = append(*out, binary.LittleEndian.Uint32(c[4+i*8:8+i*8]))
		}
	case "li": // offset(4) per entry
		if 4+count*4 > len(c) {
			count = (len(c) - 4) / 4
		}
		for i := 0; i < count; i++ {
			*out = append(*out, binary.LittleEndian.Uint32(c[4+i*4:8+i*4]))
		}
	case "ri": // offset(4) of a nested subkey list per entry
		if 4+count*4 > len(c) {
			count = (len(c) - 4) / 4
		}
		for i := 0; i < count; i++ {
			sub := binary.LittleEndian.Uint32(c[4+i*4 : 8+i*4])
			if err := h.subkeyOffsets(sub, out, depth+1); err != nil {
				continue // skip a bad branch, keep the rest
			}
		}
	default:
		return fmt.Errorf("hive: unknown subkey list signature %q", sig)
	}
	if len(*out) > hiveMaxList {
		return errors.New("hive: implausibly many subkeys")
	}
	return nil
}

// Child returns the named subkey (case-insensitive).
func (k *HiveKey) Child(name string) (*HiveKey, error) {
	subs, err := k.SubKeys()
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		if strings.EqualFold(s.Name, name) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("hive: subkey %q not found", name)
}

// Values returns every value under the key, with its raw type and bytes, ready
// for the Value decoders (String, Uint32, ...). A malformed entry is skipped.
func (k *HiveKey) Values() ([]Value, error) {
	if k.numValues == 0 || k.valueListOff == hiveCellNil {
		return nil, nil
	}
	lc, err := k.h.cell(k.valueListOff)
	if err != nil {
		return nil, err
	}
	// numValues is attacker-controlled; derive the cap from what the cell can
	// hold without multiplying, so it can't overflow int on a 32-bit build
	// (which would skip the clamp and drive an out-of-bounds read and an absurd
	// allocation).
	n := len(lc) / 4
	if int64(k.numValues) < int64(n) {
		n = int(k.numValues)
	}
	out := make([]Value, 0, n)
	for i := 0; i < n; i++ {
		if v, err := k.h.value(binary.LittleEndian.Uint32(lc[i*4 : i*4+4])); err == nil {
			out = append(out, v)
		}
	}
	return out, nil
}

// ValueMap returns the key's values keyed by lower-cased name, for the common
// case of looking several up by name.
func (k *HiveKey) ValueMap() map[string]Value {
	vs, _ := k.Values()
	m := make(map[string]Value, len(vs))
	for _, v := range vs {
		m[strings.ToLower(v.Name)] = v
	}
	return m
}

func (h *Hive) value(off uint32) (Value, error) {
	c, err := h.cell(off)
	if err != nil {
		return Value{}, err
	}
	if len(c) < 20 || c[0] != 'v' || c[1] != 'k' {
		return Value{}, errors.New("hive: not a value cell")
	}
	nameLen := int(binary.LittleEndian.Uint16(c[2:4]))
	dataSize := binary.LittleEndian.Uint32(c[4:8])
	dataOff := binary.LittleEndian.Uint32(c[8:12])
	flags := binary.LittleEndian.Uint16(c[16:18])
	v := Value{Type: binary.LittleEndian.Uint32(c[12:16])}

	if nameLen < 0 || 20+nameLen > len(c) {
		nameLen = len(c) - 20
	}
	nb := c[20 : 20+nameLen]
	if flags&0x0001 != 0 { // VALUE_COMP_NAME: Latin-1
		v.Name = latin1(nb)
	} else {
		v.Name = UTF16Bytes(nb)
	}

	// The top bit of the size marks data stored inline in the offset field.
	if dataSize&0x80000000 != 0 {
		size := int(dataSize & 0x7fffffff)
		if size > 4 {
			size = 4
		}
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], dataOff)
		v.Data = append([]byte(nil), buf[:size]...)
		return v, nil
	}
	size := int(dataSize)
	if size == 0 {
		return v, nil
	}
	dc, err := h.cell(dataOff)
	if err != nil {
		return v, nil // the name is still useful even if the data cell is bad
	}
	if len(dc) >= 2 && dc[0] == 'd' && dc[1] == 'b' { // big data: a segment list
		v.Data = h.readBigData(dc, size)
		return v, nil
	}
	if size > len(dc) {
		size = len(dc)
	}
	v.Data = append([]byte(nil), dc[:size]...)
	return v, nil
}

func (h *Hive) readBigData(db []byte, total int) []byte {
	if len(db) < 8 {
		return nil
	}
	count := int(binary.LittleEndian.Uint16(db[2:4]))
	lc, err := h.cell(binary.LittleEndian.Uint32(db[4:8]))
	if err != nil {
		return nil
	}
	buf := make([]byte, 0, total)
	for i := 0; i < count && i*4+4 <= len(lc); i++ {
		seg, err := h.cell(binary.LittleEndian.Uint32(lc[i*4 : i*4+4]))
		if err != nil {
			break
		}
		take := len(seg)
		if take > hiveBigDataMax {
			take = hiveBigDataMax
		}
		buf = append(buf, seg[:take]...)
		if len(buf) >= total {
			break
		}
	}
	if len(buf) > total {
		buf = buf[:total]
	}
	return buf
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}
