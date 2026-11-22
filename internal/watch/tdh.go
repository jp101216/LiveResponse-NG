package watch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf16"
)

// tdhProp mirrors one EVENT_PROPERTY_INFO: how one field of an event's
// payload is laid out, as the provider's manifest says (via TDH).
type tdhProp struct {
	name          string
	flags         uint32
	inType        uint16
	outType       uint16
	structStart   uint16 // flags&propStruct: first member's index
	structMembers uint16
	count         uint16 // a fixed count, or with propParamCount the index of the property holding it
	length        uint16 // a fixed length, or with propParamLength the index of the property holding it
}

const (
	propStruct      = 0x1
	propParamLength = 0x2
	propParamCount  = 0x4
)

// TDH in-types the walker sizes.
const (
	inUnicodeString       = 1
	inAnsiString          = 2
	inInt8                = 3
	inUint8               = 4
	inInt16               = 5
	inUint16              = 6
	inInt32               = 7
	inUint32              = 8
	inInt64               = 9
	inUint64              = 10
	inFloat               = 11
	inDouble              = 12
	inBoolean             = 13
	inBinary              = 14
	inGUID                = 15
	inPointer             = 16
	inFiletime            = 17
	inSystemtime          = 18
	inSID                 = 19
	inHexInt32            = 20
	inHexInt64            = 21
	inCountedString       = 22
	inCountedAnsiString   = 23
	inCountedBinary       = 25
	inSizeT               = 308
	outPort               = 22
	maxTDHProps           = 512
	maxStructDepth        = 4
	maxArrayCount         = 4096
	errTDHUnsupportedType = "unsupported TDH in-type"
)

// tdhSchema is an event version's property list; the first top entries are
// the payload's top-level fields in order.
type tdhSchema struct {
	props []tdhProp
	top   int
}

// field is one decoded top-level property: its raw bytes and how to read them.
type field struct {
	raw     []byte
	inType  uint16
	outType uint16
}

// decode walks data by the schema and returns the wanted top-level fields.
// It stops at the first field it can't size; fields before it still decode.
func (s *tdhSchema) decode(data []byte, ptrSize int, want map[string]bool) (map[string]field, error) {
	out := make(map[string]field, len(want))
	values := make([]uint64, len(s.props))
	off := 0
	for i := 0; i < s.top && i < len(s.props); i++ {
		n, err := s.size(i, data[off:], values, ptrSize, 0)
		if err != nil {
			return out, fmt.Errorf("property %q: %w", s.props[i].name, err)
		}
		p := s.props[i]
		raw := data[off : off+n]
		if want[p.name] {
			out[p.name] = field{raw: raw, inType: p.inType, outType: p.outType}
		}
		if p.flags&propStruct == 0 {
			if v, ok := scalar(raw, p.inType); ok {
				values[i] = v
			}
		}
		off += n
	}
	return out, nil
}

// size is how many bytes property i occupies at the start of data.
func (s *tdhSchema) size(i int, data []byte, values []uint64, ptrSize, depth int) (int, error) {
	if depth > maxStructDepth {
		return 0, errors.New("structs nested too deep")
	}
	p := s.props[i]
	count := 1
	switch {
	case p.flags&propParamCount != 0:
		if int(p.count) >= len(values) {
			return 0, errors.New("count refers to a missing property")
		}
		count = int(values[p.count])
	case p.count > 1:
		count = int(p.count)
	}
	if count > maxArrayCount {
		return 0, fmt.Errorf("array of %d elements", count)
	}
	total := 0
	for k := 0; k < count; k++ {
		var n int
		var err error
		if p.flags&propStruct != 0 {
			for m := int(p.structStart); m < int(p.structStart)+int(p.structMembers); m++ {
				if m >= len(s.props) {
					return 0, errors.New("struct member out of range")
				}
				mn, err := s.size(m, data[total:], values, ptrSize, depth+1)
				if err != nil {
					return 0, err
				}
				total += mn
			}
			continue
		}
		length := int(p.length)
		if p.flags&propParamLength != 0 {
			if int(p.length) >= len(values) {
				return 0, errors.New("length refers to a missing property")
			}
			length = int(values[p.length])
		}
		n, err = elemSize(p.inType, data[total:], length, ptrSize)
		if err != nil {
			return 0, err
		}
		total += n
	}
	if total > len(data) {
		return 0, errors.New("runs past the payload")
	}
	return total, nil
}

func elemSize(in uint16, data []byte, length, ptrSize int) (int, error) {
	need := func(n int) (int, error) {
		if n < 0 || n > len(data) {
			return 0, errors.New("runs past the payload")
		}
		return n, nil
	}
	switch in {
	case inUnicodeString:
		if length > 0 {
			return need(2 * length)
		}
		for j := 0; j+1 < len(data); j += 2 {
			if data[j] == 0 && data[j+1] == 0 {
				return j + 2, nil
			}
		}
		return len(data) &^ 1, nil // unterminated at the end of the payload
	case inAnsiString:
		if length > 0 {
			return need(length)
		}
		for j, b := range data {
			if b == 0 {
				return j + 1, nil
			}
		}
		return len(data), nil
	case inInt8, inUint8:
		return need(1)
	case inInt16, inUint16:
		return need(2)
	case inInt32, inUint32, inFloat, inBoolean, inHexInt32:
		return need(4)
	case inInt64, inUint64, inDouble, inFiletime, inHexInt64:
		return need(8)
	case inGUID, inSystemtime:
		return need(16)
	case inPointer, inSizeT:
		return need(ptrSize)
	case inBinary:
		return need(length)
	case inCountedString, inCountedAnsiString, inCountedBinary:
		if len(data) < 2 {
			return 0, errors.New("runs past the payload")
		}
		return need(2 + int(binary.LittleEndian.Uint16(data)))
	case inSID:
		if len(data) < 8 {
			return 0, errors.New("runs past the payload")
		}
		return need(8 + 4*int(data[1]))
	}
	return 0, fmt.Errorf("%s %d", errTDHUnsupportedType, in)
}

// scalar reads an integer field's value, for count and length references.
func scalar(raw []byte, in uint16) (uint64, bool) {
	switch {
	case len(raw) == 1 && (in == inInt8 || in == inUint8):
		return uint64(raw[0]), true
	case len(raw) == 2 && (in == inInt16 || in == inUint16):
		return uint64(binary.LittleEndian.Uint16(raw)), true
	case len(raw) == 4 && (in == inInt32 || in == inUint32 || in == inHexInt32):
		return uint64(binary.LittleEndian.Uint32(raw)), true
	case len(raw) == 8 && (in == inInt64 || in == inUint64 || in == inHexInt64):
		return binary.LittleEndian.Uint64(raw), true
	}
	return 0, false
}

func (f field) uint() (uint64, bool) {
	if f.outType == outPort && len(f.raw) == 2 {
		return uint64(binary.BigEndian.Uint16(f.raw)), true // ports are in network order
	}
	return scalar(f.raw, f.inType)
}

func (f field) str() string {
	switch f.inType {
	case inUnicodeString:
		u := make([]uint16, 0, len(f.raw)/2)
		for j := 0; j+1 < len(f.raw); j += 2 {
			c := binary.LittleEndian.Uint16(f.raw[j:])
			if c == 0 {
				break
			}
			u = append(u, c)
		}
		return string(utf16.Decode(u))
	case inAnsiString:
		for j, b := range f.raw {
			if b == 0 {
				return string(f.raw[:j])
			}
		}
		return string(f.raw)
	}
	return ""
}

// addr reads an IPv4 (4 bytes, network order) or IPv6 (16 bytes) address.
func (f field) addr() netip.Addr {
	switch len(f.raw) {
	case 4:
		return netip.AddrFrom4([4]byte(f.raw))
	case 16:
		return netip.AddrFrom16([16]byte(f.raw)).Unmap()
	}
	return netip.Addr{}
}
