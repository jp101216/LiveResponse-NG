package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// A dependency-free, read-only reader for systemd journal files
// (https://systemd.io/JOURNAL_FILE_FORMAT/). It walks the file's objects in
// order from the end of the header, so it reads live (ONLINE) and partly
// written files as well as archived ones, and stops at the first object that
// doesn't fit. Both entry layouts are handled — regular, and the compact one
// systemd 252+ writes by default — and DATA payloads compressed with LZ4 are
// decoded here; zstd (the modern default) and XZ payloads are counted as
// undecoded rather than guessed at. journald only compresses payloads above a
// threshold (512 bytes by default), so ordinary log fields read in full.
// No build tag: pure parsing, unit-tested on any OS.

const (
	journalSignature       = "LPKSHHRH"
	journalMinHeader       = 208 // through tail_entry_monotonic (systemd 187+)
	journalObjHeader       = 16
	journalObjData         = 1
	journalObjEntry        = 3
	journalCompressXZ      = 1 << 0 // object flags
	journalCompressLZ4     = 1 << 1
	journalCompressZstd    = 1 << 2
	journalIncompatCompact = 1 << 4 // header incompatible_flags
	journalMaxPayload      = 16 << 20
	journalDataCacheMax    = 1 << 18
)

// journalFile is one journal file held in memory.
type journalFile struct {
	data       []byte
	compact    bool
	incompat   uint32
	state      byte // 0 offline, 1 online, 2 archived
	headerSize uint64
	end        uint64 // first byte past the last object
	nEntries   uint64
	headRT     uint64 // head/tail entry realtime (usec since epoch)
	tailRT     uint64

	cache map[uint64]journalField
	// Counters over everything read.
	undecoded int // DATA payloads compressed with zstd/XZ, or undecodable
	badRefs   int // entry items that don't point at a valid DATA object
}

// journalField is one decoded DATA payload.
type journalField struct {
	name, value string
	ok          bool // false: compressed with an unsupported codec, or corrupt
}

// journalEntry is one log entry.
type journalEntry struct {
	Seqnum    uint64
	Realtime  uint64 // usec since the epoch
	Monotonic uint64
	Fields    []journalField
	Undecoded int
}

// Get returns the first value of a field, or "".
func (e *journalEntry) Get(name string) string {
	for _, f := range e.Fields {
		if f.ok && f.name == name {
			return f.value
		}
	}
	return ""
}

func le64(b []byte, o uint64) (uint64, bool) {
	if o+8 < o || o+8 > uint64(len(b)) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[o:]), true
}

func le32(b []byte, o uint64) (uint32, bool) {
	if o+4 < o || o+4 > uint64(len(b)) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[o:]), true
}

func align8(x uint64) uint64 { return (x + 7) &^ 7 }

// openJournal parses a journal file's header.
func openJournal(data []byte) (*journalFile, error) {
	if len(data) < journalMinHeader || string(data[:8]) != journalSignature {
		return nil, errors.New("not a journal file (bad signature)")
	}
	j := &journalFile{data: data, cache: map[uint64]journalField{}}
	j.incompat, _ = le32(data, 12)
	j.compact = j.incompat&journalIncompatCompact != 0
	j.state = data[16]
	j.headerSize, _ = le64(data, 88)
	arena, _ := le64(data, 96)
	tail, _ := le64(data, 136)
	j.nEntries, _ = le64(data, 152)
	j.headRT, _ = le64(data, 184)
	j.tailRT, _ = le64(data, 192)
	if j.headerSize < journalMinHeader || j.headerSize > uint64(len(data)) {
		return nil, fmt.Errorf("implausible header size %d", j.headerSize)
	}
	j.end = uint64(len(data))
	if e := j.headerSize + arena; arena > 0 && e >= j.headerSize && e < j.end {
		j.end = e
	}
	// Past the tail object there is only preallocated space.
	if tail >= j.headerSize && tail < j.end {
		if size, ok := le64(data, tail+8); ok && size >= journalObjHeader && size <= j.end-tail {
			j.end = tail + size
		}
	}
	return j, nil
}

// entries calls fn for every entry, in file (append) order, until fn returns
// false. It stops quietly at the first object that doesn't fit: the end of a
// live file, or corruption.
func (j *journalFile) entries(fn func(*journalEntry) bool) {
	off := align8(j.headerSize)
	for off+journalObjHeader <= j.end {
		typ := j.data[off]
		size, _ := le64(j.data, off+8)
		if size < journalObjHeader || off+size < off || off+size > j.end {
			return
		}
		if typ == journalObjEntry {
			if e, ok := j.readEntry(off, size); ok && !fn(e) {
				return
			}
		}
		off = align8(off + size)
	}
}

func (j *journalFile) readEntry(off, size uint64) (*journalEntry, bool) {
	if size < 64 {
		return nil, false
	}
	e := &journalEntry{}
	e.Seqnum, _ = le64(j.data, off+16)
	e.Realtime, _ = le64(j.data, off+24)
	e.Monotonic, _ = le64(j.data, off+32)
	itemSize := uint64(16)
	if j.compact {
		itemSize = 4
	}
	for p := off + 64; p+itemSize <= off+size; p += itemSize {
		var at uint64
		if j.compact {
			v, _ := le32(j.data, p)
			at = uint64(v)
		} else {
			at, _ = le64(j.data, p)
		}
		if at == 0 {
			continue
		}
		f, ok := j.readData(at)
		if !ok {
			j.badRefs++
			continue
		}
		if !f.ok {
			e.Undecoded++
		}
		e.Fields = append(e.Fields, f)
	}
	return e, true
}

// readData decodes the DATA object at off into "FIELD=value".
func (j *journalFile) readData(off uint64) (journalField, bool) {
	if f, ok := j.cache[off]; ok {
		return f, true
	}
	if off < j.headerSize || off >= j.end || j.end-off < journalObjHeader || j.data[off] != journalObjData {
		return journalField{}, false
	}
	size, _ := le64(j.data, off+8)
	payloadAt := uint64(64)
	if j.compact {
		payloadAt = 72
	}
	if size < payloadAt || off+size < off || off+size > j.end {
		return journalField{}, false
	}
	payload := j.data[off+payloadAt : off+size]
	var f journalField
	switch flags := j.data[off+1]; {
	case flags&journalCompressLZ4 != 0:
		if raw, err := journalLZ4(payload); err == nil {
			f = splitJournalField(raw)
		} else {
			j.undecoded++
		}
	case flags&(journalCompressZstd|journalCompressXZ) != 0:
		j.undecoded++
		f.name = fieldNameGuess(flags)
	default:
		f = splitJournalField(payload)
	}
	if len(j.cache) < journalDataCacheMax {
		j.cache[off] = f
	}
	return f, true
}

func fieldNameGuess(flags byte) string {
	if flags&journalCompressZstd != 0 {
		return "(zstd-compressed field)"
	}
	return "(xz-compressed field)"
}

// splitJournalField splits a payload at its first '='.
func splitJournalField(b []byte) journalField {
	i := bytes.IndexByte(b, '=')
	if i <= 0 {
		return journalField{}
	}
	return journalField{name: string(b[:i]), value: string(b[i+1:]), ok: true}
}

// journalLZ4 decodes journald's LZ4 payload: the uncompressed size as a
// little-endian 64-bit integer, then one LZ4 block.
func journalLZ4(p []byte) ([]byte, error) {
	if len(p) < 8 {
		return nil, errors.New("lz4: short payload")
	}
	n := binary.LittleEndian.Uint64(p)
	if n > journalMaxPayload {
		return nil, errors.New("lz4: implausible size")
	}
	return lz4Block(p[8:], int(n))
}

// lz4Block decodes one LZ4 block (the frame-less format) of known output size.
func lz4Block(src []byte, size int) ([]byte, error) {
	dst := make([]byte, 0, size)
	ext := func(i int, v int) (int, int, error) {
		for {
			if i >= len(src) {
				return 0, 0, errors.New("lz4: truncated length")
			}
			b := src[i]
			i++
			v += int(b)
			if b != 255 {
				return i, v, nil
			}
		}
	}
	for i := 0; i < len(src); {
		token := src[i]
		i++
		lit := int(token >> 4)
		var err error
		if lit == 15 {
			if i, lit, err = ext(i, lit); err != nil {
				return nil, err
			}
		}
		if lit > len(src)-i || len(dst)+lit > size {
			return nil, errors.New("lz4: literals overrun")
		}
		dst = append(dst, src[i:i+lit]...)
		i += lit
		if i == len(src) {
			break // the last sequence carries literals only
		}
		if i+2 > len(src) {
			return nil, errors.New("lz4: truncated offset")
		}
		back := int(src[i]) | int(src[i+1])<<8
		i += 2
		ml := int(token & 15)
		if ml == 15 {
			if i, ml, err = ext(i, ml); err != nil {
				return nil, err
			}
		}
		ml += 4
		if back == 0 || back > len(dst) || len(dst)+ml > size {
			return nil, errors.New("lz4: bad match")
		}
		from := len(dst) - back
		for k := 0; k < ml; k++ { // byte by byte: the match may overlap its own output
			dst = append(dst, dst[from+k])
		}
	}
	if len(dst) != size {
		return nil, fmt.Errorf("lz4: decoded %d bytes, want %d", len(dst), size)
	}
	return dst, nil
}
