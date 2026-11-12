package collector

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// zstd.go — a dependency-free Zstandard decoder (RFC 8878) for the journal
// fields systemd compresses with zstd, its default codec since systemd 246.
// It decodes single frames without dictionaries: raw, RLE and compressed
// blocks, Huffman-coded literals (one or four streams, including treeless
// blocks that reuse the previous table) and FSE-coded sequences (predefined,
// RLE, compressed and repeated tables) with the three repeat offsets.
//
// The input comes from a host under investigation, so every read is bounds
// checked, every table is validated before use and the output never grows
// past the size the caller allows. A malformed frame is an error, never a
// panic or an unbounded allocation. The content checksum is skipped, not
// verified: a corrupt field is still caught by the structural checks.

var (
	errZstd        = errors.New("zstd: corrupt frame")
	errZstdTooBig  = errors.New("zstd: output exceeds the allowed size")
	errZstdUnsupp  = errors.New("zstd: dictionary frames are not supported")
	errZstdNoMagic = errors.New("zstd: not a zstd frame")
)

const (
	zstdMagic        = 0xFD2FB528
	zstdMaxBlock     = 128 << 10
	zstdHuffMaxBits  = 11
	zstdMaxWeights   = 255
	zstdLLMaxSymbol  = 35
	zstdMLMaxSymbol  = 52
	zstdOFMaxSymbol  = 31
	zstdLLMaxLog     = 9
	zstdMLMaxLog     = 9
	zstdOFMaxLog     = 8
	zstdWeightMaxLog = 6
)

// zstdDecompress decodes the first zstd frame in src (skippable frames before
// it are passed over). The output may not exceed max bytes.
func zstdDecompress(src []byte, max int) ([]byte, error) {
	for {
		if len(src) < 4 {
			return nil, errZstdNoMagic
		}
		m := binary.LittleEndian.Uint32(src)
		if m&0xFFFFFFF0 != 0x184D2A50 { // not a skippable frame
			break
		}
		if len(src) < 8 {
			return nil, errZstd
		}
		n := uint64(binary.LittleEndian.Uint32(src[4:]))
		if n > uint64(len(src)-8) {
			return nil, errZstd
		}
		src = src[8+n:]
	}
	if binary.LittleEndian.Uint32(src) != zstdMagic {
		return nil, errZstdNoMagic
	}
	d := &zstdDecoder{src: src, pos: 4, max: max, rep: [3]int{1, 4, 8}}
	return d.frame()
}

type zstdDecoder struct {
	src []byte
	pos int
	out []byte
	max int

	rep     [3]int
	huff    *huffTable // the last Huffman table, for treeless literal blocks
	llTable *fseTable  // the last sequence tables, for "repeat" mode
	ofTable *fseTable
	mlTable *fseTable
}

func (d *zstdDecoder) byteAt(i int) (byte, bool) {
	if i < 0 || i >= len(d.src) {
		return 0, false
	}
	return d.src[i], true
}

func (d *zstdDecoder) frame() ([]byte, error) {
	fhd, ok := d.byteAt(d.pos)
	if !ok {
		return nil, errZstd
	}
	d.pos++
	fcsFlag := fhd >> 6
	single := fhd&0x20 != 0
	checksum := fhd&0x04 != 0
	dictFlag := fhd & 0x03
	if fhd&0x08 != 0 { // reserved bit
		return nil, errZstd
	}
	if !single {
		d.pos++ // window descriptor: the whole output is kept, so unused
	}
	dictLen := [4]int{0, 1, 2, 4}[dictFlag]
	if dictLen > 0 {
		if d.pos+dictLen > len(d.src) {
			return nil, errZstd
		}
		id := uint32(0)
		for i := dictLen - 1; i >= 0; i-- {
			id = id<<8 | uint32(d.src[d.pos+i])
		}
		if id != 0 {
			return nil, errZstdUnsupp
		}
		d.pos += dictLen
	}
	fcsLen := [4]int{0, 2, 4, 8}[fcsFlag]
	if fcsFlag == 0 && single {
		fcsLen = 1
	}
	if d.pos+fcsLen > len(d.src) {
		return nil, errZstd
	}
	var size uint64
	for i := fcsLen - 1; i >= 0; i-- {
		size = size<<8 | uint64(d.src[d.pos+i])
	}
	if fcsLen == 2 {
		size += 256
	}
	d.pos += fcsLen
	if fcsLen > 0 {
		if size > uint64(d.max) {
			return nil, errZstdTooBig
		}
		d.out = make([]byte, 0, int(size))
	}

	for {
		if d.pos+3 > len(d.src) {
			return nil, errZstd
		}
		h := uint32(d.src[d.pos]) | uint32(d.src[d.pos+1])<<8 | uint32(d.src[d.pos+2])<<16
		d.pos += 3
		last := h&1 != 0
		bsize := int(h >> 3)
		switch (h >> 1) & 3 {
		case 0: // raw
			if bsize > zstdMaxBlock || d.pos+bsize > len(d.src) {
				return nil, errZstd
			}
			if err := d.emit(d.src[d.pos : d.pos+bsize]); err != nil {
				return nil, err
			}
			d.pos += bsize
		case 1: // RLE: one byte, repeated bsize times
			b, ok := d.byteAt(d.pos)
			if !ok || bsize > zstdMaxBlock {
				return nil, errZstd
			}
			if len(d.out)+bsize > d.max {
				return nil, errZstdTooBig
			}
			for i := 0; i < bsize; i++ {
				d.out = append(d.out, b)
			}
			d.pos++
		case 2:
			if bsize > zstdMaxBlock || d.pos+bsize > len(d.src) {
				return nil, errZstd
			}
			if err := d.compressedBlock(d.src[d.pos : d.pos+bsize]); err != nil {
				return nil, err
			}
			d.pos += bsize
		default:
			return nil, errZstd
		}
		if last {
			break
		}
	}
	if checksum && d.pos+4 > len(d.src) {
		return nil, errZstd
	}
	if fcsLen > 0 && uint64(len(d.out)) != size {
		return nil, errZstd
	}
	return d.out, nil
}

func (d *zstdDecoder) emit(b []byte) error {
	if len(d.out)+len(b) > d.max {
		return errZstdTooBig
	}
	d.out = append(d.out, b...)
	return nil
}

// ---- literals ---------------------------------------------------------------

func (d *zstdDecoder) compressedBlock(b []byte) error {
	lits, n, err := d.literals(b)
	if err != nil {
		return err
	}
	return d.sequences(b[n:], lits)
}

// literals decodes a block's literals section, returning the literals and the
// bytes the section took.
func (d *zstdDecoder) literals(b []byte) ([]byte, int, error) {
	if len(b) == 0 {
		return nil, 0, errZstd
	}
	typ := b[0] & 3
	sf := (b[0] >> 2) & 3
	switch typ {
	case 0, 1: // raw, RLE
		var size, hdr int
		switch sf {
		case 0, 2:
			size, hdr = int(b[0]>>3), 1
		case 1:
			if len(b) < 2 {
				return nil, 0, errZstd
			}
			size, hdr = int(b[0]>>4)|int(b[1])<<4, 2
		case 3:
			if len(b) < 3 {
				return nil, 0, errZstd
			}
			size, hdr = int(b[0]>>4)|int(b[1])<<4|int(b[2])<<12, 3
		}
		if size > zstdMaxBlock {
			return nil, 0, errZstd
		}
		if typ == 0 {
			if hdr+size > len(b) {
				return nil, 0, errZstd
			}
			return b[hdr : hdr+size], hdr + size, nil
		}
		if hdr >= len(b) {
			return nil, 0, errZstd
		}
		out := make([]byte, size)
		for i := range out {
			out[i] = b[hdr]
		}
		return out, hdr + 1, nil
	}

	// Compressed (2) or treeless (3): Huffman-coded.
	var regen, comp, hdr int
	streams := 4
	switch sf {
	case 0, 1:
		if len(b) < 3 {
			return nil, 0, errZstd
		}
		v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		regen, comp, hdr = int(v>>4)&0x3FF, int(v>>14)&0x3FF, 3
		if sf == 0 {
			streams = 1
		}
	case 2:
		if len(b) < 4 {
			return nil, 0, errZstd
		}
		v := binary.LittleEndian.Uint32(b)
		regen, comp, hdr = int(v>>4)&0x3FFF, int(v>>18)&0x3FFF, 4
	case 3:
		if len(b) < 5 {
			return nil, 0, errZstd
		}
		v := uint64(binary.LittleEndian.Uint32(b)) | uint64(b[4])<<32
		regen, comp, hdr = int(v>>4)&0x3FFFF, int(v>>22)&0x3FFFF, 5
	}
	if regen > zstdMaxBlock || hdr+comp > len(b) {
		return nil, 0, errZstd
	}
	data := b[hdr : hdr+comp]
	if typ == 2 {
		t, n, err := readHuffTable(data)
		if err != nil {
			return nil, 0, err
		}
		d.huff = t
		data = data[n:]
	} else if d.huff == nil {
		return nil, 0, errZstd
	}
	out := make([]byte, regen)
	if streams == 1 {
		if err := d.huff.decode(data, out); err != nil {
			return nil, 0, err
		}
		return out, hdr + comp, nil
	}
	if len(data) < 6 {
		return nil, 0, errZstd
	}
	s1 := int(binary.LittleEndian.Uint16(data))
	s2 := int(binary.LittleEndian.Uint16(data[2:]))
	s3 := int(binary.LittleEndian.Uint16(data[4:]))
	data = data[6:]
	if s1+s2+s3 > len(data) {
		return nil, 0, errZstd
	}
	seg := (regen + 3) / 4
	if 3*seg > regen {
		return nil, 0, errZstd
	}
	parts := [][]byte{data[:s1], data[s1 : s1+s2], data[s1+s2 : s1+s2+s3], data[s1+s2+s3:]}
	for i, p := range parts {
		lo, hi := i*seg, (i+1)*seg
		if i == 3 {
			hi = regen
		}
		if err := d.huff.decode(p, out[lo:hi]); err != nil {
			return nil, 0, err
		}
	}
	return out, hdr + comp, nil
}

// huffTable is a single-level Huffman decoding table indexed by maxBits bits.
type huffTable struct {
	maxBits int
	sym     []byte
	nbits   []uint8
}

// readHuffTable reads a Huffman tree description, returning the table and the
// bytes it took.
func readHuffTable(b []byte) (*huffTable, int, error) {
	if len(b) == 0 {
		return nil, 0, errZstd
	}
	h := int(b[0])
	var weights []uint8
	n := 0
	if h >= 128 { // direct: 4-bit weights, two per byte
		count := h - 127
		n = 1 + (count+1)/2
		if n > len(b) {
			return nil, 0, errZstd
		}
		weights = make([]uint8, count)
		for i := range weights {
			v := b[1+i/2]
			if i%2 == 0 {
				weights[i] = v >> 4
			} else {
				weights[i] = v & 15
			}
		}
	} else { // FSE-compressed weights
		n = 1 + h
		if n > len(b) {
			return nil, 0, errZstd
		}
		w, err := fseWeights(b[1:n])
		if err != nil {
			return nil, 0, err
		}
		weights = w
	}
	t, err := buildHuffTable(weights)
	return t, n, err
}

// fseWeights decodes FSE-compressed Huffman weights: a table description,
// then a backward bitstream read with two interleaved states.
func fseWeights(b []byte) ([]uint8, error) {
	norm, accLog, used, err := readFSEDistribution(b, zstdWeightMaxLog, 15)
	if err != nil {
		return nil, err
	}
	t, err := buildFSETable(norm, accLog)
	if err != nil {
		return nil, err
	}
	r, err := newRevBits(b[used:])
	if err != nil {
		return nil, err
	}
	s1 := int(r.read(uint(accLog)))
	s2 := int(r.read(uint(accLog)))
	var out []uint8
	for len(out) < zstdMaxWeights {
		out = append(out, uint8(t.sym[s1]))
		s1 = t.next(s1, r)
		if r.pos < 0 {
			out = append(out, uint8(t.sym[s2]))
			break
		}
		out = append(out, uint8(t.sym[s2]))
		s2 = t.next(s2, r)
		if r.pos < 0 {
			out = append(out, uint8(t.sym[s1]))
			break
		}
	}
	if len(out) > zstdMaxWeights {
		return nil, errZstd
	}
	return out, nil
}

// buildHuffTable turns the stated weights into a decoding table. The last
// symbol's weight is implied: the one that completes a power of two.
func buildHuffTable(w []uint8) (*huffTable, error) {
	if len(w) == 0 || len(w) > zstdMaxWeights {
		return nil, errZstd
	}
	var total uint32
	for _, x := range w {
		if x > zstdHuffMaxBits {
			return nil, errZstd
		}
		if x > 0 {
			total += 1 << (x - 1)
		}
	}
	if total == 0 {
		return nil, errZstd
	}
	maxBits := bits.Len32(total) // the next power of two above total
	rest := uint32(1)<<maxBits - total
	if rest&(rest-1) != 0 || maxBits > zstdHuffMaxBits {
		return nil, errZstd
	}
	weights := append(append([]uint8(nil), w...), uint8(bits.Len32(rest)))
	size := 1 << maxBits
	t := &huffTable{maxBits: maxBits, sym: make([]byte, size), nbits: make([]uint8, size)}
	pos := 0
	for wt := uint8(1); wt <= uint8(maxBits); wt++ {
		for s, x := range weights {
			if x != wt {
				continue
			}
			span := 1 << (wt - 1)
			if pos+span > size {
				return nil, errZstd
			}
			for i := 0; i < span; i++ {
				t.sym[pos+i] = byte(s)
				t.nbits[pos+i] = uint8(maxBits + 1 - int(wt))
			}
			pos += span
		}
	}
	if pos != size {
		return nil, errZstd
	}
	return t, nil
}

// decode fills out from one backward Huffman stream, which must be consumed
// exactly.
func (t *huffTable) decode(b []byte, out []byte) error {
	r, err := newRevBits(b)
	if err != nil {
		return err
	}
	for i := range out {
		v := r.peek(uint(t.maxBits))
		out[i] = t.sym[v]
		r.pos -= int(t.nbits[v])
		if r.pos < 0 {
			return errZstd
		}
	}
	if r.pos != 0 {
		return errZstd
	}
	return nil
}

// ---- FSE ----------------------------------------------------------------------

// fseTable is an FSE decoding table: for each state, the symbol it emits and
// how the next state is formed (baseline + nbits read from the stream).
type fseTable struct {
	accLog int
	sym    []uint16
	nbits  []uint8
	base   []uint16
}

func (t *fseTable) next(state int, r *revBits) int {
	return int(t.base[state]) + int(r.read(uint(t.nbits[state])))
}

// readFSEDistribution reads an FSE table description (normalized counts) from
// a forward bitstream, returning the counts, accuracy log and bytes used.
func readFSEDistribution(b []byte, maxLog, maxSym int) ([]int16, int, int, error) {
	if len(b) == 0 {
		return nil, 0, 0, errZstd
	}
	r := fwdBits{b: b}
	accLog := int(r.read(4)) + 5
	if accLog > maxLog {
		return nil, 0, 0, errZstd
	}
	remaining := (1 << accLog) + 1
	threshold := 1 << accLog
	nb := accLog + 1
	norm := make([]int16, 0, maxSym+1)
	for remaining > 1 {
		if len(norm) > maxSym {
			return nil, 0, 0, errZstd
		}
		max := 2*threshold - 1 - remaining
		var count int
		low := int(r.peek(uint(nb - 1)))
		if low < max {
			count = low
			r.skip(uint(nb - 1))
		} else {
			count = int(r.peek(uint(nb)))
			if count >= threshold {
				count -= max
			}
			r.skip(uint(nb))
		}
		count-- // a stored 0 means "less than one": probability -1
		if count < 0 {
			remaining--
		} else {
			remaining -= count
		}
		norm = append(norm, int16(count))
		if count == 0 { // zeros may repeat: 2-bit run lengths, 3 = continue
			for {
				rep := int(r.read(2))
				for i := 0; i < rep; i++ {
					norm = append(norm, 0)
				}
				if len(norm) > maxSym+1 {
					return nil, 0, 0, errZstd
				}
				if rep != 3 {
					break
				}
			}
		}
		for remaining < threshold && nb > 1 {
			nb--
			threshold >>= 1
		}
		if r.over {
			return nil, 0, 0, errZstd
		}
	}
	if remaining != 1 || len(norm) > maxSym+1 {
		return nil, 0, 0, errZstd
	}
	return norm, accLog, (r.n + 7) / 8, nil
}

// buildFSETable spreads the symbols over the states and derives each state's
// transition, as RFC 8878 section 4.1.1 describes.
func buildFSETable(norm []int16, accLog int) (*fseTable, error) {
	size := 1 << accLog
	t := &fseTable{accLog: accLog, sym: make([]uint16, size), nbits: make([]uint8, size), base: make([]uint16, size)}
	next := make([]int, len(norm))
	high := size - 1
	total := 0
	for s, c := range norm {
		switch {
		case c == -1:
			if high < 0 {
				return nil, errZstd
			}
			t.sym[high] = uint16(s)
			high--
			next[s] = 1
			total++
		case c > 0:
			next[s] = int(c)
			total += int(c)
		case c < -1:
			return nil, errZstd
		}
	}
	if total != size {
		return nil, errZstd
	}
	step := size>>1 + size>>3 + 3
	mask := size - 1
	pos := 0
	for s, c := range norm {
		for i := 0; i < int(c); i++ {
			t.sym[pos] = uint16(s)
			for {
				pos = (pos + step) & mask
				if pos <= high {
					break
				}
			}
		}
	}
	if pos != 0 {
		return nil, errZstd
	}
	for u := 0; u < size; u++ {
		s := t.sym[u]
		n := next[s]
		next[s]++
		if n <= 0 {
			return nil, errZstd
		}
		nb := accLog - (bits.Len(uint(n)) - 1)
		t.nbits[u] = uint8(nb)
		t.base[u] = uint16(n<<nb - size)
	}
	return t, nil
}

// rleFSETable is the one-state table of an RLE-mode sequence field.
func rleFSETable(sym int) *fseTable {
	return &fseTable{accLog: 0, sym: []uint16{uint16(sym)}, nbits: []uint8{0}, base: []uint16{0}}
}

var (
	zstdLLDefault = []int16{4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1}
	zstdMLDefault = []int16{1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1}
	zstdOFDefault = []int16{1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1}

	zstdLLBase = [36]uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40,
		48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}
	zstdLLBits = [36]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3,
		4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	zstdMLBase = [53]uint32{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051,
		4099, 8195, 16387, 32771, 65539}
	zstdMLBits = [53]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16}
)

func mustFSE(norm []int16, accLog int) *fseTable {
	t, err := buildFSETable(norm, accLog)
	if err != nil {
		panic("zstd: bad predefined distribution")
	}
	return t
}

var (
	zstdLLPredef = mustFSE(zstdLLDefault, 6)
	zstdMLPredef = mustFSE(zstdMLDefault, 6)
	zstdOFPredef = mustFSE(zstdOFDefault, 5)
)

// ---- sequences ----------------------------------------------------------------

// seqTable reads one field's table for this block in the given mode.
func (d *zstdDecoder) seqTable(mode byte, b []byte, pos *int, prev **fseTable, predef *fseTable, maxLog, maxSym int) error {
	switch mode {
	case 0:
		*prev = predef
	case 1:
		if *pos >= len(b) {
			return errZstd
		}
		s := int(b[*pos])
		if s > maxSym {
			return errZstd
		}
		*prev = rleFSETable(s)
		*pos++
	case 2:
		norm, accLog, used, err := readFSEDistribution(b[*pos:], maxLog, maxSym)
		if err != nil {
			return err
		}
		t, err := buildFSETable(norm, accLog)
		if err != nil {
			return err
		}
		*prev = t
		*pos += used
	case 3:
		if *prev == nil {
			return errZstd
		}
	}
	return nil
}

func (d *zstdDecoder) sequences(b []byte, lits []byte) error {
	if len(b) == 0 {
		return errZstd
	}
	n := int(b[0])
	pos := 1
	switch {
	case n == 0:
		return d.emit(lits)
	case n < 128:
	case n < 255:
		if len(b) < 2 {
			return errZstd
		}
		n = (n-128)<<8 + int(b[1])
		pos = 2
	default:
		if len(b) < 3 {
			return errZstd
		}
		n = int(b[1]) + int(b[2])<<8 + 0x7F00
		pos = 3
	}
	if pos >= len(b) {
		return errZstd
	}
	modes := b[pos]
	pos++
	if modes&3 != 0 {
		return errZstd
	}
	if err := d.seqTable(modes>>6, b, &pos, &d.llTable, zstdLLPredef, zstdLLMaxLog, zstdLLMaxSymbol); err != nil {
		return err
	}
	if err := d.seqTable((modes>>4)&3, b, &pos, &d.ofTable, zstdOFPredef, zstdOFMaxLog, zstdOFMaxSymbol); err != nil {
		return err
	}
	if err := d.seqTable((modes>>2)&3, b, &pos, &d.mlTable, zstdMLPredef, zstdMLMaxLog, zstdMLMaxSymbol); err != nil {
		return err
	}
	r, err := newRevBits(b[pos:])
	if err != nil {
		return err
	}
	ll, of, ml := d.llTable, d.ofTable, d.mlTable
	sLL := int(r.read(uint(ll.accLog)))
	sOF := int(r.read(uint(of.accLog)))
	sML := int(r.read(uint(ml.accLog)))
	litPos := 0
	for i := 0; i < n; i++ {
		if r.pos < 0 {
			return errZstd
		}
		llCode, ofCode, mlCode := ll.sym[sLL], of.sym[sOF], ml.sym[sML]
		if llCode > zstdLLMaxSymbol || mlCode > zstdMLMaxSymbol || ofCode > zstdOFMaxSymbol {
			return errZstd
		}
		ov := uint64(1)<<ofCode + r.read(uint(ofCode))
		if ov > uint64(len(d.out))+uint64(len(lits))+3 {
			return errZstd // farther back than anything decoded (and int-safe on 32-bit)
		}
		offVal := int(ov)
		matchLen := int(zstdMLBase[mlCode]) + int(r.read(uint(zstdMLBits[mlCode])))
		litLen := int(zstdLLBase[llCode]) + int(r.read(uint(zstdLLBits[llCode])))

		var off int
		switch {
		case offVal > 3:
			off = offVal - 3
			d.rep[2], d.rep[1], d.rep[0] = d.rep[1], d.rep[0], off
		default:
			idx := offVal - 1 // 0, 1 or 2: which repeat offset
			if litLen == 0 {
				idx++ // with no literals the choices shift by one
			}
			switch idx {
			case 0:
				off = d.rep[0]
			case 1:
				off = d.rep[1]
				d.rep[1], d.rep[0] = d.rep[0], off
			case 2:
				off = d.rep[2]
				d.rep[2], d.rep[1], d.rep[0] = d.rep[1], d.rep[0], off
			default: // 3: repeat offset 1 minus one
				off = d.rep[0] - 1
				if off <= 0 {
					return errZstd
				}
				d.rep[2], d.rep[1], d.rep[0] = d.rep[1], d.rep[0], off
			}
		}

		if litLen > len(lits)-litPos {
			return errZstd
		}
		if err := d.emit(lits[litPos : litPos+litLen]); err != nil {
			return err
		}
		litPos += litLen
		if off > len(d.out) {
			return errZstd // no dictionary: a match can't reach before the output
		}
		if len(d.out)+matchLen > d.max {
			return errZstdTooBig
		}
		start := len(d.out) - off
		for k := 0; k < matchLen; k++ { // byte by byte: a match may overlap itself
			d.out = append(d.out, d.out[start+k])
		}

		if i < n-1 {
			sLL = ll.next(sLL, r)
			sML = ml.next(sML, r)
			sOF = of.next(sOF, r)
		}
	}
	if r.pos != 0 {
		return errZstd
	}
	return d.emit(lits[litPos:])
}

// ---- bit readers ------------------------------------------------------------------

// revBits reads a zstd backward bitstream: from the highest set bit of the
// last byte (a padding marker) down towards bit 0 of the first byte. pos is
// the number of bits left; reading past the start yields zero bits and drives
// pos negative, which callers check.
type revBits struct {
	b   []byte
	pos int
}

func newRevBits(b []byte) (*revBits, error) {
	if len(b) == 0 || b[len(b)-1] == 0 {
		return nil, errZstd
	}
	return &revBits{b: b, pos: 8*len(b) - 1 - bits.LeadingZeros8(b[len(b)-1])}, nil
}

// peek returns the next n bits (most significant first) without consuming them.
func (r *revBits) peek(n uint) uint64 {
	var v uint64
	for i := r.pos - 1; i >= r.pos-int(n); i-- {
		v <<= 1
		if i >= 0 {
			v |= uint64(r.b[i>>3]>>(uint(i)&7)) & 1
		}
	}
	return v
}

func (r *revBits) read(n uint) uint64 {
	v := r.peek(n)
	r.pos -= int(n)
	return v
}

// fwdBits reads a little-endian forward bitstream, as FSE table descriptions
// are written. over is set when a read runs past the end.
type fwdBits struct {
	b    []byte
	n    int // bits consumed
	over bool
}

func (r *fwdBits) peek(k uint) uint64 {
	var v uint64
	for i := 0; i < int(k); i++ {
		at := r.n + i
		if at>>3 >= len(r.b) {
			continue
		}
		v |= uint64(r.b[at>>3]>>(uint(at)&7)&1) << uint(i)
	}
	return v
}

func (r *fwdBits) skip(k uint) {
	r.n += int(k)
	if r.n > 8*len(r.b) {
		r.over = true
	}
}

func (r *fwdBits) read(k uint) uint64 {
	v := r.peek(k)
	r.skip(k)
	return v
}
