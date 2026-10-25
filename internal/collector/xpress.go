package collector

import (
	"errors"
	"fmt"
)

// Xpress Huffman (LZXPRESS Huffman, COMPRESSION_FORMAT_XPRESS_HUFF)
// decompression, per [MS-XCA] section 2.2.4. Windows 10 and later store
// prefetch (.pf) bodies in this format behind a "MAM\x04" header; on Windows
// the body is produced by RtlCompressBuffer / consumed by RtlDecompressBufferEx
// with COMPRESSION_FORMAT_XPRESS_HUFF. We decode it ourselves so the collector
// runs the same on any host and never shells out.
//
// No build tag: it decodes a plain byte slice, bounds-checked, and is
// unit-tested on any OS. The authoritative checks are against Windows' own
// codec: prefetch_windows_test.go decodes streams from ntdll's
// RtlCompressBuffer and the runner's own .pf files, and
// prefetch_samples_test.go decodes real .pf files on any OS
// (LRNG_PREFETCH_SAMPLES).
//
// Stream layout. The compressed data is a sequence of blocks, each decoding to
// 65536 bytes (the last may be shorter). A block is a 256-byte Huffman table
// followed by an encoded stream:
//
//   - The table holds 512 four-bit code lengths, two per byte, low nibble
//     first: symbols 0-255 are literal bytes, 256-511 a back-reference whose
//     low nibble is the match length - 3 and high nibble the distance's bit
//     length.
//   - The stream interleaves little-endian 16-bit words, whose bits are read
//     most significant first, with raw bytes: a match length of 18 or more
//     continues in one raw byte, or 0xff and a 16-bit raw length (or 0 and a
//     32-bit one).
//   - The decoder keeps 16 to 32 bits buffered: it starts by loading two
//     words and loads the next as soon as fewer than 16 remain. Raw bytes are
//     read from the position after the last word loaded, and the next block's
//     table starts there too, so where a raw byte or table sits depends on
//     that lookahead -- the encoder lays the stream out to match it.
//   - A match may run past the block's 65536 bytes; the next block's count
//     starts wherever the output then is.

const (
	xpChunkSize  = 65536
	xpNumSymbols = 512
	xpNumLiteral = 256
	xpMinMatch   = 3
	xpMaxCodeLen = 15 // code lengths are 4-bit nibbles, so at most 15
)

var (
	errXpTruncated = errors.New("xpress: compressed stream truncated")
	errXpBadCode   = errors.New("xpress: no Huffman code matches the bit stream")
	errXpBadDist   = errors.New("xpress: back-reference points before the output start")
	errXpBadLength = errors.New("xpress: invalid extended match length")
	errXpOverrun   = errors.New("xpress: match runs past the end of the output")
	errXpOverSub   = errors.New("xpress: over-subscribed Huffman table")
)

// xpressHuffmanDecompress decompresses an Xpress Huffman stream to exactly
// outSize bytes. outSize is carried uncompressed in the .pf MAM header, so it
// is known up front and decompression stops when it is reached.
func xpressHuffmanDecompress(in []byte, outSize int) ([]byte, error) {
	if outSize < 0 {
		return nil, fmt.Errorf("xpress: negative output size %d", outSize)
	}
	if outSize == 0 {
		return []byte{}, nil
	}
	out := make([]byte, 0, outSize)
	table := new(xpTable) // rebuilt for each block
	pos := 0              // the current block's table
	for len(out) < outSize {
		if pos > len(in) || len(in)-pos < 256 {
			return nil, errXpTruncated
		}
		if err := table.build(xpReadCodeLengths(in[pos : pos+256])); err != nil {
			return nil, err
		}
		var br xpBitReader
		br.init(in, pos+256)

		blockEnd := len(out) + xpChunkSize
		if blockEnd > outSize {
			blockEnd = outSize
		}
		for len(out) < blockEnd {
			sym, err := br.symbol(table)
			if err != nil {
				return nil, err
			}
			if sym < xpNumLiteral {
				out = append(out, byte(sym))
				continue
			}
			ms := sym - xpNumLiteral
			length := ms & 0xF
			if length == 0xF {
				// The extension is raw bytes, read before the distance bits are
				// consumed (that consumption may load the next word).
				if length, err = br.matchLength(outSize - len(out)); err != nil {
					return nil, err
				}
			}
			length += xpMinMatch
			offset, err := br.offset(ms >> 4)
			if err != nil {
				return nil, err
			}
			if offset > len(out) {
				return nil, errXpBadDist
			}
			if length > outSize-len(out) {
				return nil, errXpOverrun
			}
			// Byte-by-byte copy: overlap (offset < length) is legal and is how
			// runs are encoded. The source may lie in an earlier block (the
			// window is the whole output, up to 65535 back).
			start := len(out) - offset
			for i := 0; i < length; i++ {
				out = append(out, out[start+i])
			}
		}
		pos = br.pos
	}
	return out, nil
}

// xpReadCodeLengths unpacks the 256-byte table into 512 four-bit code lengths,
// two per byte with the low nibble first.
func xpReadCodeLengths(tbl []byte) []uint8 {
	out := make([]uint8, xpNumSymbols)
	for i := 0; i < 256; i++ {
		out[2*i] = tbl[i] & 0x0F
		out[2*i+1] = tbl[i] >> 4
	}
	return out
}

// xpTable maps the next 15 bits of the stream to a symbol and its code length.
// Canonical Huffman: codes are assigned by increasing length, and by
// increasing symbol within a length, which is what the encoder must also do.
type xpTable struct {
	sym    [1 << xpMaxCodeLen]uint16
	length [1 << xpMaxCodeLen]uint8 // 0 means "no code here"
}

// build fills the table from 512 code lengths. Entries no code reaches (an
// incomplete code) keep length 0; sym is only read where length isn't.
func (t *xpTable) build(lengths []uint8) error {
	t.length = [1 << xpMaxCodeLen]uint8{}
	var code uint32
	for l := 1; l <= xpMaxCodeLen; l++ {
		for sym := 0; sym < xpNumSymbols; sym++ {
			if int(lengths[sym]) != l {
				continue
			}
			start := code << uint(xpMaxCodeLen-l)
			n := uint32(1) << uint(xpMaxCodeLen-l)
			if start+n > (1 << xpMaxCodeLen) {
				return errXpOverSub
			}
			for j := uint32(0); j < n; j++ {
				t.sym[start+j] = uint16(sym)
				t.length[start+j] = uint8(l)
			}
			code++
		}
		code <<= 1
	}
	return nil
}

// xpBitReader is [MS-XCA]'s stream reader: a 32-bit window over the 16-bit
// words, refilled whenever fewer than 16 bits remain, plus raw byte reads from
// the position after the last word loaded.
type xpBitReader struct {
	src   []byte
	pos   int    // the byte after the last word loaded
	buf   uint32 // the valid bits are the top `valid`
	valid int    // 16..32 between reads
	pad   int    // how many of those are zeros supplied past the input's end
}

func (r *xpBitReader) init(src []byte, pos int) {
	*r = xpBitReader{src: src, pos: pos}
	r.buf = uint32(r.word())<<16 | uint32(r.word())
	r.valid = 32
}

// word loads the next 16-bit word. Past the end of the input it supplies zero
// bits, counted in pad: the lookahead may run off the end of the last block,
// but consuming those bits means the stream was truncated.
func (r *xpBitReader) word() uint32 {
	if r.pos < 0 || r.pos > len(r.src)-2 {
		r.pos += 2
		r.pad += 16
		return 0
	}
	w := uint32(r.src[r.pos]) | uint32(r.src[r.pos+1])<<8
	r.pos += 2
	return w
}

// consume drops n (<= 16) bits and refills, as the decoder does after every
// symbol and every distance.
func (r *xpBitReader) consume(n int) error {
	if n > r.valid-r.pad {
		return errXpTruncated
	}
	r.buf <<= uint(n)
	r.valid -= n
	if r.valid < 16 {
		r.buf |= r.word() << uint(16-r.valid)
		r.valid += 16
	}
	return nil
}

// symbol decodes one Huffman symbol.
func (r *xpBitReader) symbol(t *xpTable) (int, error) {
	idx := r.buf >> (32 - xpMaxCodeLen) // the top 15 bits
	clen := int(t.length[idx])
	if clen == 0 {
		if r.valid-r.pad < xpMaxCodeLen {
			return 0, errXpTruncated // the bits it would need aren't there
		}
		return 0, errXpBadCode
	}
	if err := r.consume(clen); err != nil {
		return 0, err
	}
	return int(t.sym[idx]), nil
}

// offset reads a distance: offset = (1<<bitLen) | <bitLen bits>.
func (r *xpBitReader) offset(bitLen int) (int, error) {
	if bitLen == 0 {
		return 1, nil
	}
	v := int(r.buf >> uint(32-bitLen))
	if err := r.consume(bitLen); err != nil {
		return 0, err
	}
	return 1<<uint(bitLen) | v, nil
}

// matchLength reads the raw-byte extension of a match whose length nibble is
// 15 and returns the length less the 3-byte minimum. room (the output still to
// produce) bounds a 16- or 32-bit length before it becomes an int, which on a
// 32-bit build a hostile 32-bit length could otherwise overflow.
func (r *xpBitReader) matchLength(room int) (int, error) {
	b, err := r.raw(1)
	if err != nil {
		return 0, err
	}
	if b != 0xFF {
		return 15 + int(b), nil
	}
	v, err := r.raw(2)
	if err == nil && v == 0 {
		v, err = r.raw(4)
	}
	if err != nil {
		return 0, err
	}
	if v < 15 {
		return 0, errXpBadLength
	}
	if uint64(v)+xpMinMatch > uint64(room) {
		return 0, errXpOverrun
	}
	return int(v), nil
}

// raw reads an n-byte little-endian value from the byte stream.
func (r *xpBitReader) raw(n int) (uint32, error) {
	if r.pos < 0 || r.pos > len(r.src)-n {
		return 0, errXpTruncated
	}
	var v uint32
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint32(r.src[r.pos+i])
	}
	r.pos += n
	return v, nil
}
