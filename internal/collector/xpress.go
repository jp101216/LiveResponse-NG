package collector

import (
	"errors"
	"fmt"
)

// Xpress Huffman (LZXPRESS Huffman, COMPRESSION_FORMAT_XPRESS_HUFF)
// decompression, per [MS-XCA] section 2.2. Windows 8 and later store prefetch
// (.pf) bodies in this format behind a "MAM\x04" header; on Windows the body
// is produced by RtlCompressBuffer / consumed by RtlDecompressBufferEx with
// COMPRESSION_FORMAT_XPRESS_HUFF. We decode it ourselves so the collector runs
// the same on any host and never shells out.
//
// No build tag: it decodes a plain byte slice, bounds-checked, and is
// unit-tested on any OS. xpress_test.go round-trips a spec-faithful encoder
// through this decoder across every code path (literals, short and extended
// matches, the 0xff length escape, multi-chunk input); a Windows CI job
// (see .github/workflows/ci.yml) decodes a live C:\Windows\Prefetch\*.pf end
// to end against real data, which is the authoritative check.
//
// Stream layout. The compressed data is a sequence of chunks, each decoding to
// exactly 65536 bytes (the final chunk may be shorter). A chunk is:
//
//	[256-byte Huffman table][bit stream]
//
// The table holds 512 four-bit code lengths, two per byte, low nibble first,
// for 512 symbols: 0-255 are literal bytes; 256-511 encode a (length,distance)
// back-reference. The bit stream is a series of little-endian 16-bit words,
// consumed most-significant-bit first. The next chunk's table begins at the
// next 16-bit boundary after the bits the current chunk consumed (trailing
// bits of the last word are padding).

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
	errXpOverrun   = errors.New("xpress: match length overruns the chunk")
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
	tableStart := 0
	for len(out) < outSize {
		if tableStart+256 > len(in) {
			return nil, errXpTruncated
		}
		table, err := xpBuildTable(xpReadCodeLengths(in[tableStart : tableStart+256]))
		if err != nil {
			return nil, err
		}
		br := xpBitReader{src: in, pos: tableStart + 256}

		chunkEnd := len(out) + xpChunkSize
		if chunkEnd > outSize {
			chunkEnd = outSize
		}
		for len(out) < chunkEnd {
			sym, err := br.symbol(table)
			if err != nil {
				return nil, err
			}
			if sym < xpNumLiteral {
				out = append(out, byte(sym))
				continue
			}
			// Match symbol: low nibble is the length, the next nibble is the
			// number of extra bits for the distance ([MS-XCA] 2.2.4).
			ms := sym - xpNumLiteral
			length := ms & 0xF
			offHigh := (ms >> 4) & 0xF
			offset, err := br.offset(offHigh)
			if err != nil {
				return nil, err
			}
			if length == 0xF {
				// Extended length: an 8-bit value, then a 16-bit escape, then
				// a 32-bit escape. Matches RtlDecompressBufferEx exactly.
				e1, err := br.bits(8)
				if err != nil {
					return nil, err
				}
				length += int(e1)
				if e1 == 0xFF {
					e2, err := br.bits(16)
					if err != nil {
						return nil, err
					}
					length = int(e2)
					if length == 0 {
						e4, err := br.bits(32)
						if err != nil {
							return nil, err
						}
						length = int(e4)
					}
				}
			}
			length += xpMinMatch
			if offset > len(out) {
				return nil, errXpBadDist
			}
			if length > chunkEnd-len(out) {
				return nil, errXpOverrun
			}
			// Byte-by-byte copy: overlap (offset < length) is legal and is how
			// runs are encoded. The source may lie in an earlier chunk (the
			// window is the whole output, up to 65535 back).
			start := len(out) - offset
			for i := 0; i < length; i++ {
				out = append(out, out[start+i])
			}
		}

		bitstreamStart := tableStart + 256
		tableStart = bitstreamStart + 2*((br.consumed+15)/16)
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

func xpBuildTable(lengths []uint8) (*xpTable, error) {
	t := &xpTable{}
	var code uint32
	for l := 1; l <= xpMaxCodeLen; l++ {
		for sym := 0; sym < xpNumSymbols; sym++ {
			if int(lengths[sym]) != l {
				continue
			}
			start := code << uint(xpMaxCodeLen-l)
			n := uint32(1) << uint(xpMaxCodeLen-l)
			if start+n > (1 << xpMaxCodeLen) {
				return nil, errXpOverSub
			}
			for j := uint32(0); j < n; j++ {
				t.sym[start+j] = uint16(sym)
				t.length[start+j] = uint8(l)
			}
			code++
		}
		code <<= 1
	}
	return t, nil
}

// xpBitReader reads the chunk bit stream. Valid bits occupy the top `nbits`
// of buf (the rest are zero); words are pulled in little-endian and consumed
// most-significant-bit first.
type xpBitReader struct {
	src      []byte
	pos      int    // next input byte to buffer
	buf      uint32 // valid bits are the top nbits
	nbits    uint   // count of valid bits
	consumed int    // bits consumed since this chunk's bit stream began
}

// fill tops the buffer up while fewer than 16 bits are buffered and input
// remains. A lone trailing byte (odd tail) is left as padding.
func (r *xpBitReader) fill() {
	for r.nbits <= 16 && r.pos+2 <= len(r.src) {
		w := uint32(r.src[r.pos]) | uint32(r.src[r.pos+1])<<8
		r.pos += 2
		r.buf |= w << (16 - r.nbits)
		r.nbits += 16
	}
}

func (r *xpBitReader) consume(n uint) {
	r.buf <<= n
	r.nbits -= n
	r.consumed += int(n)
}

// symbol decodes one Huffman symbol.
func (r *xpBitReader) symbol(t *xpTable) (int, error) {
	r.fill()
	if r.nbits == 0 {
		return 0, errXpTruncated
	}
	idx := r.buf >> (32 - xpMaxCodeLen) // top 15 bits
	clen := t.length[idx]
	if clen == 0 || uint(clen) > r.nbits {
		return 0, errXpBadCode
	}
	sym := t.sym[idx]
	r.consume(uint(clen))
	return int(sym), nil
}

// offset reconstructs a distance from its high-bit position and extra bits:
// offset = (1<<offHigh) | <offHigh extra bits>.
func (r *xpBitReader) offset(offHigh int) (int, error) {
	base := 1 << uint(offHigh)
	if offHigh == 0 {
		return base, nil
	}
	ex, err := r.bits(uint(offHigh))
	if err != nil {
		return 0, err
	}
	return base | int(ex), nil
}

// bits reads n bits (1..32) MSB-first and returns them right-aligned.
func (r *xpBitReader) bits(n uint) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if n > 16 {
		hi, err := r.bits(16)
		if err != nil {
			return 0, err
		}
		lo, err := r.bits(n - 16)
		if err != nil {
			return 0, err
		}
		return hi<<(n-16) | lo, nil
	}
	r.fill()
	if r.nbits < n {
		return 0, errXpTruncated
	}
	v := r.buf >> (32 - n)
	r.consume(n)
	return v, nil
}
