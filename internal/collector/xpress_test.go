package collector

import (
	"bytes"
	"math/bits"
	"math/rand"
	"testing"
)

// A spec-faithful Xpress Huffman encoder, used only by these tests to validate
// the production decompressor (xpress.go) by round trip. It mirrors the
// decoder's conventions exactly: canonical Huffman codes assigned by
// (length, symbol), a bit stream of little-endian 16-bit words written
// most-significant-bit first, distance extra bits after the symbol, then the
// length extension. Any valid tokenization decompresses correctly, so the
// matcher is deliberately simple.

type xpTok struct {
	lit   byte
	isLit bool
	mlen  int
	dist  int
}

func xpKey(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

// xpressHuffmanCompress produces a stream xpressHuffmanDecompress accepts.
func xpressHuffmanCompress(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	last := map[uint32]int{} // 3-byte key -> most recent absolute position
	var out []byte
	for lo := 0; lo < len(data); lo += xpChunkSize {
		hi := lo + xpChunkSize
		if hi > len(data) {
			hi = len(data)
		}
		out = append(out, xpEncodeTokens(xpTokenize(data, lo, hi, last))...)
	}
	return out
}

func xpTokenize(data []byte, lo, hi int, last map[uint32]int) []xpTok {
	var toks []xpTok
	for pos := lo; pos < hi; {
		bestLen, bestDist := 0, 0
		if pos+3 <= len(data) {
			key := xpKey(data[pos : pos+3])
			if p, ok := last[key]; ok {
				if d := pos - p; d >= 1 && d <= 65535 {
					maxL := hi - pos
					l := 0
					for l < maxL && l < 65536 && data[p+l] == data[pos+l] {
						l++
					}
					if l >= 3 {
						bestLen, bestDist = l, d
					}
				}
			}
			last[key] = pos
		}
		if bestLen >= xpMinMatch {
			toks = append(toks, xpTok{mlen: bestLen, dist: bestDist})
			end := pos + bestLen
			for q := pos + 1; q < end && q+3 <= len(data); q++ {
				last[xpKey(data[q:q+3])] = q
			}
			pos = end
		} else {
			toks = append(toks, xpTok{lit: data[pos], isLit: true})
			pos++
		}
	}
	return toks
}

func xpMatchSymbol(t xpTok) (sym, lenNib, offHigh int) {
	lenNib = t.mlen - xpMinMatch
	if lenNib > 15 {
		lenNib = 15
	}
	offHigh = bits.Len(uint(t.dist)) - 1
	sym = xpNumLiteral + (offHigh<<4 | lenNib)
	return
}

func xpEncodeTokens(toks []xpTok) []byte {
	freq := make([]int, xpNumSymbols)
	for _, t := range toks {
		if t.isLit {
			freq[t.lit]++
			continue
		}
		sym, _, _ := xpMatchSymbol(t)
		freq[sym]++
	}
	lengths := xpHuffLengths(freq)
	codes := xpCanonicalCodes(lengths)

	tbl := make([]byte, 256)
	for s := 0; s < xpNumSymbols; s++ {
		if s%2 == 0 {
			tbl[s/2] |= lengths[s] & 0x0F
		} else {
			tbl[s/2] |= lengths[s] << 4
		}
	}

	w := &xpBitWriter{}
	for _, t := range toks {
		if t.isLit {
			w.write(codes[t.lit], uint(lengths[t.lit]))
			continue
		}
		sym, lenNib, offHigh := xpMatchSymbol(t)
		w.write(codes[sym], uint(lengths[sym]))
		if offHigh > 0 {
			w.write(uint32(t.dist-(1<<uint(offHigh))), uint(offHigh))
		}
		if lenNib == 15 {
			T := t.mlen - xpMinMatch // >= 15
			if T <= 269 {
				w.write(uint32(T-15), 8)
			} else {
				w.write(0xFF, 8)
				w.write(uint32(T), 16)
			}
		}
	}
	return append(tbl, w.flush()...)
}

// xpHuffLengths computes a canonical Huffman code length per symbol (0 for
// absent symbols) by repeatedly combining the two lowest-frequency nodes.
func xpHuffLengths(freq []int) []uint8 {
	lengths := make([]uint8, len(freq))
	type nd struct {
		freq, sym int
		l, r      *nd
	}
	var work []*nd
	for s, f := range freq {
		if f > 0 {
			work = append(work, &nd{freq: f, sym: s})
		}
	}
	switch len(work) {
	case 0:
		return lengths
	case 1:
		lengths[work[0].sym] = 1
		return lengths
	}
	for len(work) > 1 {
		i, j := 0, 1
		if work[j].freq < work[i].freq {
			i, j = j, i
		}
		for k := 2; k < len(work); k++ {
			if work[k].freq < work[i].freq {
				j, i = i, k
			} else if work[k].freq < work[j].freq {
				j = k
			}
		}
		a, b := work[i], work[j]
		m := &nd{freq: a.freq + b.freq, sym: -1, l: a, r: b}
		hi, lo := i, j
		if lo > hi {
			hi, lo = lo, hi
		}
		work = append(work[:hi], work[hi+1:]...)
		work = append(work[:lo], work[lo+1:]...)
		work = append(work, m)
	}
	var walk func(n *nd, d int)
	walk = func(n *nd, d int) {
		if n.sym >= 0 {
			if d == 0 {
				d = 1
			}
			lengths[n.sym] = uint8(d)
			return
		}
		walk(n.l, d+1)
		walk(n.r, d+1)
	}
	walk(work[0], 0)
	xpLimitLengths(lengths, xpMaxCodeLen)
	return lengths
}

// xpLimitLengths caps code lengths at limit while keeping a valid (prefix-free)
// code, as a real Xpress encoder must — the decoder's table is only 15 bits
// wide. It clamps, then lengthens the longest sub-limit codes until the Kraft
// sum no longer over-subscribes. Optimality doesn't matter here, only validity.
func xpLimitLengths(lengths []uint8, limit int) {
	for i, l := range lengths {
		if int(l) > limit {
			lengths[i] = uint8(limit)
		}
	}
	total := 0
	for _, l := range lengths {
		if l > 0 {
			total += 1 << (limit - int(l))
		}
	}
	for total > (1 << limit) {
		best, bestLen := -1, -1
		for s, l := range lengths {
			if l > 0 && int(l) < limit && int(l) > bestLen {
				bestLen, best = int(l), s
			}
		}
		if best < 0 {
			break
		}
		lengths[best]++
		total -= 1 << (limit - bestLen - 1)
	}
}

func xpCanonicalCodes(lengths []uint8) []uint32 {
	codes := make([]uint32, len(lengths))
	var code uint32
	for l := 1; l <= xpMaxCodeLen; l++ {
		for s := 0; s < len(lengths); s++ {
			if int(lengths[s]) == l {
				codes[s] = code
				code++
			}
		}
		code <<= 1
	}
	return codes
}

// xpBitWriter accumulates bits MSB-first and emits little-endian 16-bit words.
type xpBitWriter struct {
	out   []byte
	acc   uint32
	nbits uint
}

func (w *xpBitWriter) write(v uint32, n uint) {
	if n == 0 {
		return
	}
	v &= (1 << n) - 1
	w.acc |= v << (32 - w.nbits - n)
	w.nbits += n
	for w.nbits >= 16 {
		word := w.acc >> 16
		w.out = append(w.out, byte(word), byte(word>>8))
		w.acc <<= 16
		w.nbits -= 16
	}
}

func (w *xpBitWriter) flush() []byte {
	if w.nbits > 0 {
		word := w.acc >> 16
		w.out = append(w.out, byte(word), byte(word>>8))
		w.acc, w.nbits = 0, 0
	}
	return w.out
}

func roundTrip(t *testing.T, name string, data []byte) {
	t.Helper()
	comp := xpressHuffmanCompress(data)
	got, err := xpressHuffmanDecompress(comp, len(data))
	if err != nil {
		t.Fatalf("%s: decompress: %v", name, err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("%s: round trip mismatch (%d bytes in, %d out)", name, len(data), len(got))
	}
}

func TestXpressRoundTrip(t *testing.T) {
	// All 256 byte values once: forces 256 distinct literal symbols, no match.
	allBytes := make([]byte, 256)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}

	// Highly repetitive: forces matches at distance 4 and long run lengths.
	repeat := bytes.Repeat([]byte("ABCD"), 10000)

	// A long single-byte run: forces the length path past 272 (the 0xff escape).
	longRun := bytes.Repeat([]byte{'Z'}, 5000)

	// Pseudo-text with structure and repetition.
	text := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 400)

	// > 64 KiB to exercise chunk boundaries and cross-chunk back-references.
	rng := rand.New(rand.NewSource(1))
	random := make([]byte, 200_000)
	rng.Read(random)
	mixed := append(append([]byte{}, bytes.Repeat([]byte("header-"), 5000)...), random...)

	cases := []struct {
		name string
		data []byte
	}{
		{"single-byte", []byte{0x42}},
		{"all-bytes", allBytes},
		{"repeat-ABCD", repeat},
		{"long-run-escape", longRun},
		{"text", text},
		{"random-200k", random},
		{"mixed-multichunk", mixed},
		{"exact-chunk", bytes.Repeat([]byte{7}, xpChunkSize)},
		{"chunk-plus-one", bytes.Repeat([]byte{9}, xpChunkSize+1)},
	}
	for _, c := range cases {
		roundTrip(t, c.name, c.data)
	}
}

func TestXpressTruncatedStream(t *testing.T) {
	data := bytes.Repeat([]byte("ABCD"), 1000)
	comp := xpressHuffmanCompress(data)
	// Claim far more output than the stream can produce: it must run out and
	// error rather than returning a short or wrong buffer.
	if _, err := xpressHuffmanDecompress(comp, len(data)*100); err == nil {
		t.Fatal("expected an error decompressing a truncated stream")
	}
}

func TestXpressShortTable(t *testing.T) {
	// A stream whose very first chunk table is incomplete.
	if _, err := xpressHuffmanDecompress([]byte{0x01, 0x02, 0x03}, 10); err != errXpTruncated {
		t.Fatalf("got %v, want errXpTruncated", err)
	}
}

func TestXpressOverSubscribedTable(t *testing.T) {
	// 256-byte table giving many symbols a 1-bit code: impossible (a 1-bit
	// code admits at most two symbols), so the table must be rejected.
	tbl := make([]byte, 256)
	for i := range tbl {
		tbl[i] = 0x11 // both nibbles length 1
	}
	stream := append(tbl, 0x00, 0x00)
	if _, err := xpressHuffmanDecompress(stream, 4); err != errXpOverSub {
		t.Fatalf("got %v, want errXpOverSub", err)
	}
}
