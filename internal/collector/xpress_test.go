package collector

import (
	"bytes"
	"math/bits"
	"math/rand"
	"testing"
)

// A spec-faithful Xpress Huffman encoder, used only by these tests to exercise
// the decompressor (xpress.go) on any OS. It lays a stream out the way the
// [MS-XCA] decoder reads it: 16-bit words of bits, most significant bit first,
// interleaved with raw bytes for match lengths of 18 or more, with each word at
// the position the decoder loads it from. The decoder holds one word of
// lookahead -- once it has consumed c bits of a block it has loaded
// ceil(c/16)+1 words (two at the start) -- so after every symbol and every
// distance the encoder reserves slots for the words loaded so far, and appends
// raw bytes after them. Any valid tokenization decompresses correctly, so the
// matcher is deliberately simple. Agreement with Windows itself is checked
// against ntdll (prefetch_windows_test.go) and real .pf files
// (prefetch_samples_test.go).

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
		hi := min(lo+xpChunkSize, len(data))
		out = xpEncodeBlock(out, xpTokenize(data, lo, hi, last))
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
	lenNib = min(t.mlen-xpMinMatch, 15)
	offHigh = bits.Len(uint(t.dist)) - 1
	sym = xpNumLiteral + (offHigh<<4 | lenNib)
	return
}

// xpEncodeBlock appends one block (table and stream) encoding toks to out.
func xpEncodeBlock(out []byte, toks []xpTok) []byte {
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

	w := xpStreamWriter{out: append(out, xpTableBytes(lengths)...)}
	w.reserve(2)
	for _, t := range toks {
		if t.isLit {
			w.bits(codes[t.lit], uint(lengths[t.lit]))
			continue
		}
		sym, lenNib, offHigh := xpMatchSymbol(t)
		w.bits(codes[sym], uint(lengths[sym]))
		if lenNib == 15 {
			// The length's extension, in raw bytes, comes before the distance.
			n := t.mlen - xpMinMatch // >= 15
			switch {
			case n-15 < 0xFF:
				w.raw(byte(n - 15))
			case n <= 0xFFFF:
				w.raw(0xFF, byte(n), byte(n>>8))
			default:
				w.raw(0xFF, 0, 0, byte(n), byte(n>>8), byte(n>>16), byte(n>>24))
			}
		}
		w.bits(uint32(t.dist-(1<<uint(offHigh))), uint(offHigh))
	}
	return w.finish()
}

// xpTableBytes packs 512 code lengths into the 256-byte table, low nibble first.
func xpTableBytes(lengths []uint8) []byte {
	tbl := make([]byte, 256)
	for s := 0; s < xpNumSymbols; s++ {
		if s%2 == 0 {
			tbl[s/2] |= lengths[s] & 0x0F
		} else {
			tbl[s/2] |= lengths[s] << 4
		}
	}
	return tbl
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

// xpStreamWriter lays out one block's stream: it reserves a 2-byte slot for
// each word at the point the decoder loads it, appends raw bytes as they come,
// and fills the slots with the block's bits at the end.
type xpStreamWriter struct {
	out   []byte
	slots []int  // where this block's words go, in stream order
	acc   []byte // the block's bits, one per byte (test code: clarity first)
}

func (w *xpStreamWriter) reserve(words int) {
	for len(w.slots) < words {
		w.slots = append(w.slots, len(w.out))
		w.out = append(w.out, 0, 0)
	}
}

// bits appends n bits of v, most significant first, as one decoder read.
func (w *xpStreamWriter) bits(v uint32, n uint) {
	for i := int(n) - 1; i >= 0; i-- {
		w.acc = append(w.acc, byte(v>>uint(i))&1)
	}
	w.reserve((len(w.acc)+15)/16 + 1) // the words loaded once these are consumed
}

func (w *xpStreamWriter) raw(b ...byte) { w.out = append(w.out, b...) }

func (w *xpStreamWriter) finish() []byte {
	for k, at := range w.slots {
		var word uint16
		for i := 0; i < 16; i++ {
			word <<= 1
			if j := 16*k + i; j < len(w.acc) {
				word |= uint16(w.acc[j])
			}
		}
		w.out[at], w.out[at+1] = byte(word), byte(word>>8)
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

// TestXpressLengthEncodings covers each form a match length takes: the nibble
// alone (3-17), one raw byte (18-272), 0xff and 16 bits (273-65538), and 0xff,
// a zero 16-bit word and 32 bits (beyond that).
func TestXpressLengthEncodings(t *testing.T) {
	for _, n := range []int{3, 17, 18, 100, 272, 273, 5000, 65534, 65538, 65539, 70000} {
		toks := []xpTok{{lit: 'A', isLit: true}, {mlen: n, dist: 1}}
		tail := []xpTok{{lit: 'z', isLit: true}}
		var stream []byte
		if 1+n < xpChunkSize {
			stream = xpEncodeBlock(nil, append(toks, tail...))
		} else {
			// The match fills the block, so the next byte starts a new one.
			stream = xpEncodeBlock(xpEncodeBlock(nil, toks), tail)
		}
		want := append(bytes.Repeat([]byte{'A'}, 1+n), 'z')
		got, err := xpressHuffmanDecompress(stream, len(want))
		if err != nil {
			t.Fatalf("match length %d: %v", n, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("match length %d: wrong output", n)
		}
	}
}

// TestXpressLengthBytesPrecedeDistance pins the order within a long match: the
// raw length bytes are read before the distance bits are consumed, and that
// consumption is what may load the next word. A 13-bit distance at varying bit
// alignments makes the distance straddle a refill in most of these cases, so
// reading the two in the other order (it matters only then) fails here.
func TestXpressLengthBytesPrecedeDistance(t *testing.T) {
	for k := 0; k < 48; k++ {
		toks := []xpTok{{lit: 'A', isLit: true}, {mlen: 9000, dist: 1}}
		want := bytes.Repeat([]byte{'A'}, 9001)
		for i := 0; i < k; i++ {
			c := "xyz"[i%3]
			toks = append(toks, xpTok{lit: c, isLit: true})
			want = append(want, c)
		}
		toks = append(toks, xpTok{mlen: 300, dist: 9000}) // copies 300 of the 'A's
		want = append(want, bytes.Repeat([]byte{'A'}, 300)...)
		got, err := xpressHuffmanDecompress(xpEncodeBlock(nil, toks), len(want))
		if err != nil {
			t.Fatalf("%d literals before the match: %v", k, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%d literals before the match: wrong output", k)
		}
	}
}

// TestXpressMatchAcrossBlocks: [MS-XCA]'s decoder lets a match run past a
// block's 65536 bytes, and the next block's 65536 count from wherever the
// output then is -- here bytes 70000 to 135536, not 65536 to 131072. (Our
// encoder never splits a match that way, but Windows' decoder accepts it, so
// ours must too.)
func TestXpressMatchAcrossBlocks(t *testing.T) {
	lits := func(from, to int) []xpTok {
		var toks []xpTok
		for i := from; i < to; i++ {
			toks = append(toks, xpTok{lit: byte('a' + i%26), isLit: true})
		}
		return toks
	}
	stream := xpEncodeBlock(nil, []xpTok{{lit: 'A', isLit: true}, {mlen: 69999, dist: 1}})
	stream = xpEncodeBlock(stream, lits(0, xpChunkSize))
	stream = xpEncodeBlock(stream, lits(xpChunkSize, 70000))
	want := bytes.Repeat([]byte{'A'}, 70000)
	for i := 0; i < 70000; i++ {
		want = append(want, byte('a'+i%26))
	}
	got, err := xpressHuffmanDecompress(stream, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("wrong output")
	}
}

// TestXpressBadExtendedLength: a 16-bit length below 15 is invalid ([MS-XCA]
// subtracts 15 from it).
func TestXpressBadExtendedLength(t *testing.T) {
	lengths := make([]uint8, xpNumSymbols)
	lengths['A'], lengths[xpNumLiteral+15] = 1, 1 // a literal and "length 18+, distance 1"
	codes := xpCanonicalCodes(lengths)
	w := xpStreamWriter{out: xpTableBytes(lengths)}
	w.reserve(2)
	w.bits(codes['A'], 1)
	w.bits(codes[xpNumLiteral+15], 1)
	w.raw(0xFF, 5, 0)
	if _, err := xpressHuffmanDecompress(w.finish(), 100); err != errXpBadLength {
		t.Fatalf("got %v, want errXpBadLength", err)
	}
}

// TestXpressDamagedInput: a cut or corrupted stream (a hostile or half-written
// .pf) must return an error or exactly outSize bytes -- never panic, never a
// short buffer.
func TestXpressDamagedInput(t *testing.T) {
	data := append(bytes.Repeat([]byte(`\VOLUME{01d1}\WINDOWS\SYSTEM32\`), 3000), bytes.Repeat([]byte{0, 'x'}, 20000)...)
	comp := xpressHuffmanCompress(data)
	for cut := 0; cut < len(comp); cut += 61 {
		if got, err := xpressHuffmanDecompress(comp[:cut], len(data)); err == nil {
			t.Fatalf("a stream cut to %d of %d bytes decoded (%d bytes)", cut, len(comp), len(got))
		}
	}
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 300; i++ {
		bad := append([]byte(nil), comp...)
		for j := 0; j < 1+rng.Intn(8); j++ {
			bad[rng.Intn(len(bad))] = byte(rng.Intn(256))
		}
		if got, err := xpressHuffmanDecompress(bad, len(data)); err == nil && len(got) != len(data) {
			t.Fatalf("corrupt stream decoded to %d bytes, want %d or an error", len(got), len(data))
		}
	}
}
