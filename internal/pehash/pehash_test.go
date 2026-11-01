package pehash

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// image builds a small PE image: section headers in the given (possibly
// unsorted) order, each section's raw data filled with its own byte, then an
// optional overlay and certificate table.
type image struct {
	plus     bool // PE32+
	sections []struct {
		ptr, size uint32
		fill      byte
	}
	overlay []byte
	cert    []byte
	nrva    uint32 // NumberOfRvaAndSizes (default 16)
}

func (im image) build() []byte {
	const peOff = 0x80
	optSize := 224
	if im.plus {
		optSize = 240
	}
	headers := uint32(0x400)
	end := int(headers)
	for _, s := range im.sections {
		end = max(end, int(s.ptr+s.size))
	}
	b := make([]byte, end)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], peOff)
	for i := 0x40; i < peOff; i++ {
		b[i] = byte(i) // a DOS stub's worth of bytes that must be hashed
	}
	copy(b[peOff:], "PE\x00\x00")
	coff := peOff + 4
	binary.LittleEndian.PutUint16(b[coff:], 0x8664)
	binary.LittleEndian.PutUint16(b[coff+2:], uint16(len(im.sections)))
	binary.LittleEndian.PutUint16(b[coff+16:], uint16(optSize))
	opt := coff + 20
	nrvaAt, dirs := opt+92, opt+96
	if im.plus {
		binary.LittleEndian.PutUint16(b[opt:], magicPE32Plus)
		nrvaAt, dirs = opt+108, opt+112
	} else {
		binary.LittleEndian.PutUint16(b[opt:], magicPE32)
	}
	binary.LittleEndian.PutUint32(b[opt+60:], headers)
	binary.LittleEndian.PutUint32(b[opt+64:], 0xC0FFEE) // CheckSum: excluded
	nrva := im.nrva
	if nrva == 0 {
		nrva = 16
	}
	binary.LittleEndian.PutUint32(b[nrvaAt:], nrva)
	for i := 0; i < 16; i++ { // directory entries the hash keeps
		binary.LittleEndian.PutUint32(b[dirs+8*i:], uint32(0x1000*i+1))
	}
	table := opt + optSize
	for i, s := range im.sections {
		h := table + 40*i
		copy(b[h:], ".s"+string(rune('a'+i)))
		binary.LittleEndian.PutUint32(b[h+8:], s.size)              // VirtualSize
		binary.LittleEndian.PutUint32(b[h+12:], 0x1000*uint32(i+1)) // VirtualAddress
		binary.LittleEndian.PutUint32(b[h+16:], s.size)             // SizeOfRawData
		binary.LittleEndian.PutUint32(b[h+20:], s.ptr)              // PointerToRawData
		for j := s.ptr; j < s.ptr+s.size; j++ {
			b[j] = s.fill
		}
	}
	b = append(b, im.overlay...)
	cert := dirs + 8*dirSecurity
	if len(im.cert) > 0 {
		binary.LittleEndian.PutUint32(b[cert:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[cert+4:], uint32(len(im.cert)))
		b = append(b, im.cert...)
	} else {
		binary.LittleEndian.PutUint64(b[cert:], 0)
	}
	return b
}

// expected hashes the byte ranges the specification says to, written out by
// hand for the images above.
func expected(b []byte, plus bool, sorted [][2]int, overlayEnd int, nrva int) Digests {
	opt := 0x80 + 24
	dirs := opt + 96
	if plus {
		dirs = opt + 112
	}
	var parts [][]byte
	if nrva > dirSecurity {
		cert := dirs + 8*dirSecurity
		parts = append(parts, b[:opt+64], b[opt+68:cert], b[cert+8:0x400])
	} else {
		parts = append(parts, b[:opt+64], b[opt+68:0x400])
	}
	sum := 0x400
	for _, s := range sorted {
		parts = append(parts, b[s[0]:s[0]+s[1]])
		sum += s[1]
	}
	if overlayEnd > sum {
		parts = append(parts, b[sum:overlayEnd])
	}
	h256, h1 := sha256.New(), sha1.New()
	for _, p := range parts {
		h256.Write(p)
		h1.Write(p)
	}
	var d Digests
	copy(d.SHA256[:], h256.Sum(nil))
	copy(d.SHA1[:], h1.Sum(nil))
	return d
}

type sec = struct {
	ptr, size uint32
	fill      byte
}

func TestAuthentihashSpecRanges(t *testing.T) {
	cases := []struct {
		name string
		im   image
	}{
		{"pe32+, sections out of order, overlay, signed", image{plus: true,
			sections: []sec{{0x1400, 0x200, 0xBB}, {0x400, 0x1000, 0xAA}, {0x1600, 0x0, 0xCC}, {0x1600, 0x400, 0xDD}},
			overlay:  []byte("overlay data that is hashed"), cert: make([]byte, 0x48)}},
		{"pe32, unsigned, no overlay", image{
			sections: []sec{{0x400, 0x600, 0x11}, {0xA00, 0x200, 0x22}}}},
		{"pe32, unsigned, overlay", image{
			sections: []sec{{0x400, 0x200, 0x33}}, overlay: []byte{1, 2, 3, 4, 5}}},
		{"no certificate-table entry (4 directories)", image{plus: true, nrva: 4,
			sections: []sec{{0x400, 0x200, 0x44}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.im.build()
			var sorted [][2]int
			for _, s := range c.im.sections {
				if s.size > 0 {
					sorted = append(sorted, [2]int{int(s.ptr), int(s.size)})
				}
			}
			for i := range sorted { // insertion sort by pointer
				for j := i; j > 0 && sorted[j][0] < sorted[j-1][0]; j-- {
					sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
				}
			}
			nrva := int(c.im.nrva)
			if nrva == 0 {
				nrva = 16
			}
			want := expected(b, c.im.plus, sorted, len(b)-len(c.im.cert), nrva)
			got, err := Authentihash(b)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("got %x, want %x", got.SHA256, want.SHA256)
			}
			// What signing changes doesn't change the digest; anything else does.
			signed := append([]byte(nil), b...)
			binary.LittleEndian.PutUint32(signed[0x80+24+64:], 0x12345678)
			if g, _ := Authentihash(signed); g != got {
				t.Error("the CheckSum field changed the digest")
			}
			if len(c.im.cert) > 0 {
				signed[len(signed)-1] ^= 0xFF
				if g, _ := Authentihash(signed); g != got {
					t.Error("the certificate table changed the digest")
				}
			}
			code := append([]byte(nil), b...)
			code[0x400] ^= 0xFF
			if g, _ := Authentihash(code); g == got {
				t.Error("a code byte didn't change the digest")
			}
		})
	}
}

// The same images digested by an independent implementation (LIEF 1.0's
// Binary.authentihash, run once over these exact bytes): out-of-order and
// empty sections, an overlay before the certificate table, PE32 and PE32+.
func TestAuthentihashMatchesLIEF(t *testing.T) {
	for i, c := range []struct {
		im   image
		want string
	}{
		{image{plus: true, sections: []sec{{0x1400, 0x200, 0xBB}, {0x400, 0x1000, 0xAA}, {0x1600, 0x0, 0xCC}, {0x1600, 0x400, 0xDD}},
			overlay: []byte("overlay data that is hashed"), cert: make([]byte, 0x48)},
			"931a480f612fa37ae7a732e47236cc927956d59b20652f2308fb9035b9a30d40"},
		{image{sections: []sec{{0x400, 0x600, 0x11}, {0xA00, 0x200, 0x22}}},
			"f1b8ba749c30ddf81a85b839aa8a51f86b718f64300fad3bb67baae5406e9b07"},
		{image{sections: []sec{{0x400, 0x200, 0x33}}, overlay: []byte{1, 2, 3, 4, 5}},
			"b83d3d738e9a82d432bb0b1ec9ba43bc58121ed9199259e7f40049959be94d3f"},
		{image{plus: true, sections: []sec{{0x400, 0x200, 0x44}}, overlay: []byte("tail"), cert: []byte("12345678")},
			"fb4327eb576adcfed0e1f998f6b941a4e571291f10c591942d7dbd3c04c7feca"},
	} {
		d, err := Authentihash(c.im.build())
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(d.SHA256[:]); got != c.want {
			t.Errorf("image %d: %s, LIEF %s", i, got, c.want)
		}
	}
}

// A known-vulnerable driver's digest as LOLDrivers (and LIEF) compute it.
// The driver isn't in the repository; point LRNG_AUTHENTIHASH_SAMPLE at a copy
// of szkg64.sys (LOLDrivers' drivers/8598e4a12eaa945b35365dd2750b9777) to run.
func TestAuthentihashKnownDriver(t *testing.T) {
	p := os.Getenv("LRNG_AUTHENTIHASH_SAMPLE")
	if p == "" {
		t.Skip("set LRNG_AUTHENTIHASH_SAMPLE to a copy of szkg64.sys")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != "6bc0e1c104fac4a8caa4237c7ae181ca11a043a3ee26426aeb7a90dc40281fad" {
		t.Skip("not the expected szkg64.sys")
	}
	d, err := Authentihash(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(d.SHA256[:]); got != "95ca14e045618fb38834d17c5cc176162a29d846c1463b840c9129fb9af47c68" {
		t.Fatalf("authentihash %s", got)
	}
}

// Cross-check against digests from an independent implementation:
// LRNG_AUTHENTIHASH_REFERENCE names a file of "path<TAB>sha256<TAB>sha1" lines
// (written, for instance, by LIEF's Binary.authentihash over a corpus).
func TestAuthentihashReference(t *testing.T) {
	ref := os.Getenv("LRNG_AUTHENTIHASH_REFERENCE")
	if ref == "" {
		t.Skip("set LRNG_AUTHENTIHASH_REFERENCE to a reference digest list")
	}
	f, err := os.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) != 3 {
			continue // the reference couldn't parse it either
		}
		img, err := os.Open(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		st, err := img.Stat()
		if err != nil {
			t.Fatal(err)
		}
		d, err := AuthentihashReader(img, st.Size()) // streamed from the file
		img.Close()
		if err != nil {
			t.Errorf("%s: %v", parts[0], err)
			continue
		}
		if hex.EncodeToString(d.SHA256[:]) != parts[1] || hex.EncodeToString(d.SHA1[:]) != parts[2] {
			t.Errorf("%s: got %x, reference %s", parts[0], d.SHA256, parts[1])
		}
		n++
	}
	t.Logf("%d images agree with the reference", n)
}

func TestAuthentihashRejectsMalformed(t *testing.T) {
	good := image{plus: true, sections: []sec{{0x400, 0x200, 1}}}.build()
	for name, mut := range map[string]func([]byte) []byte{
		"empty":        func([]byte) []byte { return nil },
		"no MZ":        func(b []byte) []byte { b[0] = 'X'; return b },
		"PE past end":  func(b []byte) []byte { binary.LittleEndian.PutUint32(b[0x3c:], 0xFFFFFFF0); return b },
		"bad magic":    func(b []byte) []byte { binary.LittleEndian.PutUint16(b[0x80+24:], 0x1234); return b },
		"cut in table": func(b []byte) []byte { return b[:0x80+24+240+10] },
		"tiny headers": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[0x80+24+60:], 0x40); return b },
		"200 sections": func(b []byte) []byte { binary.LittleEndian.PutUint16(b[0x80+6:], 200); return b },
	} {
		b := mut(append([]byte(nil), good...))
		if _, err := Authentihash(b); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := Authentihash([]byte("MZ not really")); !errors.Is(err, ErrNotPE) {
		t.Errorf("short input: %v", err)
	}
	// Sections and a certificate size reaching past the end are clamped, not a panic.
	odd := image{sections: []sec{{0x400, 0x200, 1}}}.build()
	h := 0x80 + 24 + 224
	binary.LittleEndian.PutUint32(odd[h+16:], 0x7FFFFFFF)
	binary.LittleEndian.PutUint32(odd[0x80+24+96+32:], 0x10)
	binary.LittleEndian.PutUint32(odd[0x80+24+96+36:], 0xFFFFFFFF)
	if _, err := Authentihash(odd); err != nil {
		t.Errorf("oversized section: %v", err)
	}
}

func FuzzAuthentihash(f *testing.F) {
	f.Add(image{plus: true, sections: []sec{{0x400, 0x200, 1}}, cert: []byte("sig")}.build())
	f.Add(image{sections: []sec{{0x600, 0x10, 2}, {0x400, 0x200, 3}}}.build())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Authentihash(b)
	})
}
