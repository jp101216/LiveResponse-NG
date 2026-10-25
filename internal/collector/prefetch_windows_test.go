//go:build windows

package collector

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// These tests validate the Xpress Huffman decompressor against the real
// Windows codec (ntdll's RtlCompressBuffer) and against real prefetch files,
// closing the loop the Linux round-trip tests (xpress_test.go) can only
// approximate with a self-consistent encoder.

var (
	ntdll          = syscall.NewLazyDLL("ntdll.dll")
	procWorkSpace  = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	procCompressBf = ntdll.NewProc("RtlCompressBuffer")
)

const (
	compressXpressHuff = 0x0004 // COMPRESSION_FORMAT_XPRESS_HUFF
	compressEngineMax  = 0x0100 // COMPRESSION_ENGINE_MAXIMUM
	compressFmtEngine  = compressXpressHuff | compressEngineMax
	prefetchChunk      = 65536 // the uncompressed chunk size the prefetcher uses
)

// rtlCompressXpressHuff compresses data with Windows' own Xpress Huffman codec,
// producing exactly the raw stream (no MAM header) that xpressHuffmanDecompress
// consumes. It skips, rather than fails, where the codec isn't available.
func rtlCompressXpressHuff(t *testing.T, data []byte) ([]byte, bool) {
	t.Helper()
	if len(data) == 0 {
		return nil, true
	}
	var wsCompress, wsFragment uint32
	st, _, _ := procWorkSpace.Call(uintptr(compressFmtEngine),
		uintptr(unsafe.Pointer(&wsCompress)), uintptr(unsafe.Pointer(&wsFragment)))
	if st != 0 {
		t.Skipf("RtlGetCompressionWorkSpaceSize unavailable (status 0x%x)", st)
		return nil, false
	}
	ws := make([]byte, wsCompress)
	out := make([]byte, len(data)+len(data)/2+4096)
	var final uint32
	st, _, _ = procCompressBf.Call(
		uintptr(compressFmtEngine),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(prefetchChunk),
		uintptr(unsafe.Pointer(&final)),
		uintptr(unsafe.Pointer(&ws[0])),
	)
	if st != 0 {
		t.Fatalf("RtlCompressBuffer status 0x%x", st)
	}
	return out[:final], true
}

func TestXpressAgainstNtdll(t *testing.T) {
	if underWine() {
		t.Skip("Wine does not implement RtlCompressBuffer XPRESS_HUFF")
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	rng := rand.New(rand.NewSource(7))
	random := make([]byte, 100_000)
	rng.Read(random)

	cases := map[string][]byte{
		"short":        []byte("hello, live response"),
		"all-bytes":    all,
		"repeat":       bytes.Repeat([]byte("ABCD"), 20_000), // > 64 KiB: multi-chunk
		"long-run":     bytes.Repeat([]byte{'Z'}, 5_000),
		"random-100k":  random,
		"exact-chunk":  bytes.Repeat([]byte{3}, prefetchChunk),
		"chunk-plus-1": bytes.Repeat([]byte{4}, prefetchChunk+1),
	}
	for name, data := range cases {
		comp, ok := rtlCompressXpressHuff(t, data)
		if !ok {
			return
		}
		got, err := xpressHuffmanDecompress(comp, len(data))
		if err != nil {
			t.Fatalf("%s: decompress Windows-compressed data: %v", name, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: decompressed output differs from the original (%d/%d bytes)", name, len(got), len(data))
		}
	}
}

// TestDecodeRealPrefetch decodes whatever .pf files the runner happens to have.
// Prefetch is off by default on Server SKUs, so an empty directory is a skip,
// not a failure; the ntdll test above is the codec's authoritative check.
func TestDecodeRealPrefetch(t *testing.T) {
	dir := filepath.Join(systemRoot(), "Prefetch")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no prefetch directory: %v", err)
	}
	decoded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".pf") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		pf, err := decodePrefetchFile(raw)
		if err != nil {
			t.Errorf("%s: decode failed: %v", e.Name(), err)
			continue
		}
		switch pf.Version {
		case 23, 26, 30, 31:
		default:
			t.Errorf("%s: unexpected format version %d", e.Name(), pf.Version)
		}
		if pf.Executable == "" {
			t.Errorf("%s: no executable name decoded", e.Name())
		}
		// The filename encodes the executable; the decoded header must agree.
		if base, _, ok := prefetchExecutable(e.Name()); ok && !strings.EqualFold(base, pf.Executable) {
			t.Errorf("%s: filename exe %q != decoded exe %q", e.Name(), base, pf.Executable)
		}
		decoded++
		if decoded >= 25 {
			break // a representative sample is enough
		}
	}
	if decoded == 0 {
		t.Skip("prefetch directory present but empty (prefetcher likely disabled)")
	}
	t.Logf("decoded %d prefetch files", decoded)
}
