package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDecodePrefetchSamples decodes a directory of real .pf files on any OS.
// Set LRNG_PREFETCH_SAMPLES to a folder of files copied from a Windows host's
// C:\Windows\Prefetch: Windows 10 and later compress them with Xpress Huffman,
// so this is the decompressor's real-data check off Windows (the synthetic
// streams in xpress_test.go come from our own encoder, which can only agree
// with our own reading of the format).
func TestDecodePrefetchSamples(t *testing.T) {
	dir := os.Getenv("LRNG_PREFETCH_SAMPLES")
	if dir == "" {
		t.Skip("set LRNG_PREFETCH_SAMPLES to a directory of .pf files")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".pf") {
			continue
		}
		found++
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		checkPrefetchSample(t, e.Name(), raw)
	}
	if found == 0 {
		t.Skip("no .pf files in LRNG_PREFETCH_SAMPLES")
	}
}

// checkPrefetchSample decodes one real .pf file and checks it end to end. The
// SCCA header records the body's own size, so a decompression that drifts by a
// single bit fails here even if the bytes it produces happen to parse.
func checkPrefetchSample(t *testing.T, name string, raw []byte) bool {
	t.Helper()
	body, err := prefetchDecompress(raw)
	if err != nil {
		t.Errorf("%s: decompress: %v", name, err)
		return false
	}
	if len(body) < sccaHeaderLen || int(le.Uint32(body[12:16])) != len(body) {
		t.Errorf("%s: the SCCA size field disagrees with the %d decompressed bytes", name, len(body))
		return false
	}
	pf, err := parsePrefetch(body)
	if err != nil {
		t.Errorf("%s: parse: %v", name, err)
		return false
	}
	switch pf.Version {
	case 23, 26, 30, 31:
	default:
		t.Errorf("%s: unexpected format version %d", name, pf.Version)
	}
	// The filename encodes the executable; the decoded header must agree.
	if base, _, ok := prefetchExecutable(name); ok && !strings.EqualFold(base, pf.Executable) {
		t.Errorf("%s: header names the executable %q", name, pf.Executable)
	}
	if len(pf.Filenames) == 0 || len(pf.Volumes) == 0 {
		t.Errorf("%s: %d referenced files, %d volumes", name, len(pf.Filenames), len(pf.Volumes))
	}
	for _, f := range pf.Filenames {
		if !strings.HasPrefix(f, `\`) {
			t.Errorf("%s: referenced file %q is not an NT path", name, f)
			break
		}
	}
	t.Logf("%s: v%d runs=%d files=%d volumes=%d image=%q (%d -> %d bytes)",
		name, pf.Version, pf.RunCount, len(pf.Filenames), len(pf.Volumes), pf.ImagePath, len(raw), len(body))
	return true
}
