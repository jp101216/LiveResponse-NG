package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileHasher(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.bin")
	data := []byte(strings.Repeat("lrng", 1<<18)) // 1 MiB, more than one read
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)

	h := NewFileHasher()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // concurrent callers share one read
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := h.Hash(context.Background(), p); r.SHA256 != hex.EncodeToString(want[:]) || r.Size != int64(len(data)) {
				t.Errorf("got %+v", r)
			}
		}()
	}
	wg.Wait()
	if len(h.cache) != 1 {
		t.Fatalf("cache has %d entries", len(h.cache))
	}

	small := &FileHasher{MaxBytes: 1024}
	if r := small.Hash(context.Background(), p); r.SHA256 != "" || !strings.Contains(r.Err, "cap") {
		t.Fatalf("size cap ignored: %+v", r)
	}
	if r := h.Hash(context.Background(), filepath.Join(dir, "missing")); r.Err == "" || !r.NotExist {
		t.Fatalf("missing file: %+v", r)
	}
	gone := map[string]any{}
	h.Fields(context.Background(), gone, "image", filepath.Join(dir, "missing"))
	if gone["image_exists"] != false {
		t.Fatalf("missing target not reported: %v", gone)
	}
	unexpanded := map[string]any{}
	h.Fields(context.Background(), unexpanded, "image", `%TEMP%\x.exe`)
	if len(unexpanded) != 0 {
		t.Fatalf("tried to hash an unexpanded path: %v", unexpanded)
	}
	if r := h.Hash(context.Background(), dir); r.Err != "not a regular file" {
		t.Fatalf("directory: %+v", r)
	}

	var nilHasher *FileHasher // hashing disabled
	f := map[string]any{}
	nilHasher.Fields(context.Background(), f, "image", p)
	if len(f) != 0 || nilHasher.Hash(context.Background(), p) != (HashResult{}) {
		t.Fatal("nil hasher must be a no-op")
	}
	h.Fields(context.Background(), f, "image", p)
	if f["image_sha256"] != hex.EncodeToString(want[:]) {
		t.Fatalf("fields %v", f)
	}
}

func TestFileHasherCancelledIsRetried(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.bin")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewFileHasher()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := h.Hash(ctx, p); r.SHA256 != "" {
		t.Fatalf("hashed despite cancellation: %+v", r)
	}
	if r := h.Hash(context.Background(), p); r.SHA256 == "" {
		t.Fatalf("cancelled result was cached: %+v", r)
	}
}
