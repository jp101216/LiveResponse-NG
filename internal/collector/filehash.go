package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
)

// DefaultHashMaxBytes caps how large a file the hasher will read. Images
// bigger than this (some Electron apps, game binaries) are reported as
// skipped rather than slowing the whole run.
const DefaultHashMaxBytes = 128 << 20

// FileHasher computes SHA-256 of the binaries the collectors report — running
// process images, service and autostart binaries — so an analyst can pivot
// straight to threat intel. One hasher is shared by every collector in a run:
// each distinct path is read at most once however many records name it, and
// concurrent requests for the same file wait for the first.
//
// Hashing reads files, which is a footprint of its own (the README lists it);
// -no-hash turns it off.
type FileHasher struct {
	MaxBytes int64

	mu    sync.Mutex
	cache map[string]*hashEntry
}

type hashEntry struct {
	once sync.Once
	res  HashResult
}

// HashResult is the outcome for one file.
type HashResult struct {
	SHA256   string
	Size     int64
	Err      string // why there's no hash ("" when SHA256 is set)
	NotExist bool   // the file isn't there (a deleted payload is evidence too)
}

// NewFileHasher returns a hasher with the default size cap.
func NewFileHasher() *FileHasher {
	return &FileHasher{MaxBytes: DefaultHashMaxBytes}
}

// Hash returns the SHA-256 of path. A nil hasher (hashing disabled) returns
// an empty result. Results — failures included — are cached per path, except
// a hash interrupted by cancellation, which a later caller may retry.
func (h *FileHasher) Hash(ctx context.Context, path string) HashResult {
	if h == nil || path == "" {
		return HashResult{}
	}
	return h.hashAs(ctx, "path:"+pathKey(path), path)
}

// HashAs hashes the file opened at path but caches the result under key, an
// identity for the file itself rather than for the name it was reached by. The
// Linux process collector uses it to hash /proc/<pid>/exe — the executable the
// process actually runs, even when it is deleted, a memfd, or inside a container
// whose mount namespace gives the same path to a different file — keyed by the
// file's device and inode, so a binary shared by many processes is still read
// once.
func (h *FileHasher) HashAs(ctx context.Context, key, path string) HashResult {
	if h == nil || key == "" || path == "" {
		return HashResult{}
	}
	return h.hashAs(ctx, "id:"+key, path)
}

// pathKey is the cache key for a path: case-folded on Windows, whose file
// system is case-insensitive, and taken verbatim elsewhere, where /tmp/A and
// /tmp/a are two different files.
func pathKey(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

func (h *FileHasher) hashAs(ctx context.Context, key, path string) HashResult {
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]*hashEntry{}
	}
	e, ok := h.cache[key]
	if !ok {
		e = &hashEntry{}
		h.cache[key] = e
	}
	h.mu.Unlock()

	e.once.Do(func() { e.res = hashFile(ctx, path, h.MaxBytes) })
	if e.res.Err == errHashCancelled.Error() {
		h.mu.Lock()
		if h.cache[key] == e {
			delete(h.cache, key) // let a caller with time left try again
		}
		h.mu.Unlock()
	}
	return e.res
}

// Fields adds <prefix>_sha256 to a record's fields ("image" ->
// "image_sha256"), or <prefix>_exists=false when the file is gone, or
// <prefix>_hash_error. Paths that still hold an unexpanded %VARIABLE% (a
// per-user value whose user isn't known) are left alone.
func (h *FileHasher) Fields(ctx context.Context, fields map[string]any, prefix, path string) {
	if h == nil || path == "" || strings.Contains(path, "%") {
		return
	}
	r := h.Hash(ctx, path)
	switch {
	case r.SHA256 != "":
		fields[prefix+"_sha256"] = r.SHA256
	case r.NotExist:
		fields[prefix+"_exists"] = false
	case r.Err != "":
		fields[prefix+"_hash_error"] = r.Err
	}
}

var errHashCancelled = errors.New("hashing cancelled (collector time budget)")

// hashBufPool recycles the 1 MiB read buffers, so hashing hundreds of images
// doesn't allocate (and garbage-collect) a fresh buffer per file.
var hashBufPool = sync.Pool{New: func() any { b := make([]byte, 1<<20); return &b }}

func hashFile(ctx context.Context, path string, max int64) HashResult {
	if max <= 0 {
		max = DefaultHashMaxBytes
	}
	f, err := os.Open(path)
	if err != nil {
		return HashResult{Err: err.Error(), NotExist: errors.Is(err, fs.ErrNotExist)}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return HashResult{Err: err.Error()}
	}
	if !st.Mode().IsRegular() {
		return HashResult{Err: "not a regular file"}
	}
	if st.Size() > max {
		return HashResult{Size: st.Size(), Err: fmt.Sprintf("not hashed: %d bytes exceeds the %d-byte cap", st.Size(), max)}
	}
	sum := sha256.New()
	bp := hashBufPool.Get().(*[]byte)
	defer hashBufPool.Put(bp)
	buf := *bp
	var n int64
	for {
		if ctx.Err() != nil {
			return HashResult{Err: errHashCancelled.Error()}
		}
		k, rerr := f.Read(buf)
		if k > 0 {
			sum.Write(buf[:k])
			n += int64(k)
			if n > max {
				return HashResult{Size: n, Err: "not hashed: file grew past the size cap while being read"}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return HashResult{Err: rerr.Error()}
		}
	}
	return HashResult{SHA256: hex.EncodeToString(sum.Sum(nil)), Size: n}
}
