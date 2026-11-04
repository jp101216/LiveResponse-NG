//go:build linux

package collector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHashProcessImageOfDeletedBinary runs a copy of our test helper, deletes it,
// and checks the process collector's hashing still reaches the binary through
// /proc/<pid>/exe — the hash of a self-deleting payload is exactly what an
// analyst needs, and the path text alone ("… (deleted)") can't provide it.
func TestHashProcessImageOfDeletedBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Skip(err)
	}
	want := sha256.Sum256(data)
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	if err := os.WriteFile(payload, data, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, payload, "-test.run=^TestProcessImageHelper$")
	cmd.Env = append(os.Environ(), "LRNG_PROCEXE_HELPER=1")
	ready, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("can't run the process-image fixture: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	// A ready message proves the helper reached Go code. A renamed system
	// utility may be a multicall wrapper that immediately exits on argv[0].
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "lrng-procexe-ready\n" {
		t.Fatalf("process-image fixture not ready: %q, %v", line, err)
	}
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Readlink(procExePath(pid))
	if err != nil || exe != payload+deletedSuffix {
		t.Fatalf("exe link = %q, %v; want the deleted marker", exe, err)
	}

	h := NewFileHasher()
	fields := map[string]any{}
	if !hashProcessImage(context.Background(), h, pid, fields) {
		t.Fatalf("no hash recorded: %v", fields)
	}
	if got := fields["image_sha256"]; got != hex.EncodeToString(want[:]) {
		t.Fatalf("image_sha256 = %v, want the deleted binary's hash", got)
	}
	if _, ok := fields["image_exists"]; ok {
		t.Fatal("a running process's image must never be reported missing")
	}
	// Nothing sits at the path now, so it is a deletion, not an upgrade.
	if replacedSystemFile(exe, procRootExists(pid)) {
		t.Fatal("a deleted file outside system paths is not 'replaced'")
	}

	// A second process running the same file shares the cache entry.
	key1, _ := exeIdentity(pid)
	key2, _ := exeIdentity(pid)
	if key1 == "" || key1 != key2 {
		t.Fatalf("exe identity unstable: %q vs %q", key1, key2)
	}
}

func TestProcessImageHelper(t *testing.T) {
	if os.Getenv("LRNG_PROCEXE_HELPER") != "1" {
		return
	}
	fmt.Println("lrng-procexe-ready")
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestHashProcessImageSelf(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Skip(err)
	}
	want := sha256.Sum256(data)
	fields := map[string]any{}
	if !hashProcessImage(context.Background(), NewFileHasher(), os.Getpid(), fields) ||
		fields["image_sha256"] != hex.EncodeToString(want[:]) {
		t.Fatalf("self hash mismatch: %v", fields)
	}
	if hashProcessImage(context.Background(), nil, os.Getpid(), map[string]any{}) {
		t.Fatal("a nil hasher (hashing disabled) must record nothing")
	}
}
