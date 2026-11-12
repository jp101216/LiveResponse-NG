//go:build linux

package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHiddenSocketsSkipsBoundInactiveTCP(t *testing.T) {
	s := diagSocket{Proto: "tcp", Family: "ipv4", State: tcpStateClose, Local: "0.0.0.0:40000", Inode: 99}
	if got := hiddenSockets([]diagSocket{s}, []diagSocket{s}, map[string]bool{}); len(got) != 0 {
		t.Fatalf("a bound, unused TCP socket is not hidden: %+v", got)
	}
	u := diagSocket{Proto: "udp", Family: "ipv4", State: tcpStateClose, Local: "0.0.0.0:40001", Inode: 98}
	if got := hiddenSockets([]diagSocket{u}, []diagSocket{u}, map[string]bool{}); len(got) != 1 {
		t.Fatalf("UDP sockets are CLOSE when unconnected and must still be compared: %+v", got)
	}
}

func TestSudoRunAsNonRoot(t *testing.T) {
	rules := parseSudoers("/etc/sudoers.d/web", []byte("deploy ALL=(www-data) NOPASSWD: ALL\nops ALL=(ALL:ALL) NOPASSWD: ALL\n"))
	if len(rules) != 2 {
		t.Fatalf("rules: %+v", rules)
	}
	f, ok := judgeSudoRule(rules[0], nil)
	if !ok || strings.Contains(f.Detail, "as root") || !strings.Contains(f.Detail, "as www-data") || f.Severity != SevNotable {
		t.Fatalf("runas www-data: %+v", f)
	}
	if f, ok := judgeSudoRule(rules[1], nil); !ok || !strings.Contains(f.Detail, "as root") {
		t.Fatalf("runas ALL: %+v", f)
	}
}

func TestKmodEmptyProcModulesIsNotCompared(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"proc/modules":               "",
		"sys/module/btrfs/initstate": "live\n",
		"sys/module/ext4/initstate":  "live\n",
	})
	res := scanKmod(context.Background(), root)
	if n := len(recordsBy(res)["hidden_module"]); n != 0 {
		t.Fatalf("an empty /proc/modules called %d modules hidden", n)
	}
}

func TestReadRegularDoesNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), ".bashrc")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan []byte, 1)
	go func() { done <- readFileSafe(fifo) }()
	select {
	case b := <-done:
		if b != nil {
			t.Fatalf("a FIFO read returned %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	if r := hashFile(context.Background(), fifo, 0); r.Err == "" {
		t.Fatal("a FIFO must not be hashed")
	}
	_ = os.Remove(fifo)
}
