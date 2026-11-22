//go:build linux

package watch

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestLinuxSourceLive records this host for a few seconds while the test
// connects, sends datagrams, asks a DNS question and starts a process, and
// checks each comes back attributed. It needs root.
func TestLinuxSourceLive(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if testing.Short() {
		t.Skip("records for several seconds")
	}
	var host netip.Addr
	for _, a := range localAddrs() {
		if a.Is4() && routableAddr(a) {
			host = a
			break
		}
	}
	if !host.IsValid() {
		t.Skip("no routable local IPv4 address to talk to")
	}
	ln, err := net.Listen("tcp", netip.AddrPortFrom(host, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	sink, err := net.ListenPacket("udp4", netip.AddrPortFrom(host, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	var raw bytes.Buffer
	var mu sync.Mutex
	done := make(chan *Recording, 1)
	go func() {
		rec, err := Record(context.Background(), RecordOptions{Duration: 4 * time.Second, Raw: lockedWriter{&raw, &mu}})
		if err != nil {
			t.Error(err)
		}
		done <- rec
	}()
	time.Sleep(time.Second)

	const hold = 30 * time.Millisecond
	tcpTo := netip.MustParseAddrPort(ln.Addr().String())
	// Each socket stays open a little while, as one crossing a real network
	// would: the source names a socket's process while the socket is open.
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", tcpTo.String())
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(hold)
		c.Close()
	}
	udpTo := netip.MustParseAddrPort(sink.LocalAddr().String())
	u, err := net.Dial("udp", udpTo.String())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = u.Write([]byte("check-in"))
	}
	time.Sleep(hold)
	u.Close()
	d, err := net.Dial("udp", netip.AddrPortFrom(host, 53).String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = d.Write(wireQuery(0x4242, "lrng-live-test.example.com", 16))
	time.Sleep(hold)
	d.Close()
	// A process start is matched by PID and by the image the kernel names:
	// where sleep is a link to a multi-call binary, that binary.
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	sleepImage, err := filepath.EvalSymlinks(sleepPath)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(sleepPath, "0.2")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	childPID := uint32(child.Process.Pid)
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}

	rec := <-done
	if rec == nil {
		t.FailNow()
	}
	mu.Lock()
	s, err := ReadStream(&raw)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	self := uint32(os.Getpid())
	var tcp, udp, dns, spawn int
	for _, e := range s.Events {
		switch {
		case e.Kind == TCPConnect && e.Remote == tcpTo:
			if e.PID != self {
				t.Errorf("connect attributed to PID %d, want %d", e.PID, self)
			}
			tcp++
		case e.Kind == UDPSend && e.Remote == udpTo:
			if e.PID != self || e.Bytes != 8 {
				t.Errorf("datagram: %+v", e)
			}
			udp++
		case e.Kind == DNS && e.Query == "lrng-live-test.example.com":
			if e.PID != self || e.QType != 16 || e.Status != dnsTimeoutStatus {
				t.Errorf("lookup: %+v", e)
			}
			dns++
		case e.Kind == ProcStart && e.PID == childPID:
			if e.Image != sleepImage || e.PPID != self || !strings.Contains(e.CmdLine, "0.2") {
				t.Errorf("process start: %+v, want image %s", e, sleepImage)
			}
			spawn++
		}
	}
	if tcp != 3 || udp != 3 || dns != 1 || spawn != 1 {
		t.Errorf("tcp %d udp %d dns %d spawn %d; meta %v errors %v", tcp, udp, dns, spawn, rec.Window.Meta, rec.Window.Errors)
	}
	t.Logf("meta: %v", rec.Window.Meta)
	if rec.Window.Meta["socket_lookup"] != "sock_diag" {
		t.Logf("socket lookup fell back: %v", rec.Window.Errors)
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// TestLinuxDiagFindsOwnSockets checks both sock_diag lookups against
// sockets this test opens.
func TestLinuxDiagFindsOwnSockets(t *testing.T) {
	d, err := openDiag()
	if err != nil {
		t.Skipf("sock_diag: %v", err)
	}
	defer d.close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local, remote := netip.MustParseAddrPort(c.LocalAddr().String()), netip.MustParseAddrPort(c.RemoteAddr().String())
	ino, err := d.lookup(ipProtoTCP, local, remote)
	if err != nil || ino == 0 {
		t.Fatalf("tcp: %d %v", ino, err)
	}
	if got := ownInode(t, c.(*net.TCPConn)); got != ino {
		t.Errorf("tcp inode %d, the fd says %d", ino, got)
	}
	u, err := net.Dial("udp4", "127.0.0.1:9") // connected
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") // unconnected
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, s := range []struct {
		name          string
		conn          syscall.Conn
		local, remote netip.AddrPort
	}{
		{"connected udp", u.(*net.UDPConn), netip.MustParseAddrPort(u.LocalAddr().String()), netip.MustParseAddrPort("127.0.0.1:9")},
		{"unconnected udp", pc.(*net.UDPConn), netip.MustParseAddrPort(pc.LocalAddr().String()), netip.MustParseAddrPort("192.0.2.9:53")},
	} {
		ino, err := d.lookup(ipProtoUDP, s.local, s.remote)
		if err != nil || ino == 0 {
			t.Errorf("%s: %d %v", s.name, ino, err)
		} else if got := ownInode(t, s.conn); got != ino {
			t.Errorf("%s: inode %d, the fd says %d", s.name, ino, got)
		}
	}
	if ino, err := d.lookup(ipProtoTCP, netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2")); err != nil || ino != 0 {
		t.Errorf("no such socket: %d %v", ino, err)
	}
}

// ownInode reads the socket inode behind one of this process's connections.
func ownInode(t *testing.T, c syscall.Conn) uint32 {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ino uint32
	_ = rc.Control(func(fd uintptr) {
		l, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
		if err == nil {
			ino, _ = socketInode(l)
		}
	})
	return ino
}
