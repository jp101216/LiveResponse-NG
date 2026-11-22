//go:build windows

package watch

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/hostinfo"
)

func requireElevated(t *testing.T) {
	t.Helper()
	if ok, err := hostinfo.Elevated(); err != nil || !ok {
		t.Skip("ETW kernel providers need an elevated process")
	}
}

// A live session sees this test's own connections, a lookup and a child
// process, decoded through TDH's schemas into the right fields.
func TestETWSourceDecodesLiveEvents(t *testing.T) {
	requireElevated(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			_, _ = c.Write([]byte("pong"))
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	var raw bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		rec *Recording
		err error
	}
	got := make(chan result, 1)
	go func() {
		rec, err := Record(ctx, RecordOptions{Duration: time.Minute, RunID: "test-" + time.Now().Format("150405.000"), Raw: &raw})
		got <- result{rec, err}
	}()
	time.Sleep(4 * time.Second) // the session needs a moment before events flow
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err == nil {
			_, _ = c.Write([]byte("ping"))
			buf := make([]byte, 4)
			_, _ = c.Read(buf)
			c.Close()
		}
		time.Sleep(300 * time.Millisecond)
	}
	_, lookupErr := net.LookupHost("www.microsoft.com")
	child := exec.Command(os.Getenv("ComSpec"), "/c", "exit", "0")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second) // let the buffers flush (FlushTimer is 1s)
	cancel()
	stopAt := time.Now()
	r := <-got
	if took := time.Since(stopAt); took > 5*time.Second {
		t.Errorf("stopping the session took %s", took)
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	st, err := ReadStream(bytes.NewReader(raw.Bytes()))
	if err != nil {
		t.Fatalf("raw stream: %v", err)
	}
	if !r.rec.Window.Interrupted {
		t.Error("a cancelled window isn't marked interrupted")
	}
	me := uint32(os.Getpid())
	var connects, sends, dns, child0 int
	for _, e := range st.Events {
		switch {
		case e.Kind == TCPConnect && e.PID == me && e.Remote.Port() == port && e.Remote.Addr().String() == "127.0.0.1":
			connects++
		case (e.Kind == TCPSend || e.Kind == TCPRecv) && e.PID == me && e.Remote.Port() == port && e.Bytes == 4:
			sends++
		case e.Kind == DNS && strings.EqualFold(e.Query, "www.microsoft.com"):
			dns++
		case e.Kind == ProcStart && e.PID == uint32(child.Process.Pid):
			if !strings.EqualFold(e.Image, os.Getenv("ComSpec")) {
				t.Errorf("child image = %q, want %q (device path not mapped to a drive?)", e.Image, os.Getenv("ComSpec"))
			}
			child0++
		}
	}
	t.Logf("events %d: connects %d, sends/recvs %d, dns %d, child %d; meta %v; errors %v",
		len(st.Events), connects, sends, dns, child0, r.rec.Window.Meta, r.rec.Window.Errors)
	if connects < 3 {
		t.Errorf("saw %d of 3 TCP connects to 127.0.0.1:%d", connects, port)
	}
	if sends == 0 {
		t.Error("no 4-byte send or receive on the test connection: sizes or ports misdecoded")
	}
	if child0 != 1 {
		t.Error("the child process's start wasn't seen")
	}
	if dns == 0 && lookupErr == nil {
		t.Error("the DNS lookup wasn't seen")
	}
	if n, _ := r.rec.Window.Meta["decode_errors"].(map[string]int64); len(n) > 0 {
		t.Errorf("decode errors: %v %v", n, r.rec.Window.Errors)
	}
	// The session is gone afterwards.
	if _, err := controlTrace(r.rec.Window.Meta["etw_session"].(string), eventTraceControlQuery); err == nil {
		t.Error("the ETW session is still running after the window")
	}
}

// A session left by a crashed run is found and stopped.
func TestStopStaleSessions(t *testing.T) {
	requireElevated(t)
	name := SessionPrefix + "stale-test"
	_, _ = controlTrace(name, eventTraceControlStop)
	props := properties()
	putProps(props)
	namep, _ := syscall.UTF16PtrFromString(name)
	var h uint64
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(&props[0])))
	if r != 0 {
		t.Fatalf("StartTrace: %v", syscall.Errno(r))
	}
	stopped, err := StopStaleSessions()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range stopped {
		found = found || s == name
	}
	if !found {
		_, _ = controlTrace(name, eventTraceControlStop)
		t.Fatalf("stale session not stopped; stopped %v", stopped)
	}
}

func putProps(p []byte) {
	le := func(off int, v uint32) {
		p[off], p[off+1], p[off+2], p[off+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	}
	le(offWnodeClientCtx, 1)
	le(offWnodeFlags, wnodeFlagTracedGUID)
	le(offLogFileMode, eventTraceRealTimeMode)
}

func TestParseDNSResults(t *testing.T) {
	got := parseDNSResults("type:  5 www.example.com.edgekey.net;type:  5 e1.a.akamaiedge.net;::ffff:23.32.1.10;2600:1408::1;")
	if len(got) != 2 || got[0] != "23.32.1.10" || got[1] != "2600:1408::1" {
		t.Fatalf("parseDNSResults = %v", got)
	}
}
