package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// ---- dispatcher -------------------------------------------------------

type fakeCollector struct {
	name string
	fn   func(ctx context.Context) (Result, error)
}

func (f fakeCollector) Name() string                                { return f.name }
func (f fakeCollector) Platforms() []string                         { return []string{"all"} }
func (f fakeCollector) Collect(ctx context.Context) (Result, error) { return f.fn(ctx) }

func ok(name string) fakeCollector {
	return fakeCollector{name, func(context.Context) (Result, error) {
		r := NewResult(name)
		r.Add(map[string]any{"k": name})
		return r.Finish(), nil
	}}
}

func TestDispatcherKeepsOrder(t *testing.T) {
	var cs []Collector
	for _, n := range []string{"c", "a", "e", "b", "d"} {
		cs = append(cs, ok(n))
	}
	res := (&Dispatcher{Workers: 3}).Run(context.Background(), cs)
	for i, r := range res {
		if r.Collector != cs[i].Name() {
			t.Fatalf("slot %d = %s, want %s", i, r.Collector, cs[i].Name())
		}
	}
}

func TestDispatcherContainsPanic(t *testing.T) {
	boom := fakeCollector{"boom", func(context.Context) (Result, error) { panic("bad sample") }}
	res := (&Dispatcher{}).Run(context.Background(), []Collector{boom, ok("fine")})
	if len(res[0].Errors) == 0 || !strings.Contains(res[0].Errors[0], "bad sample") {
		t.Fatalf("panic not reported: %+v", res[0])
	}
	if res[0].Records == nil {
		t.Fatal("records must be [] not null")
	}
	if len(res[1].Records) != 1 {
		t.Fatal("healthy collector lost its results")
	}
}

func TestDispatcherAbandonsHungCollector(t *testing.T) {
	hung := fakeCollector{"hung", func(context.Context) (Result, error) {
		time.Sleep(5 * time.Second) // ignores ctx, like a blocking syscall
		return Result{}, nil
	}}
	start := time.Now()
	res := (&Dispatcher{Timeout: 50 * time.Millisecond, Grace: 50 * time.Millisecond}).
		Run(context.Background(), []Collector{hung, ok("fine")})
	if took := time.Since(start); took > time.Second {
		t.Fatalf("run waited %s for a hung collector", took)
	}
	if len(res[0].Errors) == 0 || !strings.Contains(res[0].Errors[0], "abandoned") {
		t.Fatalf("hung collector not reported: %+v", res[0])
	}
	if len(res[1].Records) != 1 {
		t.Fatal("healthy collector lost its results")
	}
}

func TestDispatcherKeepsPartialResultsOnTimeout(t *testing.T) {
	polite := fakeCollector{"polite", func(ctx context.Context) (Result, error) {
		r := NewResult("polite")
		r.Add(map[string]any{"n": 1})
		<-ctx.Done()
		r.Fail("cancelled: " + ctx.Err().Error())
		return r.Finish(), nil
	}}
	res := (&Dispatcher{Timeout: 30 * time.Millisecond}).Run(context.Background(), []Collector{polite})
	if len(res[0].Records) != 1 || len(res[0].Errors) != 1 {
		t.Fatalf("partial results lost: %+v", res[0])
	}
}

// ---- TCP table parsing ------------------------------------------------

func tcp4Row(state uint32, local [4]byte, lport uint16, remote [4]byte, rport uint16, pid uint32) []byte {
	b := make([]byte, tcp4RowSize)
	binary.LittleEndian.PutUint32(b[0:], state)
	copy(b[4:8], local[:])
	b[8], b[9] = byte(lport>>8), byte(lport)
	copy(b[12:16], remote[:])
	b[16], b[17] = byte(rport>>8), byte(rport)
	binary.LittleEndian.PutUint32(b[20:], pid)
	return b
}

func table(rows ...[]byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(rows)))
	for _, r := range rows {
		buf.Write(r)
	}
	return buf.Bytes()
}

func TestParseTCP4Table(t *testing.T) {
	buf := table(
		tcp4Row(5, [4]byte{10, 0, 0, 5}, 49832, [4]byte{203, 0, 113, 10}, 443, 4242),
		tcp4Row(2, [4]byte{0, 0, 0, 0}, 445, [4]byte{}, 0, 4),
	)
	rows, err := parseTCP4Table(buf)
	if err != nil {
		t.Fatal(err)
	}
	want := tcpConn{"ipv4", 5,
		netip.MustParseAddrPort("10.0.0.5:49832"), netip.MustParseAddrPort("203.0.113.10:443"), 4242}
	if len(rows) != 2 || rows[0] != want {
		t.Fatalf("got %+v\nwant %+v", rows[0], want)
	}
	if tcpStateName(rows[1].State) != "LISTEN" || rows[1].Local.Port() != 445 {
		t.Fatalf("row 2: %+v", rows[1])
	}
}

func TestParseTCP6Table(t *testing.T) {
	r := make([]byte, tcp6RowSize)
	local := netip.MustParseAddr("fe80::1").As16()
	remote := netip.MustParseAddr("2001:db8::10").As16()
	copy(r[0:16], local[:])
	binary.LittleEndian.PutUint32(r[16:], 7) // scope id
	r[20], r[21] = 0xC2, 0x6A                // 49770
	copy(r[24:40], remote[:])
	r[44], r[45] = 0x01, 0xBB // 443
	binary.LittleEndian.PutUint32(r[48:], tcpStateTimeWait)
	binary.LittleEndian.PutUint32(r[52:], 0)

	rows, err := parseTCP6Table(table(r))
	if err != nil {
		t.Fatal(err)
	}
	got := rows[0]
	if got.Local.String() != "[fe80::1%7]:49770" || got.Remote.String() != "[2001:db8::10]:443" ||
		tcpStateName(got.State) != "TIME_WAIT" || got.Family != "ipv6" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseRejectsTruncatedTable(t *testing.T) {
	buf := table(tcp4Row(5, [4]byte{1, 2, 3, 4}, 1, [4]byte{5, 6, 7, 8}, 2, 3))
	binary.LittleEndian.PutUint32(buf, 1000) // header lies about the row count
	if _, err := parseTCP4Table(buf); err == nil {
		t.Fatal("expected an error for a header that overstates the rows")
	}
	if _, err := parseTCP6Table([]byte{1, 0}); err == nil {
		t.Fatal("expected an error for a buffer shorter than the header")
	}
	if rows, err := parseTCP4Table(table()); err != nil || len(rows) != 0 {
		t.Fatalf("empty table: %v %v", rows, err)
	}
}

func TestTCPStateNameUnknown(t *testing.T) {
	if got := tcpStateName(99); got != "UNKNOWN(99)" {
		t.Fatal(got)
	}
}

// ---- UNICODE_STRING decoding -----------------------------------------

func TestDecodeUnicodeString(t *testing.T) {
	const ptrSize = int(unsafe.Sizeof(uintptr(0)))
	const base = uintptr(0x10000)
	text := `"C:\Windows\System32\cmd.exe" /c whoami`
	hdr := 2 * ptrSize
	buf := make([]byte, hdr+2*len(text))
	binary.LittleEndian.PutUint16(buf[0:], uint16(2*len(text)))
	binary.LittleEndian.PutUint16(buf[2:], uint16(2*len(text)))
	if ptrSize == 8 {
		binary.LittleEndian.PutUint64(buf[8:], uint64(base)+uint64(hdr))
	} else {
		binary.LittleEndian.PutUint32(buf[4:], uint32(base)+uint32(hdr))
	}
	for i, c := range text {
		binary.LittleEndian.PutUint16(buf[hdr+2*i:], uint16(c))
	}

	got, err := decodeUnicodeString(buf, base)
	if err != nil || got != text {
		t.Fatalf("got %q, %v", got, err)
	}

	// A pointer outside the buffer must be rejected, not followed.
	if _, err := decodeUnicodeString(buf, base+0x1000); err == nil {
		t.Fatal("pointer before buffer accepted")
	}
	binary.LittleEndian.PutUint16(buf[0:], 0xFFFE) // length past the end
	if _, err := decodeUnicodeString(buf, base); err == nil {
		t.Fatal("length past buffer accepted")
	}
}
