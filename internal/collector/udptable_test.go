package collector

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func udp4Row(local [4]byte, lport uint16, pid uint32) []byte {
	b := make([]byte, udp4RowSize)
	copy(b[0:4], local[:])
	b[4], b[5] = byte(lport>>8), byte(lport) // network byte order in low two bytes
	binary.LittleEndian.PutUint32(b[8:], pid)
	return b
}

func TestParseUDP4Table(t *testing.T) {
	buf := table(
		udp4Row([4]byte{0, 0, 0, 0}, 53, 1234),
		udp4Row([4]byte{192, 168, 1, 10}, 137, 4),
	)
	rows, err := parseUDP4Table(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Local.Port() != 53 || rows[0].PID != 1234 || rows[0].Family != "ipv4" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Local.Addr().String() != "192.168.1.10" || rows[1].Local.Port() != 137 {
		t.Errorf("row 1 = %+v", rows[1])
	}
}

func TestParseUDP6Table(t *testing.T) {
	r := make([]byte, udp6RowSize)
	addr := netip.MustParseAddr("fe80::1").As16()
	copy(r[0:16], addr[:])
	binary.LittleEndian.PutUint32(r[16:], 9) // scope id
	r[20], r[21] = 0x00, 0x35                // port 53
	binary.LittleEndian.PutUint32(r[24:], 777)

	rows, err := parseUDP6Table(table(r))
	if err != nil {
		t.Fatal(err)
	}
	got := rows[0]
	if got.Local.String() != "[fe80::1%9]:53" || got.PID != 777 || got.Family != "ipv6" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseUDPRejectsTruncated(t *testing.T) {
	buf := table(udp4Row([4]byte{1, 2, 3, 4}, 1, 2))
	binary.LittleEndian.PutUint32(buf, 500) // header overstates the count
	if _, err := parseUDP4Table(buf); err == nil {
		t.Fatal("expected error for overstated row count")
	}
}
