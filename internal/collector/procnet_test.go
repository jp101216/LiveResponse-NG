package collector

import (
	"net/netip"
	"testing"
)

func TestParseHexAddrPortV4(t *testing.T) {
	// 0100007F:0035 -> 127.0.0.1:53 (address bytes are little-endian).
	ap, err := parseHexAddrPort("0100007F:0035", false)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Addr() != netip.MustParseAddr("127.0.0.1") || ap.Port() != 53 {
		t.Errorf("got %v, want 127.0.0.1:53", ap)
	}
	// 0.0.0.0:22 (a wildcard listener).
	ap, _ = parseHexAddrPort("00000000:0016", false)
	if ap.Addr() != netip.MustParseAddr("0.0.0.0") || ap.Port() != 22 {
		t.Errorf("got %v, want 0.0.0.0:22", ap)
	}
}

func TestParseHexAddrPortV6(t *testing.T) {
	// IPv6 loopback ::1 is the 16th byte set; per-word little-endian layout.
	ap, err := parseHexAddrPort("00000000000000000000000001000000:1F90", true)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Addr() != netip.MustParseAddr("::1") || ap.Port() != 8080 {
		t.Errorf("got %v, want [::1]:8080", ap)
	}
}

func TestParseProcNetTCP(t *testing.T) {
	data := []byte(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
			"   1: 0100007F:1F40 0200A8C0:D431 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 20 4 30 10 -1\n")
	rows, err := parseProcNet(data, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Row 0: a LISTEN on 127.0.0.1:53, inode 12345.
	if rows[0].State != 0x0A || linuxTCPStateName(rows[0].State) != "LISTEN" {
		t.Errorf("row0 state = %d (%s)", rows[0].State, linuxTCPStateName(rows[0].State))
	}
	if rows[0].Inode != 12345 || rows[0].Local.Port() != 53 {
		t.Errorf("row0 = %+v", rows[0])
	}
	// Row 1: ESTABLISHED to 192.168.0.2:54321, uid 1000, inode 67890.
	if linuxTCPStateName(rows[1].State) != "ESTABLISHED" {
		t.Errorf("row1 state = %s", linuxTCPStateName(rows[1].State))
	}
	if rows[1].Remote.Addr() != netip.MustParseAddr("192.168.0.2") || rows[1].Remote.Port() != 54321 {
		t.Errorf("row1 remote = %v", rows[1].Remote)
	}
	if rows[1].UID != 1000 || rows[1].Inode != 67890 {
		t.Errorf("row1 uid/inode = %d/%d", rows[1].UID, rows[1].Inode)
	}
}

func TestParseProcNetSkipsJunk(t *testing.T) {
	data := []byte("sl local_address rem_address st\nnot enough fields\n")
	rows, _ := parseProcNet(data, false)
	if len(rows) != 0 {
		t.Errorf("expected no rows, got %d", len(rows))
	}
}

func TestLinuxTCPStateNames(t *testing.T) {
	for code, want := range map[uint8]string{0x01: "ESTABLISHED", 0x02: "SYN_SENT", 0x0A: "LISTEN", 0x06: "TIME_WAIT"} {
		if got := linuxTCPStateName(code); got != want {
			t.Errorf("state %d = %q, want %q", code, got, want)
		}
	}
	if linuxTCPStateName(0xFF) == "" {
		t.Error("unknown state should produce a non-empty label")
	}
}
