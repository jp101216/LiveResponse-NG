package collector

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// procnet.go — parsers for /proc/net/{tcp,tcp6,udp,udp6}. No build tag: they
// work on plain text so they're unit-tested on any OS (like tcptable.go for the
// Windows tables). The kernel prints addresses as hex in CPU byte order, so the
// decoding here is the counterpart to GetExtendedTcpTable's binary rows.

// procNetRow is one decoded socket line from /proc/net/{tcp,udp}{,6}.
type procNetRow struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8  // raw Linux TCP state code (meaningless for UDP)
	Inode  uint64 // socket inode, for mapping to the owning PID
	UID    int
}

// parseProcNet decodes a /proc/net/tcp|udp table (v6 selects the 16-byte
// address layout). The header line and malformed rows are skipped.
func parseProcNet(data []byte, v6 bool) ([]procNetRow, error) {
	var out []procNetRow
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if i == 0 && f[0] == "sl" {
			continue // header
		}
		local, err := parseHexAddrPort(f[1], v6)
		if err != nil {
			continue
		}
		remote, err := parseHexAddrPort(f[2], v6)
		if err != nil {
			continue
		}
		st, err := strconv.ParseUint(f[3], 16, 8)
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, procNetRow{
			Local:  local,
			Remote: remote,
			State:  uint8(st),
			Inode:  inode,
			UID:    uid,
		})
	}
	return out, nil
}

// parseHexAddrPort decodes an "ADDR:PORT" field. The port is big-endian hex; the
// address is a hex of the raw bytes in CPU (little-endian) order, so each 32-bit
// word's bytes are reversed to recover the on-wire address.
func parseHexAddrPort(s string, v6 bool) (netip.AddrPort, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("no port in %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", portHex, err)
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("addr %q: %w", host, err)
	}
	var addr netip.Addr
	if v6 {
		if len(raw) != 16 {
			return netip.AddrPort{}, fmt.Errorf("ipv6 addr %q is %d bytes", host, len(raw))
		}
		var b [16]byte
		for w := 0; w < 4; w++ { // four little-endian 32-bit words
			word := raw[w*4 : w*4+4]
			b[w*4+0], b[w*4+1], b[w*4+2], b[w*4+3] = word[3], word[2], word[1], word[0]
		}
		addr = netip.AddrFrom16(b).Unmap()
	} else {
		if len(raw) != 4 {
			return netip.AddrPort{}, fmt.Errorf("ipv4 addr %q is %d bytes", host, len(raw))
		}
		addr = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// linuxTCPStateNames maps the Linux TCP state codes to the canonical names the
// shared network heuristics expect (LISTEN / ESTABLISHED / SYN_SENT / ...).
// These codes differ from the Windows MIB_TCP_STATE values.
var linuxTCPStateNames = map[uint8]string{
	0x01: "ESTABLISHED", 0x02: "SYN_SENT", 0x03: "SYN_RCVD", 0x04: "FIN_WAIT1",
	0x05: "FIN_WAIT2", 0x06: "TIME_WAIT", 0x07: "CLOSED", 0x08: "CLOSE_WAIT",
	0x09: "LAST_ACK", 0x0A: "LISTEN", 0x0B: "CLOSING", 0x0C: "SYN_RCVD",
}

func linuxTCPStateName(code uint8) string {
	if n, ok := linuxTCPStateNames[code]; ok {
		return n
	}
	return "UNKNOWN(" + strconv.FormatUint(uint64(code), 10) + ")"
}
