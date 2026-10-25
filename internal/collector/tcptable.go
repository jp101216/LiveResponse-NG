package collector

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
)

// Decoding for the owner-PID TCP tables returned by GetExtendedTcpTable.
//
// This file has no build tag on purpose: the parsers work on plain byte
// slices, so they're unit-tested on any OS even though only Windows produces
// the tables. Decoding with encoding/binary instead of casting the buffer to
// structs also means a short or corrupt table returns an error instead of an
// out-of-bounds read. (Every Windows architecture Go targets is little-endian.)

// tcpConn is one decoded row from either the IPv4 or IPv6 table.
type tcpConn struct {
	Family string // "ipv4" or "ipv6"
	State  uint32 // MIB_TCP_STATE
	Local  netip.AddrPort
	Remote netip.AddrPort
	PID    uint32
}

const (
	tcp4RowSize = 24 // MIB_TCPROW_OWNER_PID: 6 DWORDs
	tcp6RowSize = 56 // MIB_TCP6ROW_OWNER_PID: 2x(16-byte addr + scope + port) + state + pid
	tableHeader = 4  // DWORD dwNumEntries; rows follow (4-byte aligned)

	tcpStateListen   = 2
	tcpStateTimeWait = 11
)

var tcpStateNames = [...]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
	5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT",
	9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

func tcpStateName(s uint32) string {
	if int(s) < len(tcpStateNames) && tcpStateNames[s] != "" {
		return tcpStateNames[s]
	}
	return "UNKNOWN(" + strconv.FormatUint(uint64(s), 10) + ")"
}

var le = binary.LittleEndian

// tableRows validates the entry count in a table header against the buffer
// length, so a bogus count can never drive reads past the end.
func tableRows(buf []byte, rowSize int) (int, error) {
	if len(buf) < tableHeader {
		return 0, fmt.Errorf("tcp table: %d-byte buffer is shorter than the header", len(buf))
	}
	n := uint64(le.Uint32(buf))
	if need := uint64(tableHeader) + n*uint64(rowSize); need > uint64(len(buf)) {
		return 0, fmt.Errorf("tcp table: header claims %d rows (%d bytes) but buffer holds %d bytes",
			n, need, len(buf))
	}
	return int(n), nil
}

// netPort decodes a port stored in network byte order in the low two bytes of
// a DWORD.
func netPort(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// parseTCP4Table decodes a MIB_TCPTABLE_OWNER_PID buffer.
func parseTCP4Table(buf []byte) ([]tcpConn, error) {
	n, err := tableRows(buf, tcp4RowSize)
	if err != nil {
		return nil, err
	}
	out := make([]tcpConn, n)
	for i := range out {
		r := buf[tableHeader+i*tcp4RowSize : tableHeader+(i+1)*tcp4RowSize]
		out[i] = tcpConn{
			Family: "ipv4",
			State:  le.Uint32(r[0:4]),
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), netPort(r[8:12])),
			Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), netPort(r[16:20])),
			PID:    le.Uint32(r[20:24]),
		}
	}
	return out, nil
}

// parseTCP6Table decodes a MIB_TCP6TABLE_OWNER_PID buffer.
func parseTCP6Table(buf []byte) ([]tcpConn, error) {
	n, err := tableRows(buf, tcp6RowSize)
	if err != nil {
		return nil, err
	}
	out := make([]tcpConn, n)
	for i := range out {
		r := buf[tableHeader+i*tcp6RowSize : tableHeader+(i+1)*tcp6RowSize]
		out[i] = tcpConn{
			Family: "ipv6",
			Local:  netip.AddrPortFrom(addr6(r[0:16], le.Uint32(r[16:20])), netPort(r[20:24])),
			Remote: netip.AddrPortFrom(addr6(r[24:40], le.Uint32(r[40:44])), netPort(r[44:48])),
			State:  le.Uint32(r[48:52]),
			PID:    le.Uint32(r[52:56]),
		}
	}
	return out, nil
}

// addr6 builds an IPv6 address, unmapping IPv4-mapped addresses (dual-stack
// sockets) so they compare equal to the same IPv4 address elsewhere, and
// keeping a non-zero scope ID as the zone of link-local addresses.
func addr6(b []byte, scope uint32) netip.Addr {
	a := netip.AddrFrom16([16]byte(b))
	if a.Is4In6() {
		return a.Unmap()
	}
	if scope != 0 && (a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast()) {
		a = a.WithZone(strconv.FormatUint(uint64(scope), 10))
	}
	return a
}
