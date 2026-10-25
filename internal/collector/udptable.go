package collector

import "net/netip"

// Decoding for the owner-PID UDP tables returned by GetExtendedUdpTable.
//
// Like tcptable.go this file has no build tag: the parsers work on plain byte
// slices and are unit-tested on any OS, decoding with bounds checks (via the
// shared tableRows helper) so a short or corrupt table returns an error rather
// than reading out of bounds.

// udpConn is one decoded row from either the IPv4 or IPv6 UDP table. UDP has
// no remote peer in the table, so only the local endpoint and owner are known.
type udpConn struct {
	Family string
	Local  netip.AddrPort
	PID    uint32
}

const (
	udp4RowSize = 12 // MIB_UDPROW_OWNER_PID: localaddr, localport, pid
	udp6RowSize = 28 // MIB_UDP6ROW_OWNER_PID: 16-byte addr, scope, localport, pid
)

// parseUDP4Table decodes a MIB_UDPTABLE_OWNER_PID buffer.
func parseUDP4Table(buf []byte) ([]udpConn, error) {
	n, err := tableRows(buf, udp4RowSize)
	if err != nil {
		return nil, err
	}
	out := make([]udpConn, n)
	for i := range out {
		r := buf[tableHeader+i*udp4RowSize : tableHeader+(i+1)*udp4RowSize]
		out[i] = udpConn{
			Family: "ipv4",
			Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[0:4])), netPort(r[4:8])),
			PID:    le.Uint32(r[8:12]),
		}
	}
	return out, nil
}

// parseUDP6Table decodes a MIB_UDP6TABLE_OWNER_PID buffer.
func parseUDP6Table(buf []byte) ([]udpConn, error) {
	n, err := tableRows(buf, udp6RowSize)
	if err != nil {
		return nil, err
	}
	out := make([]udpConn, n)
	for i := range out {
		r := buf[tableHeader+i*udp6RowSize : tableHeader+(i+1)*udp6RowSize]
		out[i] = udpConn{
			Family: "ipv6",
			Local:  netip.AddrPortFrom(addr6(r[0:16], le.Uint32(r[16:20])), netPort(r[20:24])),
			PID:    le.Uint32(r[24:28]),
		}
	}
	return out, nil
}
