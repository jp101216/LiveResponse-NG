package watch

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// packet is a captured packet's headers, read from the network layer on
// (Linux's cooked packet sockets drop the link layer).
type packet struct {
	proto    uint8 // 6 TCP, 17 UDP
	src, dst netip.AddrPort
	syn, ack bool
	size     int    // UDP payload length, from the header (the capture may be shorter)
	payload  []byte // as much of the UDP payload as was captured
}

const (
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// parsePacket reads an IPv4 or IPv6 header and the TCP or UDP header after
// it. Fragments after the first and IPv6 extension headers are skipped:
// they carry no ports.
func parsePacket(b []byte) (packet, bool) {
	var p packet
	if len(b) < 1 {
		return p, false
	}
	var l4 int
	var src, dst netip.Addr
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, false
		}
		if binary.BigEndian.Uint16(b[6:])&0x1fff != 0 {
			return p, false // a later fragment
		}
		p.proto = b[9]
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		l4 = ihl
	case 6:
		if len(b) < 40 {
			return p, false
		}
		p.proto = b[6]
		src = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		l4 = 40
	default:
		return p, false
	}
	switch p.proto {
	case ipProtoTCP:
		if len(b) < l4+14 {
			return p, false
		}
		flags := b[l4+13]
		p.syn, p.ack = flags&0x02 != 0, flags&0x10 != 0
	case ipProtoUDP:
		if len(b) < l4+8 {
			return p, false
		}
		if n := int(binary.BigEndian.Uint16(b[l4+4:])) - 8; n > 0 {
			p.size = n
		}
		p.payload = b[l4+8:]
	default:
		return p, false
	}
	p.src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[l4:]))
	p.dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[l4+2:]))
	return p, true
}

// dnsMessage is what watch mode needs from a DNS query or response.
type dnsMessage struct {
	id       uint16
	response bool
	rcode    uint8
	name     string
	qtype    uint16
	answers  []string // A and AAAA addresses
}

const (
	maxDNSAnswers = 64
	maxNameJumps  = 16
)

// parseDNS reads a DNS message's header, first question and address answers.
func parseDNS(b []byte) (dnsMessage, bool) {
	var m dnsMessage
	if len(b) < 12 {
		return m, false
	}
	m.id = binary.BigEndian.Uint16(b)
	flags := binary.BigEndian.Uint16(b[2:])
	m.response = flags&0x8000 != 0
	m.rcode = uint8(flags & 0x000f)
	qd := binary.BigEndian.Uint16(b[4:])
	an := binary.BigEndian.Uint16(b[6:])
	if qd == 0 {
		return m, false
	}
	name, off, ok := dnsName(b, 12)
	if !ok || off+4 > len(b) {
		return m, false
	}
	m.name = name
	m.qtype = binary.BigEndian.Uint16(b[off:])
	off += 4
	for q := 1; q < int(qd); q++ { // further questions (rare): skip
		if _, off, ok = dnsName(b, off); !ok || off+4 > len(b) {
			return m, true
		}
		off += 4
	}
	for i := 0; i < int(an) && len(m.answers) < maxDNSAnswers; i++ {
		if _, off, ok = dnsName(b, off); !ok || off+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[off:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			break
		}
		switch {
		case typ == 1 && rdlen == 4:
			m.answers = append(m.answers, netip.AddrFrom4([4]byte(b[off:off+4])).String())
		case typ == 28 && rdlen == 16:
			m.answers = append(m.answers, netip.AddrFrom16([16]byte(b[off:off+16])).Unmap().String())
		}
		off += rdlen
	}
	return m, true
}

// dnsName reads a possibly compressed name at off; it returns the offset
// after the name as it appears there.
func dnsName(b []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	jumps := 0
	total := 0
	for {
		if off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) || jumps >= maxNameJumps {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:]) & 0x3fff)
			jumps++
		case l&0xc0 != 0:
			return "", 0, false
		default:
			if off+1+l > len(b) {
				return "", 0, false
			}
			total += l + 1
			if total > 255 {
				return "", 0, false
			}
			labels = append(labels, strings.ToLower(string(b[off+1:off+1+l])))
			off += 1 + l
		}
	}
}

// dnsStatus maps a DNS response code to the status Windows reports for it,
// so periodic failed lookups read the same on both systems.
func dnsStatus(rcode uint8) uint32 {
	switch rcode {
	case 0:
		return 0
	case 3:
		return 9003 // DNS_ERROR_RCODE_NAME_ERROR
	}
	return 9000 + uint32(rcode)
}

// dnsTimeoutStatus is a lookup no answer came back for (ERROR_TIMEOUT).
const dnsTimeoutStatus = 1460
