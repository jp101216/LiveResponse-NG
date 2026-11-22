package watch

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// Wire formats the Linux source reads, kept free of syscalls so they are
// tested on any OS. Netlink structures are in host byte order; addresses and
// ports inside them are in network order.

const (
	nlmsgHdrLen      = 16
	nlmsgError       = 2
	nlmsgDone        = 3
	nlmFRequest      = 0x1
	nlmFDump         = 0x300
	sockDiagByFamily = 20
	afInet           = 2
	afInet6          = 10
	errnoENOENT      = 2

	// The process connector (linux/cn_proc.h).
	cnIdxProc         = 1
	cnValProc         = 1
	cnMsgLen          = 20
	procCnMcastListen = 1
	procCnMcastIgnore = 2
	procEventNone     = 0x0
	procEventFork     = 0x1
	procEventExec     = 0x2
	procEventExit     = 0x80000000

	inetDiagReqLen = 56
	inetDiagMsgLen = 72
)

var ne = binary.NativeEndian

// procConnMessage is a control message to the process connector.
func procConnMessage(op uint32) []byte {
	b := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], nlmsgDone)
	ne.PutUint32(b[8:], 1) // sequence
	ne.PutUint32(b[16:], cnIdxProc)
	ne.PutUint32(b[20:], cnValProc)
	ne.PutUint16(b[32:], 4)
	ne.PutUint32(b[36:], op)
	return b
}

// procEvent is one process connector event: for fork, pid and tgid are the
// child's and ppid the parent's thread group.
type procEvent struct {
	what      uint32
	pid, tgid uint32
	ptgid     uint32
	err       uint32 // the connector's acknowledgement of a control message
}

// parseProcEvents reads the netlink messages of one datagram.
func parseProcEvents(b []byte) []procEvent {
	var out []procEvent
	for len(b) >= nlmsgHdrLen {
		l := int(ne.Uint32(b))
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		typ := ne.Uint16(b[4:])
		msg := b[nlmsgHdrLen:l]
		if a := (l + 3) &^ 3; a <= len(b) {
			b = b[a:]
		} else {
			b = b[len(b):]
		}
		if typ != nlmsgDone || len(msg) < cnMsgLen+16 || ne.Uint32(msg) != cnIdxProc || ne.Uint32(msg[4:]) != cnValProc {
			continue
		}
		dlen := int(ne.Uint16(msg[16:]))
		ev := msg[cnMsgLen:]
		if dlen < len(ev) {
			ev = ev[:dlen]
		}
		if len(ev) < 16 {
			continue
		}
		e := procEvent{what: ne.Uint32(ev)}
		d := ev[16:]
		switch e.what {
		case procEventNone:
			if len(d) >= 4 {
				e.err = ne.Uint32(d)
			}
		case procEventFork:
			if len(d) < 16 {
				continue
			}
			e.ptgid, e.pid, e.tgid = ne.Uint32(d[4:]), ne.Uint32(d[8:]), ne.Uint32(d[12:])
		case procEventExec, procEventExit:
			if len(d) < 8 {
				continue
			}
			e.pid, e.tgid = ne.Uint32(d), ne.Uint32(d[4:])
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}

// diagRequest is a sock_diag request for the socket with src and dst as
// its source and destination, or with dump a probe that lists no sockets.
func diagRequest(seq uint32, proto uint8, src, dst netip.AddrPort, dump bool) []byte {
	b := make([]byte, nlmsgHdrLen+inetDiagReqLen)
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], sockDiagByFamily)
	flags := uint16(nlmFRequest)
	if dump {
		flags |= nlmFDump
	}
	ne.PutUint16(b[6:], flags)
	ne.PutUint32(b[8:], seq)
	r := b[nlmsgHdrLen:]
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	r[0] = afInet
	if (s.IsValid() && !s.Is4()) || (d.IsValid() && !d.Is4()) {
		r[0] = afInet6
	}
	r[1] = proto
	if !dump {
		ne.PutUint32(r[4:], 0xffffffff) // any state
	}
	id := r[8:]
	binary.BigEndian.PutUint16(id[0:], src.Port())
	binary.BigEndian.PutUint16(id[2:], dst.Port())
	put := func(at []byte, a netip.Addr) {
		if !a.IsValid() {
			return
		}
		if r[0] == afInet {
			v := a.As4()
			copy(at, v[:])
		} else {
			v := a.As16()
			copy(at, v[:])
		}
	}
	put(id[4:20], s)
	put(id[20:36], d)
	ne.PutUint32(id[40:], 0xffffffff) // INET_DIAG_NOCOOKIE
	ne.PutUint32(id[44:], 0xffffffff)
	return b
}

// parseDiagReply reads a reply to request seq. done is false when b holds
// only other requests' replies. A socket found on another local port than
// sport (a lookup that matched something else) counts as not found.
func parseDiagReply(b []byte, seq uint32, sport uint16) (inode uint32, done bool, errno int) {
	for len(b) >= nlmsgHdrLen {
		l := int(ne.Uint32(b))
		if l < nlmsgHdrLen || l > len(b) {
			break
		}
		typ, s := ne.Uint16(b[4:]), ne.Uint32(b[8:])
		msg := b[nlmsgHdrLen:l]
		if a := (l + 3) &^ 3; a <= len(b) {
			b = b[a:]
		} else {
			b = b[len(b):]
		}
		if s != seq {
			continue
		}
		switch typ {
		case nlmsgError:
			if len(msg) < 4 {
				return 0, true, -1
			}
			return 0, true, int(-int32(ne.Uint32(msg)))
		case nlmsgDone:
			if len(msg) >= 4 {
				if e := int(-int32(ne.Uint32(msg))); e != 0 {
					return 0, true, e
				}
			}
			return 0, true, 0
		case sockDiagByFamily:
			if len(msg) < inetDiagMsgLen {
				return 0, true, -1
			}
			if binary.BigEndian.Uint16(msg[4:]) != sport {
				return 0, true, 0
			}
			return ne.Uint32(msg[68:]), true, 0
		}
	}
	return 0, false, 0
}

// procNetInode finds a socket's inode in a /proc/net/{tcp,udp}{,6} table:
// TCP by local port and remote end, UDP by local port and, when the socket
// is connected, its remote end.
func procNetInode(table []byte, tcp bool, local, remote netip.AddrPort) uint32 {
	rem := remote.Addr().Unmap()
	for _, line := range bytes.Split(table, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		la, lok := procNetAddr(f[1])
		ra, rok := procNetAddr(f[2])
		if !lok || !rok || la.Port() != local.Port() {
			continue
		}
		if tcp || ra.Port() != 0 {
			if ra.Port() != remote.Port() || ra.Addr().Unmap() != rem {
				continue
			}
		}
		if ino, err := strconv.ParseUint(f[9], 10, 32); err == nil && ino != 0 {
			return uint32(ino)
		}
	}
	return 0
}

// procNetAddr reads ADDR:PORT, the address as the kernel printed its 32-bit
// words in host order.
func procNetAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	var raw [16]byte
	switch len(h) {
	case 8, 32:
	default:
		return netip.AddrPort{}, false
	}
	for i := 0; i*8 < len(h); i++ {
		w, err := strconv.ParseUint(h[i*8:i*8+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		ne.PutUint32(raw[i*4:], uint32(w))
	}
	var a netip.Addr
	if len(h) == 8 {
		a = netip.AddrFrom4([4]byte(raw[:4]))
	} else {
		a = netip.AddrFrom16(raw).Unmap()
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}

// socketInode reads a /proc/<pid>/fd link's "socket:[inode]".
func socketInode(link string) (uint32, bool) {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok || !strings.HasSuffix(rest, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(rest[:len(rest)-1], 10, 32)
	return uint32(n), err == nil && n != 0
}

// statPPID reads the parent PID from /proc/<pid>/stat.
func statPPID(stat []byte) uint32 {
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}
