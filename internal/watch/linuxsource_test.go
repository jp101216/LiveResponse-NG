package watch

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Tests of the Linux source's pieces that need no kernel: the socket
// filter (run by a small classic-BPF interpreter), the packet, DNS, netlink
// and procfs parsers, and the tracker's attribution.

// runBPF interprets the instructions captureFilter uses, with the kernel's
// rule that a load past the packet's end drops it.
func runBPF(t *testing.T, prog []bpfInsn, pkt []byte, proto uint16, pkttype uint32) uint32 {
	t.Helper()
	var a, x uint32
	var mem [16]uint32
	load := func(off uint32, size int) (uint32, bool) {
		if int(off)+size > len(pkt) {
			return 0, false
		}
		switch size {
		case 4:
			return binary.BigEndian.Uint32(pkt[off:]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(pkt[off:])), true
		}
		return uint32(pkt[off]), true
	}
	sizes := map[uint16]int{bpfLdWAbs: 4, bpfLdHAbs: 2, bpfLdBAbs: 1, bpfLdHInd: 2, bpfLdBInd: 1}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs, bpfLdHAbs, bpfLdBAbs:
			switch in.K {
			case skfProtocol:
				a = uint32(proto)
				continue
			case skfPkttype:
				a = pkttype
				continue
			}
			v, ok := load(in.K, sizes[in.Code])
			if !ok {
				return 0
			}
			a = v
		case bpfLdHInd, bpfLdBInd:
			v, ok := load(x+in.K, sizes[in.Code])
			if !ok {
				return 0
			}
			a = v
		case bpfLdxMsh:
			if int(in.K) >= len(pkt) {
				return 0
			}
			x = 4 * uint32(pkt[in.K]&0xf)
		case bpfLdMem:
			a = mem[in.K]
		case bpfSt:
			mem[in.K] = a
		case bpfAndK:
			a &= in.K
		case bpfJeqK:
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJsetK:
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("instruction %d: opcode %#x", pc, in.Code)
		}
	}
	t.Fatal("the program ran off its end")
	return 0
}

func ip4(proto byte, src, dst string, l4 []byte) []byte {
	b := make([]byte, 20, 20+len(l4))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(l4)))
	b[8], b[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	return append(b, l4...)
}

func ip6(next byte, src, dst string, l4 []byte) []byte {
	b := make([]byte, 40, 40+len(l4))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(l4)))
	b[6], b[7] = next, 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	return append(b, l4...)
}

const (
	tcpSYN = 0x02
	tcpACK = 0x10
)

func tcpHdr(sport, dport uint16, flags byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12], b[13] = 5<<4, flags
	return b
}

func udpHdr(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(b, sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
	return append(b, payload...)
}

func wireQuery(id uint16, name string, qtype uint16) []byte {
	b := []byte{byte(id >> 8), byte(id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}

// wireAnswer answers wireQuery with address records whose names point back
// at the question (compression), after a CNAME record to skip.
func wireAnswer(id uint16, name string, qtype uint16, rcode byte, addrs ...string) []byte {
	b := wireQuery(id, name, qtype)
	b[2], b[3] = 0x81, 0x80|rcode
	binary.BigEndian.PutUint16(b[6:], uint16(len(addrs)+1))
	b = append(b, 0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12) // CNAME -> the question
	for _, s := range addrs {
		ip := netip.MustParseAddr(s)
		b = append(b, 0xc0, 12)
		if ip.Is4() {
			v := ip.As4()
			b = append(b, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			b = append(b, v[:]...)
		} else {
			v := ip.As16()
			b = append(b, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
			b = append(b, v[:]...)
		}
	}
	return b
}

func TestCaptureFilter(t *testing.T) {
	prog := captureFilter()
	if len(prog) > 4096 {
		t.Fatalf("%d instructions", len(prog))
	}
	withOptions := ip4(6, "10.0.0.5", "203.0.113.9", tcpHdr(40000, 443, tcpSYN))
	withOptions = append(withOptions[:20], append([]byte{1, 1, 1, 1}, withOptions[20:]...)...)
	withOptions[0] = 0x46
	fragment := ip4(17, "10.0.0.5", "203.0.113.9", udpHdr(5000, 53, wireQuery(1, "a.example.com", 1)))
	binary.BigEndian.PutUint16(fragment[6:], 0x0010)
	query := wireQuery(7, "c2.example.com", 16)
	for _, c := range []struct {
		name    string
		pkt     []byte
		proto   uint16
		pkttype uint32
		want    uint32
	}{
		{"outgoing SYN", ip4(6, "10.0.0.5", "203.0.113.9", tcpHdr(40000, 443, tcpSYN)), etherIPv4, pktOutgoing, snapHeaders},
		{"outgoing SYN, IP options", withOptions, etherIPv4, pktOutgoing, snapHeaders},
		{"incoming SYN", ip4(6, "203.0.113.9", "10.0.0.5", tcpHdr(443, 40000, tcpSYN)), etherIPv4, 0, 0},
		{"outgoing SYN-ACK", ip4(6, "10.0.0.5", "203.0.113.9", tcpHdr(22, 40000, tcpSYN|tcpACK)), etherIPv4, pktOutgoing, 0},
		{"outgoing data", ip4(6, "10.0.0.5", "203.0.113.9", tcpHdr(40000, 443, tcpACK)), etherIPv4, pktOutgoing, 0},
		{"outgoing QUIC", ip4(17, "10.0.0.5", "203.0.113.9", udpHdr(50000, 443, make([]byte, 1200))), etherIPv4, pktOutgoing, snapHeaders},
		{"outgoing DNS query", ip4(17, "10.0.0.5", "203.0.113.53", udpHdr(50000, 53, query)), etherIPv4, pktOutgoing, snapDNS},
		{"incoming DNS answer", ip4(17, "203.0.113.53", "10.0.0.5", udpHdr(53, 50000, query)), etherIPv4, 0, snapDNS},
		{"incoming other UDP", ip4(17, "203.0.113.9", "10.0.0.5", udpHdr(443, 50000, nil)), etherIPv4, 0, 0},
		{"later fragment", fragment, etherIPv4, pktOutgoing, 0},
		{"ICMP", ip4(1, "10.0.0.5", "203.0.113.9", make([]byte, 8)), etherIPv4, pktOutgoing, 0},
		{"ARP", make([]byte, 28), 0x0806, pktOutgoing, 0},
		{"EtherType says IPv4, version 6", ip6(6, "2001:db8::5", "2001:db8::9", tcpHdr(40000, 443, tcpSYN)), etherIPv4, pktOutgoing, 0},
		{"truncated", ip4(6, "10.0.0.5", "203.0.113.9", nil), etherIPv4, pktOutgoing, 0},
		{"IPv6 outgoing SYN", ip6(6, "2001:db8::5", "2001:db8::9", tcpHdr(40000, 443, tcpSYN)), etherIPv6, pktOutgoing, snapHeaders},
		{"IPv6 incoming SYN", ip6(6, "2001:db8::9", "2001:db8::5", tcpHdr(443, 40000, tcpSYN)), etherIPv6, 0, 0},
		{"IPv6 outgoing UDP", ip6(17, "2001:db8::5", "2001:db8::9", udpHdr(50000, 443, nil)), etherIPv6, pktOutgoing, snapHeaders},
		{"IPv6 DNS query", ip6(17, "2001:db8::5", "2001:db8::53", udpHdr(50000, 53, query)), etherIPv6, pktOutgoing, snapDNS},
		{"IPv6 DNS answer", ip6(17, "2001:db8::53", "2001:db8::5", udpHdr(53, 50000, query)), etherIPv6, 0, snapDNS},
		{"IPv6 extension header", ip6(0, "2001:db8::5", "2001:db8::9", make([]byte, 40)), etherIPv6, pktOutgoing, 0},
	} {
		if got := runBPF(t, prog, c.pkt, c.proto, c.pkttype); got != c.want {
			t.Errorf("%s: kept %d bytes, want %d", c.name, got, c.want)
		}
	}
}

func TestBuildBPFRejectsBadJumps(t *testing.T) {
	if _, err := buildBPF([]bpfStep{jeq(1, "nowhere", "")}); err == nil {
		t.Error("a jump to a missing label")
	}
	if _, err := buildBPF([]bpfStep{label("back", ins(bpfRetK, 0)), jeq(1, "back", "")}); err == nil {
		t.Error("a backward jump")
	}
}

func TestParsePacket(t *testing.T) {
	p, ok := parsePacket(ip4(6, "10.0.0.5", "203.0.113.9", tcpHdr(40000, 443, tcpSYN)))
	if !ok || p.proto != ipProtoTCP || !p.syn || p.ack || p.src.String() != "10.0.0.5:40000" || p.dst.String() != "203.0.113.9:443" {
		t.Errorf("tcp: %+v %v", p, ok)
	}
	p, ok = parsePacket(ip6(17, "2001:db8::5", "2001:db8::9", udpHdr(50000, 443, make([]byte, 1200)))[:96])
	if !ok || p.proto != ipProtoUDP || p.size != 1200 || len(p.payload) != 96-48 || p.dst.String() != "[2001:db8::9]:443" {
		t.Errorf("udp6, captured short: %+v %v", p, ok)
	}
	p, ok = parsePacket(ip6(17, "::ffff:10.0.0.5", "::ffff:203.0.113.9", udpHdr(1, 2, nil)))
	if !ok || !p.src.Addr().Is4() {
		t.Errorf("a mapped address stays IPv4: %+v", p)
	}
	for name, b := range map[string][]byte{
		"empty":     nil,
		"version 5": {0x50, 0, 0, 0},
		"short ihl": append([]byte{0x44}, make([]byte, 30)...),
		"short tcp": ip4(6, "10.0.0.5", "203.0.113.9", make([]byte, 10)),
		"icmp":      ip4(1, "10.0.0.5", "203.0.113.9", make([]byte, 8)),
	} {
		if _, ok := parsePacket(b); ok {
			t.Errorf("%s parsed", name)
		}
	}
}

func TestParseDNS(t *testing.T) {
	m, ok := parseDNS(wireQuery(0x1234, "Beacon.Example.COM", 65))
	if !ok || m.response || m.id != 0x1234 || m.name != "beacon.example.com" || m.qtype != 65 || len(m.answers) != 0 {
		t.Errorf("query: %+v %v", m, ok)
	}
	m, ok = parseDNS(wireAnswer(0x1234, "cdn.example.com", 1, 0, "203.0.113.7", "2001:db8::7"))
	if !ok || !m.response || m.rcode != 0 || fmt.Sprint(m.answers) != "[203.0.113.7 2001:db8::7]" {
		t.Errorf("answer: %+v %v", m, ok)
	}
	if m, _ := parseDNS(wireAnswer(9, "nx.example.com", 1, 3)); m.rcode != 3 || dnsStatus(m.rcode) != 9003 {
		t.Errorf("NXDOMAIN: %+v", m)
	}
	short := wireAnswer(1, "cdn.example.com", 1, 0, "203.0.113.7", "203.0.113.8")
	if m, ok := parseDNS(short[:len(short)-2]); !ok || len(m.answers) != 1 {
		t.Errorf("a truncated answer keeps what fits: %+v %v", m, ok)
	}
	loop := []byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}
	if _, ok := parseDNS(loop); ok {
		t.Error("a name pointing at itself parsed")
	}
	long := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, strings.Repeat("a", 63)...)
	}
	if _, ok := parseDNS(append(long, 0, 0, 1, 0, 1)); ok {
		t.Error("a name over 255 bytes parsed")
	}
	if _, ok := parseDNS([]byte{0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Error("no question parsed")
	}
}

func nlmsg(typ uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, nlmsgHdrLen, nlmsgHdrLen+len(payload)+3)
	ne.PutUint32(b, uint32(nlmsgHdrLen+len(payload)))
	ne.PutUint16(b[4:], typ)
	ne.PutUint32(b[8:], seq)
	b = append(b, payload...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func procMsg(what uint32, data ...uint32) []byte {
	ev := make([]byte, 16+4*len(data))
	ne.PutUint32(ev, what)
	for i, d := range data {
		ne.PutUint32(ev[16+4*i:], d)
	}
	cn := make([]byte, cnMsgLen)
	ne.PutUint32(cn, cnIdxProc)
	ne.PutUint32(cn[4:], cnValProc)
	ne.PutUint16(cn[16:], uint16(len(ev)))
	return nlmsg(nlmsgDone, 0, append(cn, ev...))
}

func TestParseProcEvents(t *testing.T) {
	var b []byte
	b = append(b, procMsg(procEventNone, 0)...)
	b = append(b, procMsg(procEventFork, 100, 100, 200, 200)...)
	b = append(b, procMsg(procEventFork, 100, 100, 201, 200)...) // a thread
	b = append(b, procMsg(procEventExec, 200, 200)...)
	b = append(b, procMsg(procEventExit, 200, 200, 0, 17)...)
	b = append(b, procMsg(0x40, 1, 1)...) // an event watch mode ignores
	b = append(b, nlmsg(nlmsgError, 0, []byte{0, 0, 0, 0})...)
	got := parseProcEvents(b)
	want := []procEvent{
		{what: procEventNone},
		{what: procEventFork, pid: 200, tgid: 200, ptgid: 100},
		{what: procEventFork, pid: 201, tgid: 200, ptgid: 100},
		{what: procEventExec, pid: 200, tgid: 200},
		{what: procEventExit, pid: 200, tgid: 200},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	bad := procMsg(procEventExec, 5, 5)
	ne.PutUint32(bad, 4096) // claims more than it has
	if got := parseProcEvents(bad); len(got) != 0 {
		t.Errorf("an overlong message: %v", got)
	}
	if got := parseProcEvents(procMsg(procEventFork, 1)); len(got) != 0 {
		t.Errorf("a short fork: %v", got)
	}
	ack := procConnMessage(procCnMcastListen)
	if len(ack) != 40 || ne.Uint32(ack) != 40 || ne.Uint32(ack[16:]) != cnIdxProc || ne.Uint16(ack[32:]) != 4 || ne.Uint32(ack[36:]) != procCnMcastListen {
		t.Errorf("listen message % x", ack)
	}
}

func TestDiagRequestAndReply(t *testing.T) {
	local, remote := netip.MustParseAddrPort("10.0.0.5:40000"), netip.MustParseAddrPort("203.0.113.9:443")
	r := diagRequest(7, ipProtoTCP, local, remote, false)
	if len(r) != 72 || ne.Uint16(r[4:]) != sockDiagByFamily || ne.Uint16(r[6:]) != nlmFRequest || ne.Uint32(r[8:]) != 7 {
		t.Fatalf("header % x", r[:16])
	}
	req := r[nlmsgHdrLen:]
	if req[0] != afInet || req[1] != ipProtoTCP || ne.Uint32(req[4:]) != 0xffffffff ||
		binary.BigEndian.Uint16(req[8:]) != 40000 || binary.BigEndian.Uint16(req[10:]) != 443 ||
		netip.AddrFrom4([4]byte(req[12:16])) != local.Addr() || netip.AddrFrom4([4]byte(req[28:32])) != remote.Addr() ||
		ne.Uint32(req[48:]) != 0xffffffff || ne.Uint32(req[52:]) != 0xffffffff {
		t.Errorf("request % x", req)
	}
	r6 := diagRequest(8, ipProtoUDP, netip.MustParseAddrPort("[2001:db8::9]:53"), netip.MustParseAddrPort("[2001:db8::5]:5353"), false)
	if r6[nlmsgHdrLen] != afInet6 || netip.AddrFrom16([16]byte(r6[nlmsgHdrLen+12:nlmsgHdrLen+28])).String() != "2001:db8::9" {
		t.Errorf("IPv6 request % x", r6)
	}
	probe := diagRequest(9, ipProtoUDP, netip.AddrPort{}, netip.AddrPort{}, true)
	if ne.Uint16(probe[6:]) != nlmFRequest|nlmFDump || ne.Uint32(probe[nlmsgHdrLen+4:]) != 0 {
		t.Errorf("probe % x", probe)
	}

	reply := func(sport uint16, inode uint32) []byte {
		m := make([]byte, inetDiagMsgLen)
		m[0] = afInet
		binary.BigEndian.PutUint16(m[4:], sport)
		ne.PutUint32(m[68:], inode)
		return m
	}
	errMsg := func(errno int32) []byte {
		b := make([]byte, 20)
		ne.PutUint32(b, uint32(-errno))
		return b
	}
	for _, c := range []struct {
		name  string
		b     []byte
		ino   uint32
		done  bool
		errno int
	}{
		{"found", nlmsg(sockDiagByFamily, 7, reply(40000, 555)), 555, true, 0},
		{"another port", nlmsg(sockDiagByFamily, 7, reply(53, 555)), 0, true, 0},
		{"not found", nlmsg(nlmsgError, 7, errMsg(2)), 0, true, errnoENOENT},
		{"other error", nlmsg(nlmsgError, 7, errMsg(22)), 0, true, 22},
		{"stale, then ours", append(nlmsg(sockDiagByFamily, 6, reply(40000, 1)), nlmsg(sockDiagByFamily, 7, reply(40000, 2))...), 2, true, 0},
		{"only stale", nlmsg(sockDiagByFamily, 6, reply(40000, 1)), 0, false, 0},
		{"dump done", nlmsg(nlmsgDone, 7, []byte{0, 0, 0, 0}), 0, true, 0},
		{"short", nlmsg(sockDiagByFamily, 7, make([]byte, 10)), 0, true, -1},
	} {
		ino, done, errno := parseDiagReply(c.b, 7, 40000)
		if ino != c.ino || done != c.done || errno != c.errno {
			t.Errorf("%s: %d %v %d", c.name, ino, done, errno)
		}
	}
}

// procNetHex writes an address the way /proc/net/tcp prints it.
func procNetHex(ap netip.AddrPort) string {
	var raw []byte
	if a := ap.Addr(); a.Is4() {
		v := a.As4()
		raw = v[:]
	} else {
		v := a.As16()
		raw = v[:]
	}
	var sb strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&sb, "%08X", ne.Uint32(raw[i:]))
	}
	return fmt.Sprintf("%s:%04X", sb.String(), ap.Port())
}

func TestProcNetInode(t *testing.T) {
	row := func(n int, local, remote string, inode int) string {
		return fmt.Sprintf("%4d: %s %s 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 20 4 30 10 -1",
			n, procNetHex(netip.MustParseAddrPort(local)), procNetHex(netip.MustParseAddrPort(remote)), inode)
	}
	tcp := strings.Join([]string{
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
		row(0, "10.0.0.5:40000", "203.0.113.1:443", 111),
		row(1, "10.0.0.5:40000", "203.0.113.9:443", 222),
		"garbage line",
	}, "\n")
	if got := procNetInode([]byte(tcp), true, netip.MustParseAddrPort("10.0.0.5:40000"), netip.MustParseAddrPort("203.0.113.9:443")); got != 222 {
		t.Errorf("tcp: %d", got)
	}
	udp6 := row(0, "[::]:5353", "[::]:0", 333) + "\n" + row(1, "[::ffff:10.0.0.5]:6000", "[::ffff:203.0.113.53]:53", 444)
	if got := procNetInode([]byte(udp6), false, netip.MustParseAddrPort("10.0.0.5:5353"), netip.MustParseAddrPort("203.0.113.53:53")); got != 333 {
		t.Errorf("unconnected udp: %d", got)
	}
	if got := procNetInode([]byte(udp6), false, netip.MustParseAddrPort("10.0.0.5:6000"), netip.MustParseAddrPort("203.0.113.53:53")); got != 444 {
		t.Errorf("connected udp6, mapped: %d", got)
	}
	if got := procNetInode([]byte(udp6), false, netip.MustParseAddrPort("10.0.0.5:6000"), netip.MustParseAddrPort("203.0.113.54:53")); got != 0 {
		t.Errorf("connected elsewhere: %d", got)
	}
}

func TestProcHelpers(t *testing.T) {
	if n, ok := socketInode("socket:[12345]"); !ok || n != 12345 {
		t.Errorf("socket: %d %v", n, ok)
	}
	for _, l := range []string{"pipe:[1]", "socket:[x]", "socket:[0]", "/dev/null", "socket:[1"} {
		if _, ok := socketInode(l); ok {
			t.Errorf("%q read as a socket", l)
		}
	}
	if got := statPPID([]byte("4242 (we(ird) name) S 77 4242 4242 0 -1")); got != 77 {
		t.Errorf("ppid %d", got)
	}
	if got := statPPID([]byte("garbage")); got != 0 {
		t.Errorf("garbage ppid %d", got)
	}
}

// fakeOwners plays the kernel for the tracker.
type fakeOwners struct {
	inodes    map[sockKey]uint32
	quick     map[uint32]uint32 // inode -> pid a fast lookup finds
	scans     int
	learnedN  map[uint32]int
	described map[uint32]bool
}

func newFake() *fakeOwners {
	return &fakeOwners{inodes: map[sockKey]uint32{}, quick: map[uint32]uint32{}, learnedN: map[uint32]int{}, described: map[uint32]bool{}}
}

func (f *fakeOwners) inode(proto uint8, l, r netip.AddrPort) uint32 {
	return f.inodes[sockKey{proto, l, r}]
}
func (f *fakeOwners) fast(inode uint32) (uint32, bool) {
	p, ok := f.quick[inode]
	return p, ok
}
func (f *fakeOwners) learned(pid uint32) { f.learnedN[pid]++ }
func (f *fakeOwners) requestScan()       { f.scans++ }
func (f *fakeOwners) describe(pid uint32, t time.Time) (Event, bool) {
	if f.described[pid] {
		return Event{}, false
	}
	f.described[pid] = true
	return Event{Time: t, Kind: ProcSeen, PID: pid, Image: fmt.Sprintf("/opt/p%d", pid)}, true
}

type collected struct{ evs []Event }

func (c *collected) add(e Event) { c.evs = append(c.evs, e) }

func (c *collected) of(k Kind) []Event {
	var out []Event
	for _, e := range c.evs {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func TestTrackerAttribution(t *testing.T) {
	f := newFake()
	var out collected
	tr := newTracker(f, out.add, []netip.Addr{netip.MustParseAddr("10.0.0.5")})
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	syn := func(sport uint16, dst string) []byte {
		ap := netip.MustParseAddrPort(dst)
		return ip4(6, "10.0.0.5", ap.Addr().String(), tcpHdr(sport, ap.Port(), tcpSYN))
	}
	key := func(proto uint8, l, r string) sockKey {
		return sockKey{proto, netip.MustParseAddrPort(l), netip.MustParseAddrPort(r)}
	}

	// Found at once, then from the cache for a retransmitted SYN.
	f.inodes[key(6, "10.0.0.5:40000", "203.0.113.9:443")] = 10
	f.quick[10] = 500
	tr.packet(syn(40000, "203.0.113.9:443"), t0, true)
	tr.packet(syn(40000, "203.0.113.9:443"), t0.Add(time.Second), true)
	// An inbound SYN and a connection to loopback are not this host's check-ins.
	tr.packet(ip4(6, "203.0.113.9", "10.0.0.5", tcpHdr(443, 40001, tcpSYN)), t0, false)
	tr.packet(ip4(6, "127.0.0.1", "127.0.0.1", tcpHdr(40002, 8080, tcpSYN)), t0, true)
	if c := out.of(TCPConnect); len(c) != 2 || c[0].PID != 500 || c[1].PID != 500 || c[0].Remote.String() != "203.0.113.9:443" {
		t.Fatalf("connects: %+v", c)
	}
	if s := out.of(ProcSeen); len(s) != 1 || s[0].PID != 500 || !out.evs[0].Time.Equal(t0) || out.evs[0].Kind != ProcSeen {
		t.Errorf("the process is named once, before its first event: %+v", out.evs)
	}

	// Waiting for a full scan: one socket's owner is found, another's is gone,
	// and one that arrived after the scan began waits for the next.
	f.inodes[key(17, "10.0.0.5:50000", "203.0.113.20:443")] = 20
	f.inodes[key(6, "10.0.0.5:40010", "203.0.113.21:443")] = 21
	f.inodes[key(6, "10.0.0.5:40011", "203.0.113.22:443")] = 22
	quic := ip4(17, "10.0.0.5", "203.0.113.20", udpHdr(50000, 443, make([]byte, 1200)))
	tr.packet(quic, t0.Add(2*time.Second), true)
	tr.packet(quic, t0.Add(2*time.Second+time.Millisecond), true) // joins the same wait
	tr.packet(syn(40010, "203.0.113.21:443"), t0.Add(2*time.Second), true)
	tr.packet(syn(40011, "203.0.113.22:443"), t0.Add(4*time.Second), true)
	if f.scans == 0 || tr.waiting() != 4 {
		t.Fatalf("scans %d, waiting %d", f.scans, tr.waiting())
	}
	tr.scanned(func(ino uint32) (uint32, bool) {
		if ino == 20 {
			return 600, true
		}
		return 0, false
	}, t0.Add(3*time.Second))
	if tr.waiting() != 1 {
		t.Errorf("waiting %d after the scan", tr.waiting())
	}
	udp := out.of(UDPSend)
	if len(udp) != 2 || udp[0].PID != 600 || udp[0].Bytes != 1200 || !udp[0].Time.Equal(t0.Add(2*time.Second)) {
		t.Errorf("datagrams keep their own times: %+v", udp)
	}
	tr.packet(quic, t0.Add(5*time.Second), true)
	if udp := out.of(UDPSend); len(udp) != 3 || udp[2].PID != 600 {
		t.Errorf("the scan's answer is cached: %+v", udp)
	}
	tr.scanned(func(ino uint32) (uint32, bool) { return 0, false }, t0.Add(5*time.Second))
	c := out.of(TCPConnect)
	if len(c) != 4 || c[2].PID != 0 || c[3].PID != 0 {
		t.Errorf("owners gone: %+v", c)
	}

	// A socket already closed is unattributed at once.
	tr.packet(syn(40020, "203.0.113.30:443"), t0.Add(6*time.Second), true)
	st := tr.stats()
	if st["unattributed_events"] != 3 || st["unattributed_owner_exited"] != 2 || st["unattributed_no_socket"] != 1 ||
		st["attributed_socket_scan_fast"] != 1 || st["attributed_cached"] != 2 || st["attributed_socket_scan_full"] != 2 {
		t.Errorf("stats %v", st)
	}
}

func TestTrackerDNS(t *testing.T) {
	f := newFake()
	var out collected
	tr := newTracker(f, out.add, []netip.Addr{netip.MustParseAddr("10.0.0.5")})
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	stub := "127.0.0.53"

	// A program asks the local stub; the stub forwards upstream; both answer.
	f.inodes[sockKey{17, netip.MustParseAddrPort("127.0.0.1:41000"), netip.MustParseAddrPort(stub + ":53")}] = 30
	f.quick[30] = 700
	ask := ip4(17, "127.0.0.1", stub, udpHdr(41000, 53, wireQuery(0x1111, "c2.example.com", 1)))
	tr.packet(ask, t0, true)
	tr.packet(ask, t0.Add(time.Second), true) // a retry
	fwd := ip4(17, "10.0.0.5", "203.0.113.53", udpHdr(42000, 53, wireQuery(0x2222, "C2.example.com", 1)))
	tr.packet(fwd, t0.Add(time.Millisecond), true)
	tr.packet(ip4(17, "203.0.113.53", "10.0.0.5", udpHdr(53, 42000, wireAnswer(0x2222, "c2.example.com", 1, 0, "198.51.100.7"))), t0.Add(20*time.Millisecond), false)
	tr.packet(ip4(17, stub, "127.0.0.1", udpHdr(53, 41000, wireAnswer(0x1111, "c2.example.com", 1, 0, "198.51.100.7"))), t0.Add(21*time.Millisecond), false)
	d := out.of(DNS)
	if len(d) != 1 || d[0].PID != 700 || d[0].Query != "c2.example.com" || d[0].Status != 0 || fmt.Sprint(d[0].Answers) != "[198.51.100.7]" || !d[0].Time.Equal(t0) {
		t.Fatalf("lookups: %+v", d)
	}
	if len(out.of(UDPSend)) != 0 || tr.stats()["dns_forwarded"] != 1 {
		t.Errorf("the forward is neither a lookup nor a flow: %+v %v", out.evs, tr.stats())
	}

	// A direct query to an outside resolver is a flow as well as a lookup;
	// unanswered, it times out.
	f.inodes[sockKey{17, netip.MustParseAddrPort("10.0.0.5:43000"), netip.MustParseAddrPort("203.0.113.99:53")}] = 31
	f.quick[31] = 701
	tr.packet(ip4(17, "10.0.0.5", "203.0.113.99", udpHdr(43000, 53, wireQuery(0x3333, "x1.tunnel.example.net", 16))), t0.Add(time.Second), true)
	if u := out.of(UDPSend); len(u) != 1 || u[0].PID != 701 {
		t.Errorf("direct DNS flow: %+v", u)
	}
	tr.tick(t0.Add(3 * time.Second))
	if len(out.of(DNS)) != 1 {
		t.Error("timed out too early")
	}
	tr.tick(t0.Add(7 * time.Second))
	if d := out.of(DNS); len(d) != 2 || d[1].PID != 701 || d[1].Status != dnsTimeoutStatus || d[1].QType != 16 {
		t.Errorf("unanswered: %+v", d)
	}

	// A lookup whose socket was already gone is named by the connection
	// that follows to its answer; one nobody connects to stays unattributed.
	for i, name := range []string{"cdn.example.org", "idle.example.org"} {
		id := uint16(0x4000 + i)
		port := uint16(44000 + i)
		tr.packet(ip4(17, "127.0.0.1", stub, udpHdr(port, 53, wireQuery(id, name, 1))), t0.Add(10*time.Second), true)
		tr.packet(ip4(17, stub, "127.0.0.1", udpHdr(53, port, wireAnswer(id, name, 1, 0, fmt.Sprintf("198.51.100.%d", 50+i)))), t0.Add(10*time.Second), false)
	}
	f.inodes[sockKey{6, netip.MustParseAddrPort("10.0.0.5:45000"), netip.MustParseAddrPort("198.51.100.50:443")}] = 32
	f.quick[32] = 702
	tr.packet(ip4(6, "10.0.0.5", "198.51.100.50", tcpHdr(45000, 443, tcpSYN)), t0.Add(10*time.Second+50*time.Millisecond), true)
	d = out.of(DNS)
	if len(d) != 3 || d[2].Query != "cdn.example.org" || d[2].PID != 702 {
		t.Fatalf("claimed by its connection: %+v", d)
	}
	tr.tick(t0.Add(15 * time.Second))
	if len(out.of(DNS)) != 3 {
		t.Error("released before the claim window ended")
	}
	tr.tick(t0.Add(21 * time.Second))
	if d := out.of(DNS); len(d) != 4 || d[3].Query != "idle.example.org" || d[3].PID != 0 {
		t.Errorf("unclaimed: %+v", d)
	}

	// The window closing settles what is still open.
	f.inodes[sockKey{17, netip.MustParseAddrPort("10.0.0.5:46000"), netip.MustParseAddrPort("203.0.113.99:53")}] = 33
	tr.packet(ip4(17, "10.0.0.5", "203.0.113.99", udpHdr(46000, 53, wireQuery(0x5555, "last.example.net", 1))), t0.Add(30*time.Second), true)
	tr.flush(t0.Add(31 * time.Second))
	d = out.of(DNS)
	if len(d) != 5 || d[4].Query != "last.example.net" || d[4].PID != 0 || d[4].Status != dnsTimeoutStatus {
		t.Errorf("flushed: %+v", d)
	}
	if tr.waiting() != 0 || len(tr.queries) != 0 || tr.norphans != 0 {
		t.Errorf("left over: waiting %d, queries %d, orphans %d", tr.waiting(), len(tr.queries), tr.norphans)
	}
}

// The tracker's stream scores like any other: a beacon from short-lived
// processes (a new PID per check-in) is one program's beacon.
func TestTrackerBeaconFromShortLivedProcesses(t *testing.T) {
	f := newFake()
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	agg := NewAggregator(t0, Limits{})
	tr := newTracker(f, agg.Add, nil)
	for i := 0; i < 12; i++ {
		at := t0.Add(time.Duration(i)*time.Minute + time.Duration(i%3)*time.Second)
		pid := uint32(1000 + i)
		agg.Add(Event{Time: at.Add(-50 * time.Millisecond), Kind: ProcStart, PID: pid, PPID: 1, Image: "/usr/bin/curl", CmdLine: "curl http://203.0.113.80/beacon"})
		f.described[pid] = true
		sport := uint16(41000 + i)
		f.inodes[sockKey{6, netip.MustParseAddrPort(fmt.Sprintf("10.0.0.5:%d", sport)), netip.MustParseAddrPort("203.0.113.80:80")}] = uint32(100 + i)
		f.quick[uint32(100+i)] = pid
		tr.packet(ip4(6, "10.0.0.5", "203.0.113.80", tcpHdr(sport, 80, tcpSYN)), at, true)
	}
	tr.flush(t0.Add(12 * time.Minute))
	agg.Close(t0.Add(12 * time.Minute))
	res := Analyze(agg, Window{Source: "netlink"}, Options{})
	var found bool
	for _, r := range res.Records {
		for _, fd := range r.Findings {
			if fd.Rule == RuleBeacon && r.Fields["image_path"] == "/usr/bin/curl" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no beacon: %+v", res.Records)
	}
}

func TestScanBudget(t *testing.T) {
	t0 := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	b := newScanBudget(0.05, 250*time.Millisecond, t0)
	// A burst: back-to-back 50 ms scans until the quarter second is spent.
	now, n := t0, 0
	for b.ready(now) && n < 100 {
		b.spend(50*time.Millisecond, now)
		n++
	}
	if n != 5 {
		t.Errorf("a burst ran %d scans, want 5", n)
	}
	// Spent, it waits for a refill at 5% of wall time (50 ms of scanning a
	// second); any refill lets the next scan start, which then repays it.
	if b.ready(now) {
		t.Error("ready with nothing left")
	}
	if !b.ready(now.Add(500 * time.Millisecond)) {
		t.Error("not ready after half a second")
	}
	b.spend(50*time.Millisecond, now.Add(500*time.Millisecond))
	if b.ready(now.Add(900 * time.Millisecond)) {
		t.Error("an overdrawn budget let a scan start before repaying")
	}
	if !b.ready(now.Add(1100 * time.Millisecond)) {
		t.Error("not ready once repaid")
	}
	// Under constant demand, scanning stays near 5% of the time.
	b = newScanBudget(0.05, 250*time.Millisecond, t0)
	var spent time.Duration
	for now = t0; now.Before(t0.Add(time.Minute)); now = now.Add(10 * time.Millisecond) {
		if b.ready(now) {
			b.spend(20*time.Millisecond, now)
			spent += 20 * time.Millisecond
		}
	}
	if share := spent.Seconds() / 60; share > 0.06 || share < 0.04 {
		t.Errorf("scanned %.1f%% of a minute", 100*share)
	}
	// The budget never banks more than its burst.
	b = newScanBudget(0.05, 250*time.Millisecond, t0)
	b.ready(t0.Add(time.Hour))
	if b.tokens != 250*time.Millisecond {
		t.Errorf("banked %v", b.tokens)
	}
}
