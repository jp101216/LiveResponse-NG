package watch

import "fmt"

// A classic BPF program for Linux's cooked packet socket, where a packet
// starts at its IP header. It keeps, headers only: outbound TCP SYNs (a
// connection starting), outbound UDP datagrams (check-ins, including QUIC),
// and DNS queries and answers with enough payload to read the names.
// Everything else (inbound TCP, data segments, other UDP) never leaves the
// kernel.

// bpfInsn mirrors struct sock_filter.
type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// Opcodes used here.
const (
	bpfLdWAbs   = 0x20 // A = word at [k]
	bpfLdHAbs   = 0x28 // A = half at [k]
	bpfLdBAbs   = 0x30 // A = byte at [k]
	bpfLdHInd   = 0x48 // A = half at [x+k]
	bpfLdBInd   = 0x50 // A = byte at [x+k]
	bpfLdxMsh   = 0xb1 // X = 4*([k]&0xf)
	bpfLdMem    = 0x60 // A = M[k]
	bpfSt       = 0x02 // M[k] = A
	bpfAndK     = 0x54 // A &= k
	bpfJeqK     = 0x15
	bpfJsetK    = 0x45
	bpfRetK     = 0x06
	skfProtocol = 0xfffff000 // SKF_AD_OFF + SKF_AD_PROTOCOL: the EtherType, host order
	skfPkttype  = 0xfffff004 // SKF_AD_OFF + SKF_AD_PKTTYPE
	pktOutgoing = 4          // PACKET_OUTGOING
	etherIPv4   = 0x0800
	etherIPv6   = 0x86dd
	// snapHeaders keeps an IPv4 or IPv6 header, the TCP or UDP header and a
	// little payload; snapDNS a DNS message as large as EDNS usually allows.
	snapHeaders = 96
	snapDNS     = 4096
)

type bpfStep struct {
	insn  bpfInsn
	label string // this step's label, if jumped to
	jt    string // jump targets by label ("" = next)
	jf    string
}

// buildBPF assembles steps, turning label jumps into relative offsets.
func buildBPF(steps []bpfStep) ([]bpfInsn, error) {
	at := map[string]int{}
	for i, s := range steps {
		if s.label != "" {
			at[s.label] = i
		}
	}
	out := make([]bpfInsn, len(steps))
	for i, s := range steps {
		in := s.insn
		rel := func(l string) (uint8, error) {
			if l == "" {
				return 0, nil
			}
			j, ok := at[l]
			if !ok || j <= i || j-i-1 > 255 {
				return 0, fmt.Errorf("bpf: bad jump from %d to %q", i, l)
			}
			return uint8(j - i - 1), nil
		}
		var err error
		if in.Jt, err = rel(s.jt); err != nil {
			return nil, err
		}
		if in.Jf, err = rel(s.jf); err != nil {
			return nil, err
		}
		out[i] = in
	}
	return out, nil
}

func ins(code uint16, k uint32) bpfStep { return bpfStep{insn: bpfInsn{Code: code, K: k}} }

func jeq(k uint32, jt, jf string) bpfStep {
	return bpfStep{insn: bpfInsn{Code: bpfJeqK, K: k}, jt: jt, jf: jf}
}

func jset(k uint32, jt, jf string) bpfStep {
	return bpfStep{insn: bpfInsn{Code: bpfJsetK, K: k}, jt: jt, jf: jf}
}

func label(l string, s bpfStep) bpfStep { s.label = l; return s }

// captureFilter is the program the Linux source attaches.
func captureFilter() []bpfInsn {
	p, err := buildBPF([]bpfStep{
		ins(bpfLdWAbs, skfPkttype),
		ins(bpfSt, 0), // M[0] = pkttype
		ins(bpfLdWAbs, skfProtocol),
		jeq(etherIPv4, "", "isv6"),
		ins(bpfLdBAbs, 0),
		ins(bpfAndK, 0xf0),
		jeq(0x40, "", "drop"),

		// IPv4
		ins(bpfLdBAbs, 9),
		jeq(ipProtoTCP, "", "u4"),
		ins(bpfLdHAbs, 6),
		jset(0x1fff, "drop", ""), // a later fragment
		ins(bpfLdxMsh, 0),
		ins(bpfLdBInd, 13), // TCP flags
		ins(bpfAndK, 0x12), // SYN|ACK
		jeq(0x02, "", "drop"),
		ins(bpfLdMem, 0),
		jeq(pktOutgoing, "small", "drop"),
		label("u4", jeq(ipProtoUDP, "", "drop")),
		ins(bpfLdHAbs, 6),
		jset(0x1fff, "drop", ""),
		ins(bpfLdxMsh, 0),
		ins(bpfLdMem, 0),
		jeq(pktOutgoing, "", "in4"),
		ins(bpfLdHInd, 2), // destination port
		jeq(53, "dns", "small"),
		label("in4", ins(bpfLdHInd, 0)), // source port
		jeq(53, "dns", "drop"),

		// IPv6, without extension headers
		label("isv6", jeq(etherIPv6, "", "drop")),
		ins(bpfLdBAbs, 0),
		ins(bpfAndK, 0xf0),
		jeq(0x60, "", "drop"),
		ins(bpfLdBAbs, 6),
		jeq(ipProtoTCP, "", "u6"),
		ins(bpfLdBAbs, 40+13),
		ins(bpfAndK, 0x12),
		jeq(0x02, "", "drop"),
		ins(bpfLdMem, 0),
		jeq(pktOutgoing, "small", "drop"),
		label("u6", jeq(ipProtoUDP, "", "drop")),
		ins(bpfLdMem, 0),
		jeq(pktOutgoing, "", "in6"),
		ins(bpfLdHAbs, 42),
		jeq(53, "dns", "small"),
		label("in6", ins(bpfLdHAbs, 40)),
		jeq(53, "dns", "drop"),

		label("small", ins(bpfRetK, snapHeaders)),
		label("dns", ins(bpfRetK, snapDNS)),
		label("drop", ins(bpfRetK, 0)),
	})
	if err != nil {
		panic(err) // a static program: a mistake here is a build bug
	}
	return p
}
