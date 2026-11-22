// Package watch records a host's process, connection and DNS activity for a
// window of time and scores it for beaconing: check-ins that are too regular
// to be a person, a periodic DNS lookup, a tunnel's burst of unique
// subdomains, or the same command started on a timer.
//
// Only the first stage depends on the platform. A source (ETW on Windows)
// turns what the kernel reports into normalized Events; from there an
// Aggregator keeps bounded per-flow history, and Analyze scores it after the
// window closes. A saved event stream (-watch-raw) replays through the same
// Aggregator, so the scoring is tested on any OS.
package watch

import (
	"net/netip"
	"time"
)

// Kind is what an Event reports.
type Kind string

const (
	// ProcSeen is a process already running when the window opened.
	ProcSeen  Kind = "proc"
	ProcStart Kind = "proc_start"
	ProcStop  Kind = "proc_stop"
	// TCPConnect is an outbound connection attempt; TCPAccept an inbound one.
	TCPConnect Kind = "tcp_connect"
	TCPAccept  Kind = "tcp_accept"
	TCPSend    Kind = "tcp_send"
	TCPRecv    Kind = "tcp_recv"
	TCPClose   Kind = "tcp_close"
	UDPSend    Kind = "udp_send"
	UDPRecv    Kind = "udp_recv"
	// DNS is a completed name lookup, with its answers.
	DNS Kind = "dns"
)

var knownKinds = map[Kind]bool{
	ProcSeen: true, ProcStart: true, ProcStop: true,
	TCPConnect: true, TCPAccept: true, TCPSend: true, TCPRecv: true, TCPClose: true,
	UDPSend: true, UDPRecv: true, DNS: true,
}

// Event is one normalized observation. Fields a kind doesn't use stay zero.
type Event struct {
	Time time.Time `json:"t"`
	Kind Kind      `json:"k"`
	PID  uint32    `json:"pid"`

	// Processes.
	PPID    uint32 `json:"ppid,omitempty"`
	Image   string `json:"image,omitempty"`
	CmdLine string `json:"cmd,omitempty"`

	// Network. Local and Remote are address:port; Bytes is the payload size
	// a send or receive reported.
	Local  netip.AddrPort `json:"src,omitzero"`
	Remote netip.AddrPort `json:"dst,omitzero"`
	Bytes  uint32         `json:"bytes,omitempty"`

	// DNS.
	Query   string   `json:"q,omitempty"`
	QType   uint16   `json:"qtype,omitempty"`
	Status  uint32   `json:"status,omitempty"`
	Answers []string `json:"a,omitempty"`
}

// DNS query types the tunnel heuristic cares about.
const (
	qtypeTXT  = 16
	qtypeNULL = 10
)
