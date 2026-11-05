//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rootkitCollector looks for what a kernel rootkit hides: processes that
// answer when asked for by PID but are filtered out of /proc's listing (the
// getdents hook Diamorphine and its kin install), and sockets the kernel's
// own socket-diagnostics netlink lists but /proc/net leaves out (the hook on
// the seq_file netstat reads). lrng reads /proc and netlink itself, so a
// userland LD_PRELOAD hider doesn't fool either side.
type rootkitCollector struct{}

func (rootkitCollector) Name() string           { return "rootkit" }
func (rootkitCollector) Platforms() []string    { return []string{"linux"} }
func (rootkitCollector) Timeout() time.Duration { return time.Minute }

func (rootkitCollector) Collect(ctx context.Context) (Result, error) {
	return collectRootkit(ctx), nil
}

func init() { Register(func() Collector { return rootkitCollector{} }) }

// pidProbeBudget bounds the PID-by-PID probe.
const pidProbeBudget = 20 * time.Second

func collectRootkit(ctx context.Context) Result {
	res := NewResult("rootkit")
	res.SetMeta("platform", "linux")

	// Processes.
	listed, err := listedPIDs()
	if err != nil {
		res.Fail("/proc: " + err.Error())
		return res.Finish()
	}
	bound := probeBound(listed)
	answering, probed, truncated := probePIDs(ctx, listed, bound)
	candidates := hiddenPIDs(listed, answering)
	var hidden []int
	if len(candidates) > 0 {
		// A process started during the probe is listed now: only those still
		// answering and still missing from a fresh listing count.
		again, _ := listedPIDs()
		for _, pid := range candidates {
			if !again[pid] && tgidOf(pid) == pid {
				hidden = append(hidden, pid)
			}
		}
	}
	for _, pid := range hidden {
		comm := strings.TrimSpace(string(readFileSafe(fmt.Sprintf("/proc/%d/comm", pid))))
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		cmdline := strings.ReplaceAll(strings.TrimRight(string(readFileSafe(fmt.Sprintf("/proc/%d/cmdline", pid))), "\x00"), "\x00", " ")
		fields := map[string]any{"kind": "hidden_process", "pid": pid, "name": comm}
		if exe != "" {
			fields["image_path"] = exe
		}
		if cmdline != "" {
			fields["command_line"] = excerpt(cmdline, 400)
		}
		res.Add(fields, Finding{Rule: "defense.hidden_process", Severity: SevCritical, Technique: "T1014", Confidence: 85,
			Detail: fmt.Sprintf("process %d (%s%s) exists, /proc/%d answers, but /proc's listing leaves it out: a kernel rootkit "+
				"hiding it from ps and top (Diamorphine, Reptile and their kin hook the directory listing)",
				pid, firstNonEmpty(comm, "unnamed"), map[bool]string{true: ", " + exe, false: ""}[exe != ""], pid)})
	}

	// Sockets.
	first, derr := allDiagSockets()
	var socketsHidden []diagSocket
	compared := 0
	if derr != nil {
		res.Fail("sock_diag netlink: " + derr.Error())
	} else {
		procKeys := procNetKeys()
		second, _ := allDiagSockets()
		compared = len(first)
		socketsHidden = hiddenSockets(first, second, procKeys)
		inodePID, comm := procSocketOwners()
		for _, s := range socketsHidden {
			fields := map[string]any{"kind": "hidden_socket", "protocol": s.Proto, "family": s.Family, "state": linuxTCPStateName(s.State),
				"local": s.Local, "remote": s.Remote, "inode": s.Inode, "uid": s.UID}
			owner := ""
			if pid := inodePID[s.Inode]; pid > 0 {
				fields["pid"] = pid
				fields["process"] = comm[pid]
				owner = fmt.Sprintf(", owned by %s (pid %d)", comm[pid], pid)
			}
			res.Add(fields, Finding{Rule: "defense.hidden_socket", Severity: SevCritical, Technique: "T1014", Confidence: 80,
				Detail: fmt.Sprintf("a %s socket %s → %s (%s%s) is in the kernel's own socket list (netlink sock_diag) but missing "+
					"from /proc/net/%s: a rootkit filtering what netstat reads, usually to hide a backdoor's port",
					s.Proto, s.Local, s.Remote, linuxTCPStateName(s.State), owner, s.Proto)})
		}
	}

	res.Add(map[string]any{"kind": "summary", "pids_listed": len(listed), "pids_probed": probed, "probe_bound": bound,
		"probe_truncated": truncated, "hidden_processes": len(hidden), "sockets_compared": compared,
		"hidden_sockets": len(socketsHidden)})
	res.SetMeta("pids_listed", len(listed))
	res.SetMeta("pids_probed", probed)
	res.SetMeta("sockets_compared", compared)
	return res.Finish()
}

// listedPIDs is /proc's listing of process directories.
func listedPIDs() (map[int]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			out[pid] = true
		}
	}
	return out, nil
}

// probeBound is the highest PID worth asking for: past the largest listed and
// the last PID the kernel handed out (/proc/loadavg), within pid_max.
func probeBound(listed map[int]bool) int {
	bound := 0
	for pid := range listed {
		bound = max(bound, pid)
	}
	if f := strings.Fields(string(readFileSafe("/proc/loadavg"))); len(f) >= 5 {
		if last, err := strconv.Atoi(f[4]); err == nil {
			bound = max(bound, last)
		}
	}
	bound += 128
	if pm, err := strconv.Atoi(strings.TrimSpace(string(readFileSafe("/proc/sys/kernel/pid_max")))); err == nil && pm > 0 {
		bound = min(bound, pm)
	}
	return bound
}

// probePIDs asks for each unlisted PID up to bound directly; those that
// answer are mapped to their thread-group id (a thread answers too, under
// its process).
func probePIDs(ctx context.Context, listed map[int]bool, bound int) (answering map[int]int, probed int, truncated bool) {
	answering = map[int]int{}
	deadline := time.Now().Add(pidProbeBudget)
	var st syscall.Stat_t
	for pid := 1; pid <= bound; pid++ {
		if listed[pid] {
			continue
		}
		if pid%4096 == 0 && (ctx.Err() != nil || time.Now().After(deadline)) {
			return answering, probed, true
		}
		probed++
		if syscall.Stat("/proc/"+strconv.Itoa(pid), &st) != nil {
			continue
		}
		answering[pid] = tgidOf(pid)
	}
	return answering, probed, false
}

// tgidOf reads a task's thread-group id from /proc/<pid>/status (0 if gone).
func tgidOf(pid int) int {
	for _, line := range strings.Split(string(readFileSafe(fmt.Sprintf("/proc/%d/status", pid))), "\n") {
		if v, ok := strings.CutPrefix(line, "Tgid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// procNetKeys are the sockets /proc/net lists, keyed like diagSocket.key.
func procNetKeys() map[string]bool {
	out := map[string]bool{}
	for _, t := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		data, err := os.ReadFile(t.file)
		if err != nil {
			continue
		}
		rows, _ := parseProcNet(data, strings.HasSuffix(t.file, "6"))
		for _, r := range rows {
			if r.Inode != 0 {
				out[fmt.Sprintf("%s/%d", t.proto, r.Inode)] = true
			}
		}
	}
	return out
}

const (
	netlinkSockDiag  = 4  // NETLINK_SOCK_DIAG
	sockDiagByFamily = 20 // SOCK_DIAG_BY_FAMILY
	inetDiagMsgLen   = 72 // struct inet_diag_msg
)

// allDiagSockets dumps TCP and UDP sockets of both families from netlink,
// keeping those with an inode (TIME_WAIT and other orphans have none).
func allDiagSockets() ([]diagSocket, error) {
	var out []diagSocket
	var firstErr error
	ok := 0
	for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		for _, proto := range []uint8{syscall.IPPROTO_TCP, syscall.IPPROTO_UDP} {
			socks, err := diagDump(fam, proto)
			if err != nil {
				if firstErr == nil && proto == syscall.IPPROTO_TCP {
					firstErr = err
				}
				continue // udp_diag may not be loaded
			}
			ok++
			out = append(out, socks...)
		}
	}
	if ok == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// diagDump asks the kernel for every socket of one family and protocol.
func diagDump(family, proto uint8) ([]diagSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	req := make([]byte, 16+56)
	binary.NativeEndian.PutUint32(req[0:], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:], 1)
	req[16], req[17] = family, proto
	binary.NativeEndian.PutUint32(req[20:], 0xffffffff) // every state
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	protoName := map[uint8]string{syscall.IPPROTO_TCP: "tcp", syscall.IPPROTO_UDP: "udp"}[proto]
	famName := map[uint8]string{syscall.AF_INET: "ipv4", syscall.AF_INET6: "ipv6"}[family]
	var out []diagSocket
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				return out, nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
						return nil, syscall.Errno(-e)
					}
				}
				return nil, errors.New("netlink error")
			}
			if s, ok := parseInetDiag(m.Data, protoName, famName); ok && s.Inode != 0 {
				out = append(out, s)
			}
		}
	}
}

// parseInetDiag decodes one struct inet_diag_msg.
func parseInetDiag(b []byte, proto, family string) (diagSocket, bool) {
	if len(b) < inetDiagMsgLen {
		return diagSocket{}, false
	}
	addr := func(raw []byte) netip.Addr {
		if b[0] == syscall.AF_INET {
			return netip.AddrFrom4([4]byte(raw[:4]))
		}
		return netip.AddrFrom16([16]byte(raw[:16]))
	}
	sport := binary.BigEndian.Uint16(b[4:6])
	dport := binary.BigEndian.Uint16(b[6:8])
	return diagSocket{
		Proto: proto, Family: family, State: b[1],
		Local:  netip.AddrPortFrom(addr(b[8:24]), sport).String(),
		Remote: netip.AddrPortFrom(addr(b[24:40]), dport).String(),
		UID:    binary.NativeEndian.Uint32(b[64:68]),
		Inode:  uint64(binary.NativeEndian.Uint32(b[68:72])),
	}, true
}
