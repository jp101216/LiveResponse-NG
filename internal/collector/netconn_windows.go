//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"syscall"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Win32 constants for the owner-PID TCP tables.
const (
	afINet              = 2  // AF_INET
	afINet6             = 23 // AF_INET6
	tcpTableOwnerPIDAll = 5  // TCP_TABLE_OWNER_PID_ALL
	tableFetchAttempts  = 5
)

var (
	modiphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

// collectConnections enumerates IPv4 and IPv6 TCP connections (owner-PID
// tables), attaches cached DNS names when correlation is on, and annotates
// each with AI module A's LLM-callout finding or the generic network
// heuristics.
func collectConnections(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("network")

	// Read the tables before anything else this collector does, so the
	// snapshot is as close to "as found" as possible.
	families := []struct {
		af    uint32
		label string
		parse func([]byte) ([]tcpConn, error)
	}{
		{afINet, "ipv4", parseTCP4Table},
		{afINet6, "ipv6", parseTCP6Table},
	}
	var conns []tcpConn
	read := 0
	for _, f := range families {
		buf, err := fetchTCPTable(f.af)
		if err != nil {
			res.Fail(f.label + ": " + err.Error())
			continue
		}
		rows, err := f.parse(buf)
		if err != nil {
			res.Fail(f.label + ": " + err.Error())
			continue
		}
		read++
		res.SetMeta(f.label+"_rows", len(rows))
		conns = append(conns, rows...)
	}
	if read == 0 {
		return res.Finish(), errors.New("could not read either TCP table")
	}
	names := procNameMap() // PID -> image name, best-effort

	// DNS correlation reads the cache before module A resolves anything, so
	// lrng's own lookups never show up as evidence.
	var hostsByAddr map[netip.Addr][]string
	res.SetMeta("dns_correlation", opts.DNSCorrelate)
	if opts.DNSCorrelate {
		m, err := dnsNamesByAddr(ctx)
		if err != nil {
			res.Fail("dns correlation: " + err.Error())
		} else {
			hostsByAddr = m
			res.SetMeta("dns_cache_addresses", len(m))
		}
	}

	if opts.ResolveLLMHosts {
		markModuleAResolving()
	}
	det := aidetect.BuildDetector(ctx, aidetect.Options{
		ExtraAllow: opts.ExtraAllowlist,
		Resolve:    opts.ResolveLLMHosts,
	})

	paths := map[uint32]string{} // image paths, looked up only where needed
	pathOf := func(pid uint32) string {
		if pid == 0 || pid == 4 {
			return ""
		}
		p, ok := paths[pid]
		if !ok {
			p, _ = imagePath(pid)
			paths[pid] = p
		}
		return p
	}

	correlated := 0
	for _, c := range conns {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}

		remote := c.Remote.Addr()
		proc := names[c.PID]
		state := tcpStateName(c.State)
		fields := map[string]any{
			"family":      c.Family,
			"state":       state,
			"local_addr":  c.Local.Addr().String(),
			"local_port":  c.Local.Port(),
			"remote_addr": remote.String(),
			"remote_port": c.Remote.Port(),
			"pid":         c.PID,
			"process":     proc,
		}
		hasPeer := c.State != tcpStateListen && remote.IsValid() && !remote.IsUnspecified()

		host := ""
		if hosts := hostsByAddr[remote.Unmap()]; hasPeer && len(hosts) > 0 {
			host = pickHost(hosts)
			fields["remote_hosts"] = capStrings(hosts, dnsMaxNamesPerRecord)
			correlated++
		}

		var findings []Finding
		if hasPeer && det.Matches(remote, host) {
			conn := aidetect.Conn{Remote: remote, RemoteHost: host, Process: proc, PID: c.PID}
			if p := pathOf(c.PID); p != "" {
				conn.ImagePath, conn.UnusualPath = p, suspiciousPath(p)
				fields["image_path"] = p
			}
			if co := det.Inspect(conn); co != nil {
				findings = append(findings, Finding{
					Rule:       co.Rule,
					Severity:   Severity(co.Severity),
					Technique:  co.Technique,
					Confidence: co.Confidence,
					Detail:     co.Detail,
				})
			}
		}
		if len(findings) == 0 && c.PID > 4 {
			cv := connView{
				State: state, Local: c.Local.Addr(), LocalPort: c.Local.Port(),
				Remote: remote, RemotePort: c.Remote.Port(), PID: c.PID, Process: proc,
			}
			// Only public outbound sockets need the image path for the
			// path heuristic; listeners are judged by name.
			if hasPeer && aidetect.PublicAddr(remote) && (state == "ESTABLISHED" || state == "SYN_SENT") {
				cv.ImagePath = pathOf(c.PID)
				if cv.ImagePath != "" {
					fields["image_path"] = cv.ImagePath
				}
			}
			cv.Self = opts.isSelf(c.PID, cv.ImagePath)
			findings = analyzeConnection(cv)
		}
		res.Add(fields, findings...)
	}

	// Detector coverage, so "no findings" can be told apart from "detector
	// had no endpoints loaded".
	for k, v := range det.Meta() {
		res.SetMeta(k, v)
	}
	if opts.DNSCorrelate {
		res.SetMeta("connections_with_hostnames", correlated)
	}
	res.SetMeta("extra_allowlist", opts.ExtraAllowlist)
	return res.Finish(), nil
}

// pickHost chooses the name to judge a connection by: an LLM provider name if
// any of the cached names is one (shared CDN addresses serve many names),
// otherwise the alphabetically first for stable output.
func pickHost(hosts []string) string {
	for _, h := range hosts {
		if _, ok := aidetect.MatchHostname(h); ok {
			return h
		}
	}
	s := append([]string(nil), hosts...)
	sort.Strings(s)
	return s[0]
}

func capStrings(s []string, n int) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// fetchTCPTable returns the raw owner-PID TCP table for one address family.
// The table can grow between the sizing call and the fetch (a busy server
// opens connections constantly), so it retries with a larger buffer instead of
// failing the whole collector on ERROR_INSUFFICIENT_BUFFER.
func fetchTCPTable(af uint32) ([]byte, error) {
	return fetchIPTable(procGetExtendedTcpTable, af, tcpTableOwnerPIDAll, "GetExtendedTcpTable")
}

// fetchIPTable implements the size-then-fetch loop shared by the TCP and UDP
// owner-PID tables.
func fetchIPTable(proc *syscall.LazyProc, af, class uint32, name string) ([]byte, error) {
	var (
		buf  []byte
		size uint32
	)
	for attempt := 0; attempt < tableFetchAttempts; attempt++ {
		var ptr uintptr
		if len(buf) > 0 {
			ptr = uintptr(unsafe.Pointer(&buf[0]))
		}
		r1, _, _ := proc.Call(ptr, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		switch syscall.Errno(r1) {
		case 0:
			if len(buf) == 0 {
				return make([]byte, tableHeader), nil // empty table
			}
			return buf, nil
		case syscall.ERROR_INSUFFICIENT_BUFFER:
			// Headroom so a table that grows a little before the next call
			// still fits.
			buf = make([]byte, int(size)+int(size)/4+4096)
			size = uint32(len(buf))
		default:
			return nil, fmt.Errorf("%s: %w", name, syscall.Errno(r1))
		}
	}
	return nil, fmt.Errorf("%s: table kept growing after %d attempts", name, tableFetchAttempts)
}
