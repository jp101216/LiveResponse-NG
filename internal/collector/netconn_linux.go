//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

// Linux network collector: reads /proc/net/tcp and tcp6, maps each socket to its
// owning process through /proc/<pid>/fd, and runs every connection through AI
// module A (the LLM-callout detector, which is OS-agnostic) and the Linux
// network heuristics. DNS-cache correlation has no portable Linux equivalent, so
// it is reported as off.
func collectConnections(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("network")

	rows, err := readProcNetFamilies(res, "tcp")
	if err != nil {
		return res.Finish(), err
	}

	inodePID, comm := procSocketOwners()
	res.SetMeta("dns_correlation", false) // no portable Linux system DNS cache to snapshot

	if opts.ResolveLLMHosts {
		markModuleAResolving()
	}
	det := aidetect.BuildDetector(ctx, aidetect.Options{
		ExtraAllow: opts.ExtraAllowlist,
		Resolve:    opts.ResolveLLMHosts,
	})

	exeCache := map[int]string{}
	pathOf := func(pid int) string {
		if pid <= 0 {
			return ""
		}
		p, ok := exeCache[pid]
		if !ok {
			p = exeOf(pid)
			exeCache[pid] = p
		}
		return p
	}

	// Listening sockets, so an established connection accepted on one of them
	// (a client of a local server) isn't mistaken for this host reaching out.
	listeners := map[netip.AddrPort]bool{}
	wildcard := map[uint16]bool{}
	for _, fr := range rows {
		if linuxTCPStateName(fr.row.State) != "LISTEN" {
			continue
		}
		if a := fr.row.Local.Addr(); a.IsUnspecified() {
			wildcard[fr.row.Local.Port()] = true
		} else {
			listeners[netip.AddrPortFrom(a.Unmap(), fr.row.Local.Port())] = true
		}
	}

	for _, fr := range rows {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		r := fr.row
		pid := inodePID[r.Inode]
		name := comm[pid]
		state := linuxTCPStateName(r.State)
		remote := r.Remote.Addr()
		local := r.Local.Addr()
		exe := pathOf(pid)

		fields := map[string]any{
			"family":      fr.label,
			"state":       state,
			"local_addr":  local.String(),
			"local_port":  r.Local.Port(),
			"remote_addr": remote.String(),
			"remote_port": r.Remote.Port(),
			"inode":       r.Inode,
			"uid":         r.UID,
		}
		if pid > 0 {
			fields["pid"] = pid
		}
		if name != "" {
			fields["process"] = name
		}
		self := pid > 0 && opts.isSelf(uint32(pid), exe)
		if self {
			fields["lrng_component"] = true
		}

		hasPeer := state != "LISTEN" && remote.IsValid() && !remote.IsUnspecified() && r.Remote.Port() != 0
		inbound := state == "ESTABLISHED" &&
			(wildcard[r.Local.Port()] || listeners[netip.AddrPortFrom(local.Unmap(), r.Local.Port())])
		if inbound {
			fields["direction"] = "inbound"
		}

		var findings []Finding
		if hasPeer && !self && det.Matches(remote, "") {
			// Only a high-risk location counts as unusual for an allowlisted
			// name here: per-user installs under ~/.local and other dot
			// directories are where Linux desktop apps normally live.
			lvl, _ := unixPathRisk(exe)
			conn := aidetect.Conn{
				Remote: remote, Process: name, PID: uint32(pid),
				ImagePath: exe, UnusualPath: lvl == riskHigh,
			}
			if co := det.Inspect(conn); co != nil {
				findings = append(findings, Finding{
					Rule: co.Rule, Severity: Severity(co.Severity), Technique: co.Technique,
					Confidence: co.Confidence, Detail: co.Detail,
				})
			}
		}
		if len(findings) == 0 {
			cv := connView{
				State: state, Local: local, LocalPort: r.Local.Port(),
				Remote: remote, RemotePort: r.Remote.Port(), PID: uint32(pid), Process: name,
				ImagePath: exe, Self: self, Inbound: inbound,
			}
			findings = linuxConnFindings(cv)
		}
		// The image path rides along on anything judged, and on every
		// connection to a public peer (the context an analyst pivots on).
		publicPeer := hasPeer && aidetect.PublicAddr(remote) && (state == "ESTABLISHED" || state == "SYN_SENT")
		if exe != "" && (len(findings) > 0 || publicPeer) {
			fields["image_path"] = exe
		}
		res.Add(fields, findings...)
	}

	for k, v := range det.Meta() {
		res.SetMeta(k, v)
	}
	res.SetMeta("platform", "linux")
	return res.Finish(), nil
}

// procNetFamRow is one /proc/net socket row and the address family it came from.
type procNetFamRow struct {
	row   procNetRow
	label string
}

// readProcNetFamilies reads the IPv4 and IPv6 tables for kind ("tcp" or "udp":
// /proc/net/<kind> and /proc/net/<kind>6). A missing IPv6 table means IPv6 is
// disabled on the host — there are no IPv6 sockets to miss — so it is noted in
// meta rather than counted as a coverage gap. It fails only when neither table
// can be read.
func readProcNetFamilies(res *Result, kind string) ([]procNetFamRow, error) {
	families := []struct {
		path, label string
		v6          bool
	}{
		{"/proc/net/" + kind, "ipv4", false},
		{"/proc/net/" + kind + "6", "ipv6", true},
	}
	var rows []procNetFamRow
	read := 0
	for _, f := range families {
		data, err := os.ReadFile(f.path)
		if err != nil {
			if f.v6 && errors.Is(err, fs.ErrNotExist) {
				res.SetMeta("ipv6", "unavailable: IPv6 is disabled on this host ("+f.path+" does not exist)")
				continue
			}
			res.Fail(f.label + ": could not read " + f.path + ": " + err.Error())
			continue
		}
		rr, _ := parseProcNet(data, f.v6)
		res.SetMeta(f.label+"_rows", len(rr))
		read++
		for _, r := range rr {
			rows = append(rows, procNetFamRow{row: r, label: f.label})
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("could not read %s or %s", families[0].path, families[1].path)
	}
	return rows, nil
}

// procSocketOwners walks /proc once and returns the two lookups the network and
// udp collectors both need: socket inode → owning PID (from /proc/<pid>/fd
// "socket:[<inode>]" links, first owner wins) and PID → comm. Building them in a
// single pass avoids enumerating /proc twice per collector.
func procSocketOwners() (inodePID map[uint64]int, comm map[int]string) {
	inodePID = map[uint64]int{}
	comm = map[int]string{}
	pids, _ := readProcPIDs()
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)
		if b := readFileSafe(base + "/comm"); b != nil {
			comm[pid] = strings.TrimSpace(string(b))
		}
		ents, err := os.ReadDir(base + "/fd")
		if err != nil {
			continue // not ours to read, or the process exited
		}
		for _, e := range ents {
			link, err := os.Readlink(base + "/fd/" + e.Name())
			if err != nil {
				continue
			}
			rest, ok := strings.CutPrefix(link, "socket:[")
			if !ok {
				continue
			}
			rest = strings.TrimSuffix(rest, "]")
			if inode, err := strconv.ParseUint(rest, 10, 64); err == nil {
				if _, seen := inodePID[inode]; !seen {
					inodePID[inode] = pid
				}
			}
		}
	}
	return inodePID, comm
}

// procCommMap maps every PID to its comm (short process name).
func procCommMap() map[int]string {
	m := map[int]string{}
	pids, _ := readProcPIDs()
	for _, pid := range pids {
		if b := readFileSafe("/proc/" + strconv.Itoa(pid) + "/comm"); b != nil {
			m[pid] = strings.TrimSpace(string(b))
		}
	}
	return m
}

// exeOf returns a process's resolved executable path, or "" if unreadable.
func exeOf(pid int) string {
	if pid <= 0 {
		return ""
	}
	p, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return p
}
