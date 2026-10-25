//go:build linux

package collector

import (
	"context"
	"errors"
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

	families := []struct {
		path, label string
		v6          bool
	}{
		{"/proc/net/tcp", "ipv4", false},
		{"/proc/net/tcp6", "ipv6", true},
	}
	type famRow struct {
		row   procNetRow
		label string
	}
	var rows []famRow
	read := 0
	for _, f := range families {
		data := readFileSafe(f.path)
		if data == nil {
			res.Fail(f.label + ": could not read " + f.path)
			continue
		}
		rr, _ := parseProcNet(data, f.v6)
		res.SetMeta(f.label+"_rows", len(rr))
		read++
		for _, r := range rr {
			rows = append(rows, famRow{row: r, label: f.label})
		}
	}
	if read == 0 {
		return res.Finish(), errors.New("could not read /proc/net/tcp or /proc/net/tcp6")
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
		self := pid > 0 && opts.isSelf(uint32(pid), pathOf(pid))
		if self {
			fields["lrng_component"] = true
		}

		hasPeer := state != "LISTEN" && remote.IsValid() && !remote.IsUnspecified() && r.Remote.Port() != 0

		var findings []Finding
		if hasPeer && !self && det.Matches(remote, "") {
			ip := pathOf(pid)
			if ip != "" {
				fields["image_path"] = ip
			}
			conn := aidetect.Conn{
				Remote: remote, Process: name, PID: uint32(pid),
				ImagePath: ip, UnusualPath: unixSuspiciousPath(ip),
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
				Remote: remote, RemotePort: r.Remote.Port(), PID: uint32(pid), Process: name, Self: self,
			}
			if hasPeer && aidetect.PublicAddr(remote) && (state == "ESTABLISHED" || state == "SYN_SENT") {
				cv.ImagePath = pathOf(pid)
				if cv.ImagePath != "" {
					fields["image_path"] = cv.ImagePath
				}
			}
			findings = linuxConnFindings(cv)
		}
		res.Add(fields, findings...)
	}

	for k, v := range det.Meta() {
		res.SetMeta(k, v)
	}
	res.SetMeta("platform", "linux")
	return res.Finish(), nil
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
