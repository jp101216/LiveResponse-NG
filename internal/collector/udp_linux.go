//go:build linux

package collector

import (
	"context"
	"errors"
	"fmt"
)

// Linux UDP collector: the local UDP sockets from /proc/net/udp and udp6, each
// mapped to its owning process. UDP has no connection state or remote peer in
// the table, so these are the listeners and client sockets (DNS, discovery, a
// UDP beacon or bind shell).
func collectUDP(ctx context.Context) (Result, error) {
	res := NewResult("udp")

	families := []struct {
		path, label string
		v6          bool
	}{
		{"/proc/net/udp", "ipv4", false},
		{"/proc/net/udp6", "ipv6", true},
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
		return res.Finish(), errors.New("could not read /proc/net/udp or /proc/net/udp6")
	}

	inodePID, comm := procSocketOwners()

	for _, fr := range rows {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		r := fr.row
		pid := inodePID[r.Inode]
		name := comm[pid]
		local := r.Local.Addr()

		fields := map[string]any{
			"family":     fr.label,
			"local_addr": local.String(),
			"local_port": r.Local.Port(),
			"inode":      r.Inode,
			"uid":        r.UID,
		}
		if pid > 0 {
			fields["pid"] = pid
		}
		if name != "" {
			fields["process"] = name
		}

		var findings []Finding
		// A shell or netcat bound to a non-loopback UDP port is an unusual
		// listener (a UDP bind shell or ad-hoc channel).
		if unixShellProcs[unixBaseName(name)] && local.IsValid() && !local.IsLoopback() && r.Local.Port() != 0 {
			findings = append(findings, Finding{
				Rule: "network.shell_listener", Severity: SevSuspect, Technique: "T1059.004", Confidence: 55,
				Detail: fmt.Sprintf("%s (pid %d) holds a UDP socket on %s port %d — shells don't normally do that",
					name, pid, local, r.Local.Port()),
			})
		}
		res.Add(fields, findings...)
	}

	res.SetMeta("platform", "linux")
	return res.Finish(), nil
}
