//go:build linux

package collector

import (
	"context"
	"fmt"
	"strings"
)

// Linux UDP collector: the local UDP sockets from /proc/net/udp and udp6, each
// mapped to its owning process. UDP has no connection state or remote peer in
// the table, so these are the listeners and client sockets (DNS, discovery, a
// UDP beacon or bind shell).
func collectUDP(ctx context.Context) (Result, error) {
	res := NewResult("udp")

	rows, err := readProcNetFamilies(res, "udp")
	if err != nil {
		return res.Finish(), err
	}

	inodePID, comm := procSocketOwners()
	exeCache := map[int]string{}

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
		// listener (a UDP bind shell or ad-hoc channel). Judged by comm and by
		// the executable's name, so a script run as ./x.sh is still a shell.
		if pid > 0 && local.IsValid() && !local.IsLoopback() && r.Local.Port() != 0 {
			exe, ok := exeCache[pid]
			if !ok {
				exe = exeOf(pid)
				exeCache[pid] = exe
			}
			if shell, _ := unixProcClass(name, exe); shell {
				label := name
				if b := unixBaseName(strings.TrimSuffix(exe, deletedSuffix)); b != "" && b != name {
					label = name + " [" + b + "]"
				}
				if exe != "" {
					fields["image_path"] = exe
				}
				findings = append(findings, Finding{
					Rule: "network.shell_listener", Severity: SevSuspect, Technique: "T1059.004", Confidence: 55,
					Detail: fmt.Sprintf("%s (pid %d) holds a UDP socket on %s port %d — shells don't normally do that",
						label, pid, local, r.Local.Port()),
				})
			}
		}
		res.Add(fields, findings...)
	}

	res.SetMeta("platform", "linux")
	return res.Finish(), nil
}
