//go:build windows

package collector

import (
	"context"
	"errors"
)

const udpTableOwnerPID = 1 // UDP_TABLE_OWNER_PID

var procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")

func collectUDP(ctx context.Context) (Result, error) {
	res := NewResult("udp")

	families := []struct {
		af    uint32
		label string
		parse func([]byte) ([]udpConn, error)
	}{
		{afINet, "ipv4", parseUDP4Table},
		{afINet6, "ipv6", parseUDP6Table},
	}
	var conns []udpConn
	read := 0
	for _, f := range families {
		buf, err := fetchUDPTable(f.af)
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
		return res.Finish(), errors.New("could not read either UDP table")
	}

	names := procNameMap()
	for _, c := range conns {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		res.Add(map[string]any{
			"family":     c.Family,
			"local_addr": c.Local.Addr().String(),
			"local_port": c.Local.Port(),
			"pid":        c.PID,
			"process":    names[c.PID],
		})
	}
	return res.Finish(), nil
}

// fetchUDPTable returns the raw owner-PID UDP table for one address family,
// retrying on a table that grows between the sizing and fetch calls.
func fetchUDPTable(af uint32) ([]byte, error) {
	return fetchIPTable(procGetExtendedUdpTable, af, udpTableOwnerPID, "GetExtendedUdpTable")
}
