//go:build windows

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

var (
	modwtsapi32                     = syscall.NewLazyDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW       = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = modwtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modwtsapi32.NewProc("WTSFreeMemory")
)

// wtsSessionInfo mirrors WTS_SESSION_INFOW. The pointer field forces 8-byte
// alignment on 64-bit, matching the C layout on both 32- and 64-bit.
type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

// WTS_INFO_CLASS values used here.
const (
	wtsUserName         = 5
	wtsDomainName       = 7
	wtsClientName       = 10
	wtsClientAddress    = 14
	wtsSessionInfoClass = 24

	// WTSINFOW is parsed by offset rather than mirrored as a struct: its
	// LARGE_INTEGER times sit at 8-byte offsets in C on every architecture,
	// which a Go struct on 386 would not reproduce.
	wtsInfoSize          = 216
	wtsInfoConnectTime   = 176
	wtsInfoDisconnectOff = 184
	wtsInfoLastInputOff  = 192
	wtsInfoLogonOff      = 200
	wtsInfoCurrentOff    = 208
)

func collectSessions(ctx context.Context) (Result, error) {
	res := NewResult("sessions")

	var pInfo unsafe.Pointer
	var count uint32
	r, _, e := procWTSEnumerateSessionsW.Call(
		0, 0, 1, // WTS_CURRENT_SERVER_HANDLE, reserved, version 1
		uintptr(unsafe.Pointer(&pInfo)), uintptr(unsafe.Pointer(&count)),
	)
	if r == 0 {
		return res.Finish(), fmt.Errorf("WTSEnumerateSessions: %w", e)
	}
	defer procWTSFreeMemory.Call(uintptr(pInfo))
	res.SetMeta("session_count", int(count))

	sessions := unsafe.Slice((*wtsSessionInfo)(pInfo), count)
	for _, s := range sessions {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		fields := map[string]any{
			"session_id": s.SessionID,
			"state":      wtsStateName(s.State),
		}
		if st := utf16PtrToString(s.WinStationName); st != "" {
			fields["station"] = st
		}
		user := wtsQueryString(s.SessionID, wtsUserName)
		if user != "" {
			if dom := wtsQueryString(s.SessionID, wtsDomainName); dom != "" {
				fields["user"] = dom + `\` + user
			} else {
				fields["user"] = user
			}
		}
		var findings []Finding
		if cn := wtsQueryString(s.SessionID, wtsClientName); cn != "" {
			fields["client_name"] = cn
			fields["remote"] = true
		}
		if addr, ok := wtsClientIPv4(s.SessionID); ok {
			fields["client_address"] = addr.String()
			fields["remote"] = true
			if aidetect.PublicAddr(addr) && user != "" {
				findings = append(findings, Finding{
					Rule: "sessions.remote_from_public_address", Severity: SevNotable, Technique: "T1021.001", Confidence: 40,
					Detail: fmt.Sprintf("session %d (%s) is connected from public address %s — RDP exposed to the internet, or a VPN/jump host",
						s.SessionID, user, addr),
				})
			}
		}
		addSessionTimes(fields, s.SessionID)
		res.Add(fields, findings...)
	}
	addRDPConfig(res)
	return res.Finish(), nil
}

// wtsQuery fetches one WTS attribute buffer for a session; the caller frees it.
func wtsQuery(sessionID uint32, infoClass uint32) (unsafe.Pointer, uint32) {
	var p unsafe.Pointer
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(
		0, uintptr(sessionID), uintptr(infoClass),
		uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 || p == nil {
		return nil, 0
	}
	return p, n
}

// wtsQueryString fetches one WTS string attribute for a session.
func wtsQueryString(sessionID uint32, infoClass uint32) string {
	p, _ := wtsQuery(sessionID, infoClass)
	if p == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(p))
	return utf16PtrToString((*uint16)(p))
}

// wtsClientIPv4 returns the IPv4 address of a remote session's client
// (WTS_CLIENT_ADDRESS: an AF_INET address sits in Address[2..5]).
func wtsClientIPv4(sessionID uint32) (netip.Addr, bool) {
	p, n := wtsQuery(sessionID, wtsClientAddress)
	if p == nil {
		return netip.Addr{}, false
	}
	defer procWTSFreeMemory.Call(uintptr(p))
	if n < 24 {
		return netip.Addr{}, false
	}
	b := unsafe.Slice((*byte)(p), 24)
	if binary.LittleEndian.Uint32(b[0:4]) != afINet {
		return netip.Addr{}, false
	}
	a := netip.AddrFrom4([4]byte{b[6], b[7], b[8], b[9]})
	if a.IsUnspecified() {
		return netip.Addr{}, false
	}
	return a, true
}

// addSessionTimes reads logon, connect, disconnect and last-input times from
// WTSINFOW, trusting them only if the structure's own CurrentTime is sane.
func addSessionTimes(fields map[string]any, sessionID uint32) {
	p, n := wtsQuery(sessionID, wtsSessionInfoClass)
	if p == nil {
		return
	}
	defer procWTSFreeMemory.Call(uintptr(p))
	if n < wtsInfoSize {
		return
	}
	b := unsafe.Slice((*byte)(p), wtsInfoSize)
	ft := func(off int) time.Time { return winreg.FiletimeToTime(binary.LittleEndian.Uint64(b[off:])) }
	if now := ft(wtsInfoCurrentOff); now.IsZero() || now.Sub(time.Now()).Abs() > 48*time.Hour {
		return // layout not as expected: report nothing rather than nonsense
	}
	for name, off := range map[string]int{
		"logon_time": wtsInfoLogonOff, "connect_time": wtsInfoConnectTime,
		"disconnect_time": wtsInfoDisconnectOff, "last_input_time": wtsInfoLastInputOff,
	} {
		if t := ft(off); !t.IsZero() && t.Year() > 1990 && t.Before(time.Now().Add(48*time.Hour)) {
			fields[name] = t
		}
	}
}

// addRDPConfig records whether Remote Desktop is enabled and its port —
// context for every remote session above.
func addRDPConfig(res *Result) {
	if v, err := winreg.ReadValue(winreg.LocalMachine, `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections"); err == nil {
		if d, ok := v.Uint32(); ok {
			res.SetMeta("rdp_enabled", d == 0)
		}
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "PortNumber"); err == nil {
		if d, ok := v.Uint32(); ok {
			res.SetMeta("rdp_port", d)
		}
	}
}
