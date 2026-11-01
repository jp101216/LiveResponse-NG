//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	modsecur32                         = syscall.NewLazyDLL("secur32.dll")
	procLsaConnectUntrusted            = modsecur32.NewProc("LsaConnectUntrusted")
	procLsaRegisterLogonProcess        = modsecur32.NewProc("LsaRegisterLogonProcess")
	procLsaDeregisterLogonProcess      = modsecur32.NewProc("LsaDeregisterLogonProcess")
	procLsaLookupAuthenticationPackage = modsecur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPackage   = modsecur32.NewProc("LsaCallAuthenticationPackage")
	procLsaFreeReturnBuffer            = modsecur32.NewProc("LsaFreeReturnBuffer")
	procLsaEnumerateLogonSessions      = modsecur32.NewProc("LsaEnumerateLogonSessions")
	procLsaGetLogonSessionData         = modsecur32.NewProc("LsaGetLogonSessionData")
)

type lsaString struct {
	Length, MaximumLength uint16
	Buffer                *byte
}

type lsaLUID struct {
	Low  uint32
	High int32
}

type lsaUnicode struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

func (u lsaUnicode) String() string {
	if u.Buffer == nil || u.Length == 0 {
		return ""
	}
	return string(utf16.Decode(unsafe.Slice(u.Buffer, u.Length/2)))
}

// securityLogonSessionData is the start of SECURITY_LOGON_SESSION_DATA.
type securityLogonSessionData struct {
	Size                  uint32
	LogonID               lsaLUID
	UserName              lsaUnicode
	LogonDomain           lsaUnicode
	AuthenticationPackage lsaUnicode
	LogonType             uint32
}

// kerbQueryTktCacheRequest is KERB_QUERY_TKT_CACHE_REQUEST.
type kerbQueryTktCacheRequest struct {
	MessageType uint32
	LogonID     lsaLUID
}

// kerbTicketCacheInfoEx is KERB_TICKET_CACHE_INFO_EX.
type kerbTicketCacheInfoEx struct {
	ClientName, ClientRealm, ServerName, ServerRealm lsaUnicode
	StartTime, EndTime, RenewTime                    int64
	EncryptionType                                   int32
	TicketFlags                                      uint32
}

const kerbQueryTicketCacheExMessage = 14

func newLsaString(s string) lsaString {
	b := append([]byte(s), 0)
	return lsaString{Length: uint16(len(s)), MaximumLength: uint16(len(b)), Buffer: &b[0]}
}

func ntStatus(st uintptr) error {
	if st == 0 {
		return nil
	}
	return fmt.Errorf("NTSTATUS 0x%08X", uint32(st))
}

// filetimeTime converts a FILETIME count (100 ns since 1601) to a time.
func filetimeTime(ft int64) time.Time {
	if ft <= 0 || ft == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	return time.Unix(0, (ft-116444736000000000)*100).UTC()
}

func collectKerberos(ctx context.Context) (Result, error) {
	res := NewResult("kerberos")
	var lsa syscall.Handle
	trusted := false
	name := newLsaString("lrng")
	var mode uint32
	if st, _, _ := procLsaRegisterLogonProcess.Call(uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&lsa)),
		uintptr(unsafe.Pointer(&mode))); st == 0 {
		trusted = true
		defer procLsaDeregisterLogonProcess.Call(uintptr(lsa))
	} else if st, _, _ := procLsaConnectUntrusted.Call(uintptr(unsafe.Pointer(&lsa))); st != 0 {
		return res.Finish(), fmt.Errorf("LsaConnectUntrusted: %v", ntStatus(st))
	} else {
		defer procLsaDeregisterLogonProcess.Call(uintptr(lsa))
	}
	res.SetMeta("all_sessions", trusted)
	if !trusted {
		res.SetMeta("note", "not running as SYSTEM: only the agent's own logon session's tickets can be read")
	}

	pkgName := newLsaString("Kerberos")
	var pkg uint32
	if st, _, _ := procLsaLookupAuthenticationPackage.Call(uintptr(lsa), uintptr(unsafe.Pointer(&pkgName)), uintptr(unsafe.Pointer(&pkg))); st != 0 {
		return res.Finish(), fmt.Errorf("LsaLookupAuthenticationPackage(Kerberos): %v", ntStatus(st))
	}

	sessions, err := logonSessions()
	if err != nil {
		res.Fail("logon sessions: " + err.Error())
	}
	var out []kerbSessionTickets
	unreadable := 0
	for _, s := range sessions {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		tickets, err := sessionTickets(lsa, pkg, s.LogonID)
		if err != nil {
			unreadable++
			continue
		}
		out = append(out, kerbSessionTickets{Session: s, Tickets: tickets})
	}
	res.SetMeta("sessions", len(sessions))
	res.SetMeta("sessions_unreadable", unreadable)
	kerberosReport(res, out)
	return res.Finish(), nil
}

// logonSessions lists the host's logon sessions with their accounts.
func logonSessions() ([]logonSession, error) {
	var count uint32
	var list unsafe.Pointer
	if st, _, _ := procLsaEnumerateLogonSessions.Call(uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list))); st != 0 {
		return nil, ntStatus(st)
	}
	defer procLsaFreeReturnBuffer.Call(uintptr(list))
	luids := unsafe.Slice((*lsaLUID)(list), count)
	out := make([]logonSession, 0, count)
	for i := range luids {
		id := luids[i]
		s := logonSession{LogonID: uint64(uint32(id.High))<<32 | uint64(id.Low)}
		var data unsafe.Pointer
		if st, _, _ := procLsaGetLogonSessionData.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&data))); st == 0 && data != nil {
			d := (*securityLogonSessionData)(data)
			s.User, s.Domain, s.Package, s.LogonType = d.UserName.String(), d.LogonDomain.String(), d.AuthenticationPackage.String(), d.LogonType
			procLsaFreeReturnBuffer.Call(uintptr(data))
		}
		out = append(out, s)
	}
	return out, nil
}

// sessionTickets reads one session's ticket cache (metadata only).
func sessionTickets(lsa syscall.Handle, pkg uint32, logonID uint64) ([]kerbTicket, error) {
	req := kerbQueryTktCacheRequest{MessageType: kerbQueryTicketCacheExMessage,
		LogonID: lsaLUID{Low: uint32(logonID), High: int32(logonID >> 32)}}
	var ret unsafe.Pointer
	var retLen uint32
	var protocol uintptr
	st, _, _ := procLsaCallAuthenticationPackage.Call(uintptr(lsa), uintptr(pkg), uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req), uintptr(unsafe.Pointer(&ret)), uintptr(unsafe.Pointer(&retLen)), uintptr(unsafe.Pointer(&protocol)))
	if ret != nil {
		defer procLsaFreeReturnBuffer.Call(uintptr(ret))
	}
	if st != 0 {
		return nil, ntStatus(st)
	}
	if uint32(protocol) != 0 {
		return nil, ntStatus(protocol)
	}
	if ret == nil || retLen < 8 {
		return nil, errors.New("empty response")
	}
	count := *(*uint32)(unsafe.Add(ret, 4))
	size := unsafe.Sizeof(kerbTicketCacheInfoEx{})
	if uintptr(retLen) < 8+uintptr(count)*size {
		return nil, fmt.Errorf("response of %d bytes is too short for %d tickets", retLen, count)
	}
	infos := unsafe.Slice((*kerbTicketCacheInfoEx)(unsafe.Add(ret, 8)), count)
	out := make([]kerbTicket, 0, count)
	for _, in := range infos {
		out = append(out, kerbTicket{
			Client: in.ClientName.String(), ClientRealm: in.ClientRealm.String(),
			Server: in.ServerName.String(), ServerRealm: in.ServerRealm.String(),
			Start: filetimeTime(in.StartTime), End: filetimeTime(in.EndTime), Renew: filetimeTime(in.RenewTime),
			EncryptionType: in.EncryptionType, Flags: in.TicketFlags,
		})
	}
	return out, nil
}
