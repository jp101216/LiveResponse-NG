//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

var (
	modnetapi32                 = syscall.NewLazyDLL("netapi32.dll")
	procNetUserEnum             = modnetapi32.NewProc("NetUserEnum")
	procNetLocalGroupGetMembers = modnetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFree        = modnetapi32.NewProc("NetApiBufferFree")
)

// userInfo3 mirrors USER_INFO_3 (NetUserEnum level 3). Pointers and DWORDs
// interleave exactly as in lmaccess.h, so Go's alignment reproduces the C
// layout on both 32- and 64-bit.
type userInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

// userInfo1 mirrors USER_INFO_1, the fallback when level 3 is refused.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// localGroupMembersInfo2 mirrors LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	Sid           *syscall.SID
	SidUsage      uint32
	DomainAndName *uint16
}

const (
	errMoreDataNet      = 234        // ERROR_MORE_DATA
	filterNormalAccount = 0x0002     // FILTER_NORMAL_ACCOUNT
	maxPreferredLength  = 0xFFFFFFFF // MAX_PREFERRED_LENGTH
	specialAccountsKey  = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
)

// privilegedGroups are the built-in groups whose membership matters for
// triage, by SID so the check works on localized Windows.
var privilegedGroups = []struct{ sid, fallback string }{
	{"S-1-5-32-544", "Administrators"},
	{"S-1-5-32-555", "Remote Desktop Users"},
	{"S-1-5-32-580", "Remote Management Users"},
	{"S-1-5-32-551", "Backup Operators"},
}

func collectLocalAccounts(ctx context.Context) (Result, error) {
	res := NewResult("localaccounts")
	hidden := hiddenFromLogon(res)
	users, level, err := enumLocalUsers()
	if err != nil {
		res.Fail(err.Error())
	}
	res.SetMeta("netuserenum_level", level)
	res.SetMeta("local_user_count", len(users))
	if len(hidden) > 0 {
		res.SetMeta("hidden_from_logon_screen", hidden)
	}
	for _, u := range users {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		_, isHidden := hidden[strings.ToLower(u.Name)]
		fields, findings := accountRecord(u, isHidden, time.Now())
		res.Add(fields, findings...)
	}
	addLocalGroupMembers(ctx, res)
	return res.Finish(), nil
}

// enumLocalUsers lists normal local accounts at the most detailed level the
// host allows: level 3 (logons, password age, RID) needs administrator
// rights; level 1 is the fallback.
func enumLocalUsers() ([]localUser, int, error) {
	var lastErr error
	for _, level := range []uint32{3, 1} {
		var buf unsafe.Pointer
		var read, total, resume uint32
		r, _, _ := procNetUserEnum.Call(
			0, uintptr(level), filterNormalAccount,
			uintptr(unsafe.Pointer(&buf)), uintptr(uint32(maxPreferredLength)),
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)),
		)
		// ERROR_MORE_DATA still returns the entries that fit; with
		// MAX_PREFERRED_LENGTH it shouldn't happen, but if it does, keep them.
		if r != 0 && r != errMoreDataNet {
			if buf != nil {
				procNetApiBufferFree.Call(uintptr(buf))
			}
			lastErr = fmt.Errorf("NetUserEnum level %d: %s", level, win32Error(r))
			continue
		}
		if buf == nil {
			return nil, int(level), nil
		}
		var out []localUser
		if level == 3 {
			for _, u := range unsafe.Slice((*userInfo3)(buf), read) {
				out = append(out, localUser{
					Name: utf16PtrToString(u.Name), FullName: utf16PtrToString(u.FullName),
					Comment: utf16PtrToString(u.Comment), Priv: u.Priv, Flags: u.Flags,
					PasswordAge: u.PasswordAge, LastLogon: u.LastLogon, AcctExpires: u.AcctExpires,
					BadPwCount: u.BadPwCount, NumLogons: u.NumLogons, RID: u.UserID,
					PasswordExpired: u.PasswordExpired != 0, Detailed: true,
				})
			}
		} else {
			for _, u := range unsafe.Slice((*userInfo1)(buf), read) {
				out = append(out, localUser{
					Name: utf16PtrToString(u.Name), Comment: utf16PtrToString(u.Comment),
					Priv: u.Priv, Flags: u.Flags, PasswordAge: u.PasswordAge,
				})
			}
		}
		procNetApiBufferFree.Call(uintptr(buf))
		return out, int(level), nil
	}
	return nil, 0, lastErr
}

// hiddenFromLogon reads Winlogon\SpecialAccounts\UserList: accounts set to 0
// there don't appear on the sign-in screen (T1564.002).
func hiddenFromLogon(res *Result) map[string]bool {
	k, err := winreg.Open(winreg.LocalMachine, specialAccountsKey)
	if err != nil {
		if !winreg.IsNotExist(err) {
			res.Fail(`HKLM\` + specialAccountsKey + ": " + err.Error())
		}
		return nil
	}
	defer k.Close()
	vals, _ := k.Values()
	out := map[string]bool{}
	for _, v := range vals {
		if d, ok := v.Uint32(); ok && d == 0 {
			out[strings.ToLower(v.Name)] = true
		}
	}
	return out
}

// addLocalGroupMembers records the membership of the privileged built-in
// groups, resolving each group's localized name from its SID.
func addLocalGroupMembers(ctx context.Context, res *Result) {
	for _, g := range privilegedGroups {
		if ctx.Err() != nil {
			return
		}
		name := g.fallback
		if sid, err := syscall.StringToSid(g.sid); err == nil {
			if n, _, _, err := sid.LookupAccount(""); err == nil && n != "" {
				name = n
			}
		}
		members, err := localGroupMembers(name)
		if err != nil {
			continue // group may not exist on this host (e.g. a client SKU)
		}
		for _, m := range members {
			f := map[string]any{"kind": "group_member", "group": name, "group_sid": g.sid, "member": m.name}
			if m.sid != "" {
				f["member_sid"] = m.sid
			}
			if m.usage != "" {
				f["member_type"] = m.usage
			}
			res.Add(f)
		}
	}
}

type groupMember struct{ name, sid, usage string }

// localGroupMembers returns every member of a local group with its SID.
func localGroupMembers(group string) ([]groupMember, error) {
	gp, err := syscall.UTF16PtrFromString(group)
	if err != nil {
		return nil, err
	}
	var buf unsafe.Pointer
	var read, total uint32
	var resume uintptr // PDWORD_PTR
	r, _, _ := procNetLocalGroupGetMembers.Call(
		0, uintptr(unsafe.Pointer(gp)), 2,
		uintptr(unsafe.Pointer(&buf)), uintptr(uint32(maxPreferredLength)),
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)),
	)
	if r != 0 && r != errMoreDataNet {
		return nil, fmt.Errorf("NetLocalGroupGetMembers(%s): %s", group, win32Error(r))
	}
	if buf == nil {
		return nil, nil
	}
	defer procNetApiBufferFree.Call(uintptr(buf))
	out := make([]groupMember, 0, read)
	for _, m := range unsafe.Slice((*localGroupMembersInfo2)(buf), read) {
		gm := groupMember{name: utf16PtrToString(m.DomainAndName), usage: sidUsageName(m.SidUsage)}
		if m.Sid != nil {
			gm.sid, _ = m.Sid.String()
		}
		if gm.name == "" {
			gm.name = gm.sid // orphaned SID: the account no longer resolves
		}
		out = append(out, gm)
	}
	return out, nil
}
