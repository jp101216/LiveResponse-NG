//go:build windows

package collector

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// Thread impersonation tokens: which threads, in which processes, are acting
// as an account other than their process's. Read once per run for the
// process collector (tokentheft.go judges them).

const (
	th32csSnapThread              = 0x00000004
	threadQueryInformation        = 0x0040 // THREAD_QUERY_INFORMATION
	threadQueryLimitedInformation = 0x0800 // THREAD_QUERY_LIMITED_INFORMATION
	tokenImpersonationLevelClass  = 9      // TOKEN_INFORMATION_CLASS TokenImpersonationLevel
	maxThreadsScanned             = 200000 // guard against a runaway snapshot
	errorNoToken                  = syscall.Errno(1008)
)

var (
	modadvapi32         = syscall.NewLazyDLL("advapi32.dll")
	procOpenThreadToken = modadvapi32.NewProc("OpenThreadToken")
	procOpenThread      = modkernel32.NewProc("OpenThread")
	procThread32First   = modkernel32.NewProc("Thread32First")
	procThread32Next    = modkernel32.NewProc("Thread32Next")
)

// threadEntry32 mirrors THREADENTRY32 (seven 32-bit fields on every
// architecture).
type threadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// threadTokenStats counts what the thread pass could and couldn't read.
type threadTokenStats struct {
	Threads, Impersonating, Unreadable int
	Err                                string
}

// impersonationLevels names SECURITY_IMPERSONATION_LEVEL values.
var impersonationLevels = []string{"anonymous", "identification", "impersonation", "delegation"}

// threadTokens walks every thread on the host and returns, by owning
// process, the impersonation tokens threads are wearing. Most threads have
// none (OpenThreadToken answers ERROR_NO_TOKEN). The System process's
// threads are the kernel's and are skipped, as is lrng itself.
func threadTokens(owners sidCache) (map[uint32][]threadToken, threadTokenStats) {
	var st threadTokenStats
	out := map[uint32][]threadToken{}
	snap, err := syscall.CreateToolhelp32Snapshot(th32csSnapThread, 0)
	if err != nil {
		st.Err = "thread snapshot: " + err.Error()
		return out, st
	}
	defer syscall.CloseHandle(snap)
	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if r, _, e := procThread32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&te))); r == 0 {
		st.Err = "thread32first: " + e.Error()
		return out, st
	}
	self := uint32(os.Getpid())
	for st.Threads < maxThreadsScanned {
		if pid := te.OwnerProcessID; pid > 4 && pid != self {
			st.Threads++
			switch t, err := threadToken1(te.ThreadID, owners); {
			case errors.Is(err, errorNoToken):
			case err != nil:
				st.Unreadable++
			default:
				st.Impersonating++
				out[pid] = append(out[pid], t)
			}
		}
		te.Size = uint32(unsafe.Sizeof(te))
		if r, _, _ := procThread32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&te))); r == 0 {
			break // ERROR_NO_MORE_FILES
		}
	}
	return out, st
}

// threadToken1 reads one thread's impersonation token, if it has one.
func threadToken1(tid uint32, owners sidCache) (threadToken, error) {
	var h uintptr
	for _, access := range []uintptr{threadQueryInformation, threadQueryLimitedInformation} {
		var e error
		if h, _, e = procOpenThread.Call(access, 0, uintptr(tid)); h != 0 {
			break
		} else if !errors.Is(e, syscall.ERROR_ACCESS_DENIED) {
			return threadToken{}, e
		}
	}
	if h == 0 {
		return threadToken{}, syscall.ERROR_ACCESS_DENIED
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	var tok syscall.Token
	// OpenAsSelf: check access to the token as lrng, not as whoever the
	// thread is impersonating.
	if r, _, e := procOpenThreadToken.Call(h, syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&tok))); r == 0 {
		return threadToken{}, e
	}
	defer tok.Close()
	t := threadToken{TID: tid}
	sid, account, err := owners.owner(tok)
	if err != nil {
		return threadToken{}, err
	}
	t.SID, t.User = sid, account
	var level, n uint32
	if err := syscall.GetTokenInformation(tok, tokenImpersonationLevelClass, (*byte)(unsafe.Pointer(&level)), 4, &n); err == nil &&
		int(level) < len(impersonationLevels) {
		t.Level = impersonationLevels[level]
	}
	return t, nil
}
