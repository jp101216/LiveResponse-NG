//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Access rights, buffer sizes and NTSTATUS values not exported by the stdlib
// syscall package.
const (
	processQueryLimitedInformation = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
	maxPath                        = 260    // MAX_PATH
	maxLongPath                    = 32768  // longest \\?\ path, in UTF-16 units
	processCommandLineInformation  = 60     // PROCESSINFOCLASS, Windows 8.1+
	maxCommandLineBytes            = 1 << 20
	tokenIntegrityLevel            = 25 // TOKEN_INFORMATION_CLASS TokenIntegrityLevel

	statusInfoLengthMismatch = 0xC0000004
	statusBufferTooSmall     = 0xC0000023
	statusBufferOverflow     = 0x80000005
)

// procEntry is one row of a Toolhelp process snapshot.
type procEntry struct {
	pid, ppid, threads uint32
	name               string
}

// snapshotProcesses reads the whole process table in one Toolhelp snapshot.
// Names come from the snapshot (no process handle needed), so they're
// available even for processes OpenProcess would deny.
func snapshotProcesses() ([]procEntry, error) {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	defer syscall.CloseHandle(snap)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := syscall.Process32First(snap, &pe); err != nil {
		return nil, fmt.Errorf("process32first: %w", err)
	}
	var out []procEntry
	for {
		out = append(out, procEntry{
			pid:     pe.ProcessID,
			ppid:    pe.ParentProcessID,
			threads: pe.Threads,
			name:    syscall.UTF16ToString(pe.ExeFile[:]),
		})
		if err := syscall.Process32Next(snap, &pe); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				return out, nil
			}
			return out, fmt.Errorf("process32next: %w", err)
		}
	}
}

// procNameMap builds a PID->image-name map, best-effort.
func procNameMap() map[uint32]string {
	entries, _ := snapshotProcesses()
	out := make(map[uint32]string, len(entries))
	for _, e := range entries {
		out[e.pid] = e.name
	}
	return out
}

// collectProcesses walks the process table and, for each process it can open,
// adds the full image path, command line, start time, owner, session and
// integrity level. Access denied on a protected process is expected and
// recorded per record rather than failing the run. Images are hashed after
// the table is read (the snapshot should be as close to "as found" as
// possible), and the whole set is then judged as a tree.
func collectProcesses(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("processes")

	entries, err := snapshotProcesses()
	if err != nil && len(entries) == 0 {
		return res.Finish(), err
	}
	if err != nil {
		res.Fail(err.Error()) // partial snapshot: keep what we have
	}

	names := make(map[uint32]string, len(entries))
	for _, e := range entries {
		names[e.pid] = e.name
	}
	created := make(map[uint32]time.Time, len(entries))
	owners := sidCache{}
	type row struct {
		e      procEntry
		d      procDetail
		fields map[string]any
	}
	rows := make([]row, 0, len(entries))

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		fields := map[string]any{
			"pid":     e.pid,
			"ppid":    e.ppid,
			"name":    e.name,
			"threads": e.threads,
		}
		d := queryProcess(e.pid, owners)
		if d.imagePath != "" {
			fields["image_path"] = d.imagePath
			fields["suspicious_path"] = suspiciousPath(d.imagePath)
		}
		if d.commandLine != "" {
			fields["command_line"] = d.commandLine
		}
		if !d.created.IsZero() {
			fields["created_at"] = d.created
			created[e.pid] = d.created
		}
		if d.userSID != "" {
			fields["user_sid"] = d.userSID
			if d.user != "" {
				fields["user"] = d.user
			}
		}
		if d.integrity != "" {
			fields["integrity_level"] = d.integrity
		}
		if sid, ok := processSessionID(e.pid); ok {
			fields["session_id"] = sid
		}
		if len(d.errs) > 0 {
			fields["query_errors"] = d.errs
		}
		if opts.isSelf(e.pid, d.imagePath) {
			fields["lrng_component"] = true
		}
		rows = append(rows, row{e, d, fields})
	}

	// Parent names, guarded against PID reuse: a "parent" created after its
	// child is an unrelated process that was handed the recycled PID.
	views := make([]procView, len(rows))
	for i, r := range rows {
		pid, ppid := r.e.pid, r.e.ppid
		v := procView{PID: pid, PPID: ppid, Name: r.e.name, ImagePath: r.d.imagePath, Self: opts.isSelf(pid, r.d.imagePath)}
		if pname, ok := names[ppid]; ok && ppid != pid && ppid != 0 {
			cc, pc := created[pid], created[ppid]
			if !cc.IsZero() && !pc.IsZero() && pc.After(cc) {
				r.fields["parent_pid_reused"] = true
			} else {
				r.fields["parent_name"] = pname
				v.ParentName = pname
				v.ParentVerified = !cc.IsZero() && !pc.IsZero()
			}
		}
		views[i] = v
	}

	tree := analyzeProcessTree(views, systemRoot())
	hashed := 0
	for i, r := range rows {
		findings := tree[r.e.pid]
		if !views[i].Self && r.d.commandLine != "" {
			findings = mergeFindings(findings, analyzeCommandLine(
				fmt.Sprintf("process %s (pid %d) command line", r.e.name, r.e.pid), r.d.imagePath, r.d.commandLine)...)
		}
		if r.d.imagePath != "" && ctx.Err() == nil {
			opts.Hasher.Fields(ctx, r.fields, "image", r.d.imagePath)
			if _, ok := r.fields["image_sha256"]; ok {
				hashed++
			}
			sig := opts.Signer.Fields(ctx, r.fields, r.d.imagePath)
			if !views[i].Self {
				findings = mergeFindings(findings, signatureFindings(r.d.imagePath, sig, systemRoot())...)
			}
		}
		res.Add(r.fields, findings...)
	}
	res.SetMeta("system_root", systemRoot())
	res.SetMeta("images_hashed", hashed)
	res.SetMeta("hashing", opts.Hasher != nil)
	res.SetMeta("signature_checks", opts.Signer != nil)
	if opts.Hasher != nil && ctx.Err() != nil {
		res.Fail("time budget ran out while hashing images; later records have no image_sha256")
	}
	return res.Finish(), nil
}

type procDetail struct {
	imagePath   string
	commandLine string
	created     time.Time
	userSID     string
	user        string
	integrity   string
	errs        []string
}

// queryProcess opens the process once with the least access that works for
// everything below, and reads each attribute independently so one failure
// doesn't hide the rest.
func queryProcess(pid uint32, owners sidCache) procDetail {
	var d procDetail
	if pid == 0 {
		return d // System Idle Process: not a real process
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		d.errs = append(d.errs, "open: "+err.Error())
		return d
	}
	defer syscall.CloseHandle(h)

	if p, err := queryImagePath(h); err == nil {
		d.imagePath = p
	} else {
		d.errs = append(d.errs, "image_path: "+err.Error())
	}
	if cl, err := queryCommandLine(h); err == nil {
		d.commandLine = cl
	} else {
		d.errs = append(d.errs, "command_line: "+err.Error())
	}
	var c, e, k, u syscall.Filetime
	if err := syscall.GetProcessTimes(h, &c, &e, &k, &u); err == nil {
		if ns := c.Nanoseconds(); ns > 0 {
			d.created = time.Unix(0, ns).UTC()
		}
	} else {
		d.errs = append(d.errs, "times: "+err.Error())
	}

	var tok syscall.Token
	if err := syscall.OpenProcessToken(h, syscall.TOKEN_QUERY, &tok); err != nil {
		d.errs = append(d.errs, "token: "+err.Error())
		return d
	}
	defer tok.Close()
	if sid, user, err := owners.owner(tok); err == nil {
		d.userSID, d.user = sid, user
	} else {
		d.errs = append(d.errs, "owner: "+err.Error())
	}
	if il, err := integrityLevel(tok); err == nil {
		d.integrity = il
	} else {
		d.errs = append(d.errs, "integrity: "+err.Error())
	}
	return d
}

// imagePath opens a process and returns its full image path. Used by the
// network collector for connections that matched an LLM endpoint.
func imagePath(pid uint32) (string, error) {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	return queryImagePath(h)
}

// queryImagePath calls QueryFullProcessImageNameW, retrying with a long-path
// buffer when the path is longer than MAX_PATH (deep or \\?\ paths would
// otherwise come back as an error and the path would be lost).
func queryImagePath(h syscall.Handle) (string, error) {
	for _, n := range []int{maxPath, maxLongPath} {
		buf := make([]uint16, n)
		size := uint32(len(buf))
		r1, _, e1 := procQueryFullProcessImageName.Call(
			uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
		)
		if r1 != 0 {
			return syscall.UTF16ToString(buf[:size]), nil
		}
		if !errors.Is(e1, syscall.ERROR_INSUFFICIENT_BUFFER) {
			return "", e1
		}
	}
	return "", syscall.ERROR_INSUFFICIENT_BUFFER
}

// queryCommandLine reads the process command line with
// NtQueryInformationProcess(ProcessCommandLineInformation), which works with
// PROCESS_QUERY_LIMITED_INFORMATION and doesn't need to read the target's
// memory (no PROCESS_VM_READ, no PEB walk).
func queryCommandLine(h syscall.Handle) (string, error) {
	size := uint32(1024)
	for attempt := 0; attempt < 4; attempt++ {
		// []uint64 backing guarantees the pointer alignment UNICODE_STRING needs.
		words := make([]uint64, (size+7)/8)
		buf := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		var need uint32
		st, _, _ := procNtQueryInformationProcess.Call(
			uintptr(h), processCommandLineInformation,
			uintptr(unsafe.Pointer(&words[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&need)),
		)
		switch uint32(st) {
		case 0:
			return decodeUnicodeString(buf, uintptr(unsafe.Pointer(&words[0])))
		case statusInfoLengthMismatch, statusBufferTooSmall, statusBufferOverflow:
			if need <= size {
				need = size * 2
			}
			if need > maxCommandLineBytes {
				return "", fmt.Errorf("command line larger than %d bytes", maxCommandLineBytes)
			}
			size = need
		default:
			return "", fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%08X", uint32(st))
		}
	}
	return "", errors.New("NtQueryInformationProcess: buffer kept growing")
}

// processSessionID returns the Terminal Services session a process runs in
// (0 = services, 1+ = interactive/RDP sessions).
func processSessionID(pid uint32) (uint32, bool) {
	var sid uint32
	r, _, _ := procProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sid)))
	return sid, r != 0
}

// tokenMandatoryLabel mirrors TOKEN_MANDATORY_LABEL (a SID_AND_ATTRIBUTES).
type tokenMandatoryLabel struct {
	Sid        *syscall.SID
	Attributes uint32
}

// integrityLevel names a token's mandatory integrity level (low, medium,
// high, system, ...). A high- or system-integrity shell is worth a look.
func integrityLevel(tok syscall.Token) (string, error) {
	var n uint32
	_ = syscall.GetTokenInformation(tok, tokenIntegrityLevel, nil, 0, &n)
	if n == 0 || n > 4096 {
		return "", fmt.Errorf("unexpected TokenIntegrityLevel size %d", n)
	}
	words := make([]uint64, (n+7)/8) // pointer-aligned
	buf := (*byte)(unsafe.Pointer(&words[0]))
	if err := syscall.GetTokenInformation(tok, tokenIntegrityLevel, buf, uint32(len(words)*8), &n); err != nil {
		return "", err
	}
	label := (*tokenMandatoryLabel)(unsafe.Pointer(&words[0]))
	if label.Sid == nil {
		return "", errors.New("no integrity label")
	}
	s, err := label.Sid.String()
	if err != nil {
		return "", err
	}
	return integrityName(s), nil
}

// sidCache maps a SID string to DOMAIN\user. Account lookups can be slow (a
// domain SID may need a DC), and a host has only a handful of distinct
// owners, so each SID is resolved once per run.
type sidCache map[string]string

func (c sidCache) owner(tok syscall.Token) (sid, account string, err error) {
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	sid, err = tu.User.Sid.String()
	if err != nil {
		return "", "", err
	}
	if acct, ok := c[sid]; ok {
		return sid, acct, nil
	}
	name, domain, _, lerr := tu.User.Sid.LookupAccount("")
	switch {
	case lerr != nil:
		account = "" // SID still recorded; name unresolvable (e.g. DC unreachable)
	case domain != "":
		account = domain + `\` + name
	default:
		account = name
	}
	c[sid] = account
	return sid, account, nil
}
