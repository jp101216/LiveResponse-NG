//go:build linux

package collector

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// bpf(2) commands used here (enum bpf_cmd).
const (
	bpfCmdObjGet         = 7
	bpfCmdProgGetNextID  = 11
	bpfCmdProgGetFdByID  = 13
	bpfCmdObjGetInfoByFd = 15

	maxBPFProgs     = 4096
	maxBPFPinWalk   = 10000
	maxXlatedLength = 16 << 20
)

// sysBPF is the bpf(2) syscall number; Go's syscall package only names it
// for some architectures.
func sysBPF() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 321
	case "arm64", "riscv64", "loong64":
		return 280
	case "ppc64", "ppc64le":
		return 361
	case "s390x":
		return 351
	}
	return 0
}

// bpf_attr layouts. Pointers are unsafe.Pointer so the garbage collector keeps
// the buffers the kernel reads and writes alive; on the 64-bit platforms this
// file runs on they fill the ABI's __aligned_u64 slots exactly.
type bpfAttrID struct {
	id        uint32 // start_id / prog_id
	nextID    uint32
	openFlags uint32
}

type bpfAttrInfo struct {
	fd      uint32
	infoLen uint32
	info    unsafe.Pointer
}

type bpfAttrObjGet struct {
	pathname  unsafe.Pointer
	fd        uint32
	fileFlags uint32
	pathFD    int32
	_         uint32
}

// bpfProgInfo is struct bpf_prog_info: the fields read here, at their uapi
// offsets, padded to 256 bytes (the kernel copies min(its size, infoLen) and
// requires anything past its own size to be zero).
type bpfProgInfo struct {
	progType        uint32         // 0
	id              uint32         // 4
	tag             [8]byte        // 8
	jitedProgLen    uint32         // 16
	xlatedProgLen   uint32         // 20
	jitedProgInsns  uint64         // 24
	xlatedProgInsns unsafe.Pointer // 32
	loadTime        uint64         // 40: ns since boot
	createdByUID    uint32         // 48
	nrMapIDs        uint32         // 52
	mapIDs          uint64         // 56
	name            [16]byte       // 64
	ifindex         uint32         // 80
	gplCompatible   uint32         // 84 (bit 0)
	_               [104]byte      // 88..192
	runTimeNs       uint64         // 192
	runCnt          uint64         // 200
	_               [48]byte       // 208..256
}

func bpfCall(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r, _, e := syscall.Syscall(sysBPF(), uintptr(cmd), uintptr(attr), size)
	if e != 0 {
		return r, e
	}
	return r, nil
}

// bpfProgIDs walks the IDs of every loaded program.
func bpfProgIDs() ([]uint32, error) {
	var ids []uint32
	attr := &bpfAttrID{}
	for len(ids) < maxBPFProgs {
		_, err := bpfCall(bpfCmdProgGetNextID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
		if errors.Is(err, syscall.ENOENT) {
			break
		}
		if err != nil {
			return ids, err
		}
		ids = append(ids, attr.nextID)
		attr.id = attr.nextID
	}
	return ids, nil
}

// bpfProgDetail reads one program's info and translated instructions.
func bpfProgDetail(id uint32) (*bpfProgInfo, []byte, error) {
	attr := &bpfAttrID{id: id}
	fd, err := bpfCall(bpfCmdProgGetFdByID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, nil, err
	}
	defer syscall.Close(int(fd))

	info := &bpfProgInfo{}
	ia := &bpfAttrInfo{fd: uint32(fd), infoLen: uint32(unsafe.Sizeof(*info)), info: unsafe.Pointer(info)}
	if _, err := bpfCall(bpfCmdObjGetInfoByFd, unsafe.Pointer(ia), unsafe.Sizeof(*ia)); err != nil {
		return nil, nil, err
	}
	n := info.xlatedProgLen
	if n == 0 || n > maxXlatedLength {
		return info, nil, nil
	}
	// A second call fills only the instruction buffer: every other length is
	// left at zero so the kernel writes nothing else.
	insns := make([]byte, n)
	second := &bpfProgInfo{xlatedProgLen: n, xlatedProgInsns: unsafe.Pointer(&insns[0])}
	ia = &bpfAttrInfo{fd: uint32(fd), infoLen: uint32(unsafe.Sizeof(*second)), info: unsafe.Pointer(second)}
	if _, err := bpfCall(bpfCmdObjGetInfoByFd, unsafe.Pointer(ia), unsafe.Sizeof(*ia)); err != nil {
		return info, nil, err
	}
	runtime.KeepAlive(insns)
	if second.xlatedProgLen < n {
		insns = insns[:second.xlatedProgLen]
	}
	return info, insns, nil
}

// bpfPinned walks the bpf filesystems and returns the paths that keep each
// program alive (ID -> paths: the program pinned itself, or a link attaching
// it), the other pinned objects (maps, links) and how many objects it found.
func bpfPinned(mounts []string) (map[uint32][]string, []map[string]any, int) {
	progs := map[uint32][]string{}
	var others []map[string]any
	seen, found := 0, 0
	for _, m := range mounts {
		_ = filepath.WalkDir(m, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if seen++; seen > maxBPFPinWalk {
				return filepath.SkipAll
			}
			path, err := syscall.BytePtrFromString(p)
			if err != nil {
				return nil
			}
			attr := &bpfAttrObjGet{pathname: unsafe.Pointer(path), fileFlags: syscall.O_RDONLY}
			fd, err := bpfCall(bpfCmdObjGet, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
			runtime.KeepAlive(path)
			if err != nil {
				return nil
			}
			info, _ := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
			syscall.Close(int(fd))
			obj := classifyPinned(info)
			switch obj.kind {
			case "link":
				o := map[string]any{"kind": "pinned_link", "path": p, "link_id": obj.kv["link_id"], "link_type": obj.kv["link_type"]}
				if obj.hasProg {
					o["prog_id"] = obj.progID
					progs[obj.progID] = append(progs[obj.progID], p) // it keeps the program attached
				}
				others = append(others, o)
			case "program":
				progs[obj.progID] = append(progs[obj.progID], p)
			case "map":
				others = append(others, map[string]any{"kind": "pinned_map", "path": p, "map_id": obj.kv["map_id"], "map_type": obj.kv["map_type"]})
			default:
				return nil
			}
			found++
			return nil
		})
	}
	return progs, others, found
}

// bootTime is when the system booted, from /proc/stat's btime.
func bootTime() time.Time {
	data, _ := os.ReadFile("/proc/stat")
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(s, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func collectEBPF(ctx context.Context) (Result, error) {
	res := NewResult("ebpf")
	if unsafe.Sizeof(uintptr(0)) != 8 || sysBPF() == 0 {
		res.Fail("eBPF enumeration is implemented for 64-bit Linux on amd64, arm64, riscv64, loong64, ppc64 and s390x")
		return res.Finish(), nil
	}
	ids, err := bpfProgIDs()
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			res.Fail("listing eBPF programs needs root (CAP_SYS_ADMIN or CAP_BPF): " + err.Error())
		} else {
			res.Fail("bpf(BPF_PROG_GET_NEXT_ID): " + err.Error())
		}
	}

	kallsyms, kerr := readCapped("/proc/kallsyms", kallsymsMaxLen)
	syms := parseKallsyms(kallsyms)
	if kerr != nil || syms.callBase == 0 {
		res.SetMeta("helper_names", "unavailable: /proc/kallsyms is unreadable, hides addresses (kernel.kptr_restrict), or lacks __bpf_call_base")
	}
	mountinfo, _ := os.ReadFile("/proc/self/mountinfo")
	mounts := bpffsMounts(mountinfo)
	pins, pinnedOthers, pinned := bpfPinned(mounts)
	booted := bootTime()

	risky := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		info, insns, err := bpfProgDetail(id)
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				continue // unloaded since it was listed
			}
			res.Fail(fmt.Sprintf("program %d: %v", id, err))
			continue
		}
		p := bpfProg{
			ID:      info.id,
			Type:    bpfProgTypeName(info.progType),
			Name:    strings.TrimRight(string(info.name[:]), "\x00"),
			UID:     info.createdByUID,
			Helpers: syms.helperNames(helperCallOffsets(insns)),
			Pins:    pins[info.id],
		}
		fields := map[string]any{
			"kind": "program", "id": p.ID, "type": p.Type, "tag": hex.EncodeToString(info.tag[:]),
			"loaded_by_uid": p.UID, "xlated_bytes": info.xlatedProgLen, "maps": info.nrMapIDs,
			"gpl_compatible": info.gplCompatible&1 == 1,
		}
		if p.Name != "" {
			fields["name"] = p.Name
		}
		if !booted.IsZero() && info.loadTime > 0 {
			fields["loaded_at"] = booted.Add(time.Duration(info.loadTime)) // a time.Time, so -timeline places it
		}
		if len(p.Helpers) > 0 {
			fields["helpers"] = p.Helpers
		}
		if len(p.Pins) > 0 {
			fields["pinned"] = p.Pins
		}
		if info.runCnt > 0 {
			fields["run_count"] = info.runCnt
		}
		findings := judgeBPFProg(p)
		if len(findings) > 0 {
			risky++
		}
		res.Add(fields, findings...)
	}
	for _, o := range pinnedOthers {
		res.Add(o)
	}

	res.SetMeta("programs", len(ids))
	res.SetMeta("programs_flagged", risky)
	res.SetMeta("bpffs_mounts", mounts)
	res.SetMeta("pinned_objects", pinned)
	return res.Finish(), nil
}

// readCapped reads a file up to max bytes.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 0, 4<<20)
	for int64(len(buf)) < max {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := f.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			break
		}
	}
	return buf, nil
}
