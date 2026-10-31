//go:build linux

package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"unsafe"
)

// The bpf_prog_info fields read must sit at their uapi offsets.
func TestBPFProgInfoLayout(t *testing.T) {
	var i bpfProgInfo
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"xlated_prog_len", unsafe.Offsetof(i.xlatedProgLen), 20},
		{"xlated_prog_insns", unsafe.Offsetof(i.xlatedProgInsns), 32},
		{"load_time", unsafe.Offsetof(i.loadTime), 40},
		{"created_by_uid", unsafe.Offsetof(i.createdByUID), 48},
		{"nr_map_ids", unsafe.Offsetof(i.nrMapIDs), 52},
		{"name", unsafe.Offsetof(i.name), 64},
		{"gpl_compatible", unsafe.Offsetof(i.gplCompatible), 84},
		{"run_time_ns", unsafe.Offsetof(i.runTimeNs), 192},
		{"run_cnt", unsafe.Offsetof(i.runCnt), 200},
		{"sizeof", unsafe.Sizeof(i), 256},
	}
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the eBPF collector runs on 64-bit Linux")
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s at %d, uapi has %d", c.name, c.got, c.want)
		}
	}
}

// bpfAttrLoad is the BPF_PROG_LOAD part of bpf_attr.
type bpfAttrLoad struct {
	progType           uint32
	insnCnt            uint32
	insns              unsafe.Pointer
	license            unsafe.Pointer
	logLevel           uint32
	logSize            uint32
	logBuf             unsafe.Pointer
	kernVersion        uint32
	progFlags          uint32
	progName           [16]byte
	progIfindex        uint32
	expectedAttachType uint32
	_                  [56]byte
}

// loadSelftestProg loads an inert socket-filter program, "lrng_selftest",
// that calls two benign helpers (bpf_get_prandom_u32 = 7, bpf_ktime_get_ns =
// 5) and returns 0. It is never attached to anything.
func loadSelftestProg(t *testing.T) int {
	t.Helper()
	var prog []byte
	prog = append(prog, insn(bpfOpCall, 0, 7)...)
	prog = append(prog, insn(bpfOpCall, 0, 5)...)
	prog = append(prog, insn(0xb7, 0, 0)...) // mov r0, 0
	prog = append(prog, insn(0x95, 0, 0)...) // exit
	license := []byte("GPL\x00")
	attr := &bpfAttrLoad{progType: 1, insnCnt: uint32(len(prog) / 8),
		insns: unsafe.Pointer(&prog[0]), license: unsafe.Pointer(&license[0])}
	copy(attr.progName[:], "lrng_selftest")
	fd, err := bpfCall(5, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	runtime.KeepAlive(prog)
	runtime.KeepAlive(license)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOSYS) {
			t.Skipf("can't load eBPF programs here: %v", err)
		}
		t.Fatalf("BPF_PROG_LOAD: %v", err)
	}
	return int(fd)
}

// TestCollectEBPFLive checks the whole chain against the running kernel:
// enumeration, the translated-instruction dump, helper-call decoding,
// __bpf_call_base arithmetic, the kallsyms lookup and the pin walk.
func TestCollectEBPFLive(t *testing.T) {
	if os.Geteuid() != 0 || sysBPF() == 0 || unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("needs root on 64-bit Linux")
	}
	fd := loadSelftestProg(t)
	defer syscall.Close(fd)

	// Pin it in a private bpffs, when one can be mounted here.
	pin := ""
	dir := t.TempDir()
	if err := syscall.Mount("bpf", dir, "bpf", 0, "mode=700"); err == nil {
		defer syscall.Unmount(dir, 0)
		p := filepath.Join(dir, "lrng_selftest")
		path, _ := syscall.BytePtrFromString(p)
		attr := &bpfAttrObjGet{pathname: unsafe.Pointer(path), fd: uint32(fd)}
		if _, err := bpfCall(6, unsafe.Pointer(attr), unsafe.Sizeof(*attr)); err == nil {
			pin = p
			defer os.Remove(p)
		}
		runtime.KeepAlive(path)
	} else {
		t.Logf("no private bpffs (%v): pin association not exercised", err)
	}

	res, err := collectEBPF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ours *Record
	for i, r := range res.Records {
		if r.Fields["name"] == "lrng_selftest" {
			ours = &res.Records[i]
		}
	}
	if ours == nil {
		t.Fatalf("test program not listed (errors %v, %d records)", res.Errors, len(res.Records))
	}
	if ours.Fields["type"] != "socket_filter" || ours.Fields["loaded_by_uid"] != uint32(0) {
		t.Fatalf("fields: %+v", ours.Fields)
	}
	helpers, _ := ours.Fields["helpers"].([]string)
	if res.Meta["helper_names"] == nil {
		// kallsyms is readable: both calls must land on named kernel functions.
		if len(helpers) != 2 || !contains(helpers, "bpf_ktime_get_ns") {
			t.Fatalf("helpers %v", helpers)
		}
		for _, h := range helpers {
			if len(h) > 7 && h[:7] == "helper@" {
				t.Fatalf("unresolved helper %s", h)
			}
		}
	}
	if len(ours.Findings) != 0 {
		t.Errorf("a benign program was flagged: %+v", ours.Findings)
	}
	if pin != "" {
		if pins, _ := ours.Fields["pinned"].([]string); len(pins) != 1 || pins[0] != pin {
			t.Errorf("pin %q not associated: %v", pin, ours.Fields["pinned"])
		}
	}
	t.Logf("lrng_selftest: %+v", ours.Fields)
}
