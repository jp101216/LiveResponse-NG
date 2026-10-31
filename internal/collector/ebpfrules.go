package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// eBPF heuristics (T1014 Rootkit). An eBPF program runs inside the kernel,
// and a few of its helpers let one change what user space sees or does:
// bpf_probe_write_user writes into a process's memory (the eBPF rootkits'
// tool for rewriting what a process reads), bpf_override_return makes a kernel
// function return a chosen value, bpf_send_signal kills or stops processes.
// ebpf_linux.go collects the loaded programs and their translated
// instructions; this file finds each helper call, names it through
// /proc/kallsyms the way bpftool does, and judges the program. No build tag:
// pure logic, unit-tested on any OS.

const (
	bpfInsnSize    = 8
	bpfOpCall      = 0x85 // BPF_JMP | BPF_CALL
	bpfOpLdImm64   = 0x18 // BPF_LD | BPF_IMM | BPF_DW: a two-slot instruction
	bpfSrcHelper   = 0    // src_reg of a helper call (1 = bpf-to-bpf, 2 = kfunc)
	kallsymsMaxLen = 64 << 20
)

// littleEndian reports the host byte order; the translated instructions the
// kernel hands back are in it.
var littleEndian = binary.NativeEndian.Uint16([]byte{1, 0}) == 1

// helperCallOffsets returns the immediate of every helper call in a program's
// translated (xlated) instructions. After verification that immediate is the
// helper's kernel address minus __bpf_call_base.
func helperCallOffsets(insns []byte) []int32 {
	var out []int32
	for i := 0; i+bpfInsnSize <= len(insns); i += bpfInsnSize {
		switch insns[i] {
		case bpfOpLdImm64:
			i += bpfInsnSize // its second slot is data, not an instruction
		case bpfOpCall:
			src := insns[i+1] >> 4
			if !littleEndian {
				src = insns[i+1] & 0x0f
			}
			if src == bpfSrcHelper {
				out = append(out, int32(binary.NativeEndian.Uint32(insns[i+4:i+8])))
			}
		}
	}
	return out
}

// kernelSyms is the kernel's text-symbol table from /proc/kallsyms.
type kernelSyms struct {
	callBase uint64            // address of __bpf_call_base (0 if unknown)
	byAddr   map[uint64]string // address -> symbol
}

// parseKallsyms reads /proc/kallsyms ("ffffffff814e5e90 T bpf_probe_write_user").
// Addresses read as zero when kptr_restrict hides them; then nothing resolves.
func parseKallsyms(data []byte) kernelSyms {
	ks := kernelSyms{byAddr: map[uint64]string{}}
	for len(data) > 0 {
		line := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			data = nil
		}
		f := bytes.Fields(line)
		if len(f) < 3 || len(f[1]) != 1 || !bytes.ContainsAny(f[1], "tTwW") {
			continue
		}
		addr, err := strconv.ParseUint(string(f[0]), 16, 64)
		if err != nil || addr == 0 {
			continue
		}
		name := string(f[2])
		if name == "__bpf_call_base" {
			ks.callBase = addr
		}
		// Several names can share an address; a helper's own (bpf_*) wins.
		if prev, ok := ks.byAddr[addr]; !ok || (!strings.HasPrefix(prev, "bpf_") && strings.HasPrefix(name, "bpf_")) {
			ks.byAddr[addr] = name
		}
	}
	return ks
}

// helperNames names a program's helper calls (sorted, unique). A call that
// doesn't land on a known symbol is shown by address.
func (ks kernelSyms) helperNames(offsets []int32) []string {
	if ks.callBase == 0 || len(offsets) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, off := range offsets {
		addr := ks.callBase + uint64(int64(off))
		name, ok := ks.byAddr[addr]
		if !ok {
			name = fmt.Sprintf("helper@0x%x", addr)
		}
		seen[name] = true
	}
	return sortedKeys(seen)
}

// bpfProg is one loaded eBPF program as the heuristics see it.
type bpfProg struct {
	ID      uint32
	Type    string
	Name    string
	UID     uint32
	Helpers []string // kernel functions its helper calls land on
	Pins    []string // bpffs paths it is pinned at (it outlives its loader)
}

// bpfProgTypes names enum bpf_prog_type.
var bpfProgTypes = []string{
	"unspec", "socket_filter", "kprobe", "sched_cls", "sched_act", "tracepoint",
	"xdp", "perf_event", "cgroup_skb", "cgroup_sock", "lwt_in", "lwt_out",
	"lwt_xmit", "sock_ops", "sk_skb", "cgroup_device", "sk_msg", "raw_tracepoint",
	"cgroup_sock_addr", "lwt_seg6local", "lirc_mode2", "sk_reuseport",
	"flow_dissector", "cgroup_sysctl", "raw_tracepoint_writable", "cgroup_sockopt",
	"tracing", "struct_ops", "ext", "lsm", "sk_lookup", "syscall", "netfilter",
}

func bpfProgTypeName(t uint32) string {
	if int(t) < len(bpfProgTypes) {
		return bpfProgTypes[t]
	}
	return "type_" + strconv.Itoa(int(t))
}

// riskyBPFHelpers are the kernel functions behind the helpers that let a
// program act on user space, keyed by symbol.
var riskyBPFHelpers = map[string]struct {
	rule string
	sev  Severity
	conf int
	what string
}{
	"bpf_probe_write_user": {"persistence.ebpf_write_user", SevSuspect, 75,
		"writes into user-space memory (bpf_probe_write_user), the helper eBPF rootkits use to rewrite what processes read; the kernel warns whenever one is loaded"},
	"bpf_override_return": {"persistence.ebpf_override_return", SevSuspect, 70,
		"overrides kernel functions' return values (bpf_override_return), which can make syscalls fail or lie"},
	"bpf_send_signal": {"persistence.ebpf_send_signal", SevNotable, 40,
		"sends signals to the task it runs in (bpf_send_signal); runtime-enforcement tools use this as well"},
	"bpf_send_signal_thread": {"persistence.ebpf_send_signal", SevNotable, 40,
		"sends signals to the task it runs in (bpf_send_signal_thread); runtime-enforcement tools use this as well"},
}

// judgeBPFProg grades one loaded program by the helpers it calls.
func judgeBPFProg(p bpfProg) []Finding {
	label := fmt.Sprintf("eBPF %s program %q (id %d, loaded by uid %d)", p.Type, p.Name, p.ID, p.UID)
	if len(p.Pins) > 0 {
		label += ", pinned at " + strings.Join(p.Pins, ", ") + " so it outlives its loader,"
	}
	var out []Finding
	seen := map[string]bool{}
	for _, h := range p.Helpers {
		r, ok := riskyBPFHelpers[h]
		if !ok || seen[r.rule] {
			continue
		}
		seen[r.rule] = true
		out = append(out, Finding{Rule: r.rule, Severity: r.sev, Technique: "T1014", Confidence: r.conf,
			Detail: label + " " + r.what})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// parseFdinfo reads /proc/<pid>/fdinfo/<fd> ("prog_id:\t42").
func parseFdinfo(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// pinnedObj is a pinned bpf object as its fdinfo describes it.
type pinnedObj struct {
	kind    string // "program", "link", "map", or "" if unrecognised
	progID  uint32 // the program it is or attaches, when hasProg
	hasProg bool
	kv      map[string]string
}

// classifyPinned tells what a pinned object is from its fdinfo. A link's
// fdinfo names the program it attaches as well ("prog_id"), so links are told
// apart first.
func classifyPinned(fdinfo []byte) pinnedObj {
	o := pinnedObj{kv: parseFdinfo(fdinfo)}
	if id, err := strconv.ParseUint(o.kv["prog_id"], 10, 32); err == nil {
		o.progID, o.hasProg = uint32(id), true
	}
	switch {
	case o.kv["link_id"] != "":
		o.kind = "link"
	case o.hasProg:
		o.kind = "program"
	case o.kv["map_id"] != "":
		o.kind = "map"
	}
	return o
}

// bpffsMounts returns the mount points of bpf filesystems from
// /proc/self/mountinfo ("... /sys/fs/bpf rw,... - bpf bpf rw").
func bpffsMounts(mountinfo []byte) []string {
	var out []string
	for _, line := range strings.Split(string(mountinfo), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		if f := strings.Fields(post); len(f) == 0 || f[0] != "bpf" {
			continue
		}
		if f := strings.Fields(pre); len(f) >= 5 {
			out = append(out, unescapeMountPath(f[4]))
		}
	}
	return out
}

// unescapeMountPath decodes mountinfo's octal escapes ("\040" is a space).
func unescapeMountPath(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
