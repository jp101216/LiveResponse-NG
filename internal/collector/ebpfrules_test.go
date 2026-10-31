package collector

import (
	"encoding/binary"
	"strings"
	"testing"
)

// insn encodes one eBPF instruction (little-endian hosts).
func insn(code, regs byte, imm int32) []byte {
	b := make([]byte, 8)
	b[0], b[1] = code, regs
	binary.LittleEndian.PutUint32(b[4:], uint32(imm))
	return b
}

func TestHelperCallOffsets(t *testing.T) {
	if !littleEndian {
		t.Skip("fixtures are little-endian")
	}
	var prog []byte
	prog = append(prog, insn(bpfOpCall, 0x00, -0xe680)...) // helper call
	prog = append(prog, insn(bpfOpCall, 0x10, 5)...)       // bpf-to-bpf call (src_reg 1)
	prog = append(prog, insn(bpfOpCall, 0x20, 1234)...)    // kfunc call (src_reg 2)
	prog = append(prog, insn(bpfOpLdImm64, 0x01, 0x11)...) // ld_imm64, first slot
	prog = append(prog, insn(bpfOpCall, 0x00, 0x7777)...)  // ...its data slot, which must not read as a call
	prog = append(prog, insn(bpfOpCall, 0x00, 0x444c0)...) // helper call
	prog = append(prog, insn(0xb7, 0x00, 0)...)            // mov r0, 0
	prog = append(prog, insn(0x95, 0x00, 0)...)            // exit
	prog = append(prog, 0x85, 0x00, 0x00)                  // truncated tail
	got := helperCallOffsets(prog)
	if len(got) != 2 || got[0] != -0xe680 || got[1] != 0x444c0 {
		t.Fatalf("got %v", got)
	}
}

// Addresses as read from a real kernel's /proc/kallsyms.
const kallsymsFixture = `ffffffff814e3ea0 T bpf_send_signal
ffffffff814e3ee0 T bpf_send_signal_thread
ffffffff814e5e90 T bpf_probe_write_user
ffffffff814e5e90 t __alias_of_write_user
ffffffff814f4510 T __bpf_call_base
ffffffff814fa450 T bpf_user_rnd_u32
ffffffff815389d0 T bpf_ktime_get_ns
ffffffff82a00000 D some_data
ffffffffc0a01000 t driver_func	[somemod]
0000000000000000 T hidden_by_kptr_restrict
`

func TestKallsymsAndHelperNames(t *testing.T) {
	ks := parseKallsyms([]byte(kallsymsFixture))
	if ks.callBase != 0xffffffff814f4510 {
		t.Fatalf("callBase %x", ks.callBase)
	}
	if ks.byAddr[0xffffffff814e5e90] != "bpf_probe_write_user" {
		t.Fatalf("a helper's own name should win at a shared address: %q", ks.byAddr[0xffffffff814e5e90])
	}
	if _, ok := ks.byAddr[0xffffffff82a00000]; ok {
		t.Error("data symbols are not text")
	}
	if ks.byAddr[0xffffffffc0a01000] != "driver_func" {
		t.Error("module symbols keep their bare name")
	}
	// The kernel stores a helper's address minus __bpf_call_base in an s32.
	off := func(addr uint64) int32 { return int32(addr - 0xffffffff814f4510) }
	names := ks.helperNames([]int32{
		off(0xffffffff814e5e90), // below the base: a negative offset
		off(0xffffffff815389d0), // above it
		off(0xffffffff815389d0), // repeated
		0x12340,                 // not a symbol
	})
	want := "bpf_ktime_get_ns,bpf_probe_write_user,helper@0xffffffff81506850"
	if strings.Join(names, ",") != want {
		t.Fatalf("got %v, want %s", names, want)
	}
	if got := (kernelSyms{}).helperNames([]int32{5}); got != nil {
		t.Errorf("no __bpf_call_base, nothing should resolve: %v", got)
	}
	if hidden := parseKallsyms([]byte("0000000000000000 T __bpf_call_base\n")); hidden.callBase != 0 {
		t.Error("zeroed (kptr_restrict) addresses must not resolve")
	}
}

func TestJudgeBPFProg(t *testing.T) {
	cases := []struct {
		p    bpfProg
		want map[string]Severity
	}{
		{bpfProg{ID: 1, Type: "cgroup_skb", Name: "sd_fw_egress", Helpers: []string{"bpf_skb_load_bytes"}}, nil},
		{bpfProg{ID: 2, Type: "kprobe", Name: "x", Helpers: []string{"bpf_probe_read_user", "bpf_probe_write_user"}},
			map[string]Severity{"persistence.ebpf_write_user": SevSuspect}},
		{bpfProg{ID: 3, Type: "lsm", Name: "enforce", Helpers: []string{"bpf_send_signal", "bpf_send_signal_thread"}},
			map[string]Severity{"persistence.ebpf_send_signal": SevNotable}},
		{bpfProg{ID: 4, Type: "kprobe", Name: "y", Helpers: []string{"bpf_override_return"}, Pins: []string{"/sys/fs/bpf/y"}},
			map[string]Severity{"persistence.ebpf_override_return": SevSuspect}},
	}
	for _, c := range cases {
		fs := judgeBPFProg(c.p)
		got := rulesOf(fs)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v", c.p.Name, keys(got))
		}
		for rule, sev := range c.want {
			if got[rule].Severity != sev || got[rule].Technique != "T1014" {
				t.Errorf("%s: %s = %+v", c.p.Name, rule, got[rule])
			}
		}
		if len(c.p.Pins) > 0 && len(fs) > 0 && !strings.Contains(fs[0].Detail, "pinned at /sys/fs/bpf/y") {
			t.Errorf("pin not mentioned: %s", fs[0].Detail)
		}
	}
}

func TestBpffsMountsAndFdinfo(t *testing.T) {
	mi := "24 30 0:22 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n" +
		"36 24 0:31 / /sys/fs/bpf rw,nosuid,nodev shared:8 - bpf bpf rw,mode=700\n" +
		"90 30 0:44 / /tmp/my\\040bpf rw,relatime - bpf none rw\n"
	got := bpffsMounts([]byte(mi))
	if len(got) != 2 || got[0] != "/sys/fs/bpf" || got[1] != "/tmp/my bpf" {
		t.Fatalf("mounts %q", got)
	}
	kv := parseFdinfo([]byte("pos:\t0\nflags:\t02000002\nprog_type:\t1\nprog_id:\t42\nprog_tag:\ta04f5eef06a7f555\n"))
	if kv["prog_id"] != "42" || kv["prog_type"] != "1" {
		t.Fatalf("fdinfo %v", kv)
	}
	if bpfProgTypeName(2) != "kprobe" || bpfProgTypeName(29) != "lsm" || bpfProgTypeName(999) != "type_999" {
		t.Error("program type names")
	}
}

func TestClassifyPinned(t *testing.T) {
	// fdinfo as the kernel prints it for a pinned program, link and map.
	prog := "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1041\nprog_type:\t1\nprog_jited:\t1\nprog_tag:\ta04f5eef06a7f555\nmemlock:\t4096\nprog_id:\t15\nrun_time_ns:\t0\nrun_cnt:\t0\n"
	link := "pos:\t0\nflags:\t02000000\nmnt_id:\t15\nino:\t1042\nlink_type:\traw_tracepoint\nlink_id:\t3\nprog_tag:\ta04f5eef06a7f555\nprog_id:\t15\ntp_name:\tsys_enter\n"
	m := "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1043\nmap_type:\t2\nkey_size:\t4\nvalue_size:\t8\nmax_entries:\t1\nmemlock:\t4096\nmap_id:\t7\nfrozen:\t0\n"
	for _, c := range []struct {
		fdinfo, kind string
		prog         uint32
		hasProg      bool
	}{
		{prog, "program", 15, true},
		{link, "link", 15, true}, // names its program, but is a link
		{m, "map", 0, false},
		{"pos:\t0\nflags:\t02\n", "", 0, false},
	} {
		o := classifyPinned([]byte(c.fdinfo))
		if o.kind != c.kind || o.progID != c.prog || o.hasProg != c.hasProg {
			t.Errorf("%q: got %+v", c.fdinfo, o)
		}
	}
}
