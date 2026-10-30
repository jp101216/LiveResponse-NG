package collector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeTree creates files (path -> content) under root.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, data := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// recordsBy groups a result's records by their "kind" field.
func recordsBy(res Result) map[string][]Record {
	out := map[string][]Record{}
	for _, r := range res.Records {
		k, _ := r.Fields["kind"].(string)
		out[k] = append(out[k], r)
	}
	return out
}

func TestScanKmodFixtureTree(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"proc/modules": "vboxdrv 704512 0 - Live 0x0000000000000000 (OE)\n" +
			"btrfs 1765376 0 - Live 0x0000000000000000\n",
		// btrfs and vboxdrv are listed; "rootkit" has a live sysfs entry but
		// isn't in /proc/modules; ext4 is built in (no initstate).
		"sys/module/vboxdrv/initstate": "live\n",
		"sys/module/btrfs/initstate":   "live\n",
		"sys/module/rootkit/initstate": "live\n",
		"sys/module/rootkit/taint":     "OE\n",
		"sys/module/ext4/parameters/x": "1\n",
		"proc/sys/kernel/tainted":      "12288\n",
		"proc/sys/kernel/osrelease":    "6.8.0-test\n",
		"lib/modules/6.8.0-test/modules.dep": "kernel/fs/btrfs/btrfs.ko.zst:\n" +
			"kernel/drivers/misc/known-mod.ko.zst:\n",
		"etc/modules-load.d/vbox.conf":  "vboxdrv\n",
		"etc/modules-load.d/extra.conf": "# extras\nknown-mod\nghostmod\n",
		// Same file name in a later directory: overridden, so never read.
		"usr/lib/modules-load.d/vbox.conf": "vboxnetflt\n",
		"etc/modprobe.d/blacklist.conf":    "blacklist pcspkr\ninstall usb-storage /bin/true\n",
		"etc/modprobe.d/zz-net.conf":       "install dccp /tmp/.cache/run \\\n  --quiet\n",
	})

	res := scanKmod(context.Background(), root)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	by := recordsBy(res)

	if len(by["module"]) != 2 {
		t.Fatalf("modules: %+v", by["module"])
	}
	vbox := by["module"][0]
	if vbox.Fields["name"] != "vboxdrv" || vbox.Fields["taint"] != "OE" ||
		len(vbox.Findings) != 1 || vbox.Findings[0].Rule != "persistence.kmod_unsigned" || vbox.Findings[0].Severity != SevSuspect {
		t.Fatalf("vboxdrv (unsigned, loads at boot): %+v", vbox)
	}
	if src, _ := vbox.Fields["loads_at_boot"].([]string); len(src) != 1 || src[0] != "/etc/modules-load.d/vbox.conf" {
		t.Fatalf("vboxdrv boot sources: %v", vbox.Fields["loads_at_boot"])
	}

	if len(by["hidden_module"]) != 1 {
		t.Fatalf("hidden modules: %+v", by["hidden_module"])
	}
	h := by["hidden_module"][0]
	if h.Fields["name"] != "rootkit" || h.Fields["taint"] != "OE" || h.Findings[0].Rule != "persistence.kmod_hidden" || h.Findings[0].Severity != SevCritical {
		t.Fatalf("hidden module: %+v", h)
	}

	boot := map[string]Record{}
	for _, r := range by["boot_load"] {
		boot[r.Fields["name"].(string)] = r
	}
	if _, ok := boot["vboxnetflt"]; ok {
		t.Error("an overridden modules-load.d file was read")
	}
	if len(boot["known_mod"].Findings) != 0 {
		t.Errorf("a module in the kernel's tree was flagged: %+v", boot["known_mod"])
	}
	if f := boot["ghostmod"].Findings; len(f) != 1 || f[0].Rule != "persistence.kmod_boot_unknown" {
		t.Errorf("ghostmod: %+v", boot["ghostmod"])
	}

	if len(by["modprobe_hook"]) != 1 {
		t.Fatalf("modprobe hooks (stock blacklist must be omitted): %+v", by["modprobe_hook"])
	}
	if mh := by["modprobe_hook"][0]; mh.Fields["module"] != "dccp" || mh.Fields["program"] != "/tmp/.cache/run" || mh.Findings[0].Severity != SevSuspect {
		t.Fatalf("dccp hook: %+v", mh)
	}

	if kt := by["kernel_taint"]; len(kt) != 1 || kt[0].Fields["flags"] != "OE" || kt[0].Findings[0].Severity != SevNotable {
		t.Fatalf("kernel taint: %+v", kt)
	}
	if res.Meta["loaded_modules"] != 2 || res.Meta["module_tree_read"] != true {
		t.Errorf("meta: %+v", res.Meta)
	}
}

func TestScanKmodWithoutModuleSupport(t *testing.T) {
	// A kernel built without loadable modules: no /proc/modules. The collector
	// still reads the boot lists and says why there are no module records.
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/modules": "loop\n"})
	res := scanKmod(context.Background(), root)
	by := recordsBy(res)
	if len(by["module"]) != 0 || len(by["boot_load"]) != 1 || res.Meta["note"] == nil {
		t.Fatalf("records %+v meta %+v", by, res.Meta)
	}
	if len(by["hidden_module"]) != 0 {
		t.Fatal("cross-view ran without /proc/modules")
	}
}

func TestScanKmodMergedUsr(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	// On merged-/usr systems /lib is a link to /usr/lib: each file once.
	root := t.TempDir()
	writeTree(t, root, map[string]string{"usr/lib/modules-load.d/a.conf": "loop\n"})
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	res := scanKmod(context.Background(), root)
	if lists, _ := res.Meta["boot_lists"].([]string); len(lists) != 1 {
		t.Fatalf("boot lists read: %v", res.Meta["boot_lists"])
	}
}

func TestScanKmodDebianModulesLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	// Debian/Ubuntu ship modules-load.d/modules.conf -> ../modules. With
	// /etc/modules present it is read once, under its own name; without it
	// the dangling link is skipped, not reported as an error.
	root := t.TempDir()
	writeTree(t, root, map[string]string{"etc/modules": "loop\n", "etc/modules-load.d/other.conf": "fuse\n"})
	link := filepath.Join(root, "etc/modules-load.d/modules.conf")
	if err := os.Symlink("../modules", link); err != nil {
		t.Fatal(err)
	}
	res := scanKmod(context.Background(), root)
	lists, _ := res.Meta["boot_lists"].([]string)
	if len(lists) != 2 || lists[0] != "/etc/modules" || lists[1] != "/etc/modules-load.d/other.conf" {
		t.Fatalf("boot lists: %v", lists)
	}
	for _, r := range recordsBy(res)["boot_load"] {
		if r.Fields["name"] == "loop" {
			if src, _ := r.Fields["sources"].([]string); len(src) != 1 {
				t.Fatalf("loop listed from %v", src)
			}
		}
	}

	if err := os.Remove(filepath.Join(root, "etc/modules")); err != nil {
		t.Fatal(err)
	}
	res = scanKmod(context.Background(), root)
	if len(res.Errors) != 0 {
		t.Fatalf("a dangling modules.conf link was reported: %v", res.Errors)
	}
}

// TestScanKmodLiveHost runs the collector against this machine's kernel. On a
// Linux host with loadable modules (the CI runner) it is a false-positive check
// for the /sys/module cross-view: a clean kernel has no hidden module.
func TestScanKmodLiveHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	if _, err := os.Stat("/proc/modules"); err != nil {
		t.Skip("this kernel has no loadable-module support")
	}
	res := scanKmod(context.Background(), "/")
	by := recordsBy(res)
	if len(by["module"]) == 0 {
		t.Fatalf("no modules read from /proc/modules: %+v", res.Errors)
	}
	for _, r := range by["hidden_module"] {
		t.Errorf("hidden-module false positive on a clean host: %+v", r)
	}
	t.Logf("%d modules, %d boot entries, %d modprobe hooks flagged, taint %v",
		len(by["module"]), len(by["boot_load"]), len(by["modprobe_hook"]), res.Meta["kernel_tainted"])
	for _, r := range res.Records {
		for _, f := range r.Findings {
			t.Logf("  %s [%s]: %s", f.Rule, f.Severity, f.Detail)
		}
	}
}
