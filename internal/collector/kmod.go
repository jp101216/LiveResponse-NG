package collector

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// kmodCollector covers Linux kernel modules: what is loaded (and its taint
// flags), what loads at boot (modules-load.d, /etc/modules), modprobe's
// install/remove hooks, a cross-view of /sys/module against /proc/modules that
// exposes a module hidden from the list, and the kernel-wide taint. It only
// reads files, so the scan takes a root directory and is tested against a
// fixture tree on any OS; it is registered for Linux.
type kmodCollector struct{}

func (kmodCollector) Name() string        { return "kmod" }
func (kmodCollector) Platforms() []string { return []string{"linux"} }

func (kmodCollector) Collect(ctx context.Context) (Result, error) {
	return scanKmod(ctx, "/"), nil
}

func init() { Register(kmodCollector{}) }

// Boot-time module lists and modprobe configuration, in systemd's and
// kmod's search order (earlier directories win for a same-named file).
var (
	modulesLoadDirs = []string{"/etc/modules-load.d", "/run/modules-load.d", "/usr/local/lib/modules-load.d", "/usr/lib/modules-load.d", "/lib/modules-load.d"}
	modprobeDirs    = []string{"/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"}
)

// configFiles lists the config files to read: each of `first` (single files)
// when present, then the *.conf files across dirs in search order, skipping a
// file name already seen in an earlier directory (it overrides; a link to
// /dev/null there masks the vendor file). Every path is resolved, so a link to
// a file already listed -- Debian's modules-load.d/modules.conf -> /etc/modules,
// or /lib -> /usr/lib on merged-/usr systems -- is read once, and a dangling
// link is skipped rather than reported as an error.
func configFiles(root string, first, dirs []string) []string {
	var out []string
	seenName, seenReal := map[string]bool{}, map[string]bool{}
	add := func(p string) {
		real, err := filepath.EvalSymlinks(filepath.Join(root, p))
		if err != nil || seenReal[real] {
			return
		}
		if st, err := os.Stat(real); err != nil || st.IsDir() {
			return
		}
		seenReal[real] = true
		out = append(out, p)
	}
	for _, f := range first {
		add(f)
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(filepath.Join(root, d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".conf") || seenName[e.Name()] {
				continue
			}
			seenName[e.Name()] = true
			add(d + "/" + e.Name()) // a host path: keep "/" on every OS
		}
	}
	return out
}

func scanKmod(ctx context.Context, root string) Result {
	res := NewResult("kmod")
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(root, p)) }

	// What loads at boot: module -> the files that list it.
	boot := map[string][]string{}
	lists := configFiles(root, []string{"/etc/modules"}, modulesLoadDirs)
	for _, f := range lists {
		data, err := read(f)
		if err != nil {
			res.Fail(f + ": " + err.Error())
			continue
		}
		for _, name := range parseModulesLoad(data) {
			if !contains(boot[name], f) {
				boot[name] = append(boot[name], f)
			}
		}
	}

	// The running kernel's module tree, to tell a known module from a stray.
	var known map[string]bool
	if rel, err := read("/proc/sys/kernel/osrelease"); err == nil {
		dir := "/lib/modules/" + strings.TrimSpace(string(rel))
		dep, derr := read(dir + "/modules.dep")
		builtin, _ := read(dir + "/modules.builtin")
		alias, _ := read(dir + "/modules.alias")
		if derr == nil {
			known = moduleTreeNames(dep, builtin, alias)
		}
	}

	// Loaded modules.
	loaded := map[string]bool{}
	procData, perr := read("/proc/modules")
	if perr != nil {
		res.SetMeta("note", "no /proc/modules: this kernel has no loadable-module support (or it is hidden); boot lists, modprobe hooks and taint are still read")
	}
	for _, m := range parseProcModules(procData) {
		loaded[m.Name] = true
		fields := map[string]any{"kind": "module", "name": m.Name, "size": m.Size, "refcount": m.Refcount, "state": m.State}
		if len(m.Deps) > 0 {
			fields["used_by"] = m.Deps
		}
		if m.Taint != "" {
			fields["taint"] = m.Taint
		}
		if src := boot[m.Name]; len(src) > 0 {
			fields["loads_at_boot"] = src
		}
		res.Add(fields, judgeLoadedModule(m, boot[m.Name])...)
	}

	// Cross-view: a module with a live /sys/module entry that /proc/modules
	// doesn't list. /proc/modules is read again before judging, so a module
	// that finished loading meanwhile isn't mistaken for a hidden one.
	if perr == nil && ctx.Err() == nil {
		var hidden []string
		for _, name := range liveSysfsModules(root) {
			if !loaded[name] {
				hidden = append(hidden, name)
			}
		}
		if len(hidden) > 0 {
			again, _ := read("/proc/modules")
			now := map[string]bool{}
			for _, m := range parseProcModules(again) {
				now[m.Name] = true
			}
			for _, name := range hidden {
				if now[name] {
					continue
				}
				fields := map[string]any{"kind": "hidden_module", "name": name}
				if t, err := read("/sys/module/" + name + "/taint"); err == nil && strings.TrimSpace(string(t)) != "" {
					fields["taint"] = strings.TrimSpace(string(t))
				}
				res.Add(fields, judgeHiddenModule(name)...)
			}
		}
	}

	// Boot entries for modules that aren't loaded now.
	for _, name := range sortedKeys(boot) {
		if loaded[name] {
			continue
		}
		res.Add(map[string]any{"kind": "boot_load", "name": name, "sources": boot[name]},
			judgeBootLoad(name, boot[name], known)...)
	}

	// modprobe install/remove hooks.
	conf := configFiles(root, []string{"/etc/modprobe.conf"}, modprobeDirs)
	hooks := 0
	for _, f := range conf {
		data, err := read(f)
		if err != nil {
			res.Fail(f + ": " + err.Error())
			continue
		}
		for _, h := range parseModprobeConf(data) {
			hooks++
			findings := judgeModprobeHook(h, f)
			if len(findings) == 0 {
				continue // a stock blacklist or modprobe chain
			}
			fields := map[string]any{"kind": "modprobe_hook", "source": f, "line": h.Line, "directive": h.Kind, "module": h.Module, "command": h.Command}
			if prog := firstProgram(h.Command); strings.HasPrefix(prog, "/") {
				fields["program"] = prog
			}
			res.Add(fields, findings...)
		}
	}

	// Kernel-wide taint.
	if t, err := read("/proc/sys/kernel/tainted"); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(t)), 10, 64); err == nil {
			letters, reasons := decodeTaint(v)
			if v != 0 {
				res.Add(map[string]any{"kind": "kernel_taint", "value": v, "flags": letters, "reasons": reasons}, judgeKernelTaint(v)...)
			}
			res.SetMeta("kernel_tainted", v)
		}
	}

	res.SetMeta("loaded_modules", len(loaded))
	res.SetMeta("boot_lists", lists)
	res.SetMeta("modprobe_files", len(conf))
	res.SetMeta("modprobe_directives", hooks)
	res.SetMeta("module_tree_read", known != nil)
	return res.Finish()
}

// liveSysfsModules lists /sys/module entries for loadable modules that are
// live (built-in modules have no initstate file).
func liveSysfsModules(root string) []string {
	entries, err := os.ReadDir(filepath.Join(root, "/sys/module"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		state, err := os.ReadFile(filepath.Join(root, "/sys/module", e.Name(), "initstate"))
		if err == nil && strings.TrimSpace(string(state)) == "live" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
