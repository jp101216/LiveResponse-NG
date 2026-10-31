package collector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Linux kernel-module heuristics (T1547.006 Kernel Modules and Extensions,
// T1014 Rootkit). A loadable kernel module runs with full kernel privilege,
// so the places that load one — the boot-time lists, and modprobe's install
// hooks, which run an arbitrary command as root whenever a module is
// requested — are persistence, and the module list itself is what a kernel
// rootkit edits to hide. No build tag: pure text handling, unit-tested on any
// OS.

// procModule is one line of /proc/modules.
type procModule struct {
	Name     string
	Size     int64
	Refcount string // "-" without CONFIG_MODULE_UNLOAD
	Deps     []string
	State    string // Live, Loading, Unloading
	Taint    string // per-module taint letters, e.g. "OE"
}

// parseProcModules parses /proc/modules:
//
//	name size refcount deps state address [(taint)]
func parseProcModules(data []byte) []procModule {
	var out []procModule
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		size, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		m := procModule{Name: f[0], Size: size, Refcount: f[2], State: f[4]}
		if f[3] != "-" {
			for _, d := range strings.Split(f[3], ",") {
				if d != "" {
					m.Deps = append(m.Deps, d)
				}
			}
		}
		if len(f) > 6 {
			m.Taint = taintLetters(strings.Join(f[6:], ""))
		}
		out = append(out, m)
	}
	return out
}

// taintLetters keeps the upper-case flag letters of a "(OE)" or "(OE+)" field.
func taintLetters(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// moduleName normalises a module name the way the kernel does: '-' and '_'
// are interchangeable, and /proc/modules uses '_'.
func moduleName(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

// parseModulesLoad returns the module names a modules-load.d file (or the
// Debian /etc/modules list) loads at boot: one per line, '#' or ';' starts a
// comment, and /etc/modules lines may carry parameters after the name.
func parseModulesLoad(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, moduleName(f[0]))
		}
	}
	return out
}

// modprobeHook is an install or remove directive from a modprobe.d file: a
// command modprobe runs (as root) instead of inserting or removing a module.
type modprobeHook struct {
	Kind    string // "install" or "remove"
	Module  string
	Command string
	Line    int
}

// parseModprobeConf returns a modprobe.d file's install and remove
// directives. Backslash-newline continues a line; '#' starts a comment line.
func parseModprobeConf(data []byte) []modprobeHook {
	var out []modprobeHook
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		start := i + 1
		line := lines[i]
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			i++
			line = strings.TrimSuffix(line, `\`) + " " + lines[i]
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != "install" && f[0] != "remove") {
			continue
		}
		// The command is the rest of the line after "install <module>".
		rest := strings.TrimSpace(line[len(f[0]):])
		rest = strings.TrimSpace(rest[len(f[1]):])
		out = append(out, modprobeHook{Kind: f[0], Module: moduleName(f[1]), Command: rest, Line: start})
	}
	return out
}

// benignModprobeCommand recognises the stock shapes: blacklisting a module by
// running true/false in its place, and chaining to modprobe itself
// ("/sbin/modprobe --ignore-install snd_pcm && /sbin/modprobe snd_pcm_oss").
func benignModprobeCommand(cmd string) bool {
	if strings.ContainsAny(cmd, "`$<>") {
		return false
	}
	segs := splitCommandSegments(cmd)
	if len(segs) == 0 {
		return false
	}
	for _, s := range segs {
		switch unixBaseName(firstProgram(s)) {
		case "true", "false", "modprobe":
		default:
			return false
		}
	}
	return true
}

// judgeModprobeHook grades one install/remove directive.
func judgeModprobeHook(h modprobeHook, source string) []Finding {
	if benignModprobeCommand(h.Command) {
		return nil
	}
	where := fmt.Sprintf("%s:%d", source, h.Line)
	sev, conf := SevNotable, 50
	detail := fmt.Sprintf("%s: `%s %s` runs a command as root whenever that module is requested (ordinary activity can trigger module loads): %s",
		where, h.Kind, h.Module, excerpt(h.Command, 200))
	prog := firstProgram(h.Command)
	if lvl, why := unixPathRisk(prog); lvl == riskHigh {
		sev, conf = SevSuspect, 70
		detail += fmt.Sprintf(" (runs %s from %s)", prog, why)
	}
	out := []Finding{{Rule: "persistence.modprobe_hook", Severity: sev, Technique: "T1547.006", Confidence: conf, Detail: detail}}
	return mergeFindings(out, analyzeUnixCommandLine(where, prog, h.Command)...)
}

// judgeLoadedModule grades one loaded module by its taint flags and whether
// it is set to load at boot.
func judgeLoadedModule(m procModule, bootSources []string) []Finding {
	var out []Finding
	if strings.ContainsRune(m.Taint, 'F') {
		out = append(out, Finding{Rule: "persistence.kmod_forced", Severity: SevSuspect, Technique: "T1547.006", Confidence: 60,
			Detail: fmt.Sprintf("kernel module %q was force-loaded, bypassing the kernel's version and symbol checks", m.Name)})
	}
	boot := ""
	if len(bootSources) > 0 {
		boot = " and is set to load at boot (" + strings.Join(bootSources, ", ") + ")"
	}
	switch {
	case strings.ContainsRune(m.Taint, 'E'):
		sev, conf := SevNotable, 40
		if boot != "" {
			sev, conf = SevSuspect, 55
		}
		out = append(out, Finding{Rule: "persistence.kmod_unsigned", Severity: sev, Technique: "T1547.006", Confidence: conf,
			Detail: fmt.Sprintf("kernel module %q is loaded without a valid signature%s; vendor drivers built locally (DKMS) also look like this, so check where it came from", m.Name, boot)})
	case strings.ContainsRune(m.Taint, 'O'):
		out = append(out, Finding{Rule: "persistence.kmod_out_of_tree", Severity: SevInfo, Technique: "T1547.006", Confidence: 25,
			Detail: fmt.Sprintf("kernel module %q was built outside the kernel tree (signed)%s", m.Name, boot)})
	}
	return out
}

// judgeHiddenModule is a loaded module that /proc/modules doesn't list.
func judgeHiddenModule(name string) []Finding {
	return []Finding{{Rule: "persistence.kmod_hidden", Severity: SevCritical, Technique: "T1014", Confidence: 80,
		Detail: fmt.Sprintf("kernel module %q is loaded (it has a live entry in /sys/module) but is missing from /proc/modules: removed from the module list, which is how kernel rootkits hide", name)}}
}

// judgeBootLoad grades a boot-time load entry for a module that isn't
// loaded now. known reports whether the running kernel's module tree has it
// (nil when the tree couldn't be read).
func judgeBootLoad(name string, sources []string, known map[string]bool) []Finding {
	if known == nil || known[name] {
		return nil
	}
	return []Finding{{Rule: "persistence.kmod_boot_unknown", Severity: SevNotable, Technique: "T1547.006", Confidence: 45,
		Detail: fmt.Sprintf("%s load module %q at boot, but the running kernel's module tree doesn't contain it: installed outside the package set, or a stale entry",
			strings.Join(sources, ", "), name)}}
}

// kernelTaintFlags are the bits of /proc/sys/kernel/tainted, in bit order.
var kernelTaintFlags = []struct {
	letter byte
	what   string
}{
	{'P', "proprietary module loaded"},
	{'F', "module force-loaded"},
	{'S', "kernel running on an out-of-specification system"},
	{'R', "module force-unloaded"},
	{'M', "machine-check exception"},
	{'B', "bad page referenced"},
	{'U', "taint requested from userspace"},
	{'D', "kernel oops or BUG"},
	{'A', "ACPI table overridden"},
	{'W', "kernel warning"},
	{'C', "staging driver loaded"},
	{'I', "platform-firmware workaround applied"},
	{'O', "out-of-tree module loaded"},
	{'E', "unsigned module loaded"},
	{'L', "soft lockup"},
	{'K', "kernel live-patched"},
	{'X', "auxiliary (distribution) taint"},
	{'T', "built with structure randomization"},
	{'N', "in-kernel test run"},
	{'J', "mutating fwctl debug operation"},
}

// decodeTaint turns the taint bitmask into its letters and reasons.
func decodeTaint(v uint64) (letters string, reasons []string) {
	var b strings.Builder
	for i, f := range kernelTaintFlags {
		if v&(1<<uint(i)) != 0 {
			b.WriteByte(f.letter)
			reasons = append(reasons, string(f.letter)+": "+f.what)
		}
	}
	return b.String(), reasons
}

// judgeKernelTaint grades the kernel-wide taint. A forced load or unload, or
// an unsigned module, is how a rootkit module usually gets in.
func judgeKernelTaint(v uint64) []Finding {
	if v == 0 {
		return nil
	}
	letters, reasons := decodeTaint(v)
	sev, conf := SevInfo, 20
	if strings.ContainsAny(letters, "FRE") {
		sev, conf = SevNotable, 40
	}
	return []Finding{{Rule: "kernel.tainted", Severity: sev, Technique: "T1547.006", Confidence: conf,
		Detail: fmt.Sprintf("the kernel is tainted (%s): %s", letters, strings.Join(reasons, "; "))}}
}

// moduleTreeNames reads module names out of modules.dep / modules.builtin
// lines ("kernel/drivers/net/foo-bar.ko.zst: deps...") and modules.alias
// lines ("alias name module").
func moduleTreeNames(dep, builtin, alias []byte) map[string]bool {
	names := map[string]bool{}
	add := func(p string) {
		base := p[strings.LastIndexByte(p, '/')+1:]
		if i := strings.Index(base, ".ko"); i > 0 {
			names[moduleName(base[:i])] = true
		}
	}
	for _, data := range [][]byte{dep, builtin} {
		for _, line := range strings.Split(string(data), "\n") {
			if p, _, _ := strings.Cut(line, ":"); strings.TrimSpace(p) != "" {
				add(strings.TrimSpace(p))
			}
		}
	}
	for _, line := range strings.Split(string(alias), "\n") {
		if f := strings.Fields(line); len(f) == 3 && f[0] == "alias" && !strings.ContainsAny(f[1], "*?[") {
			names[moduleName(f[1])] = true
		}
	}
	return names
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
