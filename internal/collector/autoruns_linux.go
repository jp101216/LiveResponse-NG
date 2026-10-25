//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Linux persistence collector (registered as "autoruns", the cross-platform
// autostart collector): the places persistence lives on Linux — the dynamic
// linker preload file, cron (system and per-user), systemd units and timers,
// rc.local, XDG autostart entries, and shell startup files. Each entry is listed
// with its source and command; a command in a world-writable/temporary location,
// one matching a reverse-shell or fetch-and-run shape, or an ld.so.preload hook
// raises a finding.
func collectAutoruns(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("autoruns")

	scanLdPreload(res)
	scanCron(res)
	scanSystemd(res)
	scanRcLocal(res)
	scanXdgAutostart(res)
	scanShellProfiles(res)

	res.SetMeta("platform", "linux")
	res.SetMeta("note", "Linux persistence surfaces: ld.so.preload, cron, systemd (system+user), rc.local, XDG autostart, shell profiles")
	return res.Finish(), nil
}

// persistenceFindings grades a persistence command: its command-line shape (via
// the shared Unix analytics) and where its program runs from.
func persistenceFindings(source, cmd string) []Finding {
	out := analyzeUnixCommandLine(source, "", cmd)
	if prog := firstProgram(cmd); prog != "" && strings.HasPrefix(prog, "/") {
		if lvl, why := unixPathRisk(prog); lvl == riskHigh {
			out = append(out, Finding{
				Rule: "persistence.unusual_path", Severity: SevSuspect, Technique: "T1543", Confidence: 55,
				Detail: fmt.Sprintf("%s runs %s from %s", source, prog, why),
			})
		} else if lvl == riskLow {
			out = append(out, Finding{
				Rule: "persistence.unusual_path", Severity: SevNotable, Technique: "T1543", Confidence: 30,
				Detail: fmt.Sprintf("%s runs %s from %s", source, prog, why),
			})
		}
	}
	return out
}

// scanLdPreload flags every library in /etc/ld.so.preload — content there is
// forced into every dynamically-linked process, a classic userland rootkit hook.
func scanLdPreload(res *Result) {
	data := readFileSafe("/etc/ld.so.preload")
	if data == nil {
		return
	}
	for _, lib := range strings.Fields(string(data)) {
		if strings.HasPrefix(lib, "#") {
			continue
		}
		res.Add(
			map[string]any{"kind": "ld_preload", "source": "/etc/ld.so.preload", "library": lib},
			Finding{
				Rule: "persistence.ld_preload", Severity: SevSuspect, Technique: "T1574.006", Confidence: 70,
				Detail: fmt.Sprintf("/etc/ld.so.preload forces %s into every dynamically-linked process — a classic library-injection rootkit hook", lib),
			},
		)
	}
}

// scanCron reads the system and per-user crontabs and the cron.* script dirs.
func scanCron(res *Result) {
	addCron := func(source, sched, user, cmd string) {
		f := map[string]any{"kind": "cron", "source": source, "schedule": sched, "command": cmd}
		if user != "" {
			f["user"] = user
		}
		res.Add(f, persistenceFindings("cron ("+source+")", cmd)...)
	}

	// System crontabs carry a user field.
	scanCrontabFile("/etc/crontab", true, "", addCron)
	for _, p := range dirFiles("/etc/cron.d") {
		scanCrontabFile(p, true, "", addCron)
	}
	// Per-user crontabs: the filename is the user, rows have no user field.
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		for _, p := range dirFiles(dir) {
			scanCrontabFile(p, false, filepath.Base(p), addCron)
		}
	}
	// cron.{hourly,daily,weekly,monthly} hold scripts, not crontab rows.
	for _, d := range []string{"hourly", "daily", "weekly", "monthly"} {
		dir := "/etc/cron." + d
		for _, p := range dirFiles(dir) {
			res.Add(
				map[string]any{"kind": "cron_script", "source": dir, "schedule": "@" + d, "command": p},
				persistenceFindings("cron ("+dir+")", p)...,
			)
		}
	}
}

// scanCrontabFile parses one crontab file and emits each entry via add.
func scanCrontabFile(path string, hasUser bool, fileUser string, add func(source, sched, user, cmd string)) {
	data := readFileSafe(path)
	if data == nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		e, ok := parseCronLine(line, hasUser)
		if !ok {
			continue
		}
		user := e.User
		if user == "" {
			user = fileUser
		}
		add(path, e.Schedule, user, e.Command)
	}
}

// scanSystemd lists admin- and runtime-added systemd units and timers (the
// common persistence spots — vendor units under /lib are not walked).
func scanSystemd(res *Result) {
	for _, dir := range []string{"/etc/systemd/system", "/run/systemd/system"} {
		for _, p := range dirFiles(dir) {
			base := filepath.Base(p)
			switch {
			case strings.HasSuffix(base, ".service"):
				execs := parseUnitExecStarts(readFileSafe(p))
				fields := map[string]any{"kind": "systemd_unit", "source": dir, "unit": base}
				if len(execs) > 0 {
					fields["exec_start"] = execs
				}
				var findings []Finding
				for _, ex := range execs {
					findings = mergeFindings(findings, persistenceFindings("systemd unit "+base, ex)...)
				}
				res.Add(fields, findings...)
			case strings.HasSuffix(base, ".timer"):
				res.Add(map[string]any{"kind": "systemd_timer", "source": dir, "unit": base})
			}
		}
	}
	// Per-user systemd units.
	for _, home := range userHomes() {
		dir := filepath.Join(home, ".config/systemd/user")
		for _, p := range dirFiles(dir) {
			base := filepath.Base(p)
			if !strings.HasSuffix(base, ".service") {
				continue
			}
			execs := parseUnitExecStarts(readFileSafe(p))
			fields := map[string]any{"kind": "systemd_user_unit", "source": dir, "unit": base}
			if len(execs) > 0 {
				fields["exec_start"] = execs
			}
			var findings []Finding
			for _, ex := range execs {
				findings = mergeFindings(findings, persistenceFindings("systemd user unit "+base, ex)...)
			}
			res.Add(fields, findings...)
		}
	}
}

// scanRcLocal flags command lines in /etc/rc.local (legacy boot persistence).
func scanRcLocal(res *Result) {
	data := readFileSafe("/etc/rc.local")
	if data == nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "exit ") || line == "exit 0" {
			continue
		}
		res.Add(
			map[string]any{"kind": "rc_local", "source": "/etc/rc.local", "command": line},
			persistenceFindings("rc.local", line)...,
		)
	}
}

// scanXdgAutostart lists enabled XDG autostart .desktop entries, system-wide and
// per-user.
func scanXdgAutostart(res *Result) {
	dirs := []string{"/etc/xdg/autostart"}
	for _, home := range userHomes() {
		dirs = append(dirs, filepath.Join(home, ".config/autostart"))
	}
	for _, dir := range dirs {
		for _, p := range dirFiles(dir) {
			if !strings.HasSuffix(p, ".desktop") {
				continue
			}
			d := parseDesktopFile(readFileSafe(p))
			if d.Hidden || d.Exec == "" {
				continue
			}
			res.Add(
				map[string]any{"kind": "xdg_autostart", "source": dir, "name": filepath.Base(p), "exec": d.Exec},
				persistenceFindings("xdg autostart "+filepath.Base(p), d.Exec)...,
			)
		}
	}
}

// scanShellProfiles scans shell startup files for suspicious command lines,
// emitting a record only when a line actually trips a heuristic (listing every
// rc file would be noise).
func scanShellProfiles(res *Result) {
	files := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"}
	for _, dir := range dirFiles("/etc/profile.d") {
		files = append(files, dir)
	}
	for _, home := range userHomes() {
		for _, name := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"} {
			files = append(files, filepath.Join(home, name))
		}
	}
	for _, path := range files {
		data := readFileSafe(path)
		if data == nil {
			continue
		}
		var findings []Finding
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			findings = mergeFindings(findings, analyzeUnixCommandLine("shell profile "+path, "", line)...)
		}
		if len(findings) > 0 {
			res.Add(map[string]any{"kind": "shell_profile", "source": path}, findings...)
		}
	}
}

// dirFiles returns the regular-file paths directly under dir (not recursing),
// sorted by ReadDir order; a missing or unreadable dir yields nothing.
func dirFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// userHomes returns the distinct, real home directories of root and human users
// (UID 0 or >= 1000) under /home or /root, for per-user persistence scans.
func userHomes() []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range parsePasswd(readFileSafe("/etc/passwd")) {
		if u.UID != 0 && u.UID < 1000 {
			continue
		}
		if u.Home == "" || seen[u.Home] {
			continue
		}
		if !strings.HasPrefix(u.Home, "/home/") && !strings.HasPrefix(u.Home, "/root") {
			continue
		}
		seen[u.Home] = true
		out = append(out, u.Home)
	}
	return out
}
