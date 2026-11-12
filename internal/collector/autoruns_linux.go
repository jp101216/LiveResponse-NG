//go:build linux

package collector

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Linux persistence collector (registered as "autoruns", the cross-platform
// autostart collector): the places persistence lives on Linux — the dynamic
// linker preload file, cron (system and per-user), systemd units, drop-ins and
// timers, rc.local, XDG autostart entries, and shell startup files. Each entry is
// listed with its source and command; a command in a world-writable/temporary
// location, one matching a reverse-shell or fetch-and-run shape, or an
// ld.so.preload hook raises a finding.
func collectAutoruns(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("autoruns")
	p := persistRecorder{res: res, ctx: ctx, hasher: opts.Hasher}

	p.scanLdPreload()
	p.scanCron()
	p.scanSystemd()
	p.scanRcLocal()
	p.scanXdgAutostart()
	p.scanShellProfiles()
	p.scanPAM()
	p.scanSudoers()
	p.scanUdev()

	res.SetMeta("platform", "linux")
	res.SetMeta("note", "Linux persistence surfaces: ld.so.preload, cron, systemd (units, drop-ins and timers; "+
		"system, vendor and user; every Exec key), anacron, at jobs, rc.local, XDG autostart, shell startup files, PAM, sudoers, udev rules in /etc. "+
		"Vendor systemd units, shell startup files, PAM lines and sudo rules are recorded only when they trip a heuristic")
	return res.Finish(), nil
}

// persistRecorder adds persistence records. It notes the program each command
// runs — so the IOC pass and an analyst can pivot on it — and hashes the
// program of any entry that raised a finding (as the Windows collectors hash
// flagged autostart binaries).
type persistRecorder struct {
	res    *Result
	ctx    context.Context
	hasher *FileHasher
}

func (p persistRecorder) add(fields map[string]any, cmd string, findings []Finding) {
	if prog := firstProgram(cmd); strings.HasPrefix(prog, "/") {
		fields["program"] = prog
		if len(findings) > 0 && p.ctx.Err() == nil {
			p.hasher.Fields(p.ctx, fields, "program", prog)
		}
	}
	p.res.Add(fields, findings...)
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
func (p persistRecorder) scanLdPreload() {
	data := readFileSafe("/etc/ld.so.preload")
	if data == nil {
		return
	}
	for _, lib := range parseLdPreload(data) {
		fields := map[string]any{"kind": "ld_preload", "source": "/etc/ld.so.preload", "library": lib}
		if strings.HasPrefix(lib, "/") && p.ctx.Err() == nil {
			p.hasher.Fields(p.ctx, fields, "library", lib)
		}
		p.res.Add(fields, Finding{
			Rule: "persistence.ld_preload", Severity: SevSuspect, Technique: "T1574.006", Confidence: 70,
			Detail: fmt.Sprintf("/etc/ld.so.preload forces %s into every dynamically-linked process — a classic library-injection rootkit hook", lib),
		})
	}
}

// scanCron reads the system and per-user crontabs and the cron.* script dirs.
func (p persistRecorder) scanCron() {
	addCron := func(source, sched, user, cmd string) {
		f := map[string]any{"kind": "cron", "source": source, "schedule": sched, "command": cmd}
		if user != "" {
			f["user"] = user
		}
		p.add(f, cmd, persistenceFindings("cron ("+source+")", cmd))
	}

	// System crontabs carry a user field.
	scanCrontabFile("/etc/crontab", true, "", addCron)
	for _, f := range dirFiles("/etc/cron.d") {
		scanCrontabFile(f, true, "", addCron)
	}
	// Per-user crontabs: the filename is the user, rows have no user field.
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		for _, f := range dirFiles(dir) {
			scanCrontabFile(f, false, filepath.Base(f), addCron)
		}
	}
	// anacron runs jobs that were due while the machine was off: the same
	// persistence with another schedule format.
	if data := readFileSafe("/etc/anacrontab"); data != nil {
		for _, j := range parseAnacrontab(data) {
			p.add(map[string]any{"kind": "anacron", "source": "/etc/anacrontab", "schedule": j.Period + "d+" + j.Delay + "m",
				"job": j.ID, "command": j.Command}, j.Command, persistenceFindings("anacron job "+j.ID, j.Command))
		}
	}
	p.scanAtJobs()
	// cron.{hourly,daily,weekly,monthly} hold scripts, not crontab rows.
	for _, d := range []string{"hourly", "daily", "weekly", "monthly"} {
		dir := "/etc/cron." + d
		for _, f := range dirFiles(dir) {
			p.add(map[string]any{"kind": "cron_script", "source": dir, "schedule": "@" + d, "command": f},
				f, persistenceFindings("cron ("+dir+")", f))
		}
	}
}

// scanAtJobs reads the jobs queued with at(1): one-shot commands that run
// later, often as a way to outlive the session that planted them. Debian keeps
// the spool in /var/spool/cron/atjobs, Red Hat in /var/spool/at.
func (p persistRecorder) scanAtJobs() {
	uidNames := uidNameMap(parsePasswd(readFileSafe("/etc/passwd")))
	for _, dir := range []string{"/var/spool/cron/atjobs", "/var/spool/at"} {
		for _, f := range dirFiles(dir) {
			name := filepath.Base(f)
			if strings.HasPrefix(name, ".") {
				continue // .SEQ: the job-number counter
			}
			data := readFileSafe(f)
			if data == nil {
				continue
			}
			j := parseAtJob(name, data)
			if len(j.Commands) == 0 {
				continue
			}
			cmd := strings.Join(j.Commands, "; ")
			fields := map[string]any{"kind": "at_job", "source": dir, "file": f, "command": excerpt(cmd, 2000)}
			if strings.HasPrefix(name, "=") {
				fields["running"] = true
			}
			if !j.RunAt.IsZero() {
				fields["run_at"] = j.RunAt
			}
			if j.UID != "" {
				fields["uid"] = j.UID
				if uid, err := strconv.Atoi(j.UID); err == nil {
					if u, ok := uidNames[uid]; ok {
						fields["user"] = u
					}
				}
			}
			var findings []Finding
			for _, c := range j.Commands {
				findings = mergeFindings(findings, persistenceFindings("at job "+name, c)...)
			}
			p.add(fields, j.Commands[0], findings)
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

// systemdDirs are the unit directories systemd loads from. Admin and runtime
// directories are listed in full. Vendor directories hold the hundreds of units
// packages ship, so they are walked too — attackers drop units there to blend
// in — but a vendor unit becomes a record only when it trips a heuristic.
var systemdDirs = []struct {
	dir    string
	user   bool // user units (systemctl --user), not system ones
	vendor bool
}{
	{"/etc/systemd/system", false, false},
	{"/run/systemd/system", false, false},
	{"/usr/local/lib/systemd/system", false, false},
	{"/usr/lib/systemd/system", false, true},
	{"/lib/systemd/system", false, true},
	{"/etc/systemd/user", true, false},
	{"/usr/lib/systemd/user", true, true},
}

// scanSystemd walks the system, vendor and per-user unit directories: each
// .service's ExecStart lines, each drop-in (<unit>.d/*.conf — an override that
// can replace a legitimate unit's ExecStart), and the timers.
func (p persistRecorder) scanSystemd() {
	seen := map[string]bool{} // resolved dirs: /lib -> /usr/lib is walked once
	for _, d := range systemdDirs {
		p.systemdDir(d.dir, d.user, d.vendor, seen)
	}
	for _, home := range userHomes() {
		p.systemdDir(filepath.Join(home, ".config/systemd/user"), true, false, seen)
	}
}

func (p persistRecorder) systemdDir(dir string, user, vendor bool, seen map[string]bool) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || seen[real] {
		return // missing, or already walked under another name
	}
	seen[real] = true
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		name := e.Name()
		path := filepath.Join(dir, name)
		switch {
		case e.IsDir() && strings.HasSuffix(name, ".d"):
			// Drop-ins override (or add to) the named unit; *.wants/ and
			// *.requires/ hold only links to units walked elsewhere.
			for _, conf := range dirFiles(path) {
				if strings.HasSuffix(conf, ".conf") {
					p.systemdUnit(conf, dir, strings.TrimSuffix(name, ".d"), user, vendor, true)
				}
			}
		case e.IsDir():
		case strings.HasSuffix(name, ".service"):
			p.systemdUnit(path, dir, name, user, vendor, false)
		case strings.HasSuffix(name, ".timer") && !vendor:
			kind := "systemd_timer"
			if user {
				kind = "systemd_user_timer"
			}
			p.res.Add(map[string]any{"kind": kind, "source": dir, "unit": name})
		}
	}
}

// systemdUnit records one unit file or drop-in, graded by its ExecStart lines.
func (p persistRecorder) systemdUnit(path, dir, unit string, user, vendor, dropin bool) {
	kind, label := "systemd_unit", "systemd unit "+unit
	switch {
	case user && dropin:
		kind, label = "systemd_user_dropin", "systemd user unit drop-in "+path
	case dropin:
		kind, label = "systemd_dropin", "systemd drop-in "+path
	case user:
		kind, label = "systemd_user_unit", "systemd user unit "+unit
	}
	all := parseUnitExecs(readFileSafe(path))
	var execs, others []string
	var findings []Finding
	culprit := ""
	for _, ex := range all {
		where := label
		if strings.HasPrefix(ex.Key, "ExecStart") {
			execs = append(execs, ex.Command)
		} else {
			// ExecStop, ExecReload and ExecCondition run too, just at other
			// moments: a payload there survives a review of ExecStart.
			others = append(others, ex.Key+"="+ex.Command)
			where = label + " (" + ex.Key + ")"
		}
		fs := persistenceFindings(where, ex.Command)
		if len(fs) > 0 && culprit == "" {
			culprit = ex.Command
		}
		findings = mergeFindings(findings, fs...)
	}
	if vendor && len(findings) == 0 {
		return
	}
	fields := map[string]any{"kind": kind, "source": dir, "unit": unit}
	if dropin {
		fields["file"] = path
	}
	if vendor {
		fields["vendor"] = true
	}
	if len(execs) > 0 {
		fields["exec_start"] = execs
	}
	if len(others) > 0 {
		fields["exec_other"] = others
	}
	if t, err := os.Readlink(path); err == nil && t == "/dev/null" {
		fields["masked"] = true
	}
	if culprit == "" && len(execs) > 0 {
		culprit = execs[0]
	}
	p.add(fields, culprit, findings)
}

// scanRcLocal flags command lines in /etc/rc.local (legacy boot persistence).
func (p persistRecorder) scanRcLocal() {
	data := readFileSafe("/etc/rc.local")
	if data == nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "exit ") || line == "exit 0" {
			continue
		}
		p.add(map[string]any{"kind": "rc_local", "source": "/etc/rc.local", "command": line},
			line, persistenceFindings("rc.local", line))
	}
}

// scanXdgAutostart lists enabled XDG autostart .desktop entries, system-wide and
// per-user.
func (p persistRecorder) scanXdgAutostart() {
	dirs := []string{"/etc/xdg/autostart"}
	for _, home := range userHomes() {
		dirs = append(dirs, filepath.Join(home, ".config/autostart"))
	}
	for _, dir := range dirs {
		for _, f := range dirFiles(dir) {
			if !strings.HasSuffix(f, ".desktop") {
				continue
			}
			d := parseDesktopFile(readFileSafe(f))
			if d.Hidden || d.Exec == "" {
				continue
			}
			p.add(map[string]any{"kind": "xdg_autostart", "source": dir, "name": filepath.Base(f), "exec": d.Exec},
				d.Exec, persistenceFindings("xdg autostart "+filepath.Base(f), d.Exec))
		}
	}
}

// systemShellStartupFiles are the shells' system-wide startup files across the
// common distributions (Debian's bash.bashrc and RHEL's bashrc; zsh reads
// zshenv for every shell, scripts included).
var systemShellStartupFiles = []string{
	"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/zsh/zshenv", "/etc/zshenv", "/etc/zsh/zprofile", "/etc/zprofile",
	"/etc/zsh/zshrc", "/etc/zshrc", "/etc/zsh/zlogin", "/etc/zlogin",
}

// userShellStartupFiles are the per-user startup files bash and zsh read.
var userShellStartupFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
	".zshenv", ".zprofile", ".zshrc", ".zlogin",
}

// scanShellProfiles scans shell startup files for suspicious command lines,
// emitting a record only when a line actually trips a heuristic (listing every
// rc file would be noise).
func (p persistRecorder) scanShellProfiles() {
	files := append([]string{}, systemShellStartupFiles...)
	files = append(files, dirFiles("/etc/profile.d")...)
	for _, home := range userHomes() {
		for _, name := range userShellStartupFiles {
			files = append(files, filepath.Join(home, name))
		}
	}
	for _, path := range files {
		data := readFileSafe(path)
		if data == nil {
			continue // missing, unreadable, or a directory
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
			p.res.Add(map[string]any{"kind": "shell_profile", "source": path}, findings...)
		}
	}
}

// dirFiles returns the non-directory entries directly under dir (not
// recursing), in ReadDir (name) order; a missing or unreadable dir yields
// nothing.
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

// userHomes returns the distinct home directories to scan for per-user
// persistence: root's and human users' (UID 0 or >= 1000), and those of any
// account with an interactive login shell — a service account made loginable
// (www-data with /bin/bash, say) is exactly where a backdoor lands. Homes that
// aren't real directories (/nonexistent) or are "/" are skipped.
func userHomes() []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range parsePasswd(readFileSafe("/etc/passwd")) {
		if u.UID != 0 && u.UID < 1000 && disabledShells[u.Shell] {
			continue
		}
		home := filepath.Clean(u.Home)
		if u.Home == "" || home == "/" || !strings.HasPrefix(home, "/") || seen[home] {
			continue
		}
		if st, err := os.Stat(home); err != nil || !st.IsDir() {
			continue
		}
		seen[home] = true
		out = append(out, home)
	}
	return out
}

// scanPAM records PAM lines worth a look (a module by absolute path outside
// the PAM directories, pam_exec) and checks every PAM module file against its
// package's checksum (dpkg's md5sums; other package managers aren't read).
func (p persistRecorder) scanPAM() {
	for _, f := range dirFiles("/etc/pam.d") {
		for _, e := range parsePAMFile(f, readFileSafe(f)) {
			if fs := judgePAMEntry(e); len(fs) > 0 {
				p.res.Add(map[string]any{"kind": "pam", "source": f, "line": e.Line, "type": e.Type, "control": e.Control,
					"module": e.Module, "args": e.Args}, fs...)
			}
		}
	}
	sums := dpkgPAMSums()
	if sums == nil {
		p.res.SetMeta("pam_module_integrity", "not checked: no dpkg database (only Debian-family packages are verified)")
		return
	}
	seen := map[string]bool{}
	checked := 0
	for _, dir := range pamModuleDirs {
		for _, f := range dirFiles(strings.TrimSuffix(dir, "/")) {
			if !strings.HasSuffix(f, ".so") {
				continue
			}
			real, err := filepath.EvalSymlinks(f)
			if err != nil || seen[real] {
				continue
			}
			seen[real] = true
			checked++
			want, owned := sums[real]
			have := ""
			if b, _, err := readRegular(real, 256<<20); err == nil {
				have = fmt.Sprintf("%x", md5.Sum(b))
			}
			if fd, ok := pamModuleFinding(f, have, want, owned); ok {
				fields := map[string]any{"kind": "pam_module", "path": f, "md5": have}
				if want != "" {
					fields["package_md5"] = want
				}
				p.add(fields, f, []Finding{fd})
			}
		}
	}
	p.res.SetMeta("pam_modules_checked", checked)
}

// dpkgPAMSums maps each PAM module a Debian package installed (by its real
// path) to the md5 the package lists for it; nil without a dpkg database.
func dpkgPAMSums() map[string]string {
	files, err := filepath.Glob("/var/lib/dpkg/info/*.md5sums")
	if err != nil || len(files) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, f := range files {
		for _, line := range strings.Split(string(readFileSafe(f)), "\n") {
			sum, rel, ok := strings.Cut(line, "  ")
			if !ok || !strings.Contains(rel, "/security/") || !strings.HasSuffix(rel, ".so") {
				continue
			}
			path := "/" + strings.TrimSpace(rel)
			if real, err := filepath.EvalSymlinks(path); err == nil {
				path = real
			}
			out[path] = strings.TrimSpace(sum)
		}
	}
	return out
}

// scanSudoers records sudo rules that run anything as root without a
// password.
func (p persistRecorder) scanSudoers() {
	users := map[string]passwdEntry{}
	for _, u := range parsePasswd(readFileSafe("/etc/passwd")) {
		users[u.Name] = u
	}
	for _, f := range append([]string{"/etc/sudoers"}, dirFiles("/etc/sudoers.d")...) {
		for _, r := range parseSudoers(f, readFileSafe(f)) {
			if fd, ok := judgeSudoRule(r, users); ok {
				p.res.Add(map[string]any{"kind": "sudoers", "source": f, "line": r.Line, "who": r.Who, "rule": r.Spec}, fd)
			}
		}
	}
}

// scanUdev records every program a udev rule in /etc/udev/rules.d runs (the
// rules administrators and intruders write; packages ship theirs elsewhere).
func (p persistRecorder) scanUdev() {
	for _, f := range dirFiles("/etc/udev/rules.d") {
		if !strings.HasSuffix(f, ".rules") {
			continue
		}
		for _, cmd := range udevRunCommands(readFileSafe(f)) {
			p.add(map[string]any{"kind": "udev", "source": f, "command": cmd}, cmd, judgeUdevCommand(f, cmd))
		}
	}
}
