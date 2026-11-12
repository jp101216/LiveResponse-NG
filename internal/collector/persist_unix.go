package collector

import (
	"strconv"
	"strings"
	"time"
)

// persist_unix.go — parsers for the Linux persistence surfaces the autoruns
// collector reads (cron, systemd units, XDG autostart). No build tag: pure text
// handling, unit-tested on any OS.

// cronEntry is one scheduled command from a crontab.
type cronEntry struct {
	Schedule string
	User     string // "" for a user crontab (the file's owner is the user)
	Command  string
}

// parseCronLine parses one crontab line. hasUser is true for the system
// crontabs (/etc/crontab, /etc/cron.d) whose rows carry a user field, and false
// for per-user crontabs. Comments, blank lines and environment assignments
// return ok=false.
func parseCronLine(line string, hasUser bool) (cronEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return cronEntry{}, false
	}
	if isEnvAssignment(line) {
		return cronEntry{}, false
	}
	fields := strings.Fields(line)

	// @reboot / @daily / @hourly ... macros replace the five time fields.
	if strings.HasPrefix(fields[0], "@") {
		e := cronEntry{Schedule: fields[0]}
		rest := fields[1:]
		if hasUser {
			if len(rest) < 2 {
				return cronEntry{}, false
			}
			e.User = rest[0]
			e.Command = strings.Join(rest[1:], " ")
		} else {
			if len(rest) < 1 {
				return cronEntry{}, false
			}
			e.Command = strings.Join(rest, " ")
		}
		return e, true
	}

	need := 5
	if hasUser {
		need = 6
	}
	if len(fields) <= need {
		return cronEntry{}, false
	}
	e := cronEntry{Schedule: strings.Join(fields[:5], " ")}
	if hasUser {
		e.User = fields[5]
		e.Command = strings.Join(fields[6:], " ")
	} else {
		e.Command = strings.Join(fields[5:], " ")
	}
	return e, true
}

// isEnvAssignment reports whether a crontab line is a NAME=value assignment
// rather than a schedule (e.g. "PATH=/usr/bin", "MAILTO=root").
func isEnvAssignment(line string) bool {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return false
	}
	name := strings.TrimSpace(line[:eq])
	if strings.ContainsAny(name, " \t") {
		return false // a schedule's first field, not a bare NAME
	}
	for _, r := range name {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// parseUnitExecStarts returns the ExecStart/ExecStartPre/ExecStartPost program
// lines from a systemd unit file, with systemd's "-@+!" exec prefixes stripped.
func parseUnitExecStarts(data []byte) []string {
	var out []string
	for _, e := range parseUnitExecs(data) {
		if strings.HasPrefix(e.Key, "ExecStart") {
			out = append(out, e.Command)
		}
	}
	return out
}

// unitExec is one command a systemd unit runs, with the key that runs it.
type unitExec struct {
	Key     string // ExecStart, ExecStop, ExecReload, ExecCondition, ...
	Command string
}

// unitExecKeys are every unit-file key whose value systemd executes. Not only
// ExecStart: ExecStop runs at every shutdown, ExecCondition and ExecStartPre
// before the service, ExecReload on every reload — each a place a payload can
// hide behind an ordinary-looking ExecStart.
var unitExecKeys = map[string]bool{
	"ExecStart": true, "ExecStartPre": true, "ExecStartPost": true, "ExecCondition": true,
	"ExecReload": true, "ExecStop": true, "ExecStopPost": true,
}

// parseUnitExecs returns every command a systemd unit or drop-in runs, with
// systemd's exec-line prefixes ("-", "@", "+", "!", "!!", ":") stripped and
// backslash-continued lines joined.
func parseUnitExecs(data []byte) []unitExec {
	var out []unitExec
	for _, line := range joinContinuations(string(data)) {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if !unitExecKeys[key] {
			continue
		}
		val = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(val), "-@+!:"))
		if val != "" {
			out = append(out, unitExec{Key: key, Command: val})
		}
	}
	return out
}

// anacronJob is one /etc/anacrontab job.
type anacronJob struct {
	Period, Delay, ID, Command string
}

// parseAnacrontab reads "period delay job-identifier command" lines,
// skipping comments and NAME=value assignments. The period is a number of
// days or @daily/@weekly/@monthly/@yearly.
func parseAnacrontab(data []byte) []anacronJob {
	var out []anacronJob
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || isEnvAssignment(line) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		cmd := strings.TrimSpace(line)
		for i := 0; i < 3; i++ {
			cmd = strings.TrimSpace(strings.TrimPrefix(cmd, f[i]))
		}
		out = append(out, anacronJob{Period: f[0], Delay: f[1], ID: f[2], Command: cmd})
	}
	return out
}

// atJob is a queued `at` job: the commands it will run, as the at spool file
// records them, and who queued it.
type atJob struct {
	UID      string
	Commands []string
	RunAt    time.Time // from the spool file's name; zero when it can't be read
}

// parseAtJob reads an at spool file. at writes a shell script: a "# atrun
// uid=N gid=M" header, the queuing user's environment, a "cd <dir> || {...}"
// block, then the user's commands — directly, or (newer at) inside a here
// document fed to $SHELL. Only those commands are returned.
func parseAtJob(name string, data []byte) atJob {
	j := atJob{RunAt: atJobTime(name)}
	lines := strings.Split(string(data), "\n")
	body := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "# atrun uid="); ok {
			j.UID, _, _ = strings.Cut(rest, " ")
		}
		if t == "}" { // the end of the "cd <dir> || { ... }" block
			body = i + 1
			break
		}
	}
	if body < 0 {
		return j
	}
	for body < len(lines) && strings.TrimSpace(lines[body]) == "" {
		body++
	}
	delim := ""
	if body < len(lines) {
		t := strings.TrimSpace(lines[body])
		if k := strings.Index(t, "<< '"); k >= 0 && strings.Contains(t[:k], "SHELL") && strings.HasSuffix(t, "'") {
			delim = t[k+4 : len(t)-1]
			body++
		}
	}
	for _, line := range lines[body:] {
		t := strings.TrimSpace(line)
		if delim != "" && t == delim {
			break
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		j.Commands = append(j.Commands, t)
	}
	return j
}

// atJobTime decodes the run time Debian's and Red Hat's at put in a spool
// file's name: a queue letter, five hex digits of job number, then eight hex
// digits of minutes since the epoch ("a0000a01b6e3c4").
func atJobTime(name string) time.Time {
	if len(name) != 14 {
		return time.Time{}
	}
	m, err := strconv.ParseUint(name[6:], 16, 64)
	if err != nil || m == 0 || m > 1<<32 {
		return time.Time{}
	}
	return time.Unix(int64(m)*60, 0).UTC()
}

// joinContinuations splits a unit file into logical lines: systemd joins a line
// ending in a backslash with the next one, so "ExecStart=/bin/true \\" followed
// by "  ; curl x | sh" is one command, and must be judged as one.
func joinContinuations(text string) []string {
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// desktopEntry is the Exec/Hidden state of an XDG autostart .desktop file.
type desktopEntry struct {
	Exec   string
	Hidden bool // Hidden=true or X-GNOME-Autostart-enabled=false disables it
}

// parseDesktopFile reads the Exec line and disabled state from a .desktop file.
func parseDesktopFile(data []byte) desktopEntry {
	var d desktopEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Exec":
			if d.Exec == "" {
				d.Exec = strings.TrimSpace(val)
			}
		case "Hidden":
			if strings.EqualFold(strings.TrimSpace(val), "true") {
				d.Hidden = true
			}
		case "X-GNOME-Autostart-enabled":
			if strings.EqualFold(strings.TrimSpace(val), "false") {
				d.Hidden = true
			}
		}
	}
	return d
}

// parseLdPreload returns the libraries named in an /etc/ld.so.preload dump,
// parsed the way glibc's dynamic linker reads the file: '#' starts a comment
// that runs to the end of the line, and entries are separated by whitespace or
// ':'. (Reading a commented-out line as libraries would raise findings for
// words in the comment; reading "a.so:b.so" as one entry would hide b.so.)
func parseLdPreload(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		out = append(out, strings.FieldsFunc(line, func(r rune) bool {
			return r == ':' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
		})...)
	}
	return out
}

// firstProgram returns the program a command line runs (its first real token),
// for grading an ExecStart/cron command's path.
func firstProgram(cmd string) string {
	for _, f := range strings.Fields(cmd) {
		f = strings.Trim(f, `"'`) // ExecStart="/opt/x/run" and quoted crontab programs
		if f == "" || strings.HasPrefix(f, "-") || isEnvAssignment(f) {
			continue
		}
		if cmdWrappers[unixBaseName(f)] {
			continue
		}
		return f
	}
	return ""
}
