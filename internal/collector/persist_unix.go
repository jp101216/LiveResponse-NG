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

// scriptArgument returns the script file an interpreter is told to run in a
// command line — the "/tmp/.x/run.sh" of "sh /tmp/.x/run.sh", the
// "/dev/shm/a.py" of "python3 -u /dev/shm/a.py" — or "" when the program isn't
// a shell or interpreter, or it runs code given inline (sh -c, python -c or
// -m, perl -e, node -e) or read from standard input. A payload is as often
// started this way as run directly, so its location matters as much as the
// program's.
func scriptArgument(cmd string) string {
	fields := strings.Fields(cmd)
	i := programIndex(fields)
	if i < 0 {
		return ""
	}
	interp := unixBaseName(strings.Trim(fields[i], `"'`))
	family := interpreterFamily(interp)
	if family == "" {
		return ""
	}
	for i++; i < len(fields); i++ {
		f := strings.Trim(fields[i], `"'`)
		switch {
		case f == "-" || f == "--":
			if f == "-" {
				return "" // the script comes from standard input
			}
			if i+1 < len(fields) {
				return strings.Trim(fields[i+1], `"'`)
			}
			return ""
		case strings.HasPrefix(f, "-") || strings.HasPrefix(f, "+"):
			if inlineCodeFlag(family, f) {
				return ""
			}
			if interpreterArgFlags[f] {
				i++ // the option's own argument
			}
		default:
			return f
		}
	}
	return ""
}

// interpreterFamily groups the interpreters by how their options read.
func interpreterFamily(name string) string {
	switch {
	case name == "sh" || name == "bash" || name == "dash" || name == "zsh" || name == "ksh":
		return "shell"
	case strings.HasPrefix(name, "python"):
		return "python"
	case name == "perl" || name == "ruby" || name == "node" || name == "php":
		return name
	}
	return ""
}

// inlineCodeFlag reports whether an option makes the interpreter run code
// given on the command line (or read from stdin) rather than a script file.
func inlineCodeFlag(family, f string) bool {
	if strings.HasPrefix(f, "--") {
		switch f {
		case "--eval", "--print", "--command":
			return true
		}
		return strings.HasPrefix(f, "--eval=") || strings.HasPrefix(f, "--print=")
	}
	cluster := strings.TrimLeft(f, "-+")
	switch family {
	case "shell":
		return strings.ContainsAny(cluster, "cs")
	case "python":
		return strings.ContainsAny(cluster, "cm")
	case "perl":
		return strings.ContainsAny(cluster, "eE")
	case "ruby":
		return strings.ContainsRune(cluster, 'e')
	case "node":
		return strings.ContainsAny(cluster, "ep")
	case "php":
		return strings.ContainsRune(cluster, 'r')
	}
	return false
}

// interpreterArgFlags are the interpreter options whose value is the next
// word ("bash -o pipefail x.sh", "python3 -W ignore x.py", "ruby -I lib x.rb").
var interpreterArgFlags = map[string]bool{
	"-o": true, "+o": true, "-O": true, "+O": true, "-W": true, "-X": true, "-I": true,
	"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true, "-C": true,
}

// unixCommandPathRisk grades where a POSIX command line's code lives: its
// program, and the script an interpreter is told to run, whichever is riskier.
// what is the path the grade is for ("" when neither is an absolute path).
func unixCommandPathRisk(cmd string) (lvl riskLevel, why, what string) {
	if prog := firstProgram(cmd); strings.HasPrefix(prog, "/") {
		lvl, why = unixPathRisk(prog)
		what = prog
	}
	if script := scriptArgument(cmd); strings.HasPrefix(script, "/") {
		if l, w := unixPathRisk(script); l > lvl {
			lvl, why, what = l, w, script
		}
	}
	return lvl, why, what
}

// joinContinuations splits a unit file into logical lines the way systemd's
// config parser does: a line ending in an unescaped backslash is joined with
// the next one (the backslash becomes a space), so "ExecStart=/bin/true \\"
// followed by "  ; curl x | sh" is one command, and must be judged as one.
// Comment lines ("#" or ";" first) are dropped wherever they are, even in the
// middle of a continuation and even when they end in a backslash themselves:
// "# old: \\" above "ExecStart=/tmp/x" doesn't swallow the ExecStart.
func joinContinuations(text string) []string {
	var out []string
	var cur strings.Builder
	pending := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if t := strings.TrimLeft(line, " \t"); t != "" && (t[0] == '#' || t[0] == ';') {
			continue
		}
		cur.WriteString(line)
		if trailingBackslashes(line)%2 == 1 {
			s := cur.String()
			cur.Reset()
			cur.WriteString(s[:len(s)-1])
			cur.WriteByte(' ')
			pending = true
			continue
		}
		out = append(out, cur.String())
		cur.Reset()
		pending = false
	}
	if pending {
		out = append(out, cur.String())
	}
	return out
}

// trailingBackslashes counts the backslashes a line ends with: an odd count
// escapes the newline, an even one is that many escaped backslashes.
func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
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
	fields := strings.Fields(cmd)
	if i := programIndex(fields); i >= 0 {
		return strings.Trim(fields[i], `"'`)
	}
	return ""
}

// programIndex returns the index of the word naming the program a command
// runs, past environment assignments, wrappers (sudo, env, nice ...), their
// flags and those flags' values ("sudo -u bob /tmp/x", "nice -n 10 /tmp/x"),
// or -1 when there is none.
func programIndex(fields []string) int {
	wrapper := ""
	for i := 0; i < len(fields); i++ {
		f := strings.Trim(fields[i], `"'`) // ExecStart="/opt/x/run" and quoted crontab programs
		switch {
		case f == "":
			continue
		case strings.HasPrefix(f, "-"):
			if wrapperValueFlags[wrapper][f] {
				i++ // the flag's value: "-u bob"
			}
			continue
		case isEnvAssignment(f):
			continue
		case cmdWrappers[unixBaseName(f)]:
			wrapper = unixBaseName(f)
			continue
		}
		return i
	}
	return -1
}

// wrapperValueFlags are, per wrapper, the flags whose value is the next word.
var wrapperValueFlags = map[string]map[string]bool{
	"sudo": {"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true, "-U": true,
		"-T": true, "--user": true, "--group": true, "--chdir": true, "--host": true, "--prompt": true, "--role": true,
		"--type": true, "--other-user": true, "--command-timeout": true, "--close-from": true},
	"doas":   {"-u": true, "-C": true},
	"env":    {"-u": true, "-C": true, "-S": true, "--unset": true, "--chdir": true, "--split-string": true},
	"nice":   {"-n": true, "--adjustment": true},
	"ionice": {"-c": true, "-n": true, "-p": true, "-P": true, "-u": true, "--class": true, "--classdata": true},
	"time":   {"-f": true, "-o": true, "--format": true, "--output": true},
	"stdbuf": {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"xargs":  {"-I": true, "-n": true, "-P": true, "-d": true, "-a": true, "-E": true, "-L": true, "-s": true},
	"exec":   {"-a": true},
}
