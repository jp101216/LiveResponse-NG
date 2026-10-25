package collector

import "strings"

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
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ExecStart", "ExecStartPre", "ExecStartPost":
			val = strings.TrimSpace(val)
			val = strings.TrimLeft(val, "-@+!:") // systemd exec-line prefixes
			val = strings.TrimSpace(val)
			if val != "" {
				out = append(out, val)
			}
		}
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

// firstProgram returns the program a command line runs (its first real token),
// for grading an ExecStart/cron command's path.
func firstProgram(cmd string) string {
	for _, f := range strings.Fields(cmd) {
		if strings.HasPrefix(f, "-") || (strings.ContainsRune(f, '=') && !strings.ContainsRune(f, '/')) {
			continue
		}
		if cmdWrappers[unixBaseName(f)] {
			continue
		}
		return f
	}
	return ""
}
