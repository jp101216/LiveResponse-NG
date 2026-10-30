package collector

import (
	"fmt"
	"strings"
)

// Unix command-line heuristics — the Linux counterpart to the command
// analytics in cmdline.go, which are tuned for PowerShell and Windows LOLBins.
// No build tag: pure string logic, unit-tested on any OS. Each rule matches a
// technique's mechanics, not a program's name, and is deliberately specific so
// an ordinary admin command (a plain curl, a chmod on /usr/local) stays quiet.

// shellInterps are the interpreters a downloaded or decoded payload is piped
// into; a pipe into one of these is the "execute" half of a fetch-and-run.
var shellInterps = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"python": true, "python2": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "node": true,
}

// analyzeUnixCommandLine returns the findings for one POSIX command line. source
// labels where it came from (a process, a cron entry, a unit's ExecStart), and
// image is the resolved program when known (unused today but kept symmetric with
// analyzeCommandLine).
func analyzeUnixCommandLine(source, image, cmd string) []Finding {
	_ = image
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}
	lc := strings.ToLower(cmd)
	var out []Finding
	add := func(rule string, sev Severity, tech string, conf int, what string) {
		out = append(out, Finding{
			Rule: rule, Severity: sev, Technique: tech, Confidence: conf,
			Detail: fmt.Sprintf("%s: %s", source, what),
		})
	}

	downloader := containsWord(lc, "curl") || containsWord(lc, "wget") || containsWord(lc, "fetch")

	// Fetch-and-run: a downloader piped into a shell/interpreter.
	if downloader && pipesToShell(lc) {
		add("exec.download_pipe_shell", SevSuspect, "T1059.004", 80,
			"downloads and pipes straight into a shell — fetch-and-run, nothing lands on disk to inspect")
	}

	// Reverse shells.
	switch {
	case strings.Contains(lc, "/dev/tcp/") || strings.Contains(lc, "/dev/udp/"):
		add("exec.reverse_shell", SevSuspect, "T1059.004", 85,
			"redirects a shell over /dev/tcp or /dev/udp — a bash reverse shell")
	case netcatExec(lc):
		add("exec.reverse_shell", SevSuspect, "T1059.004", 80,
			"netcat with command execution (-e / --exec) — a reverse or bind shell")
	case containsWord(lc, "socat") && (strings.Contains(lc, "exec:") || strings.Contains(lc, "system:")):
		add("exec.reverse_shell", SevSuspect, "T1059.004", 80,
			"socat with EXEC/SYSTEM — a reverse or bind shell")
	case interpreterReverseShell(lc):
		add("exec.reverse_shell", SevSuspect, "T1059.004", 75,
			"an interpreter one-liner opening a socket and spawning a shell")
	case strings.Contains(lc, "mkfifo") && (containsWord(lc, "nc") || containsWord(lc, "ncat")):
		add("exec.reverse_shell", SevSuspect, "T1059.004", 75,
			"a named-pipe + netcat pair — a classic reverse shell")
	}

	// Encoded payloads piped to a shell.
	if (strings.Contains(lc, "base64 -d") || strings.Contains(lc, "base64 --decode") || strings.Contains(lc, "base64 -di")) && pipesToShell(lc) {
		add("exec.base64_decode", SevSuspect, "T1140", 70,
			"base64-decodes and pipes into a shell — obfuscated execution")
	}

	// chmod +x on a payload in a temporary/world-writable location (the "make it
	// runnable" step). Only high-risk paths (/tmp, /dev/shm, ...) count — a chmod
	// under a home cache dir is far too common to flag.
	if strings.Contains(lc, "chmod") && (strings.Contains(lc, "+x") || strings.Contains(lc, "0755") || strings.Contains(lc, "777")) {
		if t := firstHighRiskToken(cmd); t != "" {
			add("exec.chmod_suspicious", SevNotable, "T1222.002", 55,
				fmt.Sprintf("makes %s executable (a world-writable/temporary location)", t))
		}
	}

	// Persistence written from a command line.
	switch {
	case strings.Contains(lc, "authorized_keys") && hasRedirect(lc):
		add("persistence.ssh_authorized_keys", SevSuspect, "T1098.004", 70,
			"writes to an SSH authorized_keys file — key-based backdoor access")
	case crontabFromStdin(lc):
		add("persistence.cron_install", SevNotable, "T1053.003", 55,
			"installs a crontab from stdin")
	case hasRedirect(lc) && mentionsShellProfile(lc):
		add("persistence.shell_profile", SevNotable, "T1546.004", 55,
			"appends to a shell startup file — runs on the next login/shell")
	case hasRedirect(lc) && (strings.Contains(lc, "ld.so.preload") || strings.Contains(lc, "/etc/rc.local")):
		add("persistence.boot_or_preload", SevSuspect, "T1574.006", 65,
			"writes to ld.so.preload or rc.local — library-preload or boot persistence")
	}

	return out
}

// cmdWrappers run another program and so may stand in front of the real
// interpreter in a pipeline stage ("| sudo python3", "| env X=1 bash").
var cmdWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "exec": true,
	"time": true, "stdbuf": true, "setsid": true, "nice": true, "ionice": true,
	"xargs": true,
}

// pipesToShell reports whether any pipeline stage after the first runs a shell
// or interpreter — the "| bash" / "| python" in a fetch-and-run. Leading
// privilege/environment wrappers, VAR=val assignments and flags are skipped so
// the real program is examined, without treating a mere argument ("| grep
// python") as an interpreter.
func pipesToShell(lc string) bool {
	parts := strings.Split(lc, "|")
	for _, seg := range parts[1:] {
		if prog := pipelineProgram(seg); prog != "" && shellInterps[prog] {
			return true
		}
	}
	return false
}

// pipelineProgram returns the base name of the program a pipeline stage runs,
// skipping wrappers, environment assignments and flags. Shell quoting and
// grouping around the word are dropped, so the "sh'" in `sh -c 'curl x | sh'`,
// the "sh)" in `$(curl x | sh)` and the "sh;" in `{ curl x | sh; }` read as sh.
func pipelineProgram(seg string) string {
	for _, f := range strings.Fields(strings.TrimSpace(seg)) {
		f = strings.Trim(f, "'\"`(){};")
		switch {
		case f == "":
			continue
		case strings.HasPrefix(f, "-"): // a flag
			continue
		case strings.ContainsRune(f, '=') && !strings.ContainsRune(f, '/'): // VAR=val
			continue
		}
		base := unixBaseName(f)
		if cmdWrappers[base] {
			continue
		}
		return base
	}
	return ""
}

// netcatExec reports whether a command segment actually runs netcat with an
// execute flag (nc/ncat/netcat as the program, plus -e/--exec/--sh-exec). This
// is checked per command segment so an unrelated `sh -c` wrapper that merely
// contains the letters "nc" somewhere is not mistaken for a netcat shell.
func netcatExec(lc string) bool {
	for _, seg := range splitCommandSegments(lc) {
		switch pipelineProgram(seg) {
		case "nc", "ncat", "netcat":
			if strings.Contains(seg, " -e ") || strings.Contains(seg, "--exec") ||
				strings.Contains(seg, "--sh-exec") || strings.Contains(seg, " -c ") {
				return true
			}
		}
	}
	return false
}

// splitCommandSegments breaks a command line at the separators that start a new
// command or pipeline stage, so each segment can be examined for its own program.
func splitCommandSegments(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == '|' || r == '&' || r == '\n' || r == '`'
	})
}

// crontabFromStdin reports whether the command installs a crontab from stdin
// ("crontab -"), as opposed to listing or editing one ("crontab -l").
func crontabFromStdin(lc string) bool {
	fields := strings.Fields(lc)
	for i, f := range fields {
		if f == "crontab" && i+1 < len(fields) && fields[i+1] == "-" {
			return true
		}
	}
	return false
}

// interpreterReverseShell spots the common python/perl/ruby socket-to-shell
// one-liners (a socket plus a shell spawn in the same command).
func interpreterReverseShell(lc string) bool {
	hasSock := strings.Contains(lc, "socket") || strings.Contains(lc, "tcpsocket") || strings.Contains(lc, "io.popen")
	spawn := strings.Contains(lc, "pty.spawn") || strings.Contains(lc, "/bin/sh") || strings.Contains(lc, "/bin/bash") ||
		strings.Contains(lc, "subprocess") || strings.Contains(lc, "exec(")
	inlineInterp := strings.Contains(lc, "python") && strings.Contains(lc, "-c") ||
		strings.Contains(lc, "perl") && strings.Contains(lc, "-e") ||
		strings.Contains(lc, "ruby") && strings.Contains(lc, "-e")
	return inlineInterp && hasSock && spawn
}

// hasRedirect reports whether the command redirects output to a file (> or >>).
func hasRedirect(lc string) bool { return strings.Contains(lc, ">") }

// mentionsShellProfile reports whether a known shell startup file is named.
func mentionsShellProfile(lc string) bool {
	for _, f := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", "/etc/profile", "bash.bashrc"} {
		if strings.Contains(lc, f) {
			return true
		}
	}
	return false
}

// firstHighRiskToken returns the first whitespace-separated token naming a path
// in a high-risk location (temporary, shared-memory, deleted/memfd) — not the
// merely-low-risk home/cache spots, which are too common to flag on a chmod.
func firstHighRiskToken(cmd string) string {
	for _, tok := range strings.Fields(cmd) {
		tok = strings.Trim(tok, `"'`)
		if !strings.HasPrefix(tok, "/") {
			continue
		}
		if lvl, _ := unixPathRisk(tok); lvl == riskHigh {
			return tok
		}
	}
	return ""
}

// containsWord reports whether word appears in s delimited by non-alphanumeric
// characters (so "nc" matches "nc -e" and "| nc" but not "sync" or "func").
func containsWord(s, word string) bool {
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isWordByte(s[i-1])
		rightIdx := i + len(word)
		rightOK := rightIdx >= len(s) || !isWordByte(s[rightIdx])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}
