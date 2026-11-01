//go:build linux

package collector

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// rootkit_rules_linux.go — the logic for the Linux checks against kernel rootkits
// and the authentication and device-event backdoors that go with them:
// processes and sockets that exist but are filtered out of what /proc lists,
// PAM modules loaded from outside the system's PAM directories or changed from
// their package's copy, pam_exec handing passwords to a program, sudo rules
// that need no password for everything, and udev rules that run programs.
// Text handling and set comparisons, unit-tested on Linux (they share the
// persistence analytics); the readers live in rootkit_linux.go and autoruns_linux.go.

// pamModuleDirs are where distributions install PAM modules.
var pamModuleDirs = []string{
	"/lib/security/", "/lib64/security/", "/usr/lib/security/", "/usr/lib64/security/",
	"/lib/x86_64-linux-gnu/security/", "/usr/lib/x86_64-linux-gnu/security/",
	"/lib/aarch64-linux-gnu/security/", "/usr/lib/aarch64-linux-gnu/security/",
	"/lib/i386-linux-gnu/security/", "/usr/lib/i386-linux-gnu/security/",
	"/lib/arm-linux-gnueabihf/security/", "/usr/lib/arm-linux-gnueabihf/security/",
}

// pamEntry is one module line of a PAM configuration file.
type pamEntry struct {
	File    string
	Line    int
	Type    string // auth, account, password, session
	Control string
	Module  string
	Args    []string
}

// parsePAMFile reads the module lines of a PAM configuration file
// (/etc/pam.d/<service>): "type control module [args]", where control may be
// a bracketed list and type may start with "-" (skip if missing).
func parsePAMFile(file string, data []byte) []pamEntry {
	var out []pamEntry
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t\r"), `\`) && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t\r"), `\`) + " " + lines[i+1]
			i++
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		e := pamEntry{File: file, Line: start + 1, Type: strings.TrimPrefix(f[0], "-")}
		rest := f[1:]
		if strings.HasPrefix(rest[0], "[") {
			// A bracketed control: up to the field that closes it.
			j := 0
			for j < len(rest) && !strings.HasSuffix(rest[j], "]") {
				j++
			}
			if j >= len(rest)-1 {
				continue
			}
			e.Control = strings.Join(rest[:j+1], " ")
			rest = rest[j+1:]
		} else {
			e.Control = rest[0]
			rest = rest[1:]
		}
		e.Module = rest[0]
		e.Args = rest[1:]
		out = append(out, e)
	}
	return out
}

// inPAMDir reports whether an absolute module path is in a PAM directory.
func inPAMDir(p string) bool {
	for _, d := range pamModuleDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// judgePAMEntry judges a PAM line: a module loaded from outside the PAM
// directories (by absolute path), and pam_exec running a program — with the
// password, when expose_authtok is set.
func judgePAMEntry(e pamEntry) []Finding {
	where := fmt.Sprintf("%s line %d (%s)", e.File, e.Line, e.Type)
	var out []Finding
	if strings.HasPrefix(e.Module, "/") && !inPAMDir(e.Module) {
		f := Finding{Rule: "persistence.pam_module", Severity: SevSuspect, Technique: "T1556.003", Confidence: 70,
			Detail: fmt.Sprintf("%s loads the PAM module %s from outside the system's PAM directories: every login through that "+
				"service runs it, the password in hand (a PAM backdoor)", where, e.Module)}
		if lvl, why := unixPathRisk(e.Module); lvl == riskHigh {
			f.Severity, f.Confidence = SevCritical, 85
			f.Detail += "; it sits in " + why
		}
		out = append(out, f)
	}
	if path.Base(e.Module) == "pam_exec.so" {
		var cmd []string
		authtok := false
		for _, a := range e.Args {
			switch {
			case a == "expose_authtok":
				authtok = true
			case strings.Contains(a, "=") && len(cmd) == 0, a == "debug", a == "quiet", a == "stdout", a == "seteuid", a == "type=auth":
				// options before the command
			default:
				cmd = append(cmd, a)
			}
		}
		command := strings.Join(cmd, " ")
		f := Finding{Rule: "persistence.pam_exec", Severity: SevNotable, Technique: "T1556.003", Confidence: 40,
			Detail: fmt.Sprintf("%s runs %q through pam_exec at every %s step", where, command, e.Type)}
		if authtok {
			f.Severity, f.Confidence = SevSuspect, 75
			f.Detail += " and hands it the password (expose_authtok): how a PAM password logger is set up"
		}
		out = append(out, f)
		out = append(out, persistenceFindings("pam_exec in "+where, command)...)
	}
	return out
}

// pamModuleFinding judges a PAM module file against its package: changed
// from the package's copy (md5 differs), or owned by no package.
func pamModuleFinding(file, have, want string, owned bool) (Finding, bool) {
	switch {
	case owned && want != "" && have != "" && !strings.EqualFold(have, want):
		return Finding{Rule: "persistence.pam_module_modified", Severity: SevCritical, Technique: "T1556.003", Confidence: 85,
			Detail: fmt.Sprintf("the PAM module %s differs from its package's copy (md5 %s, the package lists %s): a patched PAM "+
				"module, the classic backdoor that accepts a master password and logs real ones", file, have, want)}, true
	case !owned:
		return Finding{Rule: "persistence.pam_module_unowned", Severity: SevNotable, Technique: "T1556.003", Confidence: 45,
			Detail: fmt.Sprintf("the PAM module %s belongs to no installed package: installed by hand, and loaded at logins if a "+
				"PAM configuration names it", file)}, true
	}
	return Finding{}, false
}

// sudoRule is one user specification of a sudoers file.
type sudoRule struct {
	File     string
	Line     int
	Who      string
	Spec     string
	NoPasswd bool
	All      bool // any command
}

// parseSudoers reads user specifications ("who hosts=(runas) TAGS: commands")
// from a sudoers file, skipping Defaults, aliases and include directives.
func parseSudoers(file string, data []byte) []sudoRule {
	var out []sudoRule
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		start := i
		line := lines[i]
		for strings.HasSuffix(strings.TrimRight(line, " \t\r"), `\`) && i+1 < len(lines) {
			line = strings.TrimSuffix(strings.TrimRight(line, " \t\r"), `\`) + " " + lines[i+1]
			i++
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue // comments, and #include/@includedir directives
		}
		first := strings.Fields(line)[0]
		if strings.HasPrefix(first, "Defaults") || strings.HasSuffix(first, "_Alias") {
			continue
		}
		who, spec, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		wf := strings.Fields(who)
		if len(wf) < 2 {
			continue
		}
		r := sudoRule{File: file, Line: start + 1, Who: wf[0], Spec: strings.TrimSpace(line)}
		cmds := spec
		if strings.HasPrefix(strings.TrimSpace(cmds), "(") {
			if j := strings.IndexByte(cmds, ')'); j >= 0 {
				cmds = cmds[j+1:]
			}
		}
		// Tags ("NOPASSWD:", "SETENV:"...) come before the commands.
		for {
			c := strings.TrimSpace(cmds)
			tag, rest, ok := strings.Cut(c, ":")
			if !ok || tag == "" || strings.ToUpper(tag) != tag || strings.ContainsAny(tag, " /,") {
				break
			}
			if tag == "NOPASSWD" {
				r.NoPasswd = true
			}
			cmds = rest
		}
		for _, c := range strings.Split(cmds, ",") {
			if strings.TrimSpace(c) == "ALL" {
				r.All = true
			}
		}
		out = append(out, r)
	}
	return out
}

// judgeSudoRule judges a sudo rule that runs anything as root with no
// password: notable for a person's account or an administrators group (cloud
// images set it for their default user), more for a service account or
// everyone.
func judgeSudoRule(r sudoRule, users map[string]passwdEntry) (Finding, bool) {
	if !r.NoPasswd || !r.All || r.Who == "root" {
		return Finding{}, false
	}
	where := fmt.Sprintf("%s line %d", r.File, r.Line)
	f := Finding{Rule: "persistence.sudo_nopasswd", Severity: SevNotable, Technique: "T1548.003", Confidence: 40,
		Detail: fmt.Sprintf("%s lets %s run any command as root without a password (%s)", where, r.Who, excerpt(r.Spec, 160))}
	switch u, known := users[r.Who]; {
	case r.Who == "ALL":
		f.Severity, f.Confidence = SevCritical, 80
		f.Detail += ": every account on the host is root"
	case known && u.UID > 0 && (u.UID < 1000 || disabledShells[u.Shell]):
		f.Severity, f.Confidence = SevSuspect, 75
		f.Detail += fmt.Sprintf(": %s is a service account (uid %d, shell %s), the kind an intruder who owns a service "+
			"gives itself root through", r.Who, u.UID, u.Shell)
	case !known && !strings.HasPrefix(r.Who, "%") && !strings.HasPrefix(r.Who, "+") && !strings.HasPrefix(r.Who, "#"):
		f.Severity, f.Confidence = SevSuspect, 60
		f.Detail += fmt.Sprintf(": no local account is named %s", r.Who)
	}
	return f, true
}

// udevRunCommands returns the programs a udev rules file runs: RUN{…}= and
// PROGRAM= assignments.
func udevRunCommands(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, key := range []string{"RUN", "PROGRAM"} {
			rest := line
			for {
				i := strings.Index(rest, key)
				if i < 0 {
					break
				}
				after := rest[i+len(key):]
				if j := strings.IndexByte(after, '{'); j == 0 {
					if k := strings.IndexByte(after, '}'); k > 0 {
						after = after[k+1:]
					}
				}
				after = strings.TrimLeft(after, "+:")
				if !strings.HasPrefix(after, "=") || strings.HasPrefix(after, "==") || (i > 0 && isWordByte(rest[i-1])) {
					rest = rest[i+len(key):]
					continue
				}
				after = strings.TrimSpace(after[1:])
				if strings.HasPrefix(after, `"`) {
					if end := strings.IndexByte(after[1:], '"'); end >= 0 {
						if cmd := strings.TrimSpace(after[1 : end+1]); cmd != "" {
							out = append(out, cmd)
						}
					}
				}
				rest = rest[i+len(key):]
			}
		}
	}
	return out
}

// judgeUdevCommand judges a program a udev rule in /etc runs as root on a
// device event: the persistence analytics, a shell interpreter, or a program
// outside the system's directories.
func judgeUdevCommand(file, cmd string) []Finding {
	where := "udev rule " + file
	out := persistenceFindings(where, cmd)
	prog := firstProgram(cmd)
	base := path.Base(prog)
	switch {
	case base == "sh" || base == "bash" || base == "dash" || base == "zsh" || base == "python3" || base == "python" || base == "perl":
		out = append(out, Finding{Rule: "persistence.udev_run", Severity: SevSuspect, Technique: "T1546", Confidence: 55,
			Detail: fmt.Sprintf("%s runs a %s script as root whenever a matching device event fires: %s", where, base, excerpt(cmd, 200))})
	case strings.HasPrefix(prog, "/") && !strings.HasPrefix(prog, "/usr/") && !strings.HasPrefix(prog, "/lib/") &&
		!strings.HasPrefix(prog, "/bin/") && !strings.HasPrefix(prog, "/sbin/") && !strings.HasPrefix(prog, "/lib64/"):
		out = append(out, Finding{Rule: "persistence.udev_run", Severity: SevNotable, Technique: "T1546", Confidence: 40,
			Detail: fmt.Sprintf("%s runs %s as root whenever a matching device event fires", where, prog)})
	}
	return out
}

// hiddenPIDs compares what /proc lists with the PIDs that answer when asked
// directly: a thread-group leader that answers but isn't listed is hidden.
// listed is the listing; answering maps each probed PID that answered to its
// thread-group id.
func hiddenPIDs(listed map[int]bool, answering map[int]int) []int {
	var out []int
	for pid, tgid := range answering {
		if !listed[pid] && tgid == pid {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

// diagSocket is a socket as the kernel's socket-diagnostics netlink lists it.
type diagSocket struct {
	Proto  string // tcp, udp
	Family string // ipv4, ipv6
	State  uint8
	Local  string // addr:port
	Remote string
	Inode  uint64
	UID    uint32
}

func (s diagSocket) key() string {
	if s.Inode != 0 {
		return fmt.Sprintf("%s/%d", s.Proto, s.Inode)
	}
	return s.Proto + "/" + s.Local + "/" + s.Remote
}

// hiddenSockets returns the sockets both netlink dumps hold (so not ones
// that merely came and went) that /proc/net leaves out. procKeys are the
// keys of the /proc/net rows read between the two dumps.
func hiddenSockets(first, second []diagSocket, procKeys map[string]bool) []diagSocket {
	again := map[string]bool{}
	for _, s := range second {
		again[s.key()] = true
	}
	var out []diagSocket
	for _, s := range first {
		if again[s.key()] && !procKeys[s.key()] {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}
