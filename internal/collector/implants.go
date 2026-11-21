package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// implants.go — specific implant families, found by what they are rather
// than how they behave: their own strings in a program running from a
// user-writable folder, and the files they stage. The families are NIK C2,
// the AI-enabled Go RAT Cisco Talos described in October 2026, and the agent
// of Project Lattice, an open adversary-emulation C2 written in Rust.
//
// Marker strings are kept XOR-encoded in this source, so that lrng's own
// binary (or its test binary, run from a temporary folder) never holds them
// and is never mistaken for the implant, by this collector or by antivirus.

type implantsCollector struct{ opts RunOptions }

func (*implantsCollector) Name() string           { return "implants" }
func (*implantsCollector) Platforms() []string    { return []string{"windows", "linux"} }
func (*implantsCollector) Timeout() time.Duration { return 2 * time.Minute }

func (c *implantsCollector) Configure(o RunOptions) { c.opts = o }

func (c *implantsCollector) Collect(ctx context.Context) (Result, error) {
	return collectImplants(ctx, c.opts)
}

func init() { Register(func() Collector { return &implantsCollector{} }) }

// xorKey decodes a marker stored XOR 0x5A.
func xorKey(s string) []byte {
	b := []byte(s)
	for i := range b {
		b[i] ^= 0x5A
	}
	return b
}

// implantFamily is one family's markers. A file is the family's when it holds
// at least one strong marker and two markers in all.
type implantFamily struct {
	Name      string
	Rule      string   // the finding's rule ID
	Technique string   // the finding's ATT&CK technique
	Strong    [][]byte // strings only the family's own code carries
	Weak      [][]byte // strings it carries that others might too
	GoOnly    bool     // the family is written in Go: only Go binaries are searched
	Critical  bool     // the implant marks its process critical (ending it crashes Windows)
	Summary   string   // what it is, for the finding
}

// implantFamilies lists the families searched for. NIK C2 stays first: the
// staged-file checks below read its bootkit marker by index.
var implantFamilies = []implantFamily{{
	Name:      "NIK C2",
	Rule:      "malware.nik_c2",
	Technique: "T1071.001",
	Strong: [][]byte{
		xorKey("\x34\x33\x31\x05\x2a\x3b\x34\x3f\x36"),                                 // its panel's build path
		xorKey("\x01\x14\x13\x11\x07\x7a\x09\x2e\x3b\x28\x2e\x33\x34\x3d"),             // its start-up log line
		xorKey("\x14\x13\x11\x05\x18\x15\x15\x0e\x11\x13\x0e\x05\x0a\x08\x1f\x0a"),     // its bootkit placeholder
		xorKey("\x75\x3b\x2a\x33\x75\x39\x68\x75\x28\x2a\x28\x35\x22\x23\x05\x2f\x2a"), // its reverse-proxy endpoint
	},
	Weak: [][]byte{
		xorKey("\x75\x3b\x2a\x33\x75\x39\x68\x75\x3c\x33\x36\x3f\x05\x39\x32\x2f\x34\x31"), // its exfiltration endpoint
		xorKey("\x39\x35\x2a\x23\x2d\x3b\x2e\x39\x32\x3e\x35\x3d"),                         // its watchdog argument
		xorKey("\x36\x35\x39\x31\x05\x29\x39\x28\x3f\x3f\x34\x74\x32\x2e\x37\x36"),         // its lock screen's file
	},
	GoOnly:   true,
	Critical: true,
	Summary: "a Go remote-access implant (Cisco Talos, October 2026) that steals browser, Discord, Wi-Fi and wallet " +
		"credentials, logs keys, runs a hidden VNC, proxies traffic, shows a fake ransomware lock screen and sends its " +
		"operator's prompts to OpenAI's API from the victim's machine",
}, {
	Name:      "Project Lattice",
	Rule:      "malware.lattice_agent",
	Technique: "T1071.001",
	Strong: [][]byte{
		xorKey("\x02\x77\x16\x3b\x2e\x2e\x33\x39\x3f\x77\x02\x15\x08"),                                                         // its custom HTTP header
		xorKey("\x2d\x28\x3b\x33\x2e\x32\x77\x36\x33\x2c\x3f\x77"),                                                             // its session-ID prefix
		xorKey("\x0d\x28\x3b\x33\x2e\x32\x7a\x16\x33\x2c\x3f\x7a\x0a\x28\x35\x39\x3f\x29\x29\x7a\x09\x2e\x3b\x28\x2e\x3f\x3e"), // its start-up line
	},
	Weak: [][]byte{
		xorKey("\x75\x3b\x2a\x33\x75\x2c\x6b\x75\x33\x37\x2a\x36\x3b\x34\x2e\x75\x39\x32\x3f\x39\x31\x33\x34"), // its check-in path
		xorKey("\x75\x3b\x2a\x33\x75\x2c\x6b\x75\x33\x37\x2a\x36\x3b\x34\x2e\x75\x28\x3f\x29\x2f\x36\x2e"),     // its result path
		xorKey("\x75\x3b\x2a\x33\x75\x2c\x68\x75\x2e\x3f\x36\x3f\x37\x3f\x2e\x28\x23"),                         // its default listener path
		xorKey("\x78\x29\x23\x29\x39\x3b\x36\x36\x05\x3f\x34\x3d\x33\x34\x3f\x78\x60\x78"),                     // a check-in JSON key
		xorKey("\x78\x36\x35\x3b\x3e\x3f\x28\x05\x37\x35\x3e\x3f\x78\x60\x78"),                                 // another check-in JSON key
	},
	Summary: "a component of Project Lattice, an adversary-emulation C2 written in Rust and Go (its agent, or its team " +
		"server, which carries the same protocol strings). The agent checks in over HTTP with a custom header, runs the " +
		"operator's shell commands and enumerates the host and its network; the project's roadmap adds DNS, DoH, HTTP/3, " +
		"SMB-pipe and WebSocket transports, sleep masking, indirect syscalls, stack spoofing, PPL stripping and kernel " +
		"callback tampering",
}}

// implantFamilyNames lists the families searched, for the collector's metadata.
func implantFamilyNames() []string {
	out := make([]string, len(implantFamilies))
	for i, f := range implantFamilies {
		out[i] = f.Name
	}
	return out
}

// goBuildID is how a Go-built program starts its code (the build ID sits at
// the start of the text section).
var goBuildID = []byte("Go build ID: \"")

const (
	implantHeadBytes  = 64 << 10 // read to tell a Go binary
	implantMaxFile    = 64 << 20 // larger files aren't searched
	implantByteBudget = 1 << 30  // bounds how much the collector reads in all
)

// unixSystemPrefixes are the folders a Linux package manager, snap, flatpak
// or Nix installs programs into. A running image under one isn't searched:
// the families here run from wherever they were dropped or built.
var unixSystemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/", "/opt/",
	"/snap/", "/nix/store/", "/var/lib/flatpak/", "/var/lib/snapd/"}

// unixImplantCandidate reports whether a running image on Linux is searched:
// it has a path, and the path (less a " (deleted)" mark) is outside the
// system's program folders.
func unixImplantCandidate(exe string) bool {
	p := strings.TrimSuffix(exe, deletedSuffix)
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, pre := range unixSystemPrefixes {
		if strings.HasPrefix(p, pre) {
			return false
		}
	}
	return true
}

// unixStagingDirs are the world-writable folders an implant is dropped into
// before it runs; executables directly inside them are searched too.
var unixStagingDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

// elfMagic is how every Linux executable starts.
var elfMagic = []byte("\x7fELF")

// errNotCandidate is a file that isn't searched (too large, not a Go binary).
var errNotCandidate = errors.New("not a candidate")

// scanImplantFile searches one file for every family's markers. It returns
// the family matched (nil for none), the markers it holds, and the bytes read.
func scanImplantFile(path string) (*implantFamily, []string, int64, error) {
	f, fi, err := openRegular(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer f.Close()
	if !fi.Mode().IsRegular() || fi.Size() > implantMaxFile {
		return nil, nil, 0, errNotCandidate
	}
	head := make([]byte, implantHeadBytes)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	isGo := bytes.Contains(head, goBuildID)
	var want []*implantFamily
	for i := range implantFamilies {
		if !implantFamilies[i].GoOnly || isGo {
			want = append(want, &implantFamilies[i])
		}
	}
	if len(want) == 0 {
		return nil, nil, int64(n), errNotCandidate
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, nil, int64(n), err
	}
	data, err := io.ReadAll(io.LimitReader(f, implantMaxFile))
	read := int64(len(data))
	if err != nil {
		return nil, nil, read, err
	}
	for _, fam := range want {
		strong, all := 0, []string{}
		for _, m := range fam.Strong {
			if bytes.Contains(data, m) {
				strong++
				all = append(all, string(m))
			}
		}
		for _, m := range fam.Weak {
			if bytes.Contains(data, m) {
				all = append(all, string(m))
			}
		}
		if strong >= 1 && len(all) >= 2 {
			return fam, all, read, nil
		}
	}
	return nil, nil, read, nil
}

// implantFileFinding reports a program holding a family's markers.
func implantFileFinding(fam *implantFamily, path string, markers []string, pids []uint32) Finding {
	running := "not running now"
	if len(pids) > 0 {
		ids := make([]string, len(pids))
		for i, p := range pids {
			ids[i] = fmt.Sprint(p)
		}
		running = "running as pid " + strings.Join(ids, ", ")
	}
	detail := fmt.Sprintf("%s (%s) holds %s's own strings (%s): %s, %s", path, running, fam.Name,
		strings.Join(quoteAll(markersShown(markers)), ", "), fam.Name, fam.Summary)
	if fam.Critical {
		detail += ". It marks itself critical, so ending it crashes Windows: suspend it rather than kill it"
	}
	return Finding{Rule: fam.Rule, Severity: SevCritical, Technique: fam.Technique, Confidence: 95, Detail: detail}
}

// markersShown keeps the report readable: at most four markers.
func markersShown(m []string) []string {
	if len(m) > 4 {
		return append(append([]string{}, m[:4]...), fmt.Sprintf("and %d more", len(m)-4))
	}
	return m
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		if strings.HasPrefix(s, "and ") {
			out[i] = s
		} else {
			out[i] = fmt.Sprintf("%q", s)
		}
	}
	return out
}

// stagedFile is a file found in a temporary folder.
type stagedFile struct {
	Name string // lower-case
	Size int64
	Head []byte // the first bytes (up to 1 KiB)
}

// nikStaged are the files NIK C2 writes to the user's temporary folder.
var nikStaged = set("bootkit.bin", "lock_screen.html", "lock_start.bat", "mbr_backup.bin", "browserdata.zip")

// isMBRCopy reports whether bytes look like a disk's master boot record: 512
// bytes or more ending its first sector with the 55 AA signature.
func isMBRCopy(f stagedFile) bool {
	return f.Size >= 512 && len(f.Head) >= 512 && f.Head[510] == 0x55 && f.Head[511] == 0xAA
}

// stagedFilesFinding judges what NIK C2 leaves in one temporary folder: its
// bootkit placeholder, its lock screen (the page and the batch file that
// reopens it), a copy of the disk's master boot record, and the archive of
// browser data it exfiltrates. Generic names alone prove little, so it takes
// the placeholder's content, or two of them together.
func stagedFilesFinding(dir string, files []stagedFile) (Finding, bool) {
	marker := implantFamilies[0].Strong[2]
	var seen []string
	placeholder, lockPair, mbr := false, 0, false
	for _, f := range files {
		if !nikStaged[f.Name] {
			continue
		}
		switch f.Name {
		case "bootkit.bin":
			if bytes.Contains(f.Head, marker) {
				placeholder = true
			}
		case "lock_screen.html", "lock_start.bat":
			lockPair++
		case "mbr_backup.bin":
			mbr = isMBRCopy(f)
			if !mbr {
				continue
			}
		}
		seen = append(seen, f.Name)
	}
	sort.Strings(seen)
	list := strings.Join(seen, ", ")
	switch {
	case placeholder:
		return Finding{Rule: "malware.nik_c2_artifact", Severity: SevCritical, Technique: "T1542.003", Confidence: 95,
			Detail: fmt.Sprintf("%s holds NIK C2's bootkit placeholder (bootkit.bin) among %s: the implant ran here, checked "+
				"the boot configuration and Secure Boot, and staged this file", dir, list)}, true
	case lockPair == 2:
		return Finding{Rule: "malware.nik_c2_artifact", Severity: SevCritical, Technique: "T1491.001", Confidence: 85,
			Detail: fmt.Sprintf("%s holds NIK C2's lock screen (%s): an HTML ransom page and the batch file that reopens it "+
				"with mshta every five seconds. Nothing is encrypted; the screen only demands payment", dir, list)}, true
	case len(seen) >= 2:
		return Finding{Rule: "malware.nik_c2_artifact", Severity: SevSuspect, Technique: "T1074.001", Confidence: 65,
			Detail: fmt.Sprintf("%s holds files NIK C2 stages (%s)", dir, list)}, true
	case mbr:
		return Finding{Rule: "malware.nik_c2_artifact", Severity: SevSuspect, Technique: "T1006", Confidence: 55,
			Detail: fmt.Sprintf("%s holds a copy of a disk's master boot record (mbr_backup.bin, ending in the 55 AA boot "+
				"signature): bootkits, wipers and fake ransomware back it up before overwriting it (NIK C2 names its copy "+
				"this)", dir)}, true
	}
	return Finding{}, false
}

// readStaged lists the files directly in a folder, with the start of each of
// NIK C2's names read for the checks above.
func readStaged(dir string) ([]stagedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []stagedFile
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() || !nikStaged[name] {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		f := stagedFile{Name: name, Size: info.Size()}
		if fh, _, err := openRegular(dir + string(os.PathSeparator) + e.Name()); err == nil {
			head := make([]byte, 1024)
			n, _ := io.ReadFull(fh, head)
			f.Head = head[:n]
			fh.Close()
		}
		out = append(out, f)
	}
	return out, nil
}
