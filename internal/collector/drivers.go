package collector

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/pehash"
	"github.com/jp101216/liveresponse-ng/internal/vulndrivers"
)

// driversCollector inventories the host's kernel drivers (every module the
// kernel has loaded, and every driver registered as a service) and checks
// each file against the bundled list of known vulnerable and malicious drivers
// (LOLDrivers; see internal/vulndrivers) by its SHA-256 and its Authenticode
// digest. That is the check for bring your own vulnerable driver (BYOVD): a
// legitimately signed driver with a known flaw, loaded to run code in the
// kernel. It also reports what decides which drivers can load at all: kernel
// code signing, test signing, memory integrity (HVCI) and Microsoft's
// vulnerable driver blocklist.
type driversCollector struct{ opts RunOptions }

func (*driversCollector) Name() string        { return "drivers" }
func (*driversCollector) Platforms() []string { return []string{"windows"} }

func (c *driversCollector) Configure(o RunOptions) { c.opts = o }

// Timeout allows for hashing every driver file twice on a slow disk (a GPU
// driver alone can be 100 MiB); a typical host takes seconds.
func (*driversCollector) Timeout() time.Duration { return 2 * time.Minute }

func (c *driversCollector) Collect(ctx context.Context) (Result, error) {
	return collectDrivers(ctx, c.opts)
}

func init() { Register(func() Collector { return &driversCollector{} }) }

// kernelModule is one entry of the kernel's loaded-module list.
type kernelModule struct {
	KernelPath string // as the kernel names it: \SystemRoot\..., \??\C:\...
	Path       string // the same file as a Win32 path
	LoadOrder  int
}

// driverService is a driver registered under HKLM\SYSTEM\...\Services.
type driverService struct {
	Name      string
	ImagePath string // the ImagePath value as stored ("" = the default path)
	Path      string // the file it loads, as a Win32 path
	Start     string
	Type      string
	LastWrite time.Time
}

// driverFile is one driver file on the host: loaded, registered, or both.
type driverFile struct {
	Path       string
	KernelPath string // as loaded ("" when not loaded)
	Loaded     bool
	LoadOrder  int
	Services   []driverService
	// DumpCopyOf is set for the crash-dump and hibernation stacks' copies of
	// a storage driver (dump_storahci.sys is storahci.sys loaded a second
	// time under another name): the file that copy came from.
	DumpCopyOf string
}

// kernelModulePath turns a path from the kernel's module list into a Win32
// path. dosPath maps an NT device path (\Device\HarddiskVolume3\x) to a drive
// letter, or returns "" when it can't.
func kernelModulePath(raw, sysRoot string, dosPath func(string) string) string {
	p := strings.TrimSpace(raw)
	lower := strings.ToLower(p)
	switch {
	case p == "":
		return ""
	case strings.HasPrefix(lower, `\??\unc\`):
		return `\\` + p[len(`\??\unc\`):]
	case strings.HasPrefix(lower, `\device\`):
		if dosPath != nil {
			if d := dosPath(p); d != "" {
				return d
			}
		}
		return `\\?\GLOBALROOT` + p // still openable
	case strings.HasPrefix(lower, `\windows\`), strings.HasPrefix(lower, `\program files`):
		// Rooted with no drive: the system drive.
		if len(sysRoot) >= 2 && sysRoot[1] == ':' {
			return sysRoot[:2] + p
		}
	case !strings.ContainsAny(p, `\/`):
		return strings.TrimRight(sysRoot, `\`) + `\System32\drivers\` + p
	}
	return normalizeImageWith(p, strings.TrimRight(sysRoot, `\`), func(string) (string, bool) { return "", false })
}

// parseModuleList reads the buffer NtQuerySystemInformation fills for
// SystemModuleInformation: RTL_PROCESS_MODULES, a module count then an array
// of RTL_PROCESS_MODULE_INFORMATION, laid out for a ptrSize-byte pointer (8 on
// amd64 and arm64, 4 on 386). Each entry's FullPathName is an ANSI string,
// converted by ansi. Only the path and load order are kept: module base
// addresses are kernel layout, not evidence, and recent Windows zeroes them
// for most callers anyway.
func parseModuleList(buf []byte, ptrSize int, ansi func([]byte) string) ([]kernelModule, error) {
	if ptrSize != 4 && ptrSize != 8 {
		return nil, fmt.Errorf("module list: pointer size %d", ptrSize)
	}
	if len(buf) < 4 {
		return nil, fmt.Errorf("module list: %d-byte buffer", len(buf))
	}
	n := int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24)
	const nameLen = 256
	entry := 3*ptrSize + 16 + nameLen
	if n < 0 || n > (len(buf)-ptrSize)/entry {
		return nil, fmt.Errorf("module list: %d modules don't fit in %d bytes", n, len(buf))
	}
	out := make([]kernelModule, 0, n)
	for i := 0; i < n; i++ {
		e := buf[ptrSize+i*entry:][:entry]
		order := int(uint16(e[3*ptrSize+8]) | uint16(e[3*ptrSize+9])<<8)
		name := e[3*ptrSize+16:]
		if z := bytes.IndexByte(name, 0); z >= 0 {
			name = name[:z]
		}
		if len(name) == 0 {
			continue
		}
		out = append(out, kernelModule{KernelPath: ansi(name), LoadOrder: order})
	}
	return out, nil
}

// defaultDriverPath is the file a driver service with no ImagePath loads.
func defaultDriverPath(service, sysRoot string) string {
	return strings.TrimRight(sysRoot, `\`) + `\System32\drivers\` + service + ".sys"
}

// dumpCopyOf returns the driver a crash-dump or hibernation copy was made
// from: System32\drivers\dump_x.sys -> System32\drivers\x.sys. Only names in
// the drivers directory count, so a "dump_" name dropped elsewhere is judged
// like any other driver.
func dumpCopyOf(path, sysRoot string) string {
	dir := strings.ToLower(strings.TrimRight(sysRoot, `\`)) + `\system32\drivers\`
	if !strings.HasPrefix(strings.ToLower(path), dir) {
		return ""
	}
	name := path[len(dir):]
	for _, pre := range []string{"dump_", "hiber_"} {
		if len(name) > len(pre) && strings.EqualFold(name[:len(pre)], pre) && !strings.ContainsAny(name, `\/`) {
			return path[:len(dir)] + name[len(pre):]
		}
	}
	return ""
}

// mergeDrivers joins the loaded modules and the registered driver services
// into one entry per file: loaded drivers first, in load order, then drivers
// that are only registered, by path.
func mergeDrivers(mods []kernelModule, svcs []driverService, sysRoot string) []driverFile {
	var out []*driverFile
	byPath := map[string]*driverFile{}
	for _, m := range mods {
		if m.Path == "" {
			continue
		}
		k := strings.ToLower(m.Path)
		if d := byPath[k]; d != nil {
			continue // listed twice: keep the first load
		}
		d := &driverFile{Path: m.Path, KernelPath: m.KernelPath, Loaded: true, LoadOrder: m.LoadOrder,
			DumpCopyOf: dumpCopyOf(m.Path, sysRoot)}
		byPath[k] = d
		out = append(out, d)
	}
	loaded := len(out)
	for _, s := range svcs {
		if s.Path == "" {
			continue
		}
		k := strings.ToLower(s.Path)
		d := byPath[k]
		if d == nil {
			d = &driverFile{Path: s.Path}
			byPath[k] = d
			out = append(out, d)
		}
		d.Services = append(d.Services, s)
	}
	rest := out[loaded:]
	sort.SliceStable(rest, func(i, j int) bool { return strings.ToLower(rest[i].Path) < strings.ToLower(rest[j].Path) })
	files := make([]driverFile, len(out))
	for i, d := range out {
		files[i] = *d
	}
	return files
}

// Code-integrity options, from NtQuerySystemInformation's
// SystemCodeIntegrityInformation (CODEINTEGRITY_OPTION_*, documented with
// that function in winternl.h).
const (
	ciEnabled    = 0x01   // kernel-mode code integrity is enforced
	ciTestSign   = 0x02   // test-signed code loads
	ciUMCI       = 0x04   // user-mode code integrity (WDAC) is enforced
	ciDebugMode  = 0x80   // a kernel debugger is enabled; unsigned code may load
	ciHVCI       = 0x400  // memory integrity (HVCI) enforces kernel code integrity
	ciHVCIAudit  = 0x800  // HVCI in audit mode
	ciHVCIStrict = 0x1000 // HVCI strict mode
)

// codeIntegrity is the host's driver-loading policy.
type codeIntegrity struct {
	Known   bool   // Options could be read
	Options uint32 // CODEINTEGRITY_OPTION_* flags
	// Blocklist is HKLM\SYSTEM\CurrentControlSet\Control\CI\Config's
	// VulnerableDriverBlocklistEnable, when it is set.
	Blocklist  *uint32
	HVCIConfig *uint32 // ...\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity Enabled
	Error      string
}

const blocklistKey = `HKLM\SYSTEM\CurrentControlSet\Control\CI\Config`

func (ci codeIntegrity) hvci() bool { return ci.Known && ci.Options&ciHVCI != 0 }

// fields describes the policy as a record.
func (ci codeIntegrity) fields() map[string]any {
	f := map[string]any{"kind": "code_integrity"}
	if ci.Known {
		f["code_integrity_options"] = fmt.Sprintf("0x%x", ci.Options)
		f["kernel_code_integrity"] = ci.Options&ciEnabled != 0
		f["test_signing"] = ci.Options&ciTestSign != 0
		f["kernel_debugging"] = ci.Options&ciDebugMode != 0
		f["user_mode_code_integrity"] = ci.Options&ciUMCI != 0
		f["hvci"] = ci.Options&ciHVCI != 0
		if ci.Options&ciHVCIAudit != 0 {
			f["hvci_audit"] = true
		}
		if ci.Options&ciHVCIStrict != 0 {
			f["hvci_strict"] = true
		}
	} else if ci.Error != "" {
		f["code_integrity_error"] = ci.Error
	}
	switch {
	case ci.Blocklist == nil:
		// Unset: on by default on Windows 11 22H2 and later, and wherever HVCI
		// is on; off by default before that.
		f["vulnerable_driver_blocklist"] = "default"
	case *ci.Blocklist == 0:
		f["vulnerable_driver_blocklist"] = "disabled"
	default:
		f["vulnerable_driver_blocklist"] = "enabled"
	}
	if ci.HVCIConfig != nil {
		f["hvci_configured"] = *ci.HVCIConfig != 0
	}
	return f
}

// findings judges the policy: settings that let a driver load that otherwise
// couldn't.
func (ci codeIntegrity) findings() []Finding {
	var out []Finding
	if ci.Blocklist != nil && *ci.Blocklist == 0 {
		out = append(out, Finding{
			Rule: "defense.driver_blocklist_disabled", Severity: SevSuspect, Technique: "T1562.001", Confidence: 60,
			Detail: "Microsoft's vulnerable driver blocklist is switched off (" + blocklistKey + ` VulnerableDriverBlocklistEnable = 0): ` +
				"drivers it would block can load. Attackers switch it off before bringing their own vulnerable driver",
		})
	}
	if !ci.Known {
		return out
	}
	if ci.Options&ciEnabled == 0 {
		out = append(out, Finding{
			Rule: "defense.code_integrity_weakened", Severity: SevSuspect, Technique: "T1553.006", Confidence: 70,
			Detail: "kernel-mode code integrity reports itself off: drivers load without a valid signature",
		})
	}
	if ci.Options&ciTestSign != 0 {
		out = append(out, Finding{
			Rule: "defense.code_integrity_weakened", Severity: SevNotable, Technique: "T1553.006", Confidence: 50,
			Detail: "test signing is on: the kernel loads drivers signed with any self-made certificate. Driver developers turn it on; anywhere else it lets unsigned rootkits load",
		})
	}
	if ci.Options&ciDebugMode != 0 {
		out = append(out, Finding{
			Rule: "defense.code_integrity_weakened", Severity: SevNotable, Technique: "T1553.006", Confidence: 40,
			Detail: "kernel debugging is enabled: code integrity may let unsigned code load",
		})
	}
	return out
}

// knownDriverFinding is the finding for a driver the vulnerable-driver list
// names; state says where it was seen ("is loaded in the kernel", ...).
func knownDriverFinding(m vulndrivers.Match, path, state string, hvciOn bool) Finding {
	d := m.Driver
	what := "LOLDrivers: " + d.Label()
	if len(d.CVEs) > 0 {
		what += ", " + strings.Join(d.CVEs[:min(len(d.CVEs), 3)], ", ")
	}
	if !d.Verified {
		what += ", entry not yet verified by LOLDrivers"
	}
	what += ", matched by " + m.By
	tech := d.Technique
	if d.Category == vulndrivers.Malicious {
		if tech == "" {
			tech = "T1014"
		}
		return Finding{
			Rule: "persistence.malicious_driver", Severity: SevCritical, Technique: tech, Confidence: 95,
			Detail: fmt.Sprintf("%s is a known malicious driver (%s) and %s. See %s", path, what, state, d.URL()),
		}
	}
	if tech == "" {
		tech = "T1068"
	}
	if strings.HasPrefix(state, "is loaded") || strings.HasPrefix(state, "was loaded") {
		return Finding{
			Rule: "privesc.vulnerable_driver_loaded", Severity: SevSuspect, Technique: tech, Confidence: 75,
			Detail: fmt.Sprintf("%s is a known vulnerable driver (%s) and %s: attackers load signed drivers like this "+
				"to run code in the kernel (bring your own vulnerable driver) — to kill EDR, strip process protection or "+
				"load a rootkit. Some hardware and tuning tools ship it legitimately; check what installed it. See %s",
				path, what, state, d.URL()),
		}
	}
	f := Finding{
		Rule: "privesc.vulnerable_driver_installed", Severity: SevNotable, Technique: tech, Confidence: 55,
		Detail: fmt.Sprintf("%s is a known vulnerable driver (%s) and %s: not loaded now, but one service start away "+
			"from the kernel. See %s", path, what, state, d.URL()),
	}
	if hvciOn && m.HVCI == vulndrivers.HVCIBlocked {
		f.Confidence = 40
		f.Detail += ". Memory integrity (HVCI) is on, and LOLDrivers records that it keeps this build from loading"
	}
	return f
}

// judgeDriver returns the findings for one driver file. m is its entry in
// the vulnerable-driver list, if any; missing says its file is gone.
func judgeDriver(d driverFile, m *vulndrivers.Match, missing, hvciOn bool) []Finding {
	var out []Finding
	if m != nil {
		out = append(out, knownDriverFinding(*m, d.Path, driverState(d), hvciOn))
	}
	if !d.Loaded {
		return out
	}
	if missing && d.DumpCopyOf == "" {
		out = append(out, Finding{
			Rule: "defense.loaded_driver_file_missing", Severity: SevNotable, Technique: "T1070.004", Confidence: 45,
			Detail: fmt.Sprintf("the kernel has %s loaded, but the file is gone from disk, so it can't be checked against the "+
				"vulnerable-driver list: tools that unpack a driver, load it and delete it leave this, and so do BYOVD loaders "+
				"cleaning up after themselves", d.Path),
		})
	}
	if lvl, why := pathRisk(d.Path); lvl == riskHigh {
		out = append(out, Finding{
			Rule: "privesc.driver_unusual_path", Severity: SevSuspect, Technique: "T1068", Confidence: 60,
			Detail: fmt.Sprintf("the kernel has %s loaded from %s: drivers are installed under the Windows directory or "+
				"Program Files, while BYOVD loaders drop theirs somewhere writable and load it from there", d.Path, why),
		})
	}
	return out
}

// driverState says how a driver is present, for a finding's detail.
func driverState(d driverFile) string {
	var svc string
	if len(d.Services) > 0 {
		s := d.Services[0]
		svc = "service " + s.Name
		if s.Start != "" {
			svc += " (start: " + s.Start + ")"
		}
		if len(d.Services) > 1 {
			svc += fmt.Sprintf(" and %d more", len(d.Services)-1)
		}
	}
	switch {
	case d.Loaded && svc != "":
		return "is loaded in the kernel, registered as " + svc
	case d.Loaded:
		return "is loaded in the kernel"
	default:
		return "is registered as " + svc
	}
}

// driverFields renders a driver as a record.
func driverFields(d driverFile) map[string]any {
	name := d.Path[strings.LastIndexAny(d.Path, `\/`)+1:]
	f := map[string]any{"kind": "driver", "name": name, "path": d.Path, "loaded": d.Loaded}
	if d.Loaded {
		f["load_order"] = d.LoadOrder
		if d.KernelPath != "" && d.KernelPath != d.Path {
			f["kernel_path"] = d.KernelPath
		}
	}
	if d.DumpCopyOf != "" {
		f["dump_copy_of"] = d.DumpCopyOf
	}
	if len(d.Services) > 0 {
		names := make([]string, len(d.Services))
		for i, s := range d.Services {
			names[i] = s.Name
		}
		f["services"] = names
		s := d.Services[0]
		if s.Start != "" {
			f["start"] = s.Start
		}
		if s.Type != "" {
			f["service_type"] = s.Type
		}
		if s.ImagePath != "" {
			f["image_path"] = s.ImagePath
		}
		if !s.LastWrite.IsZero() {
			f["service_key_last_write"] = s.LastWrite
		}
	}
	return f
}

// matchFields records a vulnerable-driver match on the record.
func matchFields(f map[string]any, m vulndrivers.Match) {
	f["loldrivers_id"] = m.Driver.ID
	f["loldrivers_category"] = m.Driver.Category.String()
	f["loldrivers_match"] = m.By
	f["loldrivers_url"] = m.Driver.URL()
	if len(m.Driver.Names) > 0 {
		f["loldrivers_names"] = m.Driver.Names
	}
	switch m.HVCI {
	case vulndrivers.HVCILoads:
		f["loldrivers_loads_despite_hvci"] = true
	case vulndrivers.HVCIBlocked:
		f["loldrivers_loads_despite_hvci"] = false
	}
}

// driverDataset is the vulnerable-driver list the collector checks against:
// the bundled one (a variable so the Windows tests can plant entries).
var driverDataset = vulndrivers.Default

// maxDriverHashBytes caps the Authenticode pass, as DefaultHashMaxBytes caps
// the file hash. The largest real drivers (GPU drivers) are under 100 MiB.
const maxDriverHashBytes = DefaultHashMaxBytes

// checkDriverFile hashes one driver file (SHA-256 through the run's shared
// hasher, then the Authenticode digest) and looks it up. It records the
// hashes on the record and reports whether the file is missing. set may be
// nil (the dataset failed to load): the hashes are still recorded.
func checkDriverFile(ctx context.Context, h *FileHasher, set *vulndrivers.Set, f map[string]any, path string) (*vulndrivers.Match, bool) {
	r := h.Hash(ctx, path)
	switch {
	case r.SHA256 != "":
		f["image_sha256"] = r.SHA256
	case r.NotExist:
		f["image_exists"] = false
		return nil, true
	case r.Err != "":
		f["image_hash_error"] = r.Err
	}
	var match *vulndrivers.Match
	try := func(m vulndrivers.Match, ok bool) {
		if ok && match == nil {
			match = &m
		}
	}
	if set != nil && r.SHA256 != "" {
		try(set.FileHex(r.SHA256))
	}
	if ctx.Err() != nil {
		return match, false
	}
	d, err := authentihashFile(path)
	if err != nil {
		f["authentihash_error"] = err.Error()
		return match, false
	}
	f["authentihash_sha256"] = hex.EncodeToString(d.SHA256[:])
	f["authentihash_sha1"] = hex.EncodeToString(d.SHA1[:])
	if set != nil {
		try(set.AuthentihashSHA256(d.SHA256))
		try(set.AuthentihashSHA1(d.SHA1))
	}
	return match, false
}

func authentihashFile(path string) (pehash.Digests, error) {
	fh, _, err := openRegular(path)
	if err != nil {
		return pehash.Digests{}, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return pehash.Digests{}, err
	}
	if !st.Mode().IsRegular() {
		return pehash.Digests{}, fmt.Errorf("not a regular file")
	}
	if st.Size() > maxDriverHashBytes {
		return pehash.Digests{}, fmt.Errorf("not hashed: %d bytes exceeds the %d-byte cap", st.Size(), int64(maxDriverHashBytes))
	}
	return pehash.AuthentihashReader(fh, st.Size())
}

// driversReport builds the result from what the platform code gathered. It is
// the portable half of collectDrivers: every judgement happens here.
func driversReport(ctx context.Context, res *Result, opts RunOptions, files []driverFile, ci codeIntegrity) {
	set, err := driverDataset()
	if err != nil {
		res.Fail("vulnerable-driver dataset: " + err.Error())
		set = nil
	} else {
		res.SetMeta("dataset", set.Info)
	}
	res.Add(ci.fields(), ci.findings()...)

	hvciOn := ci.hvci()
	loaded, registered, hashed, matched := 0, 0, 0, 0
	for _, d := range files {
		f := driverFields(d)
		if d.Loaded {
			loaded++
		} else {
			registered++
		}
		var m *vulndrivers.Match
		missing := false
		if opts.Hasher != nil && ctx.Err() == nil {
			file := d.Path
			if d.DumpCopyOf != "" {
				file = d.DumpCopyOf
			}
			m, missing = checkDriverFile(ctx, opts.Hasher, set, f, file)
			if _, ok := f["image_sha256"]; ok {
				hashed++
			}
		} else if d.DumpCopyOf == "" && checkLocalPath(d.Path) == nil && fileMissing(d.Path) {
			f["image_exists"] = false
			missing = true
		}
		if m != nil {
			matched++
			matchFields(f, *m)
		}
		findings := judgeDriver(d, m, missing, hvciOn)
		// Name who signed the drivers that need a second look.
		if len(findings) > 0 && opts.Signer != nil && !missing && ctx.Err() == nil {
			opts.Signer.Fields(ctx, f, d.Path)
		}
		res.Add(f, findings...)
	}
	res.SetMeta("loaded", loaded)
	res.SetMeta("registered_not_loaded", registered)
	res.SetMeta("hashed", hashed)
	res.SetMeta("known_vulnerable_or_malicious", matched)
	switch {
	case opts.Hasher == nil:
		res.SetMeta("known_driver_check", "off: hashing is disabled (-no-hash), so drivers were listed but not checked against the list")
	case ctx.Err() != nil:
		res.SetMeta("known_driver_check", "partial: the time budget ran out")
	default:
		res.SetMeta("known_driver_check", "file SHA-256 and Authenticode digest of every driver file")
	}
}
