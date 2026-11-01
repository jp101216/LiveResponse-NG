package collector

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/pehash"
	"github.com/jp101216/liveresponse-ng/internal/vulndrivers"
)

const testSysRoot = `C:\Windows`

func TestKernelModulePath(t *testing.T) {
	dos := func(nt string) string {
		if strings.HasPrefix(strings.ToLower(nt), `\device\harddiskvolume3\`) {
			return `D:` + nt[len(`\Device\HarddiskVolume3`):]
		}
		return ""
	}
	for raw, want := range map[string]string{
		`\SystemRoot\system32\ntoskrnl.exe`:          `C:\Windows\system32\ntoskrnl.exe`,
		`\SystemRoot\System32\drivers\tcpip.sys`:     `C:\Windows\System32\drivers\tcpip.sys`,
		`System32\drivers\afd.sys`:                   `C:\Windows\System32\drivers\afd.sys`,
		`\??\C:\Users\x\AppData\Local\Temp\a.sys`:    `C:\Users\x\AppData\Local\Temp\a.sys`,
		`\??\UNC\srv\share\b.sys`:                    `\\srv\share\b.sys`,
		`\Windows\System32\drivers\c.sys`:            `C:\Windows\System32\drivers\c.sys`,
		`\Program Files\Vendor\d.sys`:                `C:\Program Files\Vendor\d.sys`,
		`\Device\HarddiskVolume3\tools\e.sys`:        `D:\tools\e.sys`,
		`\Device\HarddiskVolume9\tools\f.sys`:        `\\?\GLOBALROOT\Device\HarddiskVolume9\tools\f.sys`,
		`g.sys`:                                      `C:\Windows\System32\drivers\g.sys`,
		`C:\ProgramData\h.sys`:                       `C:\ProgramData\h.sys`,
		`  \SystemRoot\System32\DRIVERS\i.sys  `:     `C:\Windows\System32\DRIVERS\i.sys`,
		``:                                           ``,
		`\SystemRoot\System32\DriverStore\j\j.sys`:   `C:\Windows\System32\DriverStore\j\j.sys`,
		`\??\C:\Windows\System32\drivers\k with.sys`: `C:\Windows\System32\drivers\k with.sys`,
	} {
		if got := kernelModulePath(raw, testSysRoot, dos); got != want {
			t.Errorf("%q -> %q, want %q", raw, got, want)
		}
	}
	if got := defaultDriverPath("Beep", testSysRoot+`\`); got != `C:\Windows\System32\drivers\Beep.sys` {
		t.Errorf("default path %q", got)
	}
}

func TestDumpCopyOf(t *testing.T) {
	for path, want := range map[string]string{
		`C:\Windows\System32\drivers\dump_storahci.sys`:  `C:\Windows\System32\drivers\storahci.sys`,
		`C:\Windows\system32\DRIVERS\Dump_dumpfve.sys`:   `C:\Windows\system32\DRIVERS\dumpfve.sys`,
		`C:\Windows\System32\drivers\hiber_stornvme.sys`: `C:\Windows\System32\drivers\stornvme.sys`,
		`C:\Windows\System32\drivers\storahci.sys`:       ``,
		`C:\Users\x\Temp\dump_evil.sys`:                  ``, // only the drivers directory counts
		`C:\Windows\System32\drivers\dump_`:              ``,
	} {
		if got := dumpCopyOf(path, testSysRoot); got != want {
			t.Errorf("%s -> %q, want %q", path, got, want)
		}
	}
}

func TestMergeDrivers(t *testing.T) {
	mods := []kernelModule{
		{KernelPath: `\SystemRoot\system32\ntoskrnl.exe`, Path: `C:\Windows\system32\ntoskrnl.exe`, LoadOrder: 0},
		{KernelPath: `\SystemRoot\System32\drivers\Beep.SYS`, Path: `C:\Windows\System32\drivers\Beep.SYS`, LoadOrder: 7},
		{KernelPath: `\SystemRoot\System32\drivers\beep.sys`, Path: `C:\Windows\System32\drivers\beep.sys`, LoadOrder: 9}, // twice
		{Path: ""},
	}
	svcs := []driverService{
		{Name: "zeta", Path: `C:\Windows\System32\drivers\zeta.sys`, Start: "manual"},
		{Name: "Beep", Path: `C:\Windows\System32\drivers\beep.sys`, Start: "system"},
		{Name: "alpha", Path: `C:\Windows\System32\drivers\alpha.sys`},
		{Name: "alpha2", Path: `C:\WINDOWS\System32\drivers\ALPHA.sys`}, // two services, one file
		{Name: "nopath"},
	}
	got := mergeDrivers(mods, svcs, testSysRoot)
	var names []string
	for _, d := range got {
		names = append(names, d.Path)
	}
	want := []string{`C:\Windows\system32\ntoskrnl.exe`, `C:\Windows\System32\drivers\Beep.SYS`,
		`C:\Windows\System32\drivers\alpha.sys`, `C:\Windows\System32\drivers\zeta.sys`}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("order %v", names)
	}
	if !got[1].Loaded || got[1].LoadOrder != 7 || len(got[1].Services) != 1 || got[1].Services[0].Name != "Beep" {
		t.Errorf("beep: %+v", got[1])
	}
	if got[2].Loaded || len(got[2].Services) != 2 {
		t.Errorf("alpha: %+v", got[2])
	}
	if s := driverState(got[2]); s != "is registered as service alpha and 1 more" {
		t.Errorf("state %q", s)
	}
	if s := driverState(got[1]); s != "is loaded in the kernel, registered as service Beep (start: system)" {
		t.Errorf("state %q", s)
	}
}

// moduleList builds the buffer NtQuerySystemInformation returns for
// SystemModuleInformation, for either pointer size.
func moduleList(ptr int, names ...string) []byte {
	entry := 3*ptr + 16 + 256
	b := make([]byte, ptr+len(names)*entry)
	binary.LittleEndian.PutUint32(b, uint32(len(names)))
	for i, n := range names {
		e := b[ptr+i*entry:]
		for j := 0; j < 3*ptr; j++ {
			e[j] = 0xEE // section, mapped base, image base: ignored
		}
		binary.LittleEndian.PutUint16(e[3*ptr+8:], uint16(100+i)) // LoadOrderIndex
		binary.LittleEndian.PutUint16(e[3*ptr+14:], 3)            // OffsetToFileName
		copy(e[3*ptr+16:], n)
	}
	return b
}

func TestParseModuleList(t *testing.T) {
	for _, ptr := range []int{8, 4} {
		buf := moduleList(ptr, `\SystemRoot\system32\ntoskrnl.exe`, ``, `\??\C:\x\`+strings.Repeat("a", 251))
		mods, err := parseModuleList(buf, ptr, func(b []byte) string { return string(b) })
		if err != nil {
			t.Fatal(err)
		}
		if len(mods) != 2 || mods[0].KernelPath != `\SystemRoot\system32\ntoskrnl.exe` || mods[0].LoadOrder != 100 ||
			mods[1].LoadOrder != 102 || len(mods[1].KernelPath) != 256 {
			t.Errorf("ptr %d: %+v", ptr, mods)
		}
		if _, err := parseModuleList(buf[:len(buf)-1], ptr, nil); err == nil {
			t.Errorf("ptr %d: a truncated list parsed", ptr)
		}
	}
	if _, err := parseModuleList([]byte{1, 0}, 8, nil); err == nil {
		t.Error("a 2-byte buffer parsed")
	}
	huge := moduleList(8)
	binary.LittleEndian.PutUint32(huge, 0xFFFFFFFF)
	if _, err := parseModuleList(huge, 8, nil); err == nil {
		t.Error("an impossible module count parsed")
	}
}

func u32p(v uint32) *uint32 { return &v }

func TestCodeIntegrity(t *testing.T) {
	clean := codeIntegrity{Known: true, Options: ciEnabled | ciHVCI}
	if f := clean.findings(); len(f) != 0 {
		t.Errorf("a normal host: %+v", f)
	}
	fields := clean.fields()
	if fields["hvci"] != true || fields["kernel_code_integrity"] != true || fields["test_signing"] != false ||
		fields["vulnerable_driver_blocklist"] != "default" || fields["kind"] != "code_integrity" {
		t.Errorf("fields %v", fields)
	}
	if !clean.hvci() {
		t.Error("hvci() false")
	}
	if (codeIntegrity{Known: true, Options: ciEnabled, Blocklist: u32p(1)}).fields()["vulnerable_driver_blocklist"] != "enabled" {
		t.Error("blocklist enabled not reported")
	}
	weak := codeIntegrity{Known: true, Options: ciTestSign | ciDebugMode, Blocklist: u32p(0), HVCIConfig: u32p(0)}
	rules := map[string]Severity{}
	for _, f := range weak.findings() {
		if SeverityRank(f.Severity) > SeverityRank(rules[f.Rule]) {
			rules[f.Rule] = f.Severity
		}
	}
	if rules["defense.driver_blocklist_disabled"] != SevSuspect || rules["defense.code_integrity_weakened"] != SevSuspect ||
		len(weak.findings()) != 4 {
		t.Errorf("weak host: %+v", weak.findings())
	}
	if weak.fields()["vulnerable_driver_blocklist"] != "disabled" || weak.fields()["hvci_configured"] != false {
		t.Errorf("weak fields %v", weak.fields())
	}
	// Options that couldn't be read: no findings from them, the error kept.
	unknown := codeIntegrity{Error: "denied"}
	if len(unknown.findings()) != 0 || unknown.fields()["code_integrity_error"] != "denied" || unknown.hvci() {
		t.Errorf("unknown: %v %v", unknown.findings(), unknown.fields())
	}
}

const testDataset = `# source: test
D	375e8de3-aae4-488d-8273-66744978b45f	vulnerable	yes	T1068	CVE-2019-16098	szkg64.sys
S	%FILE%	-	-	-	no
D	22222222-2222-2222-2222-222222222222	malicious	no	-	-	evil.sys
S	-	-	%AUTH%	-	-
`

// testPE is a small PE32+ image with one section and, optionally, a
// certificate table (whose bytes stand in for a signature).
func testPE(cert []byte) []byte {
	b := make([]byte, 0x600)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], 0x8664)
	binary.LittleEndian.PutUint16(b[0x86:], 1)
	binary.LittleEndian.PutUint16(b[0x94:], 240)
	opt := 0x98
	binary.LittleEndian.PutUint16(b[opt:], 0x20b)
	binary.LittleEndian.PutUint32(b[opt+60:], 0x400)
	binary.LittleEndian.PutUint32(b[opt+108:], 16)
	sec := opt + 240
	copy(b[sec:], ".text")
	binary.LittleEndian.PutUint32(b[sec+16:], 0x200)
	binary.LittleEndian.PutUint32(b[sec+20:], 0x400)
	for i := 0x400; i < 0x600; i++ {
		b[i] = 0xC3
	}
	if len(cert) > 0 {
		binary.LittleEndian.PutUint32(b[opt+112+32:], uint32(len(b)))
		binary.LittleEndian.PutUint32(b[opt+112+36:], uint32(len(cert)))
		b = append(b, cert...)
	}
	return b
}

// A known driver is found by its file hash; a re-signed copy (different file
// hash, same code) by its Authenticode digest.
func TestCheckDriverFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	known := write("known.sys", testPE(nil))
	resigned := write("resigned.sys", testPE([]byte("a different signature")))
	other := testPE([]byte("x"))
	other[0x400] = 0x90 // different code
	unknown := write("unknown.sys", other)

	fileSum := sha256.Sum256(testPE(nil))
	auth, err := pehash.Authentihash(testPE(nil))
	if err != nil {
		t.Fatal(err)
	}
	data := strings.ReplaceAll(testDataset, "%FILE%", hex.EncodeToString(fileSum[:]))
	// The malicious entry lists the same code by its Authenticode digest.
	data = strings.ReplaceAll(data, "%AUTH%", hex.EncodeToString(auth.SHA256[:]))
	set, err := vulndrivers.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	h := NewFileHasher()
	ctx := context.Background()

	f := map[string]any{}
	m, missing := checkDriverFile(ctx, h, set, f, known)
	if m == nil || missing || m.By != "file SHA-256" || m.Driver.Label() != "szkg64.sys" {
		t.Fatalf("known: %+v %v", m, missing)
	}
	if f["image_sha256"] != hex.EncodeToString(fileSum[:]) || f["authentihash_sha256"] != hex.EncodeToString(auth.SHA256[:]) {
		t.Errorf("known fields %v", f)
	}

	f = map[string]any{}
	m, _ = checkDriverFile(ctx, h, set, f, resigned)
	if m == nil || m.By != "Authenticode SHA-256" || m.Driver.Category != vulndrivers.Malicious {
		t.Fatalf("re-signed copy: %+v", m)
	}
	if f["authentihash_sha256"] != hex.EncodeToString(auth.SHA256[:]) || f["image_sha256"] == hex.EncodeToString(fileSum[:]) {
		t.Errorf("re-signed fields %v", f)
	}

	if m, _ := checkDriverFile(ctx, h, set, map[string]any{}, unknown); m != nil {
		t.Errorf("an unknown driver matched: %+v", m)
	}
	f = map[string]any{}
	if m, missing := checkDriverFile(ctx, h, set, f, filepath.Join(dir, "gone.sys")); m != nil || !missing || f["image_exists"] != false {
		t.Errorf("missing file: %v %v %v", m, missing, f)
	}
	f = map[string]any{}
	notPE := write("notpe.sys", []byte("not a driver"))
	if m, missing := checkDriverFile(ctx, h, nil, f, notPE); m != nil || missing || f["authentihash_error"] == nil || f["image_sha256"] == nil {
		t.Errorf("not a PE: %v %v %v", m, missing, f)
	}
}

func TestJudgeDriver(t *testing.T) {
	vuln := &vulndrivers.Driver{ID: "375e8de3-aae4-488d-8273-66744978b45f", Category: vulndrivers.Vulnerable, Verified: true,
		Technique: "T1068", CVEs: []string{"CVE-2019-16098"}, Names: []string{"RTCore64.sys"}}
	mal := &vulndrivers.Driver{ID: "22222222-2222-2222-2222-222222222222", Category: vulndrivers.Malicious, Names: []string{"evil.sys"}}
	loaded := driverFile{Path: `C:\Windows\System32\drivers\RTCore64.sys`, Loaded: true,
		Services: []driverService{{Name: "RTCore64", Start: "manual"}}}
	installed := driverFile{Path: loaded.Path, Services: loaded.Services}

	one := func(fs []Finding) Finding {
		t.Helper()
		if len(fs) != 1 {
			t.Fatalf("want one finding, got %+v", fs)
		}
		return fs[0]
	}
	f := one(judgeDriver(loaded, &vulndrivers.Match{Sample: vulndrivers.Sample{Driver: vuln}, By: "file SHA-256"}, false, false))
	if f.Rule != "privesc.vulnerable_driver_loaded" || f.Severity != SevSuspect || f.Technique != "T1068" ||
		!strings.Contains(f.Detail, "CVE-2019-16098") || !strings.Contains(f.Detail, "loldrivers.io/drivers/375e8de3") ||
		!strings.Contains(f.Detail, "registered as service RTCore64") {
		t.Errorf("loaded: %+v", f)
	}
	f = one(judgeDriver(installed, &vulndrivers.Match{Sample: vulndrivers.Sample{Driver: vuln}, By: "Authenticode SHA-1"}, false, false))
	if f.Rule != "privesc.vulnerable_driver_installed" || f.Severity != SevNotable || f.Confidence != 55 {
		t.Errorf("installed: %+v", f)
	}
	// HVCI on, and this build is one HVCI blocks: still reported, lower.
	blocked := &vulndrivers.Match{Sample: vulndrivers.Sample{Driver: vuln, HVCI: vulndrivers.HVCIBlocked}, By: "file SHA-256"}
	if f := one(judgeDriver(installed, blocked, false, true)); f.Confidence != 40 || !strings.Contains(f.Detail, "HVCI") {
		t.Errorf("installed, HVCI on: %+v", f)
	}
	if f := one(judgeDriver(installed, blocked, false, false)); f.Confidence != 55 {
		t.Errorf("installed, HVCI off: %+v", f)
	}
	f = one(judgeDriver(installed, &vulndrivers.Match{Sample: vulndrivers.Sample{Driver: mal}, By: "file SHA-256"}, false, false))
	if f.Rule != "persistence.malicious_driver" || f.Severity != SevCritical || f.Technique != "T1014" ||
		!strings.Contains(f.Detail, "not yet verified") {
		t.Errorf("malicious: %+v", f)
	}

	// No match: a loaded driver whose file is gone, and one loaded from Temp.
	gone := driverFile{Path: `C:\Windows\System32\drivers\cpuz152_x64.sys`, Loaded: true}
	if f := one(judgeDriver(gone, nil, true, false)); f.Rule != "defense.loaded_driver_file_missing" || f.Severity != SevNotable {
		t.Errorf("missing: %+v", f)
	}
	if fs := judgeDriver(driverFile{Path: gone.Path}, nil, true, false); len(fs) != 0 {
		t.Errorf("a registered-only driver with no file is the services collector's business: %+v", fs)
	}
	dump := driverFile{Path: `C:\Windows\System32\drivers\dump_iaStorAC.sys`, Loaded: true, DumpCopyOf: `C:\Windows\System32\drivers\iaStorAC.sys`}
	if fs := judgeDriver(dump, nil, true, false); len(fs) != 0 {
		t.Errorf("a crash-dump copy is never a missing file: %+v", fs)
	}
	temp := driverFile{Path: `C:\Users\bob\AppData\Local\Temp\x64.sys`, Loaded: true}
	if f := one(judgeDriver(temp, nil, false, false)); f.Rule != "privesc.driver_unusual_path" || !strings.Contains(f.Detail, "temporary") {
		t.Errorf("temp: %+v", f)
	}
	if fs := judgeDriver(driverFile{Path: `C:\Windows\System32\drivers\tcpip.sys`, Loaded: true}, nil, false, false); len(fs) != 0 {
		t.Errorf("a normal driver: %+v", fs)
	}
}

// The portable half end to end, on real files: records, fields, meta.
func TestDriversReport(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.sys")
	if err := os.WriteFile(present, testPE(nil), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []driverFile{
		{Path: present, Loaded: true, LoadOrder: 3, KernelPath: `\??\` + present},
		{Path: filepath.Join(dir, "gone.sys"), Loaded: true, LoadOrder: 4},
		{Path: filepath.Join(dir, "registered.sys"), Services: []driverService{{Name: "reg", Start: "manual", LastWrite: time.Unix(1700000000, 0)}}},
	}
	res := NewResult("drivers")
	driversReport(context.Background(), res, RunOptions{Hasher: NewFileHasher()}, files,
		codeIntegrity{Known: true, Options: ciEnabled})
	if len(res.Records) != 4 || res.Records[0].Fields["kind"] != "code_integrity" {
		t.Fatalf("records %+v", res.Records)
	}
	p := res.Records[1].Fields
	if p["kind"] != "driver" || p["name"] != "present.sys" || p["loaded"] != true || p["load_order"] != 3 ||
		p["image_sha256"] == nil || p["authentihash_sha256"] == nil || p["kernel_path"] != `\??\`+present {
		t.Errorf("present: %v", p)
	}
	if res.Records[2].Fields["image_exists"] != false || !hasRule(res.Records[2].Findings, "defense.loaded_driver_file_missing") {
		t.Errorf("gone: %+v", res.Records[2])
	}
	if r := res.Records[3]; r.Fields["services"] == nil || r.Fields["start"] != "manual" || len(r.Findings) != 0 {
		t.Errorf("registered: %+v", r)
	}
	if res.Meta["loaded"] != 2 || res.Meta["registered_not_loaded"] != 1 || res.Meta["hashed"] != 1 ||
		res.Meta["known_vulnerable_or_malicious"] != 0 || res.Meta["dataset"] == nil {
		t.Errorf("meta %v", res.Meta)
	}

	// -no-hash: listed, not hashed, and the meta says the check was off.
	res = NewResult("drivers")
	driversReport(context.Background(), res, RunOptions{}, files, codeIntegrity{})
	if res.Records[1].Fields["image_sha256"] != nil || !strings.HasPrefix(res.Meta["known_driver_check"].(string), "off") ||
		res.Records[2].Fields["image_exists"] != false {
		t.Errorf("no-hash: %+v %v", res.Records, res.Meta)
	}
}

func TestSysmonDriverLoad(t *testing.T) {
	ev := func(data map[string]string, provider string) winEvent {
		return winEvent{EventID: 6, Provider: provider, Channel: "Microsoft-Windows-Sysmon/Operational",
			TimeCreated: time.Date(2026, 10, 1, 3, 4, 5, 0, time.UTC), Data: data, UserData: map[string]string{}}
	}
	// szkg64.sys, by the hashes Sysmon writes (upper case, several algorithms).
	sysmon := ev(map[string]string{
		"ImageLoaded": `C:\Users\Public\szkg64.sys`,
		"Hashes":      "SHA1=D7698828CDC3C96CC17FE2D4FF6D93BB0CD355D8,MD5=0123456789ABCDEF0123456789ABCDEF,SHA256=6BC0E1C104FAC4A8CAA4237C7AE181CA11A043A3EE26426AEB7A90DC40281FAD,IMPHASH=00",
		"Signed":      "true", "Signature": "Some Vendor", "SignatureStatus": "Valid",
	}, "Microsoft-Windows-Sysmon")
	_, fs, keep := classifyWinEvent(sysmon, nil)
	if !keep || len(fs) != 1 || fs[0].Rule != "privesc.vulnerable_driver_loaded" ||
		!strings.Contains(fs[0].Detail, "2026-10-01T03:04:05Z") || !strings.Contains(fs[0].Detail, "file SHA-256") {
		t.Fatalf("sysmon event 6: keep %v, %+v", keep, fs)
	}
	// Sysmon's default: SHA-1 only.
	sha1only := ev(map[string]string{"ImageLoaded": `C:\x.sys`, "Hashes": "SHA1=d7698828cdc3c96cc17fe2d4ff6d93bb0cd355d8"}, "Microsoft-Windows-Sysmon")
	if fs := eventFindings(sha1only); len(fs) != 1 || !strings.Contains(fs[0].Detail, "file SHA-1") {
		t.Errorf("sha1 only: %+v", fs)
	}
	unsigned := ev(map[string]string{"ImageLoaded": `C:\Temp\rk.sys`, "Hashes": "SHA256=" + strings.Repeat("A", 64), "Signed": "false"}, "Microsoft-Windows-Sysmon")
	if fs := eventFindings(unsigned); len(fs) != 1 || fs[0].Rule != "defense.unsigned_driver_loaded" {
		t.Errorf("unsigned: %+v", fs)
	}
	normal := ev(map[string]string{"ImageLoaded": `C:\Windows\System32\drivers\x.sys`, "Hashes": "SHA256=" + strings.Repeat("A", 64), "Signed": "true"}, "Microsoft-Windows-Sysmon")
	if _, fs, keep := classifyWinEvent(normal, nil); keep || len(fs) != 0 {
		t.Errorf("an ordinary driver load is not kept: %v %+v", keep, fs)
	}
	// Event 6 from anyone but Sysmon is something else entirely.
	other := sysmon
	other.Provider, other.Channel = "Microsoft-Windows-FilterManager", "System"
	if fs := eventFindings(other); len(fs) != 0 {
		t.Errorf("non-Sysmon event 6: %+v", fs)
	}
	if got := sysmonHashes("MD5=AA, SHA1 = bb ,SHA256=cc,IMPHASH=dd"); strings.Join(got, ",") != "cc,bb" {
		t.Errorf("sysmonHashes %v", got)
	}
}
