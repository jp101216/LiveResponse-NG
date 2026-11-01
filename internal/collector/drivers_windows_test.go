//go:build windows

package collector

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/vulndrivers"
)

// windowsAuthenticodeHash computes a file's Authenticode SHA-256 digest with
// Windows' own implementation (the hash security catalogs index files by), as
// an independent check on internal/pehash.
func windowsAuthenticodeHash(path string) (string, error) {
	if procCatAdminAcquireContext2.Find() != nil {
		return "", fmt.Errorf("catalog API unavailable")
	}
	var admin uintptr
	algo, _ := syscall.UTF16PtrFromString("SHA256")
	if r, _, err := procCatAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(algo)), 0, 0); r == 0 {
		return "", fmt.Errorf("CryptCATAdminAcquireContext2: %v", err)
	}
	defer procCatAdminReleaseContext.Call(admin, 0)
	p, _ := syscall.UTF16PtrFromString(path)
	h, err := syscall.CreateFile(p, cGenericRead, cShareRead|cShareWrite|cShareDelete, nil, cOpenExisting, 0, 0)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	n := uint32(32)
	sum := make([]byte, 32)
	if r, _, err := procCatAdminCalcHashFromFileHandle2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&sum[0])), 0); r == 0 {
		return "", fmt.Errorf("CryptCATAdminCalcHashFromFileHandle2: %v", err)
	}
	return hex.EncodeToString(sum[:n]), nil
}

func driverRecords(t *testing.T) Result {
	t.Helper()
	res, err := collectDrivers(context.Background(), RunOptions{Hasher: NewFileHasher(), Signer: NewSignatureVerifier()})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Errors {
		t.Logf("error: %s", e)
	}
	return res
}

// The real kernel module list and driver services, resolved to files,
// hashed, and every Authenticode digest checked against Windows' own.
func TestDriversOnWindows(t *testing.T) {
	if testing.Short() || underWine() {
		t.Skip("needs a real Windows kernel")
	}
	res := driverRecords(t)
	t.Logf("meta: %v", res.Meta)
	ci := res.Records[0].Fields
	t.Logf("code integrity: %v", ci)
	if ci["kind"] != "code_integrity" || ci["kernel_code_integrity"] != true {
		t.Errorf("code integrity on a normal host: %v", ci)
	}
	loaded, compared := 0, 0
	var kernel map[string]any
	for _, r := range res.Records[1:] {
		f := r.Fields
		p, _ := f["path"].(string)
		if f["loaded"] == true {
			loaded++
		}
		if !(len(p) > 2 && p[1] == ':') && !strings.HasPrefix(p, `\\`) {
			t.Errorf("a path that isn't a Win32 path: %q (kernel %v)", p, f["kernel_path"])
		}
		if strings.EqualFold(fmt.Sprint(f["name"]), "ntoskrnl.exe") {
			kernel = f
		}
		if c, ok := f["dump_copy_of"]; ok {
			t.Logf("crash-dump copy: %s of %v", p, c)
		}
		for _, fd := range r.Findings {
			t.Logf("finding [%s] %s: %s", fd.Severity, fd.Rule, fd.Detail)
		}
		ours, ok := f["authentihash_sha256"].(string)
		if !ok || f["loaded"] != true {
			continue
		}
		file := p
		if c, ok := f["dump_copy_of"].(string); ok {
			file = c
		}
		theirs, err := windowsAuthenticodeHash(file)
		if err != nil {
			t.Logf("%s: Windows couldn't hash it: %v", file, err)
			continue
		}
		if ours != theirs {
			t.Errorf("%s: Authenticode digest %s, Windows says %s", file, ours, theirs)
		}
		compared++
	}
	if loaded < 50 {
		t.Errorf("only %d loaded drivers", loaded)
	}
	if kernel == nil || kernel["loaded"] != true || kernel["image_sha256"] == nil || kernel["authentihash_sha256"] == nil {
		t.Errorf("ntoskrnl.exe: %v", kernel)
	}
	if compared < 50 {
		t.Errorf("only %d Authenticode digests compared with Windows'", compared)
	}
	findings := map[string]int{}
	for _, r := range res.Records {
		for _, f := range r.Findings {
			findings[f.Rule]++
		}
	}
	t.Logf("lrng-selftest: drivers: %d loaded, %d registered only; %d Authenticode digests identical to Windows' own; findings %v; policy %v",
		loaded, len(res.Records)-1-loaded, compared, findings, ci)
}

// Plant entries in the vulnerable-driver list for drivers this host really
// has loaded, plus a registered (never started) copy of one, and check each
// is reported the way a real BYOVD driver would be: by file hash, by an
// Authenticode digest Windows computed, and installed-but-not-loaded.
func TestDriversFindPlantedDriversOnWindows(t *testing.T) {
	if testing.Short() || underWine() {
		t.Skip("needs a real Windows kernel")
	}
	root := strings.ToLower(systemRoot()) + `\system32\drivers\`
	var byFile, byAuth map[string]any
	for _, r := range driverRecords(t).Records[1:] {
		f := r.Fields
		p, _ := f["path"].(string)
		if f["loaded"] != true || f["image_sha256"] == nil || f["dump_copy_of"] != nil || !strings.HasPrefix(strings.ToLower(p), root) {
			continue
		}
		if byFile == nil {
			byFile = f
		} else if byAuth == nil && f["image_sha256"] != byFile["image_sha256"] {
			byAuth = f
			break
		}
	}
	if byFile == nil || byAuth == nil {
		t.Fatal("no two loaded drivers in System32\\drivers to plant")
	}
	auth, err := windowsAuthenticodeHash(byAuth["path"].(string))
	if err != nil {
		t.Fatal(err)
	}

	// A copy of the first driver, registered as a demand-start kernel driver
	// and never started.
	svc := fmt.Sprintf("lrngbyovdtest%d", os.Getpid())
	cp := filepath.Join(t.TempDir(), svc+".sys")
	data, err := os.ReadFile(byFile["path"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, data, 0o644); err != nil {
		t.Fatal(err)
	}
	installed := false
	if out, err := exec.Command("sc.exe", "create", svc, "type=", "kernel", "start=", "demand", "binPath=", cp).CombinedOutput(); err != nil {
		t.Logf("couldn't register a test driver service (%v: %s); checking loaded drivers only", err, strings.TrimSpace(string(out)))
	} else {
		installed = true
		defer exec.Command("sc.exe", "delete", svc).Run()
	}

	set, err := vulndrivers.Parse([]byte(fmt.Sprintf(`# source: planted by the test
D	11111111-1111-1111-1111-111111111111	vulnerable	yes	T1068	-	planted.sys
S	%s	-	-	-	-
D	22222222-2222-2222-2222-222222222222	malicious	yes	T1014	-	planted-evil.sys
S	-	-	%s	-	-
`, byFile["image_sha256"], auth)))
	if err != nil {
		t.Fatal(err)
	}
	old := driverDataset
	driverDataset = func() (*vulndrivers.Set, error) { return set, nil }
	defer func() { driverDataset = old }()

	res := driverRecords(t)
	found := map[string]string{}
	for _, r := range res.Records[1:] {
		for _, f := range r.Findings {
			if strings.HasPrefix(f.Rule, "privesc.vulnerable_driver") || f.Rule == "persistence.malicious_driver" {
				found[f.Rule] = fmt.Sprint(r.Fields["path"])
				t.Logf("[%s] %s: %s", f.Severity, f.Rule, f.Detail)
			}
		}
	}
	if !strings.EqualFold(found["privesc.vulnerable_driver_loaded"], byFile["path"].(string)) {
		t.Errorf("planted by file hash: %s not reported loaded (%v)", byFile["path"], found)
	}
	if !strings.EqualFold(found["persistence.malicious_driver"], byAuth["path"].(string)) {
		t.Errorf("planted by Windows' Authenticode digest: %s not reported (%v)", byAuth["path"], found)
	}
	if installed && !strings.HasSuffix(strings.ToLower(found["privesc.vulnerable_driver_installed"]), strings.ToLower(svc+".sys")) {
		t.Errorf("the registered copy %s not reported installed (%v)", cp, found)
	}
	if res.Meta["known_vulnerable_or_malicious"].(int) < 2 {
		t.Errorf("meta %v", res.Meta)
	}
	t.Logf("lrng-selftest: planted drivers found: %v (registered copy checked: %v)", found, installed)
}
