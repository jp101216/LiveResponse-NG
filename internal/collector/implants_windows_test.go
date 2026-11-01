//go:build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestImplantsOnWindows puts inert look-alikes where NIK C2 leaves its files
// — bytes shaped like a Go program holding its strings (not a runnable
// program) in the folder it copies itself to, and its bootkit placeholder in
// the temporary folder — requires the implants collector to report both, and
// removes them.
func TestImplantsOnWindows(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	netDir := filepath.Join(home, `AppData\Roaming\Microsoft\Network`)
	if _, err := os.Stat(netDir); os.IsNotExist(err) {
		if err := os.MkdirAll(netDir, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(netDir)
	}
	nik := implantFamilies[0]
	fake := filepath.Join(netDir, fmt.Sprintf("lrng-test-%d.exe", os.Getpid()))
	if err := os.WriteFile(fake, fakeGoProgram(nik.Strong[0], nik.Strong[1], nik.Weak[0]), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fake)
	temp := filepath.Join(home, `AppData\Local\Temp`)
	placeholder := filepath.Join(temp, "bootkit.bin")
	if _, err := os.Stat(placeholder); err == nil {
		t.Skip("a bootkit.bin is already in this user's temporary folder; leaving it alone")
	}
	if err := os.WriteFile(placeholder, nik.Strong[2], 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(placeholder)

	res, err := collectImplants(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("meta: %v; errors %v", res.Meta, res.Errors)
	var file, staged bool
	for _, r := range res.Records {
		switch r.Fields["kind"] {
		case "implant_file":
			if p, _ := r.Fields["path"].(string); strings.EqualFold(p, fake) {
				file = hasFinding(r.Findings, "malware.nik_c2") != nil
			}
		case "staged_files":
			if d, _ := r.Fields["folder"].(string); strings.EqualFold(d, temp) {
				f := hasFinding(r.Findings, "malware.nik_c2_artifact")
				staged = f != nil && f.Severity == SevCritical
			}
		}
	}
	if !file || !staged {
		t.Errorf("look-alike program reported: %v; placeholder reported: %v; records %+v", file, staged, res.Records)
	}
}
