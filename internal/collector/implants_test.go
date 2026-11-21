package collector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGoProgram is bytes shaped like a Go-built program holding the given
// markers (not a runnable program: a header, Go's build-ID line, filler).
func fakeGoProgram(markers ...[]byte) []byte {
	b := append([]byte("MZ"), bytes.Repeat([]byte{0}, 0x600)...)
	b = append(b, goBuildID...)
	b = append(b, []byte(`abc/def"`)...)
	for _, m := range markers {
		b = append(b, bytes.Repeat([]byte{0x90}, 4096)...)
		b = append(b, m...)
	}
	return b
}

func TestScanImplantFile(t *testing.T) {
	nik := implantFamilies[0]
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fam, markers, _, err := scanImplantFile(write("nik.exe", fakeGoProgram(nik.Strong[0], nik.Strong[1], nik.Weak[1])))
	if err != nil || fam == nil || fam.Name != "NIK C2" || len(markers) != 3 {
		t.Fatalf("NIK-shaped program: %v %v %v", fam, markers, err)
	}
	f := implantFileFinding(fam, `C:\Users\bob\AppData\Roaming\Microsoft\Network\svchost.exe`, markers, []uint32{4242})
	if f.Rule != "malware.nik_c2" || f.Severity != SevCritical || !strings.Contains(f.Detail, "pid 4242") ||
		!strings.Contains(f.Detail, "suspend it") {
		t.Errorf("finding: %+v", f)
	}
	// One strong marker and a weak one is enough; weak ones alone, or a
	// single strong one, aren't.
	if fam, _, _, _ := scanImplantFile(write("a.exe", fakeGoProgram(nik.Strong[3], nik.Weak[0]))); fam == nil {
		t.Error("strong + weak")
	}
	if fam, _, _, _ := scanImplantFile(write("b.exe", fakeGoProgram(nik.Weak[0], nik.Weak[1], nik.Weak[2]))); fam != nil {
		t.Error("weak markers alone")
	}
	if fam, _, _, _ := scanImplantFile(write("c.exe", fakeGoProgram(nik.Strong[2]))); fam != nil {
		t.Error("one strong marker alone")
	}
	// NIK C2 is a Go program: anything else is searched only for the
	// families that aren't (Project Lattice), so NIK's markers there are not
	// NIK C2.
	notGo := append([]byte("MZ not go "), append(append([]byte{}, nik.Strong[0]...), nik.Strong[1]...)...)
	if fam, _, _, err := scanImplantFile(write("d.exe", notGo)); fam != nil || err != nil {
		t.Errorf("a program that isn't Go: %v %v", fam, err)
	}
	big := write("e.exe", nil)
	if err := os.Truncate(big, implantMaxFile+1); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := scanImplantFile(big); err != errNotCandidate {
		t.Errorf("too large: %v", err)
	}
}

// fakeELF is bytes shaped like a Linux executable (not a Go one) holding the
// given markers.
func fakeELF(markers ...[]byte) []byte {
	b := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, bytes.Repeat([]byte{0}, 0x400)...)
	for _, m := range markers {
		b = append(b, bytes.Repeat([]byte{0xcc}, 2048)...)
		b = append(b, m...)
	}
	return b
}

func latticeFamily(t *testing.T) implantFamily {
	t.Helper()
	for _, f := range implantFamilies {
		if f.Name == "Project Lattice" {
			return f
		}
	}
	t.Fatal("Project Lattice family missing")
	return implantFamily{}
}

func TestScanImplantFileLattice(t *testing.T) {
	lat := latticeFamily(t)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fam, markers, _, err := scanImplantFile(write("wraith", fakeELF(lat.Strong[0], lat.Strong[1], lat.Weak[0], lat.Weak[3])))
	if err != nil || fam == nil || fam.Name != "Project Lattice" || len(markers) != 4 {
		t.Fatalf("Lattice-shaped ELF: %v %v %v", fam, markers, err)
	}
	f := implantFileFinding(fam, "/home/op/Project-Lattice/wraith/target/release/wraith", markers, []uint32{10487})
	if f.Rule != "malware.lattice_agent" || f.Severity != SevCritical || f.Technique != "T1071.001" ||
		!strings.Contains(f.Detail, "pid 10487") || strings.Contains(f.Detail, "suspend it") {
		t.Errorf("finding: %+v", f)
	}
	// A Windows build is searched the same way; it isn't a Go program.
	pe := append([]byte("MZ"), fakeELF(lat.Strong[2], lat.Weak[1])[4:]...)
	if fam, _, _, _ := scanImplantFile(write("wraith.exe", pe)); fam == nil || fam.Rule != "malware.lattice_agent" {
		t.Errorf("PE build: %v", fam)
	}
	// The check-in paths and JSON keys alone are generic web-API strings.
	if fam, _, _, _ := scanImplantFile(write("api-client", fakeELF(lat.Weak...))); fam != nil {
		t.Errorf("weak markers alone: %v", fam)
	}
	if fam, _, _, _ := scanImplantFile(write("one", fakeELF(lat.Strong[0]))); fam != nil {
		t.Errorf("one strong marker alone: %v", fam)
	}
	// NIK C2's markers in a program that isn't Go are not NIK C2.
	nik := implantFamilies[0]
	if fam, _, _, _ := scanImplantFile(write("nik-elf", fakeELF(nik.Strong[0], nik.Strong[1]))); fam != nil {
		t.Errorf("NIK markers outside a Go program: %v", fam)
	}
	// The NIK finding keeps its rule and its warning about killing it.
	if f := implantFileFinding(&implantFamilies[0], `C:\x.exe`, []string{"a", "b"}, nil); f.Rule != "malware.nik_c2" ||
		!strings.Contains(f.Detail, "suspend it") {
		t.Errorf("NIK finding: %+v", f)
	}
}

func TestUnixImplantCandidate(t *testing.T) {
	for exe, want := range map[string]bool{
		"/home/op/Project-Lattice/wraith/target/release/wraith": true,
		"/tmp/.x/agent":                      true,
		"/dev/shm/a (deleted)":               true,
		"/root/agent":                        true,
		"/usr/bin/python3.12":                false,
		"/usr/lib/systemd/systemd (deleted)": false,
		"/opt/google/chrome/chrome":          false,
		"/snap/firefox/123/usr/lib/firefox":  false,
		"/nix/store/abc-bash-5.2/bin/bash":   false,
		"":                                   false,
		"relative/path":                      false,
	} {
		if got := unixImplantCandidate(exe); got != want {
			t.Errorf("%q: %v, want %v", exe, got, want)
		}
	}
}

// TestImplantMarkersNotInOwnBinary: lrng (here, its test binary) must never
// carry a marker in the clear, or it would be found as the implant.
func TestImplantMarkersNotInOwnBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Skip(err)
	}
	for _, fam := range implantFamilies {
		for _, m := range fam.Strong {
			if bytes.Contains(data, m) {
				t.Errorf("%s marker %q is in the clear in %s", fam.Name, m, exe)
			}
		}
	}
}

func TestStagedFilesFinding(t *testing.T) {
	mbr := make([]byte, 1024)
	mbr[510], mbr[511] = 0x55, 0xAA
	placeholder := stagedFile{Name: "bootkit.bin", Size: 16, Head: implantFamilies[0].Strong[2]}
	for _, c := range []struct {
		name  string
		files []stagedFile
		want  Severity
	}{
		{"placeholder", []stagedFile{placeholder}, SevCritical},
		{"lock screen", []stagedFile{{Name: "lock_screen.html", Size: 900}, {Name: "lock_start.bat", Size: 80}}, SevCritical},
		{"two staged files", []stagedFile{{Name: "lock_screen.html", Size: 900}, {Name: "browserdata.zip", Size: 1 << 20}}, SevSuspect},
		{"an MBR copy", []stagedFile{{Name: "mbr_backup.bin", Size: 512, Head: mbr[:512]}}, SevSuspect},
		{"a file named like an MBR copy", []stagedFile{{Name: "mbr_backup.bin", Size: 512, Head: make([]byte, 512)}}, ""},
		{"an archive named browserdata", []stagedFile{{Name: "browserdata.zip", Size: 100}}, ""},
		{"a bootkit.bin of someone else's", []stagedFile{{Name: "bootkit.bin", Size: 4, Head: []byte("test")}}, ""},
		{"nothing", nil, ""},
	} {
		f, ok := stagedFilesFinding(`C:\Users\bob\AppData\Local\Temp`, c.files)
		if c.want == "" {
			if ok {
				t.Errorf("%s: %+v", c.name, f)
			}
			continue
		}
		if !ok || f.Rule != "malware.nik_c2_artifact" || f.Severity != c.want {
			t.Errorf("%s: %+v, want %s", c.name, f, c.want)
		}
	}

	dir := t.TempDir()
	for name, data := range map[string][]byte{"BootKit.bin": implantFamilies[0].Strong[2], "lock_screen.html": []byte("<html>"),
		"notes.txt": []byte("x")} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := readStaged(dir)
	if err != nil || len(files) != 2 {
		t.Fatalf("staged: %+v %v", files, err)
	}
	if f, ok := stagedFilesFinding(dir, files); !ok || f.Severity != SevCritical {
		t.Errorf("from disk: %+v", f)
	}
}
