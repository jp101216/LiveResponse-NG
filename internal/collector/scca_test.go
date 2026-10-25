package collector

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// 2021-01-01T00:00:00Z and 2021-06-01T00:00:00Z as Windows FILETIMEs.
const (
	ftJan2021 = 132539328000000000
	ftJun2021 = 132669792000000000
)

func u16(s string) []byte {
	r := utf16.Encode([]rune(s))
	b := make([]byte, len(r)*2)
	for i, c := range r {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

type volSpec struct {
	dev     string
	serial  uint32
	created uint64
}

// buildSCCA assembles an uncompressed SCCA body with one volume. Offsets are
// written explicitly (not via sccaLayoutFor) so the test independently checks
// the version constants the parser relies on.
func buildSCCA(version int, exe string, hash, runCount uint32, lastRuns []uint64, vol volSpec, filenames []string) []byte {
	var fiSize, lastRunOff, lastRunCount, runCountOff, volEntry int
	switch version {
	case 23:
		fiSize, lastRunOff, lastRunCount, runCountOff, volEntry = 156, 44, 1, 68, 104
	default:
		fiSize, lastRunOff, lastRunCount, runCountOff, volEntry = 224, 44, 8, 124, 96
	}
	const fileInfoAt = 84
	volAt := fileInfoAt + fiSize

	entry := make([]byte, volEntry)
	binary.LittleEndian.PutUint32(entry[0:], uint32(volEntry)) // device path right after the entry
	binary.LittleEndian.PutUint32(entry[4:], uint32(len([]rune(vol.dev))))
	binary.LittleEndian.PutUint64(entry[8:], vol.created)
	binary.LittleEndian.PutUint32(entry[16:], vol.serial)
	volSection := append(entry, u16(vol.dev)...)

	fnAt := volAt + len(volSection)
	var fn []byte
	for _, f := range filenames {
		fn = append(fn, u16(f)...)
		fn = append(fn, 0, 0)
	}

	total := fnAt + len(fn)
	b := make([]byte, total)
	binary.LittleEndian.PutUint32(b[0:], uint32(version))
	copy(b[4:8], "SCCA")
	binary.LittleEndian.PutUint32(b[12:], uint32(total))
	copy(b[16:76], u16(exe))
	binary.LittleEndian.PutUint32(b[76:], hash)

	sec := b[fileInfoAt:]
	binary.LittleEndian.PutUint32(sec[16:], uint32(fnAt))
	binary.LittleEndian.PutUint32(sec[20:], uint32(len(fn)))
	binary.LittleEndian.PutUint32(sec[24:], uint32(volAt))
	binary.LittleEndian.PutUint32(sec[28:], 1)
	binary.LittleEndian.PutUint32(sec[32:], uint32(len(volSection)))
	binary.LittleEndian.PutUint32(sec[runCountOff:], runCount)
	for i := 0; i < lastRunCount && i < len(lastRuns); i++ {
		binary.LittleEndian.PutUint64(sec[lastRunOff+i*8:], lastRuns[i])
	}
	copy(b[volAt:], volSection)
	copy(b[fnAt:], fn)
	return b
}

func TestParsePrefetchV30(t *testing.T) {
	body := buildSCCA(30, "CMD.EXE", 0xDEADBEEF, 7,
		[]uint64{ftJun2021, ftJan2021},
		volSpec{dev: `\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}`, serial: 0xA1B2C3D4, created: ftJan2021},
		[]string{
			`\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}\WINDOWS\SYSTEM32\CMD.EXE`,
			`\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}\WINDOWS\SYSTEM32\NTDLL.DLL`,
		})

	pf, err := parsePrefetch(body)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Version != 30 || pf.Executable != "CMD.EXE" || pf.PathHash != 0xDEADBEEF {
		t.Fatalf("header = %+v", pf)
	}
	if pf.RunCount != 7 {
		t.Errorf("run count = %d, want 7", pf.RunCount)
	}
	if len(pf.LastRun) != 2 || pf.LastRun[0].UTC().Format("2006-01-02") != "2021-06-01" {
		t.Errorf("last-run times = %v", pf.LastRun)
	}
	if len(pf.Volumes) != 1 || pf.Volumes[0].Serial != 0xA1B2C3D4 {
		t.Fatalf("volumes = %+v", pf.Volumes)
	}
	if pf.Volumes[0].DevicePath != `\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}` {
		t.Errorf("device path = %q", pf.Volumes[0].DevicePath)
	}
	if pf.Volumes[0].Created.UTC().Format("2006-01-02") != "2021-01-01" {
		t.Errorf("volume created = %v", pf.Volumes[0].Created)
	}
	if len(pf.Filenames) != 2 {
		t.Fatalf("filenames = %v", pf.Filenames)
	}
	if pf.ImagePath != `\VOLUME{01d7a1b2c3d4e5f6-a1b2c3d4}\WINDOWS\SYSTEM32\CMD.EXE` {
		t.Errorf("image path = %q", pf.ImagePath)
	}
}

func TestParsePrefetchV23(t *testing.T) {
	body := buildSCCA(23, "APP.EXE", 0x12345678, 3,
		[]uint64{ftJan2021},
		volSpec{dev: `\DEVICE\HARDDISKVOLUME2`, serial: 0x11112222, created: ftJan2021},
		[]string{`\DEVICE\HARDDISKVOLUME2\APP.EXE`})

	pf, err := parsePrefetch(body)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Version != 23 || pf.RunCount != 3 {
		t.Fatalf("v23 header = %+v", pf)
	}
	if len(pf.LastRun) != 1 || pf.LastRun[0].UTC().Format("2006-01-02") != "2021-01-01" {
		t.Errorf("v23 last run = %v", pf.LastRun)
	}
	if pf.ImagePath != `\DEVICE\HARDDISKVOLUME2\APP.EXE` {
		t.Errorf("v23 image path = %q", pf.ImagePath)
	}
}

func TestPrefetchDecompressRoundTrip(t *testing.T) {
	body := buildSCCA(30, "NOTEPAD.EXE", 0xCAFEBABE, 1,
		[]uint64{ftJan2021}, volSpec{dev: `\VOLUME{x}`, serial: 1, created: ftJan2021},
		[]string{`\VOLUME{x}\WINDOWS\NOTEPAD.EXE`})

	// Wrap it the way Windows 8+ stores it: "MAM\x04" + uncompressed size + stream.
	var mam []byte
	mam = append(mam, 'M', 'A', 'M', 0x04)
	var sz [4]byte
	binary.LittleEndian.PutUint32(sz[:], uint32(len(body)))
	mam = append(mam, sz[:]...)
	mam = append(mam, xpressHuffmanCompress(body)...)

	got, err := prefetchDecompress(mam)
	if err != nil {
		t.Fatal(err)
	}
	pf, err := parsePrefetch(got)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Executable != "NOTEPAD.EXE" || pf.PathHash != 0xCAFEBABE {
		t.Fatalf("decoded header = %+v", pf)
	}
}

func TestPrefetchFindings(t *testing.T) {
	// Executed from the Public profile -> a high-risk finding.
	pub := buildSCCA(30, "X.EXE", 1, 2, []uint64{ftJan2021},
		volSpec{dev: `\VOLUME{x}`, serial: 1, created: ftJan2021},
		[]string{`\VOLUME{x}\USERS\PUBLIC\X.EXE`})
	pf, err := parsePrefetch(pub)
	if err != nil {
		t.Fatal(err)
	}
	f := prefetchFindings(pf)
	if len(f) != 1 || f[0].Rule != "execution.prefetch_unusual_path" {
		t.Fatalf("findings = %+v", f)
	}

	// Executed from System32 -> nothing.
	ok := buildSCCA(30, "CMD.EXE", 1, 2, []uint64{ftJan2021},
		volSpec{dev: `\VOLUME{x}`, serial: 1, created: ftJan2021},
		[]string{`\VOLUME{x}\WINDOWS\SYSTEM32\CMD.EXE`})
	pf2, _ := parsePrefetch(ok)
	if f := prefetchFindings(pf2); len(f) != 0 {
		t.Fatalf("expected no finding for System32, got %+v", f)
	}
}

func TestParsePrefetchRejects(t *testing.T) {
	good := buildSCCA(30, "A.EXE", 1, 1, []uint64{ftJan2021},
		volSpec{dev: `\VOLUME{x}`, serial: 1, created: ftJan2021},
		[]string{`\VOLUME{x}\A.EXE`})

	if _, err := parsePrefetch(good[:40]); err == nil {
		t.Error("expected an error for a truncated header")
	}
	bad := append([]byte{}, good...)
	bad[4] = 'X' // break the SCCA signature
	if _, err := parsePrefetch(bad); err == nil {
		t.Error("expected an error for a bad signature")
	}
	unk := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(unk[0:], 17) // Windows XP, unsupported
	if _, err := parsePrefetch(unk); err == nil {
		t.Error("expected an error for an unsupported version")
	}
}

// TestParsePrefetchHostileOffsetsNoOOB guards the file-information bounds checks
// against integer overflow. The locators there are attacker-controlled; the
// values below stay positive int32 individually but overflow when added, which
// on a 32-bit build slipped past `off+size <= len(b)` into an out-of-bounds
// slice. parsePrefetch must simply skip the unreadable region and never panic,
// on every architecture.
func TestParsePrefetchHostileOffsetsNoOOB(t *testing.T) {
	good := buildSCCA(30, "A.EXE", 1, 1, []uint64{ftJan2021},
		volSpec{dev: `\VOLUME{x}`, serial: 1, created: ftJan2021},
		[]string{`\VOLUME{x}\A.EXE`})

	cases := map[string]func([]byte){
		"filename offset+size overflow": func(b []byte) {
			sec := b[sccaFileInfo:]
			binary.LittleEndian.PutUint32(sec[16:], 0x7ffffff0) // fnOff
			binary.LittleEndian.PutUint32(sec[20:], 0x7ffffff0) // fnSize
		},
		"volume offset overflow": func(b []byte) {
			sec := b[sccaFileInfo:]
			binary.LittleEndian.PutUint32(sec[24:], 0x7ffffff0) // volOff
			binary.LittleEndian.PutUint32(sec[28:], 1)          // nVol
		},
	}
	for name, mutate := range cases {
		b := append([]byte(nil), good...)
		mutate(b)
		pf, err := parsePrefetch(b) // must not panic
		if pf == nil {
			t.Fatalf("%s: nil result (err %v)", name, err)
		}
	}
}
