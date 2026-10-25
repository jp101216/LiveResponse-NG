package collector

import (
	"errors"
	"fmt"
	"time"
)

// Windows Prefetch (.pf) body parsing: Xpress Huffman decompression (xpress.go)
// then the SCCA structure. Prefetch is strong execution evidence — unlike
// ShimCache, which records only that a binary existed, a .pf means the program
// actually ran — carrying a run count, up to eight recent run times, and the
// files the program touched on first execution.
//
// No build tag: it decodes a plain byte slice, bounds-checked against hostile
// input, and is unit-tested on any OS. Format versions: 23 (Windows Vista/7,
// uncompressed), 26 (Windows 8.1), 30 (Windows 10), 31 (Windows 11 — same
// file-information layout as 30). Supported hosts are Windows 10 / Server 2016
// and later, so 30/31 are the common cases; 23/26 are handled for completeness.

const (
	sccaHeaderLen = 84
	sccaFileInfo  = 84      // the file-information section starts here
	sccaMaxDecomp = 1 << 26 // 64 MiB sanity cap on a decompressed .pf body
	sccaMaxCount  = 1 << 16 // sanity cap on volume / string-length counts
)

// inBounds reports whether the slice [off, off+size) lies within a buffer of
// blen bytes. Offsets and sizes here come from an attacker-controlled .pf, so
// the test is written to avoid off+size, which can overflow int on a 32-bit
// build and wrap past a naive `off+size <= blen` check into an out-of-bounds
// slice. All comparisons stay within [0, blen].
func inBounds(off, size, blen int) bool {
	return off >= 0 && size >= 0 && off <= blen && size <= blen-off
}

type prefetchVolume struct {
	DevicePath string
	Serial     uint32 // volume serial number
	Created    time.Time
}

type prefetchInfo struct {
	Version    int
	Executable string // from the header (name only, up to 29 characters)
	PathHash   uint32
	RunCount   int // -1 if the version's layout is unknown
	LastRun    []time.Time
	Volumes    []prefetchVolume
	Filenames  []string // referenced NT paths (the image plus loaded files)
	ImagePath  string   // best-effort full path of the executable itself
}

type sccaLayout struct {
	lastRunOff   int // run-time array offset within the file-info section
	lastRunCount int
	runCountOff  int // run-count offset within the file-info section
	volEntrySize int
}

func sccaLayoutFor(version int) (sccaLayout, bool) {
	switch version {
	case 23:
		return sccaLayout{lastRunOff: 44, lastRunCount: 1, runCountOff: 68, volEntrySize: 104}, true
	case 26, 30, 31:
		return sccaLayout{lastRunOff: 44, lastRunCount: 8, runCountOff: 124, volEntrySize: 96}, true
	}
	return sccaLayout{}, false
}

// prefetchDecompress unwraps the "MAM" compression header used since Windows 8
// and returns the SCCA body. A file already starting with "SCCA" (older hosts)
// is returned unchanged.
func prefetchDecompress(raw []byte) ([]byte, error) {
	if len(raw) >= 8 && raw[0] == 'M' && raw[1] == 'A' && raw[2] == 'M' {
		flag := raw[3]
		if flag&0x0F != 0x04 {
			return nil, fmt.Errorf("prefetch: unsupported MAM compression format 0x%02x", flag)
		}
		size := int(le.Uint32(raw[4:8]))
		off := 8
		if flag&0x80 != 0 { // the checksummed variant adds a 4-byte CRC
			if len(raw) < 12 {
				return nil, errXpTruncated
			}
			off = 12
		}
		if size < 0 || size > sccaMaxDecomp {
			return nil, fmt.Errorf("prefetch: implausible uncompressed size %d", size)
		}
		return xpressHuffmanDecompress(raw[off:], size)
	}
	return raw, nil
}

// decodePrefetchFile decompresses a raw .pf file (unwrapping the MAM header
// when present) and parses the SCCA body.
func decodePrefetchFile(raw []byte) (*prefetchInfo, error) {
	body, err := prefetchDecompress(raw)
	if err != nil {
		return nil, err
	}
	return parsePrefetch(body)
}

// parsePrefetch decodes a decompressed SCCA body.
func parsePrefetch(b []byte) (*prefetchInfo, error) {
	if len(b) < sccaHeaderLen {
		return nil, errors.New("prefetch: shorter than the 84-byte header")
	}
	if b[4] != 'S' || b[5] != 'C' || b[6] != 'C' || b[7] != 'A' {
		return nil, errors.New("prefetch: missing SCCA signature")
	}
	version := int(le.Uint32(b[0:4]))
	lay, ok := sccaLayoutFor(version)
	if !ok {
		return nil, fmt.Errorf("prefetch: unsupported format version %d", version)
	}
	pf := &prefetchInfo{
		Version:    version,
		Executable: decodeUTF16LEZ(b[16:76]),
		PathHash:   le.Uint32(b[76:80]),
		RunCount:   -1,
	}

	sec := b[sccaFileInfo:]
	// Offsets 16..36 of the file-information section (the filename-strings and
	// volumes locators) are the same across every version.
	if len(sec) < 36 {
		return pf, errors.New("prefetch: file information section truncated")
	}
	fnOff := int(le.Uint32(sec[16:20]))
	fnSize := int(le.Uint32(sec[20:24]))
	volOff := int(le.Uint32(sec[24:28]))
	nVol := int(le.Uint32(sec[28:32]))

	if lay.runCountOff+4 <= len(sec) {
		pf.RunCount = int(le.Uint32(sec[lay.runCountOff : lay.runCountOff+4]))
	}
	for i := 0; i < lay.lastRunCount; i++ {
		off := lay.lastRunOff + i*8
		if off+8 > len(sec) {
			break
		}
		if t := fileTimeToTime(le.Uint64(sec[off : off+8])); !t.IsZero() {
			pf.LastRun = append(pf.LastRun, t)
		}
	}

	if fnSize > 0 && inBounds(fnOff, fnSize, len(b)) {
		pf.Filenames = splitUTF16Z(b[fnOff : fnOff+fnSize])
	}

	if nVol > 0 && nVol <= sccaMaxCount && volOff >= 0 {
		for i := 0; i < nVol; i++ {
			base := volOff + i*lay.volEntrySize
			if !inBounds(base, 20, len(b)) {
				break
			}
			v := prefetchVolume{
				Created: fileTimeToTime(le.Uint64(b[base+8 : base+16])),
				Serial:  le.Uint32(b[base+16 : base+20]),
			}
			dpOff := volOff + int(le.Uint32(b[base:base+4]))
			dpChars := int(le.Uint32(b[base+4 : base+8]))
			if dpChars > 0 && dpChars < sccaMaxCount && inBounds(dpOff, dpChars*2, len(b)) {
				v.DevicePath = decodeUTF16LE(b[dpOff : dpOff+dpChars*2])
			}
			pf.Volumes = append(pf.Volumes, v)
		}
	}

	pf.ImagePath = prefetchImagePath(pf.Executable, pf.Filenames)
	return pf, nil
}

// prefetchImagePath picks the referenced file whose base name matches the
// executable from the header — the program's own full path.
func prefetchImagePath(exe string, filenames []string) string {
	if exe == "" {
		return ""
	}
	want := baseName(exe)
	for _, f := range filenames {
		if baseName(f) == want {
			return f
		}
	}
	return ""
}

// prefetchFindings flags a program that actually executed from an unusual
// location. It mirrors execution.shimcache_unusual_path but is stronger: a .pf
// is proof of execution, with a count and recent run times.
func prefetchFindings(pf *prefetchInfo) []Finding {
	if pf.ImagePath == "" {
		return nil
	}
	lvl, why := pathRisk(pf.ImagePath)
	if lvl != riskHigh {
		return nil
	}
	detail := fmt.Sprintf("Prefetch shows %s executed from %s", pf.Executable, why)
	if pf.RunCount > 0 {
		detail += fmt.Sprintf(" (%d run(s)", pf.RunCount)
		if len(pf.LastRun) > 0 {
			detail += ", last " + pf.LastRun[0].UTC().Format(time.RFC3339)
		}
		detail += ")"
	}
	detail += ": " + pf.ImagePath
	return []Finding{{
		Rule:       "execution.prefetch_unusual_path",
		Severity:   SevNotable,
		Technique:  "T1204.002",
		Confidence: 50,
		Detail:     detail,
	}}
}

// decodeUTF16LEZ decodes a fixed-width UTF-16LE field up to its first NUL.
func decodeUTF16LEZ(b []byte) string {
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return decodeUTF16LE(b[:i])
		}
	}
	return decodeUTF16LE(b)
}

// splitUTF16Z splits a block of NUL-terminated UTF-16LE strings.
func splitUTF16Z(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			if i > start {
				out = append(out, decodeUTF16LE(b[start:i]))
			}
			start = i + 2
		}
	}
	if start+1 < len(b) {
		if s := decodeUTF16LE(b[start:]); s != "" {
			out = append(out, s)
		}
	}
	return out
}
