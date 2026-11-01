// Package pehash computes the Authenticode digest of a PE image: the hash a
// code signature covers. It leaves out the parts that signing itself changes
// (the header checksum, the certificate-table directory entry and the
// certificate table), so two files with the same digest hold the same headers,
// code and data however each was signed or re-signed. That makes it the
// identity vulnerable-driver lists record next to file hashes: Microsoft's
// recommended driver block rules deny drivers by it, and LOLDrivers lists it
// for every sample it can.
//
// The algorithm is "Calculating the PE Image Hash" from Microsoft's Windows
// Authenticode Portable Executable Signature Format. The input is a file,
// which may be hostile: every offset is bounds-checked, nothing panics, and a
// malformed image is an error rather than a guess. Files are streamed through
// a small buffer, so a large driver isn't read into memory whole.
package pehash

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Digests are an image's Authenticode digests. Both are computed in the same
// pass: SHA-256 is what current signatures and lists use, SHA-1 what older
// ones (and some block rules) record.
type Digests struct {
	SHA256 [32]byte
	SHA1   [20]byte
}

// ErrNotPE means the input is not a PE image at all (no MZ/PE signatures).
var ErrNotPE = errors.New("not a PE image")

var errTruncated = errors.New("pehash: truncated headers")

const (
	magicPE32     = 0x10b
	magicPE32Plus = 0x20b
	dirSecurity   = 4  // IMAGE_DIRECTORY_ENTRY_SECURITY: the certificate table
	sectionHeader = 40 // sizeof(IMAGE_SECTION_HEADER)
	maxSections   = 96 // the PE format's own limit
)

// Authentihash returns the Authenticode digests of the PE image in b.
func Authentihash(b []byte) (Digests, error) {
	return AuthentihashReader(bytes.NewReader(b), int64(len(b)))
}

// AuthentihashReader returns the Authenticode digests of the size-byte PE
// image r reads:
//
//  1. the headers, up to SizeOfHeaders, without the CheckSum field and the
//     certificate-table entry of the data directory;
//  2. each section's raw data, in file order, skipping empty ones;
//  3. any data after that (an overlay), up to where the certificate table
//     begins: the file size less the table's size.
//
// A section or header reaching past the end of the file is hashed as far as
// the file goes, as signing tools read it.
func AuthentihashReader(r io.ReaderAt, size int64) (Digests, error) {
	var d Digests
	read := func(off int64, n int) ([]byte, error) {
		if off < 0 || off+int64(n) > size {
			return nil, errTruncated
		}
		b := make([]byte, n)
		if _, err := r.ReadAt(b, off); err != nil {
			return nil, err
		}
		return b, nil
	}
	dos, err := read(0, 0x40)
	if err != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return d, ErrNotPE
	}
	pe := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	nt, err := read(pe, 24+2)
	if err != nil || string(nt[:4]) != "PE\x00\x00" {
		return d, ErrNotPE
	}
	nsec := int64(binary.LittleEndian.Uint16(nt[4+2:]))
	optSize := int64(binary.LittleEndian.Uint16(nt[4+16:]))
	opt := pe + 24
	if nsec > maxSections {
		return d, fmt.Errorf("pehash: %d sections (the format allows %d)", nsec, maxSections)
	}
	var nrvaAt, dirs int64
	switch m := binary.LittleEndian.Uint16(nt[24:]); m {
	case magicPE32:
		nrvaAt, dirs = opt+92, opt+96
	case magicPE32Plus:
		nrvaAt, dirs = opt+108, opt+112
	default:
		return d, fmt.Errorf("pehash: unknown optional header magic 0x%x", m)
	}
	if nrvaAt+4 > opt+optSize {
		return d, errTruncated
	}
	oh, err := read(opt, int(nrvaAt+4-opt))
	if err != nil {
		return d, err
	}
	checksum := opt + 64
	headers := int64(binary.LittleEndian.Uint32(oh[60:])) // SizeOfHeaders
	if headers < nrvaAt+4 {
		return d, fmt.Errorf("pehash: SizeOfHeaders 0x%x ends inside the optional header", headers)
	}
	// The certificate-table entry exists when the directory has a fifth entry
	// and it lies inside the optional header.
	certEntry := dirs + dirSecurity*8
	hasCert := binary.LittleEndian.Uint32(oh[nrvaAt-opt:]) > dirSecurity && certEntry+8 <= opt+optSize
	var certSize int64
	if hasCert {
		e, err := read(certEntry, 8)
		if err != nil {
			return d, err
		}
		if binary.LittleEndian.Uint32(e) != 0 {
			certSize = int64(binary.LittleEndian.Uint32(e[4:]))
		}
	}

	type section struct{ ptr, size int64 }
	table, err := read(opt+optSize, int(nsec*sectionHeader))
	if err != nil {
		return d, errors.New("pehash: truncated section table")
	}
	secs := make([]section, 0, nsec)
	for i := int64(0); i < nsec; i++ {
		s := table[i*sectionHeader:]
		if raw := int64(binary.LittleEndian.Uint32(s[16:])); raw > 0 { // SizeOfRawData
			secs = append(secs, section{ptr: int64(binary.LittleEndian.Uint32(s[20:])), size: raw}) // PointerToRawData
		}
	}
	sort.SliceStable(secs, func(i, j int) bool { return secs[i].ptr < secs[j].ptr })

	h256, h1 := sha256.New(), sha1.New()
	buf := make([]byte, 64<<10)
	write := func(lo, hi int64) error {
		hi = min(hi, size)
		for lo < hi {
			n := int(min(hi-lo, int64(len(buf))))
			if _, err := r.ReadAt(buf[:n], lo); err != nil {
				return err
			}
			h256.Write(buf[:n])
			h1.Write(buf[:n])
			lo += int64(n)
		}
		return nil
	}
	ranges := [][2]int64{{0, checksum}}
	if hasCert {
		ranges = append(ranges, [2]int64{checksum + 4, min(certEntry, headers)}, [2]int64{certEntry + 8, headers})
	} else {
		ranges = append(ranges, [2]int64{checksum + 4, headers})
	}
	hashed := headers
	for _, s := range secs {
		ranges = append(ranges, [2]int64{s.ptr, s.ptr + s.size})
		hashed += s.size
	}
	if size > hashed {
		ranges = append(ranges, [2]int64{hashed, size - certSize})
	}
	for _, rg := range ranges {
		if err := write(rg[0], rg[1]); err != nil {
			return d, err
		}
	}
	copy(d.SHA256[:], h256.Sum(nil))
	copy(d.SHA1[:], h1.Sum(nil))
	return d, nil
}
