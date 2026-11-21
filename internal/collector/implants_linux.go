//go:build linux

package collector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// collectImplants searches, for implant families' own strings, the images of
// running processes that live outside the system's program folders (read
// through /proc/<pid>/exe, so an image deleted after launch is still
// searched), then the executables sitting directly in the world-writable
// temporary folders implants are dropped into.
func collectImplants(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("implants")

	type candidate struct {
		shown string // the path reported (the image's path, " (deleted)" when it is)
		open  string // the path read (/proc/<pid>/exe for a running image)
		pids  []uint32
	}
	byPath := map[string]*candidate{}
	var order []*candidate

	procs, err := os.ReadDir("/proc")
	if err != nil {
		res.Fail("process list: " + err.Error())
	}
	for _, de := range procs {
		pid64, err := strconv.ParseUint(de.Name(), 10, 32)
		if err != nil || !de.IsDir() {
			continue
		}
		pid := uint32(pid64)
		link := "/proc/" + de.Name() + "/exe"
		exe, err := os.Readlink(link)
		if err != nil || !unixImplantCandidate(exe) || opts.isSelf(pid, strings.TrimSuffix(exe, deletedSuffix)) {
			continue
		}
		if c := byPath[exe]; c != nil {
			c.pids = append(c.pids, pid)
			continue
		}
		c := &candidate{shown: exe, open: link, pids: []uint32{pid}}
		byPath[exe] = c
		order = append(order, c)
	}

	staging := 0
	for _, dir := range unixStagingDirs {
		des, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		staging++
		for _, de := range des {
			if !de.Type().IsRegular() {
				continue
			}
			p := filepath.Join(dir, de.Name())
			if _, seen := byPath[p]; seen || opts.isSelf(0, p) || !hasELFMagic(p) {
				continue
			}
			c := &candidate{shown: p, open: p}
			byPath[p] = c
			order = append(order, c)
		}
	}

	checked, searched, unreadable := 0, 0, 0
	var budget int64 = implantByteBudget
	for _, c := range order {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		if budget <= 0 {
			res.Fail("byte budget spent; later programs weren't searched")
			break
		}
		checked++
		fam, markers, read, err := scanImplantFile(c.open)
		budget -= read
		switch {
		case errors.Is(err, errNotCandidate):
			continue
		case err != nil:
			unreadable++
			continue
		}
		searched++
		if fam == nil {
			continue
		}
		fields := map[string]any{"kind": "implant_file", "path": c.shown, "family": fam.Name, "markers": len(markers)}
		if len(c.pids) > 0 {
			fields["pids"] = c.pids
		}
		opts.Hasher.Fields(ctx, fields, "file", c.open)
		res.Add(fields, implantFileFinding(fam, c.shown, markers, c.pids))
	}

	res.SetMeta("families", implantFamilyNames())
	res.SetMeta("programs_checked", checked)
	res.SetMeta("programs_searched", searched)
	res.SetMeta("programs_unreadable", unreadable)
	res.SetMeta("bytes_read", implantByteBudget-budget)
	res.SetMeta("staging_folders_checked", staging)
	return res.Finish(), nil
}

// hasELFMagic reports whether a regular file starts like a Linux executable,
// reading only its first four bytes.
func hasELFMagic(path string) bool {
	f, _, err := openRegular(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(elfMagic))
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return bytes.Equal(head, elfMagic)
}
