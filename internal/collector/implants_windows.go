//go:build windows

package collector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// implantByteBudget bounds how much the collector reads in all.
const implantByteBudget = 1 << 30

// collectImplants searches the programs running from outside the Windows and
// Program Files folders, and the programs sitting in the folders NIK C2 copies
// itself to, for implant families' own strings; and lists what NIK C2 stages
// in users' temporary folders.
func collectImplants(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("implants")
	sysRoot := systemRoot()
	trusted := []string{sysRoot}
	for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"} {
		if p := os.Getenv(v); p != "" {
			trusted = append(trusted, p)
		}
	}
	outside := func(p string) bool {
		for _, t := range trusted {
			if underDir(p, t) {
				return false
			}
		}
		return true
	}

	// Candidates: running images (with their pids), then executables in the
	// folders NIK C2 copies itself to.
	pids := map[string][]uint32{}
	var order []string
	add := func(p string, pid uint32) {
		key := strings.ToLower(p)
		if _, seen := pids[key]; !seen {
			order = append(order, p)
			pids[key] = nil
		}
		if pid != 0 {
			pids[key] = append(pids[key], pid)
		}
	}
	entries, err := snapshotProcesses()
	if err != nil {
		res.Fail("process list: " + err.Error())
	}
	for _, e := range entries {
		if e.pid <= 4 {
			continue
		}
		img, err := imagePath(e.pid)
		if err != nil || img == "" || opts.isSelf(e.pid, img) || !outside(img) {
			continue
		}
		add(img, e.pid)
	}
	profiles, err := userProfiles()
	if err != nil {
		res.Fail("profile list: " + err.Error())
	}
	var temps []string
	homes := make([]string, 0, len(profiles))
	for _, home := range profiles {
		homes = append(homes, home)
	}
	sort.Strings(homes)
	for _, home := range homes {
		temps = append(temps, filepath.Join(home, `AppData\Local\Temp`))
		for _, dir := range []string{filepath.Join(home, `AppData\Local\Temp`), filepath.Join(home, `AppData\Roaming\Microsoft\Network`)} {
			des, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, de := range des {
				if !de.IsDir() && strings.EqualFold(filepath.Ext(de.Name()), ".exe") {
					if p := filepath.Join(dir, de.Name()); !opts.isSelf(0, p) {
						add(p, 0)
					}
				}
			}
		}
	}
	temps = append(temps, filepath.Join(sysRoot, "Temp"))

	checked, searched, unreadable := 0, 0, 0
	var budget int64 = implantByteBudget
	for _, p := range order {
		if ctx.Err() != nil {
			res.Fail("cancelled: " + ctx.Err().Error())
			break
		}
		if budget <= 0 {
			res.Fail("byte budget spent; later programs weren't searched")
			break
		}
		checked++
		fam, markers, read, err := scanImplantFile(p)
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
		ids := pids[strings.ToLower(p)]
		fields := map[string]any{"kind": "implant_file", "path": p, "family": fam.Name, "markers": len(markers)}
		if len(ids) > 0 {
			fields["pids"] = ids
		}
		opts.Hasher.Fields(ctx, fields, "file", p)
		res.Add(fields, implantFileFinding(fam, p, markers, ids))
	}

	folders := 0
	for _, dir := range temps {
		files, err := readStaged(dir)
		if err != nil {
			continue
		}
		folders++
		if f, ok := stagedFilesFinding(dir, files); ok {
			names := make([]string, len(files))
			for i, sf := range files {
				names[i] = sf.Name
			}
			res.Add(map[string]any{"kind": "staged_files", "folder": dir, "files": names}, f)
		}
	}
	res.SetMeta("families", []string{implantFamilies[0].Name})
	res.SetMeta("programs_checked", checked)
	res.SetMeta("programs_searched", searched)
	res.SetMeta("programs_unreadable", unreadable)
	res.SetMeta("bytes_read", implantByteBudget-budget)
	res.SetMeta("temp_folders_checked", folders)
	return res.Finish(), nil
}
