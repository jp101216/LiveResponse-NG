//go:build linux

package collector

import (
	"context"
	"fmt"
	"strconv"
)

// Linux modules collector: the executable, file-backed mappings of each process
// (the main image and its shared libraries), read from /proc/<pid>/maps. A
// library loaded from a world-writable or temporary path is the shape of
// LD_PRELOAD abuse and shared-object hijacking; executable code mapped from an
// anonymous memfd is fileless loading; a library whose file has been deleted
// while still mapped is the shape of a loader that cleans up after itself. A
// system library that was replaced on disk (a package upgrade the process
// hasn't been restarted after) also shows as deleted, so it is told apart and
// reported at low severity.
func collectModules(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("modules")

	pids, err := readProcPIDs()
	if err != nil && len(pids) == 0 {
		return res.Finish(), err
	}
	comm := procCommMap()

	scanned, inaccessible, withReplaced := 0, 0, 0
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		data := readFileSafe("/proc/" + strconv.Itoa(pid) + "/maps")
		if data == nil {
			inaccessible++
			continue
		}
		mods := parseExecMappedFiles(data)
		if len(mods) == 0 {
			continue // kernel thread or nothing mapped executable
		}
		scanned++
		name := comm[pid]
		self := opts.isSelf(uint32(pid), mods[0].Path)

		list := make([]map[string]any, 0, len(mods))
		var j moduleJudgement
		if !self {
			j = judgeLinuxModules(mods, procRootExists(pid))
		}
		for _, m := range mods {
			list = append(list, map[string]any{"path": m.Path, "deleted": m.Deleted})
		}

		fields := map[string]any{
			"pid":          pid,
			"process":      name,
			"module_count": len(list),
			"modules":      list,
		}
		if self {
			fields["lrng_component"] = true
		}
		if len(j.replaced) > 0 {
			withReplaced++
		}
		fields, findings := j.annotate(fields, fmt.Sprintf("%s (pid %d)", name, pid))
		res.Add(fields, findings...)
	}

	res.SetMeta("platform", "linux")
	res.SetMeta("processes_scanned", scanned)
	res.SetMeta("processes_inaccessible", inaccessible)
	if withReplaced > 0 {
		res.SetMeta("processes_with_replaced_libraries", withReplaced)
	}
	return res.Finish(), nil
}
