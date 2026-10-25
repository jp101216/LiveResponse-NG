//go:build linux

package collector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Linux modules collector: the executable, file-backed mappings of each process
// (the main image and its shared libraries), read from /proc/<pid>/maps. A
// library loaded from a world-writable or temporary path is the shape of
// LD_PRELOAD abuse and shared-object hijacking; a library whose file has been
// deleted while still mapped is the shape of a fileless loader.
func collectModules(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("modules")

	pids, err := readProcPIDs()
	if err != nil && len(pids) == 0 {
		return res.Finish(), err
	}
	comm := procCommMap()

	scanned, inaccessible := 0, 0
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
		var high, low, deleted []string
		for _, m := range mods {
			list = append(list, map[string]any{"path": m.Path, "deleted": m.Deleted})
			if self {
				continue
			}
			if m.Deleted {
				deleted = append(deleted, m.Path)
			}
			switch lvl, _ := unixPathRisk(m.Path); lvl {
			case riskHigh:
				high = append(high, m.Path)
			case riskLow:
				low = append(low, m.Path)
			}
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

		var findings []Finding
		if len(deleted) > 0 {
			fields["deleted_modules"] = deleted
			findings = append(findings, Finding{
				Rule: "modules.deleted_file", Severity: SevSuspect, Technique: "T1620", Confidence: 65,
				Detail: fmt.Sprintf("%s (pid %d) has %d mapped library file(s) deleted from disk while still loaded: %s",
					name, pid, len(deleted), strings.Join(deleted, ", ")),
			})
		}
		if susp := append(append([]string{}, high...), low...); len(susp) > 0 {
			fields["suspicious_modules"] = susp
			sev, conf := SevNotable, 30
			why := "a world-writable or temporary location"
			if len(high) > 0 {
				sev, conf = SevSuspect, 55
			}
			findings = append(findings, Finding{
				Rule: "modules.unusual_path", Severity: sev, Technique: "T1574.006", Confidence: conf,
				Detail: fmt.Sprintf("%s (pid %d) has %d module(s) loaded from %s: %s",
					name, pid, len(susp), why, strings.Join(susp, ", ")),
			})
		}
		res.Add(fields, findings...)
	}

	res.SetMeta("platform", "linux")
	res.SetMeta("processes_scanned", scanned)
	res.SetMeta("processes_inaccessible", inaccessible)
	return res.Finish(), nil
}
