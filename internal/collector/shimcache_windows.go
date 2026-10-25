//go:build windows

package collector

import (
	"context"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const appCompatCacheKey = `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

func collectShimcache(ctx context.Context) (Result, error) {
	res := NewResult("shimcache")

	k, err := winreg.Open(winreg.LocalMachine, appCompatCacheKey)
	if err != nil {
		return res.Finish(), err
	}
	v, err := k.Value("AppCompatCache")
	lw := k.LastWrite()
	k.Close()
	if err != nil {
		return res.Finish(), err
	}
	res.SetMeta("source", `HKLM\`+appCompatCacheKey+`\AppCompatCache`)
	res.SetMeta("value_bytes", len(v.Data))
	if !lw.IsZero() {
		res.SetMeta("key_last_write", lw)
	}
	res.SetMeta("note", "the registry copy is written at shutdown: it holds entries up to the last shutdown, "+
		"not the current session's in-memory cache; timestamps are the files' last-modified times, not run times")

	entries, perr := parseAppCompatCache(v.Data)
	if perr != nil {
		res.Fail(perr.Error())
	}
	res.SetMeta("entry_count", len(entries))

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		lvl, why := pathRisk(e.Path)
		fields := map[string]any{
			"index":           e.Index,
			"path":            e.Path,
			"suspicious_path": lvl != riskNone,
		}
		if !e.LastModified.IsZero() {
			fields["last_modified"] = e.LastModified
		}
		var findings []Finding
		if lvl == riskHigh {
			findings = append(findings, Finding{
				Rule:       "execution.shimcache_unusual_path",
				Severity:   SevNotable,
				Technique:  "T1204.002",
				Confidence: 45,
				Detail:     "AppCompatCache recorded a program in " + why + " (it existed there, and may have run): " + e.Path,
			})
		}
		res.Add(fields, findings...)
	}
	return res.Finish(), nil
}
