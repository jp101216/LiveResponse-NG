//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const prefetchParamsKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`

// prefetchReadCap bounds how much of a .pf file we read before decoding. Real
// prefetch files are well under a megabyte; anything far larger is skipped
// rather than trusted.
const prefetchReadCap = 8 << 20

func collectPrefetch(ctx context.Context) (Result, error) {
	res := NewResult("prefetch")

	dir := filepath.Join(systemRoot(), "Prefetch")
	res.SetMeta("prefetch_dir", dir)
	res.SetMeta("note", "bodies are decompressed (Xpress Huffman) and decoded: run count, recent run "+
		"times, referenced files and volumes. Prefetch is evidence of execution, not just existence")
	// Whether the prefetcher is on explains an empty or missing directory:
	// it's off by default on Windows Server.
	if v, err := winreg.ReadValue(winreg.LocalMachine, prefetchParamsKey, "EnablePrefetcher"); err == nil {
		if n, ok := v.Uint32(); ok {
			res.SetMeta("enable_prefetcher", n)
			res.SetMeta("prefetch_enabled", n&1 != 0)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res.SetMeta("prefetch_dir_present", false)
			return res.Finish(), nil // prefetch disabled: nothing to collect, not an error
		}
		return res.Finish(), err
	}

	count, decoded := 0, 0
	for _, d := range entries {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(d.Name()), ".pf") {
			continue
		}
		info, err := d.Info()
		if err != nil {
			res.Fail(d.Name() + ": " + err.Error())
			continue
		}
		fields := map[string]any{
			"file": d.Name(),
			"size": info.Size(),
		}
		addFileTimes(fields, "", info) // modified_at ~ the most recent run
		if exe, hash, ok := prefetchExecutable(d.Name()); ok {
			fields["executable"] = exe
			fields["path_hash"] = hash
		}

		findings := decodePrefetchInto(res, dir, d.Name(), info, fields)
		if dv, _ := fields["decoded"].(bool); dv {
			decoded++
		}
		res.Add(fields, findings...)
		count++
	}
	res.SetMeta("file_count", count)
	res.SetMeta("decoded_count", decoded)
	return res.Finish(), nil
}

// decodePrefetchInto reads and decodes one .pf body, adding the decoded fields
// to fields and returning any findings. Decode problems are recorded on res and
// leave the file listed with decoded=false rather than failing the collector.
func decodePrefetchInto(res *Result, dir, name string, info fs.FileInfo, fields map[string]any) []Finding {
	if info.Size() <= 0 {
		fields["decoded"] = false
		return nil
	}
	if info.Size() > prefetchReadCap {
		fields["decoded"] = false
		res.Fail(fmt.Sprintf("%s: %d bytes exceeds the %d-byte decode cap", name, info.Size(), prefetchReadCap))
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		fields["decoded"] = false
		res.Fail(name + ": " + err.Error())
		return nil
	}
	pf, err := decodePrefetchFile(raw)
	if err != nil {
		fields["decoded"] = false
		res.Fail(name + ": " + err.Error())
		return nil
	}

	fields["decoded"] = true
	fields["format_version"] = pf.Version
	if pf.RunCount >= 0 {
		fields["run_count"] = pf.RunCount
	}
	if len(pf.LastRun) > 0 {
		fields["run_times"] = pf.LastRun
		fields["last_run"] = pf.LastRun[0]
	}
	if pf.ImagePath != "" {
		fields["image_path"] = pf.ImagePath
	}
	fields["referenced_file_count"] = len(pf.Filenames)
	if len(pf.Filenames) > 0 {
		fields["referenced_files"] = pf.Filenames
	}
	if len(pf.Volumes) > 0 {
		vols := make([]map[string]any, 0, len(pf.Volumes))
		for _, v := range pf.Volumes {
			vm := map[string]any{
				"device_path": v.DevicePath,
				"serial":      fmt.Sprintf("%08x", v.Serial),
			}
			if !v.Created.IsZero() {
				vm["created_at"] = v.Created
			}
			vols = append(vols, vm)
		}
		fields["volumes"] = vols
	}
	return prefetchFindings(pf)
}
