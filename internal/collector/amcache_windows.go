//go:build windows

package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const amcacheRelPath = `AppCompat\Programs\Amcache.hve`

// amcacheReadCap bounds how much of the hive we read. Real Amcache.hve files
// run to tens of megabytes; this is a generous sanity ceiling.
const amcacheReadCap = 512 << 20

const (
	cGenericRead  = 0x80000000
	cShareRead    = 0x00000001
	cShareWrite   = 0x00000002
	cShareDelete  = 0x00000004
	cOpenExisting = 3
	cBackupSem    = 0x02000000 // FILE_FLAG_BACKUP_SEMANTICS
)

func collectAmcache(ctx context.Context) (Result, error) {
	res := NewResult("amcache")
	full := filepath.Join(systemRoot(), amcacheRelPath)
	res.SetMeta("source", full)
	res.SetMeta("note", "read from the live hive while the system runs: a possibly dirty snapshot whose .LOG "+
		"transaction logs are not replayed. For a clean parse, point this at a hive copied via VSS or from an image")

	data, err := readHiveFile(full, amcacheReadCap)
	if err != nil {
		// A locked or absent hive is a normal live-response condition, not a
		// run failure: report it and move on.
		res.SetMeta("hive_readable", false)
		res.Fail("Amcache.hve: " + err.Error() + " (the hive may be in use; provide a VSS or image copy)")
		return res.Finish(), nil
	}
	res.SetMeta("hive_readable", true)
	res.SetMeta("hive_bytes", len(data))

	h, err := winreg.ParseHive(data)
	if err != nil {
		res.Fail("Amcache.hve: " + err.Error())
		return res.Finish(), nil
	}
	if !h.ModTime.IsZero() {
		res.SetMeta("hive_last_written", h.ModTime)
	}

	entries, meta := extractAmcache(h)
	for k, v := range meta {
		res.SetMeta(k, v)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		res.Add(amcacheFields(e), amcacheFindings(e)...)
	}
	return res.Finish(), nil
}

// readHiveFile reads a registry hive that the running system may hold open. The
// broad share mode (read/write/delete) matches how the kernel opens a mounted
// hive, which is what usually lets the read succeed; backup semantics lets an
// elevated agent open it by intent. The read is strictly read-only.
func readHiveFile(path string, maxBytes int64) ([]byte, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, cGenericRead,
		cShareRead|cShareWrite|cShareDelete, nil, cOpenExisting, cBackupSem, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("hive exceeds the %d-byte cap", maxBytes)
	}
	return data, nil
}
