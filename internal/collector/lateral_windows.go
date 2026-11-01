//go:build windows

package collector

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// outputRead is how much of a leftover output file is kept in its record.
const outputRead = 512

func collectLateral(ctx context.Context) (Result, error) {
	res := NewResult("lateral")
	pipes, err := listPipes()
	if err != nil {
		res.Fail("named pipes: " + err.Error())
	}
	lateralReport(res, pipes, leftoverFiles(ctx))
	return res.Finish(), nil
}

// listPipes lists every named pipe on the host (FindFirstFile over
// \\.\pipe\*, which opens none of them).
func listPipes() ([]string, error) {
	pattern, err := syscall.UTF16PtrFromString(`\\.\pipe\*`)
	if err != nil {
		return nil, err
	}
	var fd syscall.Win32finddata
	h, err := syscall.FindFirstFile(pattern, &fd)
	if err != nil {
		return nil, err
	}
	defer syscall.FindClose(h)
	var out []string
	for {
		if name := syscall.UTF16ToString(fd.FileName[:]); name != "" {
			out = append(out, name)
		}
		if syscall.FindNextFile(h, &fd) != nil {
			return out, nil
		}
	}
}

// leftoverFiles finds Impacket's output files in the Windows folder (ADMIN$)
// and the system drive's root (C$), with the start of each.
func leftoverFiles(ctx context.Context) []leftoverFile {
	root := systemRoot()
	var out []leftoverFile
	for _, dir := range []string{root, filepath.VolumeName(root) + `\`} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ctx.Err() != nil {
				return out
			}
			name := e.Name()
			if e.IsDir() || !strings.HasPrefix(name, "__") {
				continue
			}
			path := filepath.Join(dir, name)
			if _, ok := leftoverFinding(path, name); !ok {
				continue
			}
			f := leftoverFile{Path: path, Name: name}
			if info, err := e.Info(); err == nil {
				f.Size, f.Modified = info.Size(), info.ModTime()
			}
			if h, err := os.Open(path); err == nil {
				head := make([]byte, outputRead)
				n, _ := io.ReadFull(h, head)
				h.Close()
				f.Content = printable(head[:n], outputRead)
			}
			out = append(out, f)
		}
	}
	return out
}
