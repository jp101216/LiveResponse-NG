//go:build windows

package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var (
	testUser32         = syscall.NewLazyDLL("user32.dll")
	procCreateDesktopW = testUser32.NewProc("CreateDesktopW")
	procCloseDesktop   = testUser32.NewProc("CloseDesktop")
)

// processRecord finds a process's record in a processes result.
func processRecord(t *testing.T, res Result, pid uint32) Record {
	t.Helper()
	for _, r := range res.Records {
		if p, _ := r.Fields["pid"].(uint32); p == pid {
			return r
		}
	}
	t.Fatalf("no record for pid %d among %d", pid, len(res.Records))
	return Record{}
}

// TestHiddenDesktopOnWindows creates a desktop and starts ping on it (a
// benign program; nothing is shown or controlled there), then reads the
// desktop back out of the child's process parameters, and requires the
// processes collector to report it.
func TestHiddenDesktopOnWindows(t *testing.T) {
	name := fmt.Sprintf("lrng-test-desktop-%d", os.Getpid())
	n16, _ := syscall.UTF16PtrFromString(name)
	const genericAll = 0x10000000
	hd, _, err := procCreateDesktopW.Call(uintptr(unsafe.Pointer(n16)), 0, 0, 0, genericAll, 0)
	if hd == 0 {
		t.Fatalf("CreateDesktop: %v", err)
	}
	defer procCloseDesktop.Call(hd)

	exe := filepath.Join(systemRoot(), "System32", "PING.EXE")
	app, _ := syscall.UTF16PtrFromString(exe)
	cl, _ := syscall.UTF16PtrFromString(`"` + exe + `" -n 30 127.0.0.1`)
	si := syscall.StartupInfo{Desktop: n16}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	const createNoWindow = 0x08000000
	if err := syscall.CreateProcess(app, cl, nil, nil, false, createNoWindow, nil, nil, &si, &pi); err != nil {
		t.Fatalf("CreateProcess on %s: %v", name, err)
	}
	syscall.CloseHandle(pi.Thread)
	defer func() {
		syscall.TerminateProcess(pi.Process, 1)
		syscall.WaitForSingleObject(pi.Process, 5000)
		syscall.CloseHandle(pi.Process)
	}()
	time.Sleep(500 * time.Millisecond)

	pp, err := processParams(pi.ProcessId)
	if err != nil {
		t.Fatal(err)
	}
	_, desk := splitDesktop(pp.Desktop)
	if !strings.EqualFold(desk, name) {
		t.Fatalf("desktop read back as %q, want %q", pp.Desktop, name)
	}
	own, _ := processParams(uint32(os.Getpid()))
	t.Logf("this test's desktop %q; the child's %q", own.Desktop, pp.Desktop)

	res, err := collectProcesses(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec := processRecord(t, res, pi.ProcessId)
	if f := hasFinding(rec.Findings, "defense.hidden_desktop"); f == nil || f.Severity != SevNotable {
		t.Errorf("ping on its own desktop: %+v (fields %v)", rec.Findings, rec.Fields["desktop"])
	}
}

// TestTimestompedImageOnWindows runs a copy of ping dated 1979, as NIK C2
// dates its own copies, and requires the processes collector to report it.
func TestTimestompedImageOnWindows(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "pong.exe")
	src, err := os.Open(filepath.Join(systemRoot(), "System32", "PING.EXE"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(out, src)
	src.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(1979, 6, 12, 9, 30, 0, 0, time.UTC)
	p16, _ := syscall.UTF16PtrFromString(dst)
	h, err := syscall.CreateFile(p16, syscall.FILE_WRITE_ATTRIBUTES, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	ft := syscall.NsecToFiletime(when.UnixNano())
	err = syscall.SetFileTime(h, &ft, &ft, &ft)
	syscall.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	if c, m, ok := statTimes(dst); !ok || !c.Equal(when) || !m.Equal(when) {
		t.Fatalf("times read back: %v %v %v", c, m, ok)
	}

	cmd := exec.Command(dst, "-n", "30", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(500 * time.Millisecond)

	res, err := collectProcesses(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec := processRecord(t, res, uint32(cmd.Process.Pid))
	if f := hasFinding(rec.Findings, "defense.timestomp"); f == nil || f.Severity != SevSuspect || !strings.Contains(f.Detail, "1979-06-12") {
		t.Errorf("a 1979 copy of ping: %+v", rec.Findings)
	}
	// Windows' own critical processes were read as such.
	t.Logf("critical: %v (read %v, unreadable %v); desktops %v", res.Meta["critical_processes"],
		res.Meta["critical_flags_read"], res.Meta["critical_flags_unreadable"], res.Meta["desktops"])
}
