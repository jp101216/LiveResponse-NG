//go:build linux

package collector

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// latticeFindings runs the collector and returns its Project Lattice records.
func latticeFindings(t *testing.T) []Record {
	t.Helper()
	res, err := collectImplants(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out []Record
	for _, r := range res.Records {
		for _, f := range r.Findings {
			if f.Rule == "malware.lattice_agent" {
				out = append(out, r)
			}
		}
	}
	return out
}

// TestImplantsLinuxRunningImage plants Lattice's markers at the end of a copy
// of sleep (an ELF runs fine with bytes appended), runs it from a home-like
// folder, and expects the collector to find it through /proc/<pid>/exe, by
// pid, before and after the file is deleted.
func TestImplantsLinuxRunningImage(t *testing.T) {
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	if !unixImplantCandidate(dir + "/x") {
		t.Skipf("temporary folder %s is under a system prefix", dir)
	}
	lat := latticeFamily(t)
	for _, m := range [][]byte{lat.Strong[0], lat.Strong[1], lat.Weak[0]} {
		data = append(append(data, 0), m...)
	}
	bin := filepath.Join(dir, "wraith")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real // /proc/<pid>/exe names the resolved path
	}
	// argv[0] stays "sleep": a multicall coreutils (uutils, busybox) picks
	// the utility by that name, and would exit at once as "wraith".
	cmd := exec.Command(bin, "30")
	cmd.Args[0] = "sleep"
	if err := cmd.Start(); err != nil {
		t.Skipf("can't run the copy: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := uint32(cmd.Process.Pid)
	running := false
	for i := 0; i < 50 && !running; i++ {
		time.Sleep(20 * time.Millisecond)
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		running = err == nil && exe == bin
	}
	if !running {
		t.Skipf("the copy of %s didn't stay running as %s", src, bin)
	}

	check := func(stage string, deleted bool) {
		recs := latticeFindings(t)
		for _, r := range recs {
			path, _ := r.Fields["path"].(string)
			pids, _ := r.Fields["pids"].([]uint32)
			if !strings.HasPrefix(path, bin) || len(pids) == 0 || pids[0] != pid {
				continue
			}
			if deleted != strings.HasSuffix(path, deletedSuffix) {
				t.Errorf("%s: path %q", stage, path)
			}
			return
		}
		t.Errorf("%s: no Lattice finding for pid %d in %+v", stage, pid, recs)
	}
	check("running", false)
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	check("deleted after launch", true)
}

// TestImplantsLinuxStagedFile plants a marked ELF directly in /tmp.
func TestImplantsLinuxStagedFile(t *testing.T) {
	lat := latticeFamily(t)
	f, err := os.CreateTemp("/tmp", "lrng-implant-test-*")
	if err != nil {
		t.Skipf("/tmp not writable: %v", err)
	}
	defer os.Remove(f.Name())
	_, err = f.Write(fakeELF(lat.Strong[2], lat.Weak[1]))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range latticeFindings(t) {
		if r.Fields["path"] == f.Name() {
			return
		}
	}
	t.Errorf("staged file %s not found", f.Name())
}
