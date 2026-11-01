//go:build windows

package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestProcessRuntimeEnvOnWindows starts a child with the .NET runtime
// variables an intruder sets (ETW off, a profiler in the Public profile) and
// a secret, and reads them back out of its memory: only the runtime ones come
// back, and they are judged.
func TestProcessRuntimeEnvOnWindows(t *testing.T) {
	// ping itself, not through cmd.exe: killing cmd wouldn't stop its child,
	// which would carry these variables on into later tests.
	cmd := exec.Command(filepath.Join(systemRoot(), "System32", "PING.EXE"), "-n", "30", "127.0.0.1")
	cmd.Env = append(os.Environ(), "COMPlus_ETWEnabled=0", "COR_ENABLE_PROFILING=1",
		"COR_PROFILER={11111111-2222-3333-4444-555555555555}", `COR_PROFILER_PATH=C:\Users\Public\prof.dll`, "LRNG_SECRET=hunter2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(500 * time.Millisecond)

	env, err := processRuntimeEnv(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if env["COMPLUS_ETWENABLED"] != "0" || env["COR_ENABLE_PROFILING"] != "1" || env["COR_PROFILER_PATH"] != `C:\Users\Public\prof.dll` || len(env) != 4 {
		t.Fatalf("environment read back: %v", env)
	}
	fs := runtimeEnvFindings("child", env, nil)
	if hasFinding(fs, "defense.dotnet_etw_disabled") == nil || hasFinding(fs, "persistence.clr_profiler") == nil {
		t.Errorf("findings: %+v", fs)
	}
	// Our own environment has none of them.
	if own, err := processRuntimeEnv(uint32(os.Getpid())); err != nil || len(own) != 0 {
		t.Errorf("own environment: %v %v", own, err)
	}
}

// TestOriginalFileNameOnWindows reads the version resources the
// accessibility check compares.
func TestOriginalFileNameOnWindows(t *testing.T) {
	if underWine() {
		t.Skip("Wine's binaries carry Wine's version resources")
	}
	for _, name := range []string{"cmd.exe", "notepad.exe", "sethc.exe"} {
		got, err := originalFileName(filepath.Join(systemRoot(), "System32", name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if strings.TrimSuffix(strings.ToLower(got), ".mui") != name {
			t.Errorf("%s: original file name %q", name, got)
		}
	}
	if _, err := originalFileName(filepath.Join(t.TempDir(), "missing.exe")); err == nil {
		t.Error("a missing file has no version resource")
	}
}
