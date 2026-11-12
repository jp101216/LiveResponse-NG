package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A flagged process's full module list is inventory, not a set of indicators:
// only the modules its findings name may become IOCs.
func TestIOCsSkipTheModuleInventoryOfAFlaggedProcess(t *testing.T) {
	rec := Record{
		Fields: map[string]any{
			"pid": 42, "process": "updater",
			"modules": []map[string]any{
				{"path": "/usr/lib/x86_64-linux-gnu/libc.so.6", "deleted": false},
				{"path": "/tmp/.x/implant.so", "deleted": false},
			},
			"suspicious_modules": []string{"/tmp/.x/implant.so"},
			"side_load_candidates": []map[string]any{
				{"path": `C:\Users\Public\app\version.dll`},
			},
		},
		Findings: []Finding{{Rule: "modules.unusual_path", Severity: SevSuspect}},
	}
	got := map[string]bool{}
	for _, r := range ExtractIOCs([]Result{{Collector: "modules", Records: []Record{rec}}}).Records {
		got[r.Fields["value"].(string)] = true
	}
	if got["/usr/lib/x86_64-linux-gnu/libc.so.6"] {
		t.Error("libc became an indicator because the process that loaded it was flagged")
	}
	for _, want := range []string{"/tmp/.x/implant.so", `C:\Users\Public\app\version.dll`} {
		if !got[want] {
			t.Errorf("flagged module %s is missing from the indicators: %v", want, got)
		}
	}
}

// Two POSIX paths differing only in case are distinct indicators; their order
// must not depend on map iteration.
func TestIOCOrderIsStableForPathsDifferingOnlyInCase(t *testing.T) {
	recs := []Record{
		{Fields: map[string]any{"image_path": "/opt/app/Run"}, Findings: []Finding{{Rule: "r", Severity: SevSuspect}}},
		{Fields: map[string]any{"image_path": "/opt/app/run"}, Findings: []Finding{{Rule: "r", Severity: SevSuspect}}},
		{Fields: map[string]any{"image_path": "/opt/app/RUN"}, Findings: []Finding{{Rule: "r", Severity: SevSuspect}}},
	}
	for i := 0; i < 50; i++ {
		var order []string
		for _, r := range ExtractIOCs([]Result{{Collector: "processes", Records: recs}}).Records {
			order = append(order, r.Fields["value"].(string))
		}
		if got := strings.Join(order, " "); got != "/opt/app/RUN /opt/app/Run /opt/app/run" {
			t.Fatalf("run %d: order %q", i, got)
		}
	}
}

// The adaptive pass follows the modules a finding names, not every library the
// flagged process has loaded, and never a path that is not a file on disk.
func TestAdaptivePlansOnlyFlaggedModulesThatExistOnDisk(t *testing.T) {
	dir := t.TempDir()
	flagged := filepath.Join(dir, "implant.so")
	system := filepath.Join(dir, "libc.so.6")
	for _, p := range []string{flagged, system} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	suspect := []Finding{{Rule: "modules.unusual_path", Severity: SevSuspect}}
	results := []Result{
		{Collector: "modules", Records: []Record{{
			Fields: map[string]any{
				"pid":                42,
				"modules":            []map[string]any{{"path": system}, {"path": flagged}, {"path": "/memfd:payload (deleted)"}},
				"suspicious_modules": []string{flagged},
			},
			Findings: suspect,
		}}},
		{Collector: "processes", Records: []Record{
			{Fields: map[string]any{"image_path": "/memfd:payload (deleted)"}, Findings: suspect},
			{Fields: map[string]any{"image_path": filepath.Join(dir, "gone") + deletedSuffix}, Findings: suspect},
		}},
	}
	tasks := planAdaptive(results)
	if len(tasks) != 1 || tasks[0].path != flagged {
		t.Fatalf("planned %+v, want only %s", tasks, flagged)
	}
}

// The finding says where the modules really are.
func TestLinuxModuleFindingNamesTheRealLocation(t *testing.T) {
	never := func(string) bool { return false }
	detail := func(paths ...string) string {
		var mods []mapsFile
		for _, p := range paths {
			mods = append(mods, mapsFile{Path: p})
		}
		_, fs := judgeLinuxModules(mods, never).annotate(map[string]any{}, "x (pid 1)")
		if len(fs) != 1 {
			t.Fatalf("%v: findings %+v", paths, fs)
		}
		return fs[0].Detail
	}
	if d := detail("/home/dev/.hidden/lib/libx.so"); strings.Contains(d, "world-writable") || !strings.Contains(d, "hidden directory in a home folder") {
		t.Errorf("hidden home directory described as: %s", d)
	}
	if d := detail("/tmp/a.so", "/dev/shm/b.so"); !strings.Contains(d, "world-writable temporary directory") || !strings.Contains(d, "shared memory") {
		t.Errorf("temporary locations described as: %s", d)
	}
}

// A mapped file's name is reported exactly as the kernel printed it.
func TestParseExecMappedFilesKeepsSpacesInNames(t *testing.T) {
	maps := "7f0000000000-7f0000001000 r-xp 00000000 fd:00 1234                       /usr/lib/libc.so.6\n" +
		"7f0000002000-7f0000003000 r-xp 00000000 fd:00 1235 /tmp/lib  two spaces.so\n" +
		"7f0000004000-7f0000005000 r-xp 00000000 fd:00 1236 /tmp/gone.so (deleted)\n" +
		"7f0000006000-7f0000007000 rw-p 00000000 fd:00 1237 /tmp/data.bin\n" +
		"7f0000008000-7f0000009000 r-xp 00000000 00:00 0 \n" +
		"7ffc00000000-7ffc00001000 r-xp 00000000 00:00 0                          [vdso]\n"
	got := parseExecMappedFiles([]byte(maps))
	want := []mapsFile{
		{Path: "/usr/lib/libc.so.6"},
		{Path: "/tmp/lib  two spaces.so"},
		{Path: "/tmp/gone.so (deleted)", Deleted: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mapping %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// An inventory the dispatcher marked partial must not turn "not listed" into
// "installed, then removed".
func TestInventoryPartialHonoursTheDispatcherMarker(t *testing.T) {
	r := Result{Meta: map[string]any{"partial": true}, Errors: []string{"walk stopped: access is denied"}}
	if !inventoryPartial(&r) {
		t.Error("meta.partial ignored")
	}
	r = Result{Errors: []string{"collection interrupted: context deadline exceeded; results may be incomplete"}}
	if !inventoryPartial(&r) {
		t.Error("the dispatcher's interruption error ignored")
	}
	r = Result{Errors: []string{"one task could not be read: access is denied"}}
	if inventoryPartial(&r) {
		t.Error("an ordinary per-record error must not suspend the correlation")
	}
}
