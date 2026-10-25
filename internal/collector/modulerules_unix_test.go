package collector

import "testing"

func moduleRules(fs []Finding) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range fs {
		m[f.Rule] = f.Severity
	}
	return m
}

func TestJudgeLinuxModules(t *testing.T) {
	present := map[string]bool{"/usr/lib/x86_64-linux-gnu/libssl.so.3": true}
	exists := func(p string) bool { return present[p] }

	cases := []struct {
		name string
		mods []mapsFile
		want map[string]Severity
	}{
		{"memfd is reported once, as a memfd",
			[]mapsFile{{Path: "/memfd:payload (deleted)", Deleted: true}},
			map[string]Severity{"modules.memfd_exec": SevSuspect}},
		{"a library replaced by an upgrade is low-severity context only",
			[]mapsFile{{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)", Deleted: true}},
			map[string]Severity{"modules.replaced_on_disk": SevInfo}},
		{"a deleted system library nothing replaced is deleted, not an unusual path",
			[]mapsFile{{Path: "/usr/lib/libgone.so (deleted)", Deleted: true}},
			map[string]Severity{"modules.deleted_file": SevSuspect}},
		{"a deleted library in /tmp is both deleted and in an unusual place",
			[]mapsFile{{Path: "/tmp/.x/hook.so (deleted)", Deleted: true}},
			map[string]Severity{"modules.deleted_file": SevSuspect, "modules.unusual_path": SevSuspect}},
		{"an ordinary process is quiet",
			[]mapsFile{{Path: "/usr/bin/bash"}, {Path: "/usr/lib/x86_64-linux-gnu/libc.so.6"}},
			map[string]Severity{}},
		{"a library under a hidden home dir is low-risk",
			[]mapsFile{{Path: "/home/a/.cache/x/libx.so"}},
			map[string]Severity{"modules.unusual_path": SevNotable}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]any{}
			_, fs := judgeLinuxModules(tc.mods, exists).annotate(fields, "p (pid 1)")
			got := moduleRules(fs)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for r, sev := range tc.want {
				if got[r] != sev {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}

	fields := map[string]any{}
	j := judgeLinuxModules([]mapsFile{
		{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)", Deleted: true},
		{Path: "/memfd:m (deleted)", Deleted: true},
	}, exists)
	j.annotate(fields, "p (pid 1)")
	if _, ok := fields["replaced_modules"]; !ok {
		t.Errorf("replaced_modules field missing: %v", fields)
	}
	if _, ok := fields["memfd_modules"]; !ok {
		t.Errorf("memfd_modules field missing: %v", fields)
	}
	if _, ok := fields["deleted_modules"]; ok {
		t.Errorf("neither mapping is a plain deletion: %v", fields)
	}
}
