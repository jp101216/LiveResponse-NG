package collector

import "testing"

func TestParseExecMappedFiles(t *testing.T) {
	data := []byte(
		"55a0-55a1 r-xp 00000000 fd:00 100 /usr/bin/bash\n" +
			"55a1-55a2 rw-p 00000000 fd:00 100 /usr/bin/bash\n" + // not executable, ignored
			"7f00-7f01 r-xp 00000000 fd:00 200 /usr/lib/x86_64-linux-gnu/libc.so.6\n" +
			"7f10-7f11 r-xp 00000000 fd:00 300 /tmp/evil.so (deleted)\n" +
			"7f20-7f21 r-xp 00000000 00:00 0 [vdso]\n" +
			"7f30-7f31 rw-p 00000000 00:00 0 [heap]\n" +
			"7f40-7f41 r-xp 00000000 fd:00 200 /usr/lib/x86_64-linux-gnu/libc.so.6\n") // dup of libc
	got := parseExecMappedFiles(data)
	if len(got) != 3 { // bash, libc, /tmp/evil.so — libc deduped, vdso/heap/non-exec skipped
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if got[0].Path != "/usr/bin/bash" {
		t.Errorf("first = %q, want /usr/bin/bash", got[0].Path)
	}
	// The /tmp one is marked deleted.
	var evil mapsFile
	for _, m := range got {
		if m.Path == "/tmp/evil.so (deleted)" {
			evil = m
		}
	}
	if !evil.Deleted {
		t.Errorf("expected /tmp/evil.so to be marked deleted: %+v", evil)
	}
}

func TestParseShadowAndPasswordState(t *testing.T) {
	data := []byte(
		"root:$6$abcd:19000:0:99999:7:::\n" +
			"backdoor::19000:0:99999:7:::\n" + // empty hash = no password
			"locked:!:19000:0:99999:7:::\n" + // passwd -l
			"lockedhash:!$y$j9T$x:19000:0:99999:7:::\n" + // locked, hash kept
			"daemon:*:19000:0:99999:7:::\n" +
			"never:!!:19000:0:99999:7:::\n" + // RHEL "never set"
			"# comment\n")
	sh := parseShadow(data)
	want := map[string]string{
		"root": pwUsable, "backdoor": pwEmpty, "locked": pwLocked,
		"lockedhash": pwLocked, "daemon": pwLocked, "never": pwLocked,
	}
	if len(sh) != len(want) {
		t.Fatalf("parsed %d entries, want %d: %v", len(sh), len(want), sh)
	}
	for name, st := range want {
		if got := passwordState(sh[name]); got != st {
			t.Errorf("%s: passwordState(%q) = %s, want %s", name, sh[name], got, st)
		}
	}
}
