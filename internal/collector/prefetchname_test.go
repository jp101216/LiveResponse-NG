package collector

import "testing"

func TestPrefetchExecutable(t *testing.T) {
	cases := []struct {
		fname string
		exe   string
		hash  string
		ok    bool
	}{
		{"CMD.EXE-0AE8D7F2.pf", "CMD.EXE", "0AE8D7F2", true},
		{"POWERSHELL.EXE-59C4ABF2.pf", "POWERSHELL.EXE", "59C4ABF2", true},
		{"update.exe-deadbeef.PF", "update.exe", "deadbeef", true},
		{"NODASHHERE.pf", "NODASHHERE", "", false},        // no hash section
		{"NAME-xyz.pf", "NAME", "xyz", false},             // hash not 8 hex
		{"NAME-123456789.pf", "NAME", "123456789", false}, // hash too long
		{"notprefetch.txt", "", "", false},
	}
	for _, c := range cases {
		exe, hash, ok := prefetchExecutable(c.fname)
		if exe != c.exe || hash != c.hash || ok != c.ok {
			t.Errorf("prefetchExecutable(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.fname, exe, hash, ok, c.exe, c.hash, c.ok)
		}
	}
}
