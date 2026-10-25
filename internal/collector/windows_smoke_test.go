//go:build windows

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// underWine reports whether the tests run under Wine (a handy Linux dev
// loop: make wine-test), where the host has no LSASS and only a handful of
// processes and services, so host-shape assertions are skipped.
func underWine() bool {
	return syscall.NewLazyDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil
}

// TestDefaultCollectorsOnWindows runs the whole default sweep on a real
// Windows host (CI runs it on windows-latest) and checks the structural
// promises every report relies on. Findings are logged, not asserted: a CI
// runner is a "known clean" host, so any finding it shows is worth reading
// as a possible false positive.
func TestDefaultCollectorsOnWindows(t *testing.T) {
	if testing.Short() {
		t.Skip("runs every collector against the live host")
	}
	cs := Defaults()
	ConfigureAll(cs, RunOptions{Hasher: NewFileHasher(), SelfPID: os.Getpid()}) // no DNS lookups
	results := (&Dispatcher{Workers: 4, Timeout: 3 * time.Minute}).Run(context.Background(), cs)

	byName := map[string]Result{}
	for _, r := range results {
		byName[r.Collector] = r
		if _, err := json.Marshal(r); err != nil {
			t.Errorf("%s: result does not serialise: %v", r.Collector, err)
		}
		for _, e := range r.Errors {
			if strings.HasPrefix(e, "panic:") || strings.Contains(e, "abandoned") {
				t.Errorf("%s: %s", r.Collector, e)
			} else {
				t.Logf("%s: error: %s", r.Collector, e)
			}
		}
		if r.Records == nil {
			t.Errorf("%s: records must be [] not nil", r.Collector)
		}
		for i, rec := range r.Records {
			for _, f := range rec.Findings {
				if f.Rule == "" || SeverityRank(f.Severity) == 0 || f.Confidence < 0 || f.Confidence > 100 || f.Detail == "" {
					t.Errorf("%s record %d: malformed finding %+v", r.Collector, i, f)
				}
				t.Logf("finding %s[%d]: [%s] %s — %s", r.Collector, i, f.Severity, f.Rule, f.Detail)
			}
		}
	}

	if underWine() {
		t.Log("running under Wine: skipping assertions about a real Windows host's shape")
		return
	}
	min := map[string]int{"processes": 10, "services": 50, "network": 1, "autoruns": 1, "localaccounts": 1}
	for name, n := range min {
		if got := len(byName[name].Records); got < n {
			t.Errorf("%s: %d records, want at least %d", name, got, n)
		}
	}

	hashed, lsassOK := 0, false
	for _, rec := range byName["processes"].Records {
		if _, ok := rec.Fields["image_sha256"]; ok {
			hashed++
		}
		name, _ := rec.Fields["name"].(string)
		if strings.EqualFold(name, "lsass.exe") {
			parent, _ := rec.Fields["parent_name"].(string)
			lsassOK = parent == "" || strings.EqualFold(parent, "wininit.exe")
			for _, f := range rec.Findings {
				if f.Rule == "process.unexpected_parent" || f.Rule == "process.masquerade_path" {
					lsassOK = false
				}
			}
		}
	}
	if hashed == 0 {
		t.Error("no process image was hashed")
	}
	if !lsassOK {
		t.Error("the real lsass.exe was judged suspicious (or not found)")
	}
}

func TestHostHelpersOnWindows(t *testing.T) {
	root := systemRoot()
	if _, err := os.Stat(root + `\System32\kernel32.dll`); err != nil {
		t.Fatalf("systemRoot %q looks wrong: %v", root, err)
	}
	if got := normalizeImage(`\SystemRoot\System32\drivers\tcpip.sys`); !strings.EqualFold(got, root+`\System32\drivers\tcpip.sys`) {
		t.Errorf("normalizeImage = %q", got)
	}
	profiles, err := userProfiles()
	if err != nil {
		t.Logf("profile list: %v", err)
	}
	t.Logf("profiles: %v", profiles)
	hives, err := loadedUserHives()
	if err != nil {
		t.Errorf("loaded hives: %v", err)
	}
	t.Logf("loaded user hives: %v", hives)
}

// The DNS cache API is undocumented; it must never take the agent down.
func TestDNSCacheSnapshotOnWindows(t *testing.T) {
	res, err := collectDNSCache(context.Background(), RunOptions{})
	if err != nil {
		t.Logf("dnscache: %v (an empty cache is possible on a fresh runner)", err)
		return
	}
	t.Logf("dnscache: %d names, meta %v", len(res.Records), res.Meta)
}
