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
	min := map[string]int{"processes": 10, "services": 50, "network": 1, "autoruns": 1, "localaccounts": 1, "drivers": 50,
		"lateral": 1, "defenses": 3}
	for name, n := range min {
		if got := len(byName[name].Records); got < n {
			t.Errorf("%s: %d records, want at least %d", name, got, n)
		}
	}
	// Every Windows host has named pipes of its own (lsass, ntsvcs, ...): the
	// listing must have found them.
	for _, rec := range byName["lateral"].Records {
		if rec.Fields["kind"] == "summary" {
			if n, _ := rec.Fields["pipes"].(int); n < 5 {
				t.Errorf("lateral: listed %d named pipes", n)
			}
			t.Logf("lateral: %v pipes, %v flagged", rec.Fields["pipes"], rec.Fields["pipes_flagged"])
		}
	}
	amsiSeen := false
	for _, rec := range byName["defenses"].Records {
		t.Logf("defenses %v: %v", rec.Fields["area"], rec.Fields)
		if rec.Fields["area"] == "amsi" {
			amsiSeen = true
			if p, _ := rec.Fields["providers"].([]string); len(p) == 0 {
				t.Errorf("defenses: no AMSI provider registered on a host with Defender: %v", rec.Fields)
			}
		}
		for _, f := range rec.Findings {
			if strings.HasPrefix(f.Rule, "defense.amsi_") || f.Rule == "defense.dotnet_etw_disabled" {
				t.Errorf("defenses: %s on a clean host: %s", f.Rule, f.Detail)
			}
		}
	}
	if !amsiSeen {
		t.Error("defenses: no AMSI record")
	}
	// The accessibility programs the logon screen runs were each read and
	// judged genuine.
	if n, _ := byName["autoruns"].Meta["accessibility_binaries_checked"].(int); n < 3 {
		t.Errorf("autoruns: checked %d accessibility programs (%v)", n, byName["autoruns"].Meta["accessibility_original_names"])
	}
	t.Logf("accessibility programs: %v", byName["autoruns"].Meta["accessibility_original_names"])
	for _, rec := range byName["autoruns"].Records {
		for _, f := range rec.Findings {
			if f.Rule == "persistence.accessibility_backdoor" {
				t.Errorf("autoruns: %s", f.Detail)
			}
		}
	}
	if ai := byName["aiagents"]; ai.Meta["entries_visited"] == nil || ai.Meta["entries_visited"] == 0 {
		t.Errorf("aiagents: swept nothing (homes %v)", ai.Meta["homes"])
	} else {
		t.Logf("aiagents: homes %v, %v entries, %v MCP servers, %v instruction files", ai.Meta["homes"], ai.Meta["entries_visited"],
			ai.Meta["mcp_servers"], ai.Meta["instruction_files"])
	}
	// Kerberos: LSA answered. The runner isn't SYSTEM, so only its own
	// session is asked about, and that must be answered (with its tickets,
	// or with Kerberos holding nothing for a local account).
	if k := byName["kerberos"]; k.Meta["sessions"] == nil {
		t.Errorf("kerberos: no logon sessions listed (errors %q)", k.Errors)
	} else {
		t.Logf("kerberos: all sessions %v, %v sessions, %v read, %v without Kerberos, %v unreadable, %v tickets",
			k.Meta["all_sessions"], k.Meta["sessions"], k.Meta["sessions_read"], k.Meta["sessions_without_kerberos"],
			k.Meta["sessions_unreadable"], k.Meta["tickets"])
		read, _ := k.Meta["sessions_read"].(int)
		none, _ := k.Meta["sessions_without_kerberos"].(int)
		if all, _ := k.Meta["all_sessions"].(bool); !all && (read+none != 1 || k.Meta["sessions_unreadable"] != 0) {
			t.Errorf("kerberos: its own session wasn't answered: %v", k.Meta)
		}
	}
	if n, _ := byName["processes"].Meta["environments_read"].(int); n < 10 {
		t.Errorf("processes: read %d environments (%v unreadable)", n, byName["processes"].Meta["environments_unreadable"])
	} else {
		t.Logf("processes: %d environments read, %v unreadable", n, byName["processes"].Meta["environments_unreadable"])
	}
	for _, rec := range byName["processes"].Records {
		for _, f := range rec.Findings {
			if f.Rule == "defense.dotnet_etw_disabled" || f.Rule == "persistence.clr_profiler" {
				t.Logf("processes: %s on the runner: %s", f.Rule, f.Detail)
			}
		}
	}
	// The event-log collector keeps only targeted events, so a clean host may
	// keep none -- but it must have read the host's logs (there is always a
	// System log). TestEvtxParserMatchesWevtutil checks what it made of them.
	if el := byName["eventlog"]; el.Meta["records_scanned"] == nil || el.Meta["records_scanned"] == 0 {
		t.Errorf("eventlog: read no records from the host's logs (logs read %v, missing %v; errors %q)",
			el.Meta["logs_read"], el.Meta["logs_missing"], el.Errors)
	}
	// The registry's AppCompatCache is real Windows data in a format we parse
	// by hand; a parse error on it is a parser bug, not a host quirk.
	for _, e := range byName["shimcache"].Errors {
		if strings.HasPrefix(e, "appcompatcache:") {
			t.Errorf("shimcache: %s (value %v bytes)", e, byName["shimcache"].Meta["value_bytes"])
		}
	}
	t.Logf("shimcache: %v entries from %v bytes", byName["shimcache"].Meta["entry_count"], byName["shimcache"].Meta["value_bytes"])

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
