package collector

import (
	"strings"
	"testing"
	"time"
)

func TestCriticalProcessFinding(t *testing.T) {
	root := `C:\Windows`
	for _, c := range []struct {
		name, image string
		want        Severity // "" for no finding
	}{
		{"lsass.exe", `C:\Windows\System32\lsass.exe`, ""},
		{"csrss.exe", `C:\Windows\system32\csrss.exe`, ""},
		{"Registry", "", ""},
		{"Registry", "Registry", ""},
		{"Memory Compression", "MemCompression", ""},
		{"Registry", `C:\Users\bob\Registry`, SevCritical},
		{"svchost.exe", `C:\Windows\System32\svchost.exe`, ""},
		// NIK C2 runs as csrss.exe from Temp, or svchost.exe / simvol.exe.
		{"csrss.exe", `C:\Users\bob\AppData\Local\Temp\csrss.exe`, SevCritical},
		{"svchost.exe", `C:\Users\bob\AppData\Roaming\Microsoft\Network\svchost.exe`, SevCritical},
		{"simvol.exe", `C:\Users\bob\AppData\Roaming\Microsoft\Network\simvol.exe`, SevCritical},
		{"rat.exe", "", SevCritical},
		// A Windows program Windows doesn't mark critical.
		{"notepad.exe", `C:\Windows\System32\notepad.exe`, SevNotable},
	} {
		f, ok := criticalProcessFinding("process "+c.name, c.name, c.image, root)
		if c.want == "" {
			if ok {
				t.Errorf("%s at %s: %+v", c.name, c.image, f)
			}
			continue
		}
		if !ok || f.Rule != "defense.critical_process" || f.Severity != c.want {
			t.Errorf("%s at %s: %+v, want %s", c.name, c.image, f, c.want)
			continue
		}
		if !strings.Contains(f.Detail, "Don't end it") || !strings.Contains(f.Detail, "CRITICAL_PROCESS_DIED") {
			t.Errorf("no warning in: %s", f.Detail)
		}
	}
}

func TestDesktopFinding(t *testing.T) {
	for _, c := range []struct {
		name, cmd, desktop string
		want               Severity
	}{
		{"notepad.exe", "", `WinSta0\Default`, ""},
		{"notepad.exe", "", "Default", ""},
		{"consent.exe", "", `WinSta0\Winlogon`, ""},
		{"svchost.exe", "", `Service-0x0-3e7$\Default`, ""},
		{"scrnsave.scr", "", `WinSta0\Screen-saver`, ""},
		{"SearchFilterHost.exe", "", `msswindowstation\mssrestricteddesk`, ""},
		{"chrome.exe", `"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en-US`,
			`WinSta0\sbox_alternate_desktop_0x1A2B3C`, ""},
		{"firefox.exe", `"C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel=1234 -childID 3 tab`,
			`sbox_alternate_desktop_local_winstation_0x4D5E`, ""},
		{"", "", "", ""},
		// HVNC: explorer and a browser on the operator's desktop.
		{"explorer.exe", `C:\Windows\explorer.exe`, `WinSta0\hvnc_4f2a`, SevCritical},
		{"explorer.exe", `C:\Windows\explorer.exe`, `WinSta0\sbox_alternate_desktop_0x99`, SevCritical},
		{"chrome.exe", `"C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir=C:\Users\bob\AppData\Local\Temp\p`,
			`WinSta0\hvnc_4f2a`, SevSuspect},
		{"powershell.exe", "powershell", "hvnc", SevSuspect},
		{"PING.EXE", "ping -n 30 127.0.0.1", "lrng-test-desktop", SevNotable},
	} {
		f, ok := desktopFinding("process "+c.name, c.name, c.cmd, c.desktop)
		if c.want == "" {
			if ok {
				t.Errorf("%s on %q: %+v", c.name, c.desktop, f)
			}
			continue
		}
		if !ok || f.Rule != "defense.hidden_desktop" || f.Severity != c.want || !strings.Contains(f.Detail, c.desktop) {
			t.Errorf("%s on %q: %+v, want %s", c.name, c.desktop, f, c.want)
		}
	}
	if w, d := splitDesktop(`WinSta0\Default`); w != "WinSta0" || d != "Default" {
		t.Errorf("split: %q %q", w, d)
	}
}

func TestTimestompFinding(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	at := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 9, 30, 0, 0, time.UTC) }
	ordinary := at(2024, 5, 8)
	for _, c := range []struct {
		name              string
		created, modified time.Time
		want              Severity
	}{
		{"ordinary", ordinary, ordinary, ""},
		{"no creation time (Unix)", time.Time{}, ordinary, ""},
		{"zero times", time.Time{}, time.Time{}, ""},
		{"DOS epoch from a zip", at(1980, 1, 1), at(1980, 1, 1), ""},
		{"npm's packing date", time.Time{}, time.Date(1985, 10, 26, 8, 15, 0, 0, time.UTC), ""},
		{"Unix time zero from a reproducible build", time.Time{}, time.Unix(1, 0), ""},
		{"NIK C2's 1979", at(1979, 6, 12), at(1979, 6, 12), SevSuspect},
		{"stomped creation only", at(1601, 1, 2), ordinary, SevSuspect},
		{"1975", time.Time{}, at(1975, 3, 1), SevSuspect},
		{"future", ordinary, now.Add(10 * 24 * time.Hour), SevNotable},
		{"a day ahead (clock skew)", ordinary, now.Add(24 * time.Hour), ""},
	} {
		f, ok := timestompFinding("the image of process x", `C:\x.exe`, c.created, c.modified, now)
		if c.want == "" {
			if ok {
				t.Errorf("%s: %+v", c.name, f)
			}
			continue
		}
		if !ok || f.Rule != "defense.timestomp" || f.Severity != c.want {
			t.Errorf("%s: %+v, want %s", c.name, f, c.want)
		}
	}
}
