//go:build windows

package collector

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestUACBypassKeyOnWindows plants fodhelper's key in this user's hive,
// pointing at a program that doesn't exist (inert: nothing starts fodhelper,
// and there would be nothing to run), requires the autoruns collector to
// report it, and removes it.
func TestUACBypassKeyOnWindows(t *testing.T) {
	const key = `HKCU\Software\Classes\ms-settings`
	if err := exec.Command("reg.exe", "query", key).Run(); err == nil {
		t.Skip("this user already has an ms-settings key of its own; leaving it alone")
	}
	absent := `C:\lrng-test-absent\never-there.exe`
	if out, err := exec.Command("reg.exe", "add", key+`\Shell\Open\command`, "/ve", "/d", absent, "/f").CombinedOutput(); err != nil {
		t.Fatalf("reg add: %v %s", err, out)
	}
	defer func() {
		if out, err := exec.Command("reg.exe", "delete", key, "/f").CombinedOutput(); err != nil {
			t.Errorf("reg delete: %v %s", err, out)
		}
	}()

	res, err := collectAutoruns(context.Background(), RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res.Records {
		if r.Fields["kind"] != "uac_bypass_key" {
			continue
		}
		t.Logf("%v: %v", r.Fields["location"], r.Findings)
		loc, _ := r.Fields["location"].(string)
		if strings.Contains(strings.ToLower(loc), `ms-settings\shell\open\command`) && r.Fields["command"] == absent {
			found = true
			if f := hasFinding(r.Findings, "privesc.uac_bypass_key"); f == nil || f.Severity != SevCritical || !strings.Contains(f.Detail, "fodhelper") {
				t.Errorf("finding: %+v", r.Findings)
			}
		}
	}
	if !found {
		t.Errorf("the planted key wasn't reported (hives checked: %v)", res.Meta["user_hives_checked"])
	}
}
