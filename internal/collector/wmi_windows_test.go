//go:build windows

package collector

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// TestVariantLayout guards the VARIANT struct size, which must match the real
// Win32 layout on each arch (16 bytes on 386, 24 on amd64/arm64) or every
// property read is misaligned. The real VARIANT is an 8-byte header plus a
// union two machine words wide, so this holds on all three Windows arches and
// is the cheap check for a bug that can't be reproduced off Windows.
func TestVariantLayout(t *testing.T) {
	want := uintptr(8) + 2*unsafe.Sizeof(uintptr(0))
	if got := unsafe.Sizeof(variant{}); got != want {
		t.Fatalf("sizeof(variant) = %d, want %d", got, want)
	}
}

// TestWMIQueryWin32OSOnWindows exercises the whole hand-rolled COM path —
// CoInitialize, ConnectServer, ExecQuery, enumerate, Get, VARIANT decode —
// without touching the subscription store, by reading a class that exists on
// every host (exactly one instance, a mix of string and integer properties).
func TestWMIQueryWin32OSOnWindows(t *testing.T) {
	if underWine() {
		t.Skip("no WMI under Wine")
	}
	rows, err := wmiQuery(`ROOT\CIMV2`,
		"SELECT Caption, OSType, Version FROM Win32_OperatingSystem",
		[]string{"Caption", "OSType", "Version"})
	if err != nil {
		t.Fatalf("wmiQuery Win32_OperatingSystem: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Win32_OperatingSystem returned %d rows, want 1", len(rows))
	}
	if !strings.Contains(strings.ToLower(rows[0]["Caption"]), "windows") {
		t.Errorf("Caption = %q, want it to mention Windows", rows[0]["Caption"])
	}
	if _, err := strconv.Atoi(rows[0]["OSType"]); err != nil {
		t.Errorf("OSType = %q, want an integer (VARIANT VT_I4 decode)", rows[0]["OSType"])
	}
}

// TestWMISubscriptionCollectorOnWindows runs the real collector. A clean
// runner has no permanent subscriptions, so the point is that enumerating the
// subscription namespace succeeds without panicking and the result is
// well-formed; any records it does find are logged for review.
func TestWMISubscriptionCollectorOnWindows(t *testing.T) {
	if underWine() {
		t.Skip("no WMI under Wine")
	}
	res, err := collectWMI(context.Background(), RunOptions{})
	if err != nil {
		t.Fatalf("collectWMI: %v", err)
	}
	for _, e := range res.Errors {
		t.Logf("wmi: error: %s", e)
	}
	t.Logf("wmi: %d records, meta %v", len(res.Records), res.Meta)
	for i, rec := range res.Records {
		for _, f := range rec.Findings {
			if f.Rule == "" || SeverityRank(f.Severity) == 0 || f.Detail == "" {
				t.Errorf("record %d: malformed finding %+v", i, f)
			}
			t.Logf("wmi finding [%s] %s — %s", f.Severity, f.Rule, f.Detail)
		}
	}
}
