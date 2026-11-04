//go:build windows

package collector

import (
	"context"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestWFPNativePrefixLayouts(t *testing.T) {
	var f wfpFilterPrefix
	var c wfpCondition
	conditions, action, value, size := uintptr(120), uintptr(128), uintptr(24), uintptr(40)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		conditions, action, value, size = 84, 88, 20, 28
	}
	if unsafe.Offsetof(f.Conditions) != conditions || unsafe.Offsetof(f.Action) != action || unsafe.Offsetof(c.Value) != value || unsafe.Sizeof(c) != size {
		t.Fatal("WFP struct prefix does not match Windows SDK ABI")
	}
}

func TestWFPAppBlobValidation(t *testing.T) {
	b := []byte{'C', 0, ':', 0, '\\', 0, 'a', 0, 0, 0}
	good := wfpBlob{uint32(len(b)), &b[0]}
	if s, ok := wfpAppPath(&good); !ok || s != `C:\a` {
		t.Fatalf("%q %v", s, ok)
	}
	plain := wfpBlob{8, &b[0]}
	if s, ok := wfpAppPath(&plain); !ok || s != `C:\a` {
		t.Fatal("length-delimited blob rejected")
	}
	for _, v := range []wfpBlob{{}, {65538, &b[0]}, {9, &b[0]}, {0, &b[0]}} {
		if _, ok := wfpAppPath(&v); ok {
			t.Fatal("invalid blob accepted")
		}
	}
}

func TestWFPReadOnlyNativeEnumeration(t *testing.T) {
	if testing.Short() || underWine() {
		t.Skip("requires Windows BFE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := (&wfpCollector{}).Collect(ctx)
	if err != nil {
		t.Logf("WFP unavailable under current rights: %v", err)
		return
	}
	if n, ok := r.Meta["filters_scanned"].(int); !ok || n == 0 {
		t.Fatal("native enumeration read no Windows filters")
	}
	for _, e := range r.Errors {
		if strings.Contains(e, "invalid") {
			t.Fatal(e)
		}
	}
	for _, rec := range r.Records {
		if rec.Fields["action"] != "block" || rec.Fields["app_path"] == "" || rec.Fields["filter_key"] == "" {
			t.Fatalf("invalid filter record: %+v", rec)
		}
	}
}
