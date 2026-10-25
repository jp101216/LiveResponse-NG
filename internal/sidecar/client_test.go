package sidecar

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeSidecar writes a shell script that behaves like a sidecar.
func fakeSidecar(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake sidecar needs a Unix shell")
	}
	p := filepath.Join(t.TempDir(), "lrng-sidecar")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nread req\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStreamDeliversEveryLine(t *testing.T) {
	p := fakeSidecar(t, `
echo '{"op":"scan_memory","ok":true,"meta":{"pid":10,"status":"scanned"}}'
echo '{"op":"scan_memory","ok":false,"error":"pid 11: no such process","meta":{"pid":11,"status":"not_found"}}'
echo '{"op":"scan_memory","ok":true,"hits":[{"rule":"yara:x","severity":"critical","offset":4096,"confidence":90,"region":{"base":4096,"size":8192,"protect":"RWX","kind":"private"}}],"meta":{"pid":12,"status":"scanned"}}'
`)
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []*Response
	if err := c.Stream(context.Background(), Request{Op: OpScanMemory, PIDs: []int{10, 11, 12}},
		func(r *Response) { got = append(got, r) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].MetaString("status") != "not_found" || got[2].MetaInt("pid") != 12 {
		t.Fatalf("got %+v", got)
	}
	if h := got[2].Hits[0]; h.Region == nil || h.Region.Protect != "RWX" {
		t.Fatalf("region not decoded: %+v", h)
	}
}

func TestStreamKeepsResultsWhenKilled(t *testing.T) {
	p := fakeSidecar(t, `
echo '{"op":"scan_memory","ok":true,"meta":{"pid":1,"status":"scanned"}}'
sleep 5
echo '{"op":"scan_memory","ok":true,"meta":{"pid":2,"status":"scanned"}}'
`)
	c, _ := New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var got []*Response
	start := time.Now()
	err := c.Stream(ctx, Request{Op: OpScanMemory, PIDs: []int{1, 2}}, func(r *Response) { got = append(got, r) })
	if err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("want deadline error, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("result received before the timeout was lost: %d", len(got))
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("Stream waited for the killed sidecar")
	}
}

func TestStreamRejectsGarbage(t *testing.T) {
	p := fakeSidecar(t, "echo 'not json'\n")
	c, _ := New(p)
	err := c.Stream(context.Background(), Request{Op: OpPing}, func(*Response) {})
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("want decode error, got %v", err)
	}
}

func TestLocateNeverUsesPATH(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	_ = os.Chdir(dir)
	// A bare name resolves against the working directory, not PATH.
	if _, err := Locate("sh"); err == nil {
		t.Fatal("bare name was resolved via PATH")
	}
}
