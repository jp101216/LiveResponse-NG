//go:build linux

package collector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/sidecar"
)

// Exercise the real collector with a protocol stub. No target memory is read:
// the Go test process's parent supplies a stable, enumerated PID.
func TestMemoryCollectorReportsIncompleteProcessCoverage(t *testing.T) {
	pid := os.Getppid()
	for _, status := range []string{"scanned", "skipped", "partial", "access_denied", "not_found", "error", "not_reached"} {
		t.Run(status, func(t *testing.T) {
			resp := sidecar.Response{Op: sidecar.OpScanMemory, OK: status == "scanned" || status == "partial",
				Meta: map[string]any{"pid": pid, "status": status},
				Hits: []sidecar.Hit{{Rule: "test.retained", Severity: "suspect"}}}
			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatal(err)
			}
			body := "#!/bin/sh\nread -r request\nprintf '%s\\n' '" + string(data) + "'\n"
			if status == "not_reached" {
				body = "#!/bin/sh\nread -r request\n" // a sidecar may exit without answering
			}
			path := filepath.Join(t.TempDir(), "sidecar-stub")
			if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			c := &memoryCollector{}
			c.Configure(RunOptions{SidecarPath: path, Memory: MemoryOptions{PIDs: []int{pid}, Workers: 1}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := c.Collect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Records) != 1 || r.Records[0].Fields["status"] != status {
				t.Fatalf("stub did not reach the target process: %+v", r)
			}
			incomplete := status != "scanned" && status != "skipped"
			if incomplete && (len(r.Errors) == 0 || r.Meta["partial"] != true || !strings.Contains(strings.Join(r.Errors, " "), status)) {
				t.Fatalf("incomplete memory scan presented as complete (%s): errors=%v, meta=%v", status, r.Errors, r.Meta)
			}
			if !incomplete && len(r.Errors) != 0 {
				t.Fatalf("normal completion/exclusion marked incomplete: %v", r.Errors)
			}
			if status != "not_reached" && (len(r.Records[0].Findings) != 1 || r.Records[0].Findings[0].Rule != "test.retained") {
				t.Fatalf("available findings were lost for %s", status)
			}
		})
	}
}
