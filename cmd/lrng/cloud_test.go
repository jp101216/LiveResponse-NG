package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func TestCloudOnlyWritesOfflineReportWithGraph(t *testing.T) {
	for _, format := range []string{output.FormatJSON, output.FormatJSONL, output.FormatHTML} {
		cfg := config.Default()
		cfg.CloudOnly = true
		cfg.CloudAudit = filepath.Join("..", "..", "demo", "cloud-audit.jsonl")
		cfg.LLMBurst = 3
		cfg.Quiet = true
		cfg.Format = format
		cfg.Output = filepath.Join(t.TempDir(), "cloud."+format)
		r, err := doEvtxOffline(context.Background(), cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		if r.Host != "(offline)" || r.HostInfo != nil || r.Run.DNSLookups || !r.Run.Graph || len(r.Results) != 2 || r.Results[0].Collector != "cloudaudit" || r.Summary.ByRule["llm.possible_resource_hijack"] != 1 {
			t.Fatalf("bad offline cloud report: %+v", r)
		}
		if len(r.Run.CloudAuditFiles) != 1 {
			t.Fatal("cloud source not recorded in run settings")
		}
		if _, err := os.Stat(cfg.Output + ".sha256"); err != nil {
			t.Fatal(err)
		}
	}
}
