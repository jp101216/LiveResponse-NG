package main

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/collector"
	"github.com/jp101216/liveresponse-ng/internal/config"
	"github.com/jp101216/liveresponse-ng/internal/output"
)

func TestValidate(t *testing.T) {
	ok := config.Default()
	if err := validate(ok, nil, 0); err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		mut  func(*config.Config)
		args []string
		pid  int
		want string
	}{
		{func(c *config.Config) {}, []string{"stray"}, 0, "unexpected argument"},
		{func(c *config.Config) { c.Workers = 0 }, nil, 0, "-workers"},
		{func(c *config.Config) { c.MemWorkers = 0 }, nil, 0, "-mem-workers"},
		{func(c *config.Config) { c.Timeout = -time.Second }, nil, 0, "negative"},
		{func(c *config.Config) { c.Format = "xml" }, nil, 0, "-format"},
		{func(c *config.Config) {}, nil, -4, "-mem-scan"},
		{func(c *config.Config) { c.FailOn = "high" }, nil, 0, "-fail-on"},
	}
	for _, b := range bad {
		c := config.Default()
		b.mut(&c)
		if err := validate(c, b.args, b.pid); err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("want error containing %q, got %v", b.want, err)
		}
	}
}

func TestParsePIDs(t *testing.T) {
	got, err := parsePIDs(" 4242, 5120,4242 ")
	if err != nil || len(got) != 2 || got[0] != 4242 || got[1] != 5120 {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"0", "-1", "abc", "12x"} {
		if _, err := parsePIDs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSelectCollectorsAddsMemoryForYara(t *testing.T) {
	cfg := config.Default()
	cfg.Collectors = []string{"memory"}
	cfg.YaraRules = "rules"
	sel, err := selectCollectors(cfg)
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("memory collector is Windows/Linux only")
	}
	if err != nil || len(sel) != 1 || sel[0].Name() != "memory" {
		t.Fatalf("memory named and implied must appear once: %v %v", sel, err)
	}
	cfg.Collectors = []string{"nope"}
	if _, err := selectCollectors(cfg); err == nil {
		t.Fatal("unknown collector accepted")
	}
}

func TestFailOn(t *testing.T) {
	s := output.Summary{BySeverity: map[collector.Severity]int{collector.SevSuspect: 2, collector.SevCritical: 0}}
	cases := map[string]bool{"": false, "notable": true, "suspect": true, "critical": false}
	for th, want := range cases {
		if got := failOnMet(s, th); got != want {
			t.Errorf("failOnMet(%q) = %v, want %v", th, got, want)
		}
	}
}
