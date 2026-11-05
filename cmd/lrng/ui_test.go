package main

import "testing"

func TestUIOptionsCannotSilentlyFallThroughToCollection(t *testing.T) {
	for _, names := range [][]string{{"ui-no-open"}, {"ui-reports"}} {
		if validateUIOptions(false, names) == nil {
			t.Fatalf("ignored UI modifier without UI: %v", names)
		}
	}
	for _, name := range []string{"out", "collectors", "case-report", "mem-scan", "version", "force"} {
		if validateUIOptions(true, []string{"ui", name}) == nil {
			t.Fatalf("ignored CLI flag in UI mode: %s", name)
		}
	}
	if err := validateUIOptions(true, []string{"ui", "ui-no-open", "ui-reports"}); err != nil {
		t.Fatal(err)
	}
	if err := validateUIOptions(false, []string{"collectors", "out"}); err != nil {
		t.Fatal(err)
	}
}
