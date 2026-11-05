package collector

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestConfigurableCollectorsNeverShareRunInstances(t *testing.T) {
	for _, c := range Available() {
		if _, ok := c.(Configurable); !ok {
			continue
		}
		other, ok := Lookup(c.Name())
		if !ok || reflect.ValueOf(c).Pointer() == reflect.ValueOf(other).Pointer() {
			t.Fatalf("%s shares mutable options between runs", c.Name())
		}
	}
}

func TestAbandonedCollectorCannotShareNextRunOptions(t *testing.T) {
	first, ok := Lookup("processes")
	if !ok {
		t.Skip("process collection is unavailable on this OS")
	}
	first.(*processCollector).Configure(RunOptions{SelfPID: 42})
	release := make(chan struct{})
	observed := make(chan int, 1)
	late := fakeCollector{"late", func(context.Context) (Result, error) {
		<-release
		observed <- first.(*processCollector).opts.SelfPID
		return Result{}, nil
	}}
	results := (&Dispatcher{Timeout: time.Millisecond, Grace: time.Millisecond}).Run(context.Background(), []Collector{late})
	if len(results[0].Errors) == 0 {
		close(release)
		t.Fatal("fixture did not outlive its run")
	}
	second, _ := Lookup("processes")
	second.(*processCollector).Configure(RunOptions{SelfPID: 99})
	close(release)
	select {
	case got := <-observed:
		if got != 42 {
			t.Fatalf("late collector inherited next run's options: %d", got)
		}
	case <-time.After(time.Second):
		t.Fatal("late collector did not finish")
	}
}

// TestExpectedCollectorsRegistered guards against a collector silently
// dropping out of the build. The registry is populated from init() in each
// shell file (no build tag), so every collector is present here regardless of
// the test host's GOOS; Available() is what filters by platform at runtime.
func TestExpectedCollectorsRegistered(t *testing.T) {
	want := []string{
		"processes", "network", "memory",
		"services", "autoruns", "scheduledtasks",
		"shimcache", "prefetch",
		"sessions", "localaccounts",
		"modules", "udp", "dnscache",
		"comhijack", "wmi", "eventlog",
		"drivers", "lateral", "defenses", "aiagents", "kerberos", "rootkit", "implants",
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, n := range want {
		c, ok := registry[n]
		if !ok {
			t.Errorf("collector %q is not registered", n)
			continue
		}
		if len(c.Platforms()) == 0 {
			t.Errorf("collector %q lists no platforms", n)
		}
	}
}

// TestOptInCollectors documents which collectors stay out of the default
// sweep. dnscache uses an undocumented API and must be opt-in; the broad
// forensic collectors run by default.
func TestOptInCollectors(t *testing.T) {
	optIn := map[string]bool{"memory": true, "dnscache": true}
	for _, name := range []string{"services", "autoruns", "scheduledtasks", "shimcache",
		"prefetch", "sessions", "localaccounts", "modules", "udp", "comhijack", "wmi", "eventlog",
		"drivers", "lateral", "defenses", "aiagents", "kerberos", "rootkit", "implants"} {
		if c, ok := registry[name]; ok && IsOptIn(c) {
			t.Errorf("collector %q should run by default, but is opt-in", name)
		}
	}
	for name := range optIn {
		c, ok := registry[name]
		if !ok {
			t.Errorf("collector %q not registered", name)
			continue
		}
		if !IsOptIn(c) {
			t.Errorf("collector %q should be opt-in", name)
		}
	}
}
