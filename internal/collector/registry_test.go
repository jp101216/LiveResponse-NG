package collector

import "testing"

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
		"prefetch", "sessions", "localaccounts", "modules", "udp", "comhijack", "wmi", "eventlog"} {
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
