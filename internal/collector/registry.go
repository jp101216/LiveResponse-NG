package collector

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// registry holds every collector compiled into the binary. Platform-specific
// files register their collectors from init(), so the set available at runtime
// is exactly the set that compiled for this GOOS.
var (
	mu       sync.RWMutex
	registry = map[string]Collector{}
)

// Register adds a collector to the global set. Called from init() in each
// collector's source file. Panics on a duplicate name — that's a build-time
// programming error, not a runtime condition.
func Register(c Collector) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.Name()]; dup {
		panic("collector: duplicate registration for " + c.Name())
	}
	registry[c.Name()] = c
}

// Available returns the collectors that support the current GOOS, sorted by
// name for stable output.
func Available() []Collector {
	mu.RLock()
	defer mu.RUnlock()
	var out []Collector
	for _, c := range registry {
		if supports(c, runtime.GOOS) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// OptIn is implemented by collectors that are expensive or intrusive enough
// that they only run when asked for by name (or enabled by a flag), never as
// part of the default "run everything" set.
type OptIn interface {
	OptIn() bool
}

// IsOptIn reports whether c only runs when requested.
func IsOptIn(c Collector) bool {
	o, ok := c.(OptIn)
	return ok && o.OptIn()
}

// Defaults returns the collectors that run when none are named: everything
// available here except opt-in collectors.
func Defaults() []Collector {
	var out []Collector
	for _, c := range Available() {
		if !IsOptIn(c) {
			out = append(out, c)
		}
	}
	return out
}

// Lookup returns a single collector by name if it exists and runs here.
func Lookup(name string) (Collector, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := registry[name]
	if !ok || !supports(c, runtime.GOOS) {
		return nil, false
	}
	return c, true
}

func supports(c Collector, goos string) bool {
	for _, p := range c.Platforms() {
		if p == goos || p == "all" {
			return true
		}
	}
	return false
}

// Select resolves collector names from the command line, in order. The name
// "default" expands to the default set (so "-collectors default,dnscache"
// adds an opt-in collector to a normal sweep), an empty list means "default",
// names are case-insensitive, and repeats are dropped.
func Select(names []string) ([]Collector, error) {
	if len(names) == 0 {
		names = []string{"default"}
	}
	var out []Collector
	seen := map[string]bool{}
	add := func(c Collector) {
		if !seen[c.Name()] {
			seen[c.Name()] = true
			out = append(out, c)
		}
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		switch n {
		case "":
		case "default", "defaults":
			for _, c := range Defaults() {
				add(c)
			}
		default:
			c, ok := Lookup(n)
			if !ok {
				return nil, fmt.Errorf("collector %q not available on %s (see -list)", n, runtime.GOOS)
			}
			add(c)
		}
	}
	return out, nil
}
