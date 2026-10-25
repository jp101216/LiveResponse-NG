package aidetect

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestModuleBEndpointPatternCoversModuleA keeps the two AI modules in step:
// every provider hostname module A resolves, and an example host for every
// regional/per-tenant pattern it matches, must also be matched by module B's
// api.endpoint pattern in the Rust sidecar (sidecar-rs/src/prompts.rs). The two
// lists are maintained by hand on either side of the language boundary; this is
// what catches one drifting from the other.
func TestModuleBEndpointPatternCoversModuleA(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "sidecar-rs", "src", "prompts.rs"))
	if err != nil {
		t.Skipf("sidecar source not available: %v", err)
	}
	s := string(src)
	i := strings.Index(s, `rule: "api.endpoint"`)
	if i < 0 {
		t.Fatal(`prompts.rs has no rule "api.endpoint"`)
	}
	const open = `pattern: r"`
	j := strings.Index(s[i:], open)
	if j < 0 {
		t.Fatal("api.endpoint has no raw-string pattern")
	}
	start := i + j + len(open)
	end := strings.Index(s[start:], `",`)
	if end < 0 {
		t.Fatal("unterminated api.endpoint pattern")
	}
	// Rust's (?i-u) is case-insensitive, ASCII mode; Go's RE2 has no -u, and
	// for these ASCII hostnames (?i) means the same thing.
	pat := strings.Replace(s[start:start+end], "(?i-u)", "(?i)", 1)
	re, err := regexp.Compile(pat)
	if err != nil {
		t.Fatalf("api.endpoint pattern doesn't compile as RE2: %v", err)
	}

	for _, h := range llmHostnames {
		if !re.MatchString(h) {
			t.Errorf("module B's api.endpoint misses module A host %q", h)
		}
	}
	for _, p := range hostPatterns {
		host := "tenant" + p.Suffix
		if p.Prefix != "" {
			host = p.Prefix + "us-east-1" + p.Suffix
		}
		if _, ok := MatchHostname(host); !ok {
			t.Fatalf("test host %q doesn't match module A's own pattern %+v", host, p)
		}
		if !re.MatchString(host) {
			t.Errorf("module B's api.endpoint misses module A pattern %s (example %q)", p.Label, host)
		}
	}
}
