package aidetect

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

var llmIP = netip.MustParseAddr("203.0.113.10")

// newTestDetector builds a detector with a fixed endpoint IP and the default
// allowlist, bypassing live DNS so the logic is tested deterministically.
func newTestDetector() *Detector {
	d := newDetector(nil)
	d.llmIPs[llmIP] = struct{}{}
	return d
}

func TestInspect(t *testing.T) {
	d := newTestDetector()

	cases := []struct {
		name     string
		conn     Conn
		wantRule string // "" = no finding
		wantSev  string
	}{
		{"script host to LLM endpoint",
			Conn{Remote: llmIP, Process: "powershell.exe", PID: 100}, "ai.llm_callout", SevCritical},
		{"case-insensitive process name",
			Conn{Remote: llmIP, Process: "PowerShell.EXE", PID: 100}, "ai.llm_callout", SevCritical},
		{"unknown app to LLM endpoint",
			Conn{Remote: llmIP, Process: "weird-service.exe", PID: 100}, "ai.llm_callout", SevSuspect},
		{"allowlisted browser",
			Conn{Remote: llmIP, Process: "chrome.exe", PID: 100}, "", ""},
		{"allowlisted name from a temp dir",
			Conn{Remote: llmIP, Process: "chrome.exe", PID: 100,
				ImagePath: `C:\Users\a\AppData\Local\Temp\chrome.exe`, UnusualPath: true},
			"ai.llm_callout_unusual_path", SevSuspect},
		{"TIME_WAIT / PID 0 is unattributed, not [System Process]",
			Conn{Remote: llmIP, Process: "[System Process]", PID: 0}, "ai.llm_callout_unattributed", SevNotable},
		{"IPv4-mapped IPv6 address still matches",
			Conn{Remote: netip.MustParseAddr("::ffff:203.0.113.10"), Process: "cmd.exe", PID: 7},
			"ai.llm_callout", SevCritical},
		{"non-LLM destination",
			Conn{Remote: netip.MustParseAddr("8.8.8.8"), Process: "powershell.exe", PID: 100}, "", ""},
		{"azure suffix match",
			Conn{Remote: netip.MustParseAddr("198.51.100.5"), RemoteHost: "myres.openai.azure.com",
				Process: "svchost.exe", PID: 9}, "ai.llm_callout", SevSuspect},
		{"bedrock regional endpoint, trailing dot",
			Conn{Remote: netip.MustParseAddr("198.51.100.6"), RemoteHost: "bedrock-runtime.us-east-1.amazonaws.com.",
				Process: "python.exe", PID: 9}, "ai.llm_callout", SevCritical},
		{"unrelated AWS service is not an LLM",
			Conn{Remote: netip.MustParseAddr("198.51.100.7"), RemoteHost: "s3.us-east-1.amazonaws.com",
				Process: "python.exe", PID: 9}, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Inspect(tc.conn)
			if tc.wantRule == "" {
				if got != nil {
					t.Fatalf("unexpected finding: %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("no finding, want %s", tc.wantRule)
			}
			if got.Rule != tc.wantRule || got.Severity != tc.wantSev {
				t.Fatalf("got %s/%s, want %s/%s (%s)", got.Rule, got.Severity, tc.wantRule, tc.wantSev, got.Detail)
			}
		})
	}
}

func TestExtraAllowAcceptsPaths(t *testing.T) {
	d := newDetector([]string{`C:\Tools\MyAIApp.EXE`, " tools.exe "})
	d.llmIPs[llmIP] = struct{}{}
	for _, p := range []string{"myaiapp.exe", "TOOLS.exe"} {
		if c := d.Inspect(Conn{Remote: llmIP, Process: p, PID: 5}); c != nil {
			t.Errorf("%s should be allowlisted, got %+v", p, c)
		}
	}
}

// fakeResolver answers from a table, can hang on chosen hosts, and counts
// concurrent lookups.
type fakeResolver struct {
	answers  map[string][]netip.Addr
	hang     map[string]bool
	inFlight atomic.Int32
	maxSeen  atomic.Int32
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	if f.hang[host] {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	time.Sleep(20 * time.Millisecond) // let lookups overlap
	if ips, ok := f.answers[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

func TestBuildDetectorResolvesConcurrentlyWithTimeout(t *testing.T) {
	r := &fakeResolver{
		answers: map[string][]netip.Addr{
			// IPv4-mapped form must be normalised on the way in.
			"api.openai.com":    {netip.MustParseAddr("::ffff:192.0.2.1")},
			"api.anthropic.com": {netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")},
		},
		hang: map[string]bool{"api.groq.com": true},
	}
	start := time.Now()
	d := BuildDetector(context.Background(), Options{Resolve: true, Resolver: r, LookupTimeout: 200 * time.Millisecond})
	took := time.Since(start)

	// ~30 lookups at 20ms each would take ~600ms serially plus the 200ms hang.
	if took > time.Second {
		t.Fatalf("resolution took %s; lookups are not concurrent or the timeout is ignored", took)
	}
	if r.maxSeen.Load() < 2 {
		t.Fatalf("lookups never overlapped (max in flight %d)", r.maxSeen.Load())
	}
	if hn, ips := d.resolved, len(d.llmIPs); hn != 2 || ips != 3 {
		t.Fatalf("resolved %d hosts / %d IPs, want 2 / 3", hn, ips)
	}
	if !d.Matches(netip.MustParseAddr("192.0.2.1"), "") {
		t.Fatal("IPv4-mapped answer was not normalised")
	}
	m := d.Meta()
	if m["dns_lookups_performed"] != true || len(m["provider_hosts_failed"].([]string)) != len(llmHostnames)-2 {
		t.Fatalf("meta does not report lookups/failures: %+v", m)
	}
}

func TestBuildDetectorIgnoresSinkholedAnswers(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{
		"api.openai.com":    {netip.MustParseAddr("0.0.0.0")},
		"api.anthropic.com": {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.1.2.3")},
		"api.mistral.ai":    {netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("::1")},
	}}
	d := BuildDetector(context.Background(), Options{Resolve: true, Resolver: r})
	if d.Matches(netip.MustParseAddr("127.0.0.1"), "") || d.Matches(netip.MustParseAddr("10.1.2.3"), "") {
		t.Fatal("sinkhole/private answer would flag local traffic")
	}
	if !d.Matches(netip.MustParseAddr("192.0.2.9"), "") || d.resolved != 1 {
		t.Fatalf("public answer lost (resolved=%d)", d.resolved)
	}
	if got := d.Meta()["non_public_answers_ignored"].([]string); len(got) != 4 {
		t.Fatalf("ignored answers not recorded: %v", got)
	}
}

func TestBuildDetectorNoResolve(t *testing.T) {
	r := &fakeResolver{}
	d := BuildDetector(context.Background(), Options{Resolve: false, Resolver: r})
	if r.maxSeen.Load() != 0 {
		t.Fatal("resolver was called with Resolve=false")
	}
	if d.Meta()["dns_lookups_performed"] != false {
		t.Fatal("meta should say no lookups were performed")
	}
}

func TestMatchHostname(t *testing.T) {
	yes := []string{
		"api.openai.com", "API.OpenAI.com.", "router.huggingface.co", "api-inference.huggingface.co",
		"myres.openai.azure.com", "bedrock-runtime.eu-west-1.amazonaws.com",
		"bedrock-runtime-fips.us-gov-west-1.amazonaws.com", "us-central1-aiplatform.googleapis.com",
		"aiplatform.googleapis.com", "x.services.ai.azure.com",
	}
	no := []string{
		"", "openai.com", "evil-api.openai.com.attacker.net", "bedrock-runtime.amazonaws.com",
		"s3.amazonaws.com", "huggingface.co", "openai.azure.com", "aiplatform.googleapis.com.evil.net",
	}
	for _, h := range yes {
		if _, ok := MatchHostname(h); !ok {
			t.Errorf("MatchHostname(%q) = false", h)
		}
	}
	for _, h := range no {
		if how, ok := MatchHostname(h); ok {
			t.Errorf("MatchHostname(%q) = true (%s)", h, how)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	pub := []string{"203.0.113.10", "8.8.8.8", "2606:4700::1111", "::ffff:8.8.8.8", "100.64.1.1", "198.18.0.5"}
	priv := []string{"10.1.2.3", "192.168.0.1", "172.16.0.1", "127.0.0.1", "0.0.0.0", "0.1.2.3",
		"169.254.1.1", "224.0.0.1", "255.255.255.255", "250.1.2.3", "::1", "fe80::1", "fd00::1", "100::1"}
	for _, s := range pub {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range priv {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
}
