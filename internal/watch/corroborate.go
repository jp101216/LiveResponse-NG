package watch

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

// transportRules are snapshot findings on the same process that corroborate a
// beacon: the traffic itself is already suspect.
var transportRules = map[string]bool{
	"network.quic_outbound": true,
	"network.doh_outbound":  true,
	"network.direct_dns":    true,
	"network.dns_tunnel":    true,
}

type pidNote struct {
	image  string
	reason string
}

// corroborator indexes the same run's snapshot for signals that raise a
// watch finding's severity: an unsigned or unusual-path image, a memory
// finding on the same process, a suspect transport, or a destination the
// intel dataset classifies as hosting, Tor or an anonymizer.
type corroborator struct {
	sha       map[string]string // image -> SHA-256
	untrusted map[string]bool   // image unsigned or untrusted
	image     map[string][]string
	pid       map[uint32][]pidNote
	intel     func(netip.Addr) []string
}

func newCorroborator(results []collector.Result) *corroborator {
	c := &corroborator{sha: map[string]string{}, untrusted: map[string]bool{},
		image: map[string][]string{}, pid: map[uint32][]pidNote{}}
	for _, r := range results {
		for _, rec := range r.Records {
			img, _ := rec.Fields["image_path"].(string)
			pid, hasPID := toUint32(rec.Fields["pid"])
			if r.Collector == "processes" && img != "" {
				key := slashLower(img)
				if sha, _ := rec.Fields["image_sha256"].(string); sha != "" {
					c.sha[key] = sha
				}
				switch state, _ := rec.Fields["signature_state"].(string); state {
				case "unsigned", "untrusted":
					c.untrusted[key] = true
					c.addImage(key, "the image is "+state)
				}
				if sp, _ := rec.Fields["suspicious_path"].(bool); sp {
					c.addImage(key, "the image is in an unusual folder")
				}
			}
			if !hasPID {
				continue
			}
			for _, f := range rec.Findings {
				if collector.SeverityRank(f.Severity) < collector.SeverityRank(collector.SevNotable) {
					continue
				}
				switch {
				case r.Collector == "memory" || strings.HasPrefix(f.Rule, "memory."):
					c.pid[pid] = append(c.pid[pid], pidNote{img, "memory finding " + f.Rule})
				case transportRules[f.Rule]:
					c.pid[pid] = append(c.pid[pid], pidNote{img, "snapshot finding " + f.Rule})
				}
			}
		}
	}
	return c
}

func (c *corroborator) addImage(key, why string) {
	for _, w := range c.image[key] {
		if w == why {
			return
		}
	}
	c.image[key] = append(c.image[key], why)
}

// forPIDs are the per-process signals for an identity's PIDs, where the
// snapshot's image for that PID matches (a reused PID doesn't count).
func (c *corroborator) forPIDs(id *identity) []string {
	var out []string
	seen := map[string]bool{}
	for pid := range id.pids {
		for _, n := range c.pid[pid] {
			if n.image != "" && id.image != "" && slashLower(n.image) != slashLower(id.image) {
				continue
			}
			if !seen[n.reason] {
				seen[n.reason] = true
				out = append(out, n.reason)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (c *corroborator) forIdentity(id *identity) []string {
	out := c.forPIDs(id)
	if id.image != "" {
		out = append(out, c.image[slashLower(id.image)]...)
		if len(c.image[slashLower(id.image)]) == 0 && collector.SuspiciousPath(id.image) {
			out = append(out, "the image is in an unusual folder")
		}
	}
	return out
}

func (c *corroborator) forFlow(fa *flowAgg) []string {
	out := c.forIdentity(fa.id)
	if c.intel != nil {
		seen := map[string]bool{}
		for a := range fa.addrs {
			for _, cat := range c.intel(a) {
				switch cat {
				case "hosting", "tor", "anonymizer":
					if !seen[cat] {
						seen[cat] = true
						out = append(out, "the destination is "+cat+" infrastructure")
					}
				}
			}
		}
	}
	return out
}

// toUint32 reads a PID from a live record (an unsigned or signed integer) or
// a decoded one (float64 or json.Number).
func toUint32(v any) (uint32, bool) {
	switch n := v.(type) {
	case uint32:
		return n, true
	case int:
		return uint32(n), n >= 0
	case int32:
		return uint32(n), n >= 0
	case int64:
		return uint32(n), n >= 0 && n <= 1<<32-1
	case uint64:
		return uint32(n), n <= 1<<32-1
	case float64:
		return uint32(n), n >= 0 && n <= 1<<32-1 && n == float64(uint32(n))
	case json.Number:
		i, err := n.Int64()
		return uint32(i), err == nil && i >= 0 && i <= 1<<32-1
	}
	return 0, false
}
