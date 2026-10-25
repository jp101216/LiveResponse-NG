package collector

import "context"

// netconnCollector enumerates IPv4 and IPv6 TCP connections with their owning
// process and runs each through the LLM-callout detector (AI module A). It's
// a pointer collector because it carries per-run options set via Configure.
type netconnCollector struct {
	opts RunOptions
}

func (*netconnCollector) Name() string        { return "network" }
func (*netconnCollector) Platforms() []string { return []string{"windows", "linux"} }

func (c *netconnCollector) Configure(o RunOptions) { c.opts = o }

func (c *netconnCollector) Collect(ctx context.Context) (Result, error) {
	return collectConnections(ctx, c.opts)
}

func init() { Register(&netconnCollector{opts: RunOptions{ResolveLLMHosts: true}}) }
