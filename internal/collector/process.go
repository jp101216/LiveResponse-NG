package collector

import "context"

// processCollector enumerates running processes: name, PID/PPID, parent name,
// image path and hash, command line, start time, owner, session and integrity
// level — and judges them: masquerading system binaries, impossible parents,
// shells spawned by document readers or servers, and malicious command lines.
// The portable shell lives here; the OS-specific enumeration is
// collectProcesses, implemented per platform behind build tags.
type processCollector struct{ opts RunOptions }

func (*processCollector) Name() string        { return "processes" }
func (*processCollector) Platforms() []string { return []string{"windows", "linux"} }

func (c *processCollector) Configure(o RunOptions) { c.opts = o }

func (c *processCollector) Collect(ctx context.Context) (Result, error) {
	return collectProcesses(ctx, c.opts)
}

func init() { Register(&processCollector{}) }
