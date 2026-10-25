package collector

import "context"

// comHijackCollector enumerates COM class registrations (CLSID servers) across
// the machine and per-user class stores, flagging the patterns behind COM
// hijacking persistence (T1546.015): a per-user registration that overrides a
// machine one, a server DLL/EXE in a user-writable or temporary path, a
// scriptlet or script-host server, and TreatAs redirection. Only registrations
// that trip a heuristic are recorded; the totals scanned go in the result's
// metadata, so the report stays lean on a host with tens of thousands of
// legitimate CLSIDs.
type comHijackCollector struct{ opts RunOptions }

func (*comHijackCollector) Name() string        { return "comhijack" }
func (*comHijackCollector) Platforms() []string { return []string{"windows"} }

func (c *comHijackCollector) Configure(o RunOptions) { c.opts = o }

func (c *comHijackCollector) Collect(ctx context.Context) (Result, error) {
	return collectCOMHijack(ctx, c.opts)
}

func init() { Register(&comHijackCollector{}) }
