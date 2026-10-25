package collector

import "context"

// modulesCollector lists the modules (the image and loaded DLLs) of every
// process it can open, one record per process. A DLL loaded from a
// user-writable or temporary path is flagged: that's the shape of DLL
// side-loading and search-order hijacking.
type modulesCollector struct{ opts RunOptions }

func (*modulesCollector) Name() string        { return "modules" }
func (*modulesCollector) Platforms() []string { return []string{"windows", "linux"} }

func (c *modulesCollector) Configure(o RunOptions) { c.opts = o }

func (c *modulesCollector) Collect(ctx context.Context) (Result, error) {
	return collectModules(ctx, c.opts)
}

func init() { Register(&modulesCollector{}) }
