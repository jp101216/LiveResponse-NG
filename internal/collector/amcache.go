package collector

import "context"

// amcacheCollector reads the AmCache hive (Amcache.hve). AmCache is a record of
// programs that were present on the host — with a SHA-1, PE link date and
// publisher per file — maintained by the Microsoft Compatibility Appraiser. It
// outlives the binaries it describes, so it surfaces tools that ran and were
// then deleted. The hive is read live and best-effort: if it's locked, the
// collector reports that rather than failing the run. A program recorded in an
// unusual path is raised as execution.amcache_unusual_path.
type amcacheCollector struct{}

func (amcacheCollector) Name() string        { return "amcache" }
func (amcacheCollector) Platforms() []string { return []string{"windows"} }

func (amcacheCollector) Collect(ctx context.Context) (Result, error) {
	return collectAmcache(ctx)
}

func init() { Register(amcacheCollector{}) }
