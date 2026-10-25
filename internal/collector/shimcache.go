package collector

import "context"

// shimcacheCollector reads the Application Compatibility Cache (ShimCache)
// from the registry. Each entry is evidence that a binary existed on the host
// (the kernel records it on various file operations), with the binary's file
// last-modified time. It's valued in DFIR for surfacing programs that have
// since been deleted.
type shimcacheCollector struct{}

func (shimcacheCollector) Name() string        { return "shimcache" }
func (shimcacheCollector) Platforms() []string { return []string{"windows"} }

func (shimcacheCollector) Collect(ctx context.Context) (Result, error) {
	return collectShimcache(ctx)
}

func init() { Register(shimcacheCollector{}) }
