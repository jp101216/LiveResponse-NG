package collector

import "context"

// prefetchCollector inventories the Windows prefetch directory. Each .pf file
// corresponds to an executable that has run on the host; the file's
// last-modified time is (very close to) the most recent run, and the filename
// encodes the executable name and a hash of its path. On top of the listing it
// decompresses each .pf body (Xpress Huffman) and decodes the SCCA structure,
// yielding the run count, the recent run times, the referenced files and the
// volumes — strong evidence that the program actually executed, with a program
// run from an unusual path raised as execution.prefetch_unusual_path.
type prefetchCollector struct{}

func (prefetchCollector) Name() string        { return "prefetch" }
func (prefetchCollector) Platforms() []string { return []string{"windows"} }

func (prefetchCollector) Collect(ctx context.Context) (Result, error) {
	return collectPrefetch(ctx)
}

func init() { Register(prefetchCollector{}) }
