//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectProcesses is a stub on platforms without a real implementation
// (everything but Windows and Linux). The collector registers itself
// everywhere so `list` is consistent, but Platforms() excludes these OSes so it
// is filtered out of Available(); this stub exists only so the tree compiles.
func collectProcesses(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("processes").Finish(),
		errors.New("process collector is implemented for windows only")
}
