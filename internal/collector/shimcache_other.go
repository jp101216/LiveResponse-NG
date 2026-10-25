//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectShimcache is a stub off Windows; the real implementation reads the
// Windows registry. See shimcache_windows.go.
func collectShimcache(ctx context.Context) (Result, error) {
	return NewResult("shimcache").Finish(),
		errors.New("shimcache collector is implemented for windows only")
}
