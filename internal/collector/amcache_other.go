//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectAmcache is a stub off Windows; the real implementation reads the
// Windows AmCache hive. See amcache_windows.go.
func collectAmcache(ctx context.Context) (Result, error) {
	return NewResult("amcache").Finish(),
		errors.New("amcache collector is implemented for windows only")
}
