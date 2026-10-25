//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectPrefetch is a stub off Windows; the real implementation reads the
// Windows prefetch directory. See prefetch_windows.go.
func collectPrefetch(ctx context.Context) (Result, error) {
	return NewResult("prefetch").Finish(),
		errors.New("prefetch collector is implemented for windows only")
}
