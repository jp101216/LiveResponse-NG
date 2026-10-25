//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectAutoruns is a stub off Windows; the real implementation reads the
// Windows registry and startup folders. See autoruns_windows.go.
func collectAutoruns(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("autoruns").Finish(),
		errors.New("autoruns collector is implemented for windows only")
}
