//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectLateral is a stub off Windows; see lateral_windows.go.
func collectLateral(ctx context.Context) (Result, error) {
	return NewResult("lateral").Finish(),
		errors.New("lateral collector is implemented for windows only")
}
