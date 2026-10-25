//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectServices is a stub off Windows; the real implementation reads the
// Windows registry. See services_windows.go.
func collectServices(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("services").Finish(),
		errors.New("services collector is implemented for windows only")
}
