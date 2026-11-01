//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectDrivers is a stub off Windows; see drivers_windows.go. (Linux
// kernel modules are the kmod collector's.)
func collectDrivers(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("drivers").Finish(),
		errors.New("drivers collector is implemented for windows only")
}
