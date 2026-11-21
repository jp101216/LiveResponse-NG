//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectImplants is a stub off Windows and Linux; see implants_windows.go and implants_linux.go.
func collectImplants(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("implants").Finish(), errors.New("implants collector is implemented for windows and linux only")
}
