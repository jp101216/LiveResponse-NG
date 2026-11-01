//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectImplants is a stub off Windows; see implants_windows.go.
func collectImplants(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("implants").Finish(), errors.New("implants collector is implemented for windows only")
}
