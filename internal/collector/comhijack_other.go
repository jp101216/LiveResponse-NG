//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectCOMHijack is a stub off Windows; the real implementation walks the
// Windows registry's CLSID class stores. See comhijack_windows.go.
func collectCOMHijack(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("comhijack").Finish(),
		errors.New("comhijack collector is implemented for windows only")
}
