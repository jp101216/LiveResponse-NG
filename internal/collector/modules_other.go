//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectModules is a stub off Windows; the real implementation uses Toolhelp
// module snapshots. See modules_windows.go.
func collectModules(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("modules").Finish(),
		errors.New("modules collector is implemented for windows only")
}
