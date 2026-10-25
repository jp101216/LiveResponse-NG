//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectConnections is a stub off Windows; the real implementation uses the
// Windows IP Helper API. See netconn_windows.go.
func collectConnections(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("network").Finish(),
		errors.New("network collector is implemented for windows only")
}
