//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectUDP is a stub off Windows; the real implementation uses the Windows
// IP Helper API. See udp_windows.go.
func collectUDP(ctx context.Context) (Result, error) {
	return NewResult("udp").Finish(),
		errors.New("udp collector is implemented for windows only")
}
