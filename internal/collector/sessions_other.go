//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectSessions is a stub off Windows; the real implementation uses the
// Windows Terminal Services API. See sessions_windows.go.
func collectSessions(ctx context.Context) (Result, error) {
	return NewResult("sessions").Finish(),
		errors.New("sessions collector is implemented for windows only")
}
