//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectDefenses is a stub off Windows; see defenses_windows.go.
func collectDefenses(ctx context.Context) (Result, error) {
	return NewResult("defenses").Finish(),
		errors.New("defenses collector is implemented for windows only")
}
