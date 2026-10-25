//go:build !windows && !linux

package collector

import (
	"context"
	"errors"
)

// collectLocalAccounts is a stub off Windows; the real implementation uses the
// Windows network-management API. See localaccounts_windows.go.
func collectLocalAccounts(ctx context.Context) (Result, error) {
	return NewResult("localaccounts").Finish(),
		errors.New("localaccounts collector is implemented for windows only")
}
