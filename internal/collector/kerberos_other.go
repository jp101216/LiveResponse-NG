//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectKerberos is a stub off Windows; see kerberos_windows.go.
func collectKerberos(ctx context.Context) (Result, error) {
	return NewResult("kerberos").Finish(), errors.New("kerberos collector is implemented for windows only")
}
