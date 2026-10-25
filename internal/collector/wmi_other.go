//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectWMI is a stub off Windows; the real implementation queries the live
// CIM repository over COM. See wmi_windows.go.
func collectWMI(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("wmi").Finish(),
		errors.New("wmi collector is implemented for windows only")
}
