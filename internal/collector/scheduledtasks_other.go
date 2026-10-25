//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectScheduledTasks is a stub off Windows; the real implementation walks
// the Windows task store. See scheduledtasks_windows.go.
func collectScheduledTasks(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("scheduledtasks").Finish(),
		errors.New("scheduledtasks collector is implemented for windows only")
}
