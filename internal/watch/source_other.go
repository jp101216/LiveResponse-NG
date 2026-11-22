//go:build !windows

package watch

import (
	"context"
	"syscall"
	"time"
)

const sourceName = "none"

func runSource(ctx context.Context, o RecordOptions, started time.Time, sink func(Event)) (Window, error) {
	return Window{Source: sourceName}, ErrUnsupported
}

func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
