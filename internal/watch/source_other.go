//go:build !windows && !linux

package watch

import (
	"context"
	"time"
)

const sourceName = "none"

func runSource(ctx context.Context, o RecordOptions, started time.Time, sink func(Event)) (Window, error) {
	return Window{Source: sourceName}, ErrUnsupported
}
