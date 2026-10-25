//go:build !windows

package collector

import (
	"context"
	"errors"
)

// collectEventLog is a stub off Windows; the real implementation reads the
// host's winevt\Logs directory. See eventlog_windows.go. (The parser and
// classifier in evtx.go / eventlog.go are portable and unit-tested here.)
func collectEventLog(ctx context.Context, sigma *SigmaRuleset) (Result, error) {
	return NewResult("eventlog").Finish(),
		errors.New("eventlog collector is implemented for windows only")
}
