//go:build !linux

package collector

import (
	"context"
	"time"
)

// rootkitCollector is registered on every OS (so the registry lists it) but
// supports Linux only; see rootkit_linux.go.
type rootkitCollector struct{}

func (rootkitCollector) Name() string           { return "rootkit" }
func (rootkitCollector) Platforms() []string    { return []string{"linux"} }
func (rootkitCollector) Timeout() time.Duration { return time.Minute }

func (rootkitCollector) Collect(ctx context.Context) (Result, error) {
	return NewResult("rootkit").Finish(), nil
}

func init() { Register(func() Collector { return rootkitCollector{} }) }
