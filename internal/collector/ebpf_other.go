//go:build !linux

package collector

import (
	"context"
	"errors"
)

// collectEBPF is a stub off Linux; see ebpf_linux.go.
func collectEBPF(ctx context.Context) (Result, error) {
	return NewResult("ebpf").Finish(), errors.New("ebpf collector is implemented for linux only")
}
