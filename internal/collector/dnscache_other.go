//go:build !windows

package collector

import (
	"context"
	"errors"
	"net/netip"
)

// collectDNSCache is a stub off Windows; the real implementation reads the
// Windows DNS resolver cache. See dnscache_windows.go.
func collectDNSCache(ctx context.Context, opts RunOptions) (Result, error) {
	return NewResult("dnscache").Finish(),
		errors.New("dnscache collector is implemented for windows only")
}

// dnsNamesByAddr is unavailable off Windows.
func dnsNamesByAddr(ctx context.Context) (map[netip.Addr][]string, error) {
	return nil, errors.New("DNS cache correlation is implemented for windows only")
}
