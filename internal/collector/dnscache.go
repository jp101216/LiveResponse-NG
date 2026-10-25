package collector

import (
	"context"
	"sync/atomic"
	"time"
)

// dnsCacheCollector snapshots the host DNS client (resolver) cache: which
// names have been resolved, their record types and — read from the cache
// only, never from the network — the addresses they resolved to. It answers
// whether a host reached out to a given domain (a C2 or an LLM provider) even
// after the connection has closed.
//
// It is opt-in because it reads the cache through the undocumented
// DnsGetCacheDataTable API. Selecting it also turns on DNS correlation in the
// network collector, which attaches cached hostnames to connections. The
// cache is snapshotted once per run, before module A resolves anything, so
// lrng's own lookups don't pollute it.
type dnsCacheCollector struct{ opts RunOptions }

func (*dnsCacheCollector) Name() string        { return "dnscache" }
func (*dnsCacheCollector) Platforms() []string { return []string{"windows"} }
func (*dnsCacheCollector) OptIn() bool         { return true }

func (c *dnsCacheCollector) Configure(o RunOptions) { c.opts = o }

func (c *dnsCacheCollector) Collect(ctx context.Context) (Result, error) {
	return collectDNSCache(ctx, c.opts)
}

func init() { Register(&dnsCacheCollector{}) }

// moduleAResolveStarted records (unix nanoseconds) when module A began its
// provider lookups this run, so the DNS-cache snapshot can say whether it was
// taken before lrng touched the cache.
var moduleAResolveStarted atomic.Int64

func markModuleAResolving() { moduleAResolveStarted.CompareAndSwap(0, time.Now().UnixNano()) }

// snapshotPolluted reports whether module A's lookups started before the
// snapshot finished.
func snapshotPolluted(done time.Time) bool {
	started := moduleAResolveStarted.Load()
	return started != 0 && started < done.UnixNano()
}
