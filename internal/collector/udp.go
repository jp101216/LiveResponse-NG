package collector

import "context"

// udpCollector enumerates IPv4 and IPv6 UDP endpoints with their owning
// process — the companion to the TCP-focused network collector. UDP has no
// connection state or remote peer in the table, so these are the local
// listeners and sockets (DNS, name resolution, beacons that use UDP).
type udpCollector struct{}

func (udpCollector) Name() string        { return "udp" }
func (udpCollector) Platforms() []string { return []string{"windows", "linux"} }

func (udpCollector) Collect(ctx context.Context) (Result, error) {
	return collectUDP(ctx)
}

func init() { Register(udpCollector{}) }
