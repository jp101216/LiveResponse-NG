package collector

import "context"

// servicesCollector enumerates Windows services from the registry
// (HKLM\SYSTEM\CurrentControlSet\Services): image path, service DLL, start
// type, service type, the account each runs as, the recovery command and the
// key's last-write time. Reading the hive rather than the Service Control
// Manager means it works read-only and sees every configured service, not
// only those currently loaded.
type servicesCollector struct{ opts RunOptions }

func (*servicesCollector) Name() string        { return "services" }
func (*servicesCollector) Platforms() []string { return []string{"windows"} }

func (c *servicesCollector) Configure(o RunOptions) { c.opts = o }

func (c *servicesCollector) Collect(ctx context.Context) (Result, error) {
	return collectServices(ctx, c.opts)
}

func init() { Register(&servicesCollector{}) }
