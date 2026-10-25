package collector

import "context"

// wmiCollector enumerates WMI permanent event subscriptions — the
// __EventFilter / __EventConsumer / __FilterToConsumerBinding objects in
// root\subscription — and flags the script and command-line consumers that
// make WMI a favourite fileless-persistence mechanism (T1546.003). A clean
// Windows install has essentially none, so anything found is surfaced.
type wmiCollector struct{ opts RunOptions }

func (*wmiCollector) Name() string        { return "wmi" }
func (*wmiCollector) Platforms() []string { return []string{"windows"} }

func (c *wmiCollector) Configure(o RunOptions) { c.opts = o }

func (c *wmiCollector) Collect(ctx context.Context) (Result, error) {
	return collectWMI(ctx, c.opts)
}

func init() { Register(&wmiCollector{}) }
