package collector

import "context"

// ebpfCollector lists the eBPF programs loaded in the kernel — type, name,
// loader uid, load time, pins — names the kernel helpers each one calls, and
// flags programs that use the helpers able to act on user space (see
// ebpfrules.go). Enumerating programs needs root (CAP_SYS_ADMIN or CAP_BPF).
type ebpfCollector struct{}

func (ebpfCollector) Name() string        { return "ebpf" }
func (ebpfCollector) Platforms() []string { return []string{"linux"} }

func (ebpfCollector) Collect(ctx context.Context) (Result, error) {
	return collectEBPF(ctx)
}

func init() { Register(ebpfCollector{}) }
