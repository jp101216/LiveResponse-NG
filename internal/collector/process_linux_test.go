//go:build linux

package collector

import "testing"

func TestLooksLikeKernelThreadName(t *testing.T) {
	kernel := []string{"kworker/0:1", "[kworker/0:1]", "ksoftirqd/3", "rcu_sched", "migration/0", "kswapd0", "irq/24-pciehp"}
	for _, n := range kernel {
		if !looksLikeKernelThreadName(n) {
			t.Errorf("%q should look like a kernel-thread name", n)
		}
	}
	ordinary := []string{"nginx", "python3", "sshd", "bash", "k9s", "containerd"}
	for _, n := range ordinary {
		if looksLikeKernelThreadName(n) {
			t.Errorf("%q should not look like a kernel-thread name", n)
		}
	}
}

func TestLinuxProcessKthreadMasquerade(t *testing.T) {
	// A process named like a kernel thread but with a real executable is flagged.
	masq := linuxProcRow{
		pid: 1337, st: procStatus{Name: "kworker/0:2"}, exe: "/tmp/.x/payload",
		fields: map[string]any{},
	}
	if _, ok := rulesOf(linuxProcessFindings(masq))["process.kthread_masquerade"]; !ok {
		t.Error("a kworker-named process with an exe should flag kthread_masquerade")
	}

	// A real kernel thread (no exe) is not flagged.
	real := linuxProcRow{
		pid: 10, st: procStatus{Name: "kworker/0:2"}, exe: "", kernel: true,
		fields: map[string]any{},
	}
	if _, ok := rulesOf(linuxProcessFindings(real))["process.kthread_masquerade"]; ok {
		t.Error("a real (exe-less) kernel thread must not be flagged")
	}
}
