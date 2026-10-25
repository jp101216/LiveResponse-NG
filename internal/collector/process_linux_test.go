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

func TestLinuxProcessKthreadMasqueradeWithoutRoot(t *testing.T) {
	// Unprivileged, another user's exe link can't be read, but the PF_KTHREAD
	// flag is: a kworker-named task without it is a masquerade either way.
	r := linuxProcRow{pid: 4242, st: procStatus{Name: "kworker/1:3"}, kernelKnown: true, fields: map[string]any{}}
	if _, ok := rulesOf(linuxProcessFindings(r))["process.kthread_masquerade"]; !ok {
		t.Error("a kworker-named userland task should be flagged even when its exe is unreadable")
	}
	// Without the flag (stat unreadable) and without an exe there is nothing to go on.
	r.kernelKnown = false
	if _, ok := rulesOf(linuxProcessFindings(r))["process.kthread_masquerade"]; ok {
		t.Error("no flag and no exe: must not guess")
	}
}

func TestLinuxProcessReplacedBinary(t *testing.T) {
	r := linuxProcRow{pid: 900, st: procStatus{Name: "sshd"}, exe: "/usr/sbin/sshd (deleted)", replaced: true, fields: map[string]any{}}
	got := rulesOf(linuxProcessFindings(r))
	if _, ok := got["process.binary_replaced"]; !ok {
		t.Fatalf("want process.binary_replaced, got %v", got)
	}
	if _, ok := got["process.deleted_binary"]; ok {
		t.Fatalf("a binary replaced by an upgrade is not a self-deleting payload: %v", got)
	}
	r.replaced = false
	if _, ok := rulesOf(linuxProcessFindings(r))["process.deleted_binary"]; !ok {
		t.Error("a deleted binary with nothing in its place stays process.deleted_binary")
	}
}
