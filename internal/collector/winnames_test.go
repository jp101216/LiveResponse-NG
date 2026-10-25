package collector

import "testing"

func TestWindowsNames(t *testing.T) {
	il := map[string]string{
		"S-1-16-0": "untrusted", "S-1-16-4096": "low", "S-1-16-8192": "medium",
		"S-1-16-8448": "medium_plus", "S-1-16-12288": "high", "S-1-16-16384": "system",
		"S-1-16-20480": "protected", "S-1-5-18": "S-1-5-18", "garbage": "garbage",
	}
	for sid, want := range il {
		if got := integrityName(sid); got != want {
			t.Errorf("integrityName(%s) = %s, want %s", sid, got, want)
		}
	}
	types := map[uint32]string{
		0x1: "kernel_driver", 0x2: "file_system_driver", 0x10: "own_process", 0x20: "share_process",
		0x110: "own_process+interactive", 0x60: "user_share_process", 0xE0: "user_share_process+user_instance",
		0xD0: "user_own_process+user_instance", 0x3: "unknown(0x3)",
	}
	for v, want := range types {
		if got := serviceType(v); got != want {
			t.Errorf("serviceType(0x%x) = %s, want %s", v, got, want)
		}
	}
	if !isDriverType(1) || !isDriverType(2) || isDriverType(0x10) || isDriverType(0x110) || isDriverType(0xE0) {
		t.Error("isDriverType")
	}
	if serviceStart(2) != "automatic" || serviceStart(9) != "unknown(9)" {
		t.Error("serviceStart")
	}
	if wtsStateName(0) != "active" || wtsStateName(4) != "disconnected" || wtsStateName(42) != "state_42" {
		t.Error("wtsStateName")
	}
	if dnsTypeName(28) != "AAAA" || dnsTypeName(999) != "type_999" || privName(2) != "admin" {
		t.Error("dns/priv names")
	}
}
