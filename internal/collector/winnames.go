package collector

import (
	"fmt"
	"strconv"
	"strings"
)

// Names for Windows enumeration values, kept free of build tags so they are
// unit-tested on any OS.

// integrityName maps a mandatory-label SID (S-1-16-<rid>) to a name.
func integrityName(sid string) string {
	i := strings.LastIndexByte(sid, '-')
	if i < 0 || !strings.HasPrefix(sid, "S-1-16-") {
		return sid
	}
	rid, err := strconv.ParseUint(sid[i+1:], 10, 32)
	if err != nil {
		return sid
	}
	switch {
	case rid >= 0x5000:
		return "protected"
	case rid >= 0x4000:
		return "system"
	case rid >= 0x3000:
		return "high"
	case rid >= 0x2100:
		return "medium_plus"
	case rid >= 0x2000:
		return "medium"
	case rid >= 0x1000:
		return "low"
	}
	return "untrusted"
}

// serviceStart names a service Start value (SERVICE_* start types).
func serviceStart(v uint32) string {
	switch v {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// serviceType names a service Type value, noting the interactive and
// per-user-instance flags.
func serviceType(v uint32) string {
	const (
		interactive  = 0x100 // SERVICE_INTERACTIVE_PROCESS
		userInstance = 0x80  // SERVICE_USERSERVICE_INSTANCE
	)
	var s string
	switch v &^ (interactive | userInstance) {
	case 0x1:
		s = "kernel_driver"
	case 0x2:
		s = "file_system_driver"
	case 0x4:
		s = "adapter"
	case 0x8:
		s = "recognizer_driver"
	case 0x10:
		s = "own_process"
	case 0x20:
		s = "share_process"
	case 0x50:
		s = "user_own_process"
	case 0x60:
		s = "user_share_process"
	default:
		s = fmt.Sprintf("unknown(0x%x)", v)
	}
	if v&userInstance != 0 {
		s += "+user_instance"
	}
	if v&interactive != 0 {
		s += "+interactive"
	}
	return s
}

// isDriverType reports whether a service Type value is a kernel or
// file-system driver.
func isDriverType(v uint32) bool { return v&0x0F != 0 && v&0xF0 == 0 }

// wtsStateName names a WTS_CONNECTSTATE_CLASS value.
func wtsStateName(s uint32) string {
	names := [...]string{"active", "connected", "connect_query", "shadow", "disconnected",
		"idle", "listen", "reset", "down", "init"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("state_%d", s)
}

// privName names a USER_INFO privilege level.
func privName(p uint32) string {
	switch p {
	case 0:
		return "guest"
	case 1:
		return "user"
	case 2:
		return "admin"
	default:
		return "unknown"
	}
}

// dnsTypeName names the common DNS record types.
func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 39:
		return "DNAME"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}
