package hostinfo

import (
	"strconv"
	"strings"
	"time"
)

// Info describes the host a report came from: enough to line a report up
// with others (OS build, time zone, domain) and to bound a timeline (boot and
// install times). Every field is best-effort; absent means unknown.
type Info struct {
	OSName           string     `json:"os_name,omitempty"`
	OSVersion        string     `json:"os_version,omitempty"` // e.g. 23H2
	OSBuild          string     `json:"os_build,omitempty"`   // e.g. 22631.4317
	Edition          string     `json:"edition,omitempty"`
	InstallationType string     `json:"installation_type,omitempty"` // Client, Server, Server Core
	InstalledAt      *time.Time `json:"installed_at,omitempty"`
	BootTime         *time.Time `json:"boot_time,omitempty"`
	TimeZone         string     `json:"time_zone,omitempty"`
	JoinType         string     `json:"join_type,omitempty"` // domain, workgroup, unjoined
	Domain           string     `json:"domain,omitempty"`    // NetBIOS domain or workgroup
	DNSDomain        string     `json:"dns_domain,omitempty"`
	FQDN             string     `json:"fqdn,omitempty"`
	Kernel           string     `json:"kernel,omitempty"`
	Errors           []string   `json:"errors,omitempty"`
}

// windowsProductName corrects the registry's ProductName, which still says
// "Windows 10" on Windows 11 (build 22000 and later).
func windowsProductName(product, build string) string {
	n, err := strconv.Atoi(strings.SplitN(build, ".", 2)[0])
	if err == nil && n >= 22000 && strings.HasPrefix(product, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	return product
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}
