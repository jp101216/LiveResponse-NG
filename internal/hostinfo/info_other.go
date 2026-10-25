//go:build !windows

package hostinfo

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// Gather collects what the host readily says about itself (Linux: os-release,
// kernel, boot time). The collectors are Windows-only; this keeps the report
// envelope meaningful for the sidecar-backed commands on other systems.
func Gather() Info {
	var in Info
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				in.OSName = v
			case "VERSION_ID":
				in.OSVersion = v
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		in.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "btime "); ok {
				if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
					in.BootTime = timePtr(time.Unix(n, 0))
				}
			}
		}
	}
	in.TimeZone, _ = time.Now().Zone()
	return in
}
