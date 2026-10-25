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
// kernel, boot time, time zone), for the report envelope.
func Gather() Info {
	var in Info
	// os-release(5): /etc/os-release, falling back to /usr/lib/os-release;
	// values may be double- or single-quoted.
	f, err := os.Open("/etc/os-release")
	if err != nil {
		f, err = os.Open("/usr/lib/os-release")
	}
	if err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
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
