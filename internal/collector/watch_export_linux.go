//go:build linux

package collector

import "strconv"

// ProcessCommandLine reads a running process's command line, redacted the
// way the process collector redacts it; "" when it can't be read.
func ProcessCommandLine(pid uint32) string {
	return redactSecrets(parseCmdline(readFileSafe("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")))
}
