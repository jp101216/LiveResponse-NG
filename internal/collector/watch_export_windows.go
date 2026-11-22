//go:build windows

package collector

// ProcessCommandLine reads a running process's command line, redacted the
// way the process collector redacts it; "" when it can't be read.
func ProcessCommandLine(pid uint32) string { return redactSecrets(commandLineOf(pid)) }
