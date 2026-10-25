//go:build windows

package collector

import (
	"context"
	"path/filepath"
)

// eventLogTargets are the DFIR-relevant channels, by file name under
// winevt\Logs. Only these are parsed, and within them only targeted events (and
// command-bearing events that trip a rule) are kept. "%4" is how the channel
// path separator "/" is encoded in the on-disk file name.
var eventLogTargets = []string{
	"Security.evtx",
	"System.evtx",
	"Application.evtx",
	"Windows PowerShell.evtx",
	"Microsoft-Windows-PowerShell%4Operational.evtx",
	"Microsoft-Windows-TaskScheduler%4Operational.evtx",
	"Microsoft-Windows-WMI-Activity%4Operational.evtx",
	"Microsoft-Windows-Windows Defender%4Operational.evtx",
	"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
	"Microsoft-Windows-Sysmon%4Operational.evtx",
}

// collectEventLog triages the host's live event logs. It builds the targeted
// source list from winevt\Logs and hands it to the portable reader
// (collectEventLogSources), which is shared with offline mode.
func collectEventLog(ctx context.Context, sigma *SigmaRuleset) (Result, error) {
	res := NewResult("eventlog")
	dir := filepath.Join(systemRoot(), "System32", "winevt", "Logs")
	res.SetMeta("log_dir", dir)
	res.SetMeta("note", "targeted DFIR channels only; security-relevant events are kept in full, "+
		"high-volume events (process creation, PowerShell script blocks) only when a rule fires. "+
		"Command lines inside events run through the same analytics as processes and services")

	sources := make([]eventLogSource, 0, len(eventLogTargets))
	for _, fname := range eventLogTargets {
		sources = append(sources, eventLogSource{
			path:    filepath.Join(dir, fname),
			channel: channelName(fname),
			label:   fname,
		})
	}
	collectEventLogSources(ctx, res, sources, true, sigma)
	return res.Finish(), nil
}
