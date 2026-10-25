package collector

import "context"

// autorunsCollector gathers the auto-start extensibility points (ASEPs) where
// persistence most often lives: per-machine and per-user Run/RunOnce keys
// (honouring Task Manager's enable/disable state), Winlogon Shell/Userinit/
// Taskman/AppSetup, AppInit_DLLs and AppCertDLLs, Image File Execution
// Options debuggers and SilentProcessExit monitors, BootExecute, the LSA
// authentication/security/notification packages, Command Processor AutoRun,
// print monitors, netsh helpers, screensavers and the Startup folders (with
// shortcut targets resolved). Each entry carries its location, the key's
// last-write time, the command and image, a hash, and findings.
type autorunsCollector struct{ opts RunOptions }

func (*autorunsCollector) Name() string        { return "autoruns" }
func (*autorunsCollector) Platforms() []string { return []string{"windows", "linux"} }

func (c *autorunsCollector) Configure(o RunOptions) { c.opts = o }

func (c *autorunsCollector) Collect(ctx context.Context) (Result, error) {
	return collectAutoruns(ctx, c.opts)
}

func init() { Register(&autorunsCollector{}) }
