//go:build linux

package collector

import "testing"

// Red Hat ships sync, shutdown, halt and operator with the root group as their
// primary group. They used to be reported on every such host.
func TestPrivilegedPrimaryGroupSkipsDistributionDefaults(t *testing.T) {
	users := parsePasswd([]byte(`root:x:0:0:root:/root:/bin/bash
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
operator:x:11:0:operator:/root:/sbin/nologin
backdoor:x:500:0::/var/tmp:/bin/bash
frank:x:1005:0::/home/frank:/bin/bash
`))
	groups := parseGroup([]byte("root:x:0:\n"))
	flagged := map[string]bool{}
	for _, m := range privilegedMemberships(groups, users) {
		if len(m.findings()) > 0 {
			flagged[m.member] = true
		}
	}
	for _, name := range []string{"sync", "shutdown", "halt", "operator"} {
		if flagged[name] {
			t.Errorf("%s: a distribution default was flagged", name)
		}
	}
	for _, name := range []string{"backdoor", "frank"} {
		if !flagged[name] {
			t.Errorf("%s: a login account with the root group as its primary group was not flagged", name)
		}
	}
}

// A cron job or unit that runs "sh /tmp/.x/run.sh" runs code from /tmp as
// surely as one that runs "/tmp/.x/run".
func TestPersistenceGradesInterpreterScripts(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/bin/sh /tmp/.x/run.sh":                    true,
		"bash /dev/shm/.a":                          true,
		"sudo -u nobody /usr/bin/python3 /tmp/p.py": true,
		"nice -n 19 /var/tmp/.cache/miner":          true,
		"/bin/sh -c 'echo hi'":                      false,
		"/usr/bin/python3 /usr/lib/x/job.py":        false,
	} {
		if got := hasRule(persistenceFindings("cron", cmd), "persistence.unusual_path"); got != want {
			t.Errorf("persistenceFindings(%q): unusual_path %v, want %v", cmd, got, want)
		}
	}
}
