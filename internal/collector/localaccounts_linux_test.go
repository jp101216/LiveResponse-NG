//go:build linux

package collector

import (
	"strings"
	"testing"
)

func TestPrivilegedMemberships(t *testing.T) {
	users := parsePasswd([]byte(`root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:6::/home/bob:/bin/bash
carol:x:1002:27::/home/carol:/bin/bash
dave:x:1003:42::/home/dave:/bin/bash
erin:x:1004:999::/home/erin:/bin/bash
docker:x:998:999::/var/lib/docker:/usr/sbin/nologin
frank:x:1005:0::/home/frank:/bin/bash
`))
	groups := parseGroup([]byte(`root:x:0:
disk:x:6:
sudo:x:27:alice
shadow:x:42:alice
docker:x:999:alice,ghost
libvirt:x:130:carol
users:x:100:
`))
	got := map[string]groupMembership{}
	rules := map[string]string{}
	for _, m := range privilegedMemberships(groups, users) {
		key := m.group + "/" + m.member
		if _, dup := got[key]; dup {
			t.Errorf("%s listed twice", key)
		}
		got[key] = m
		for _, f := range m.findings() {
			rules[key] = f.Rule + "@" + string(f.Severity)
		}
	}
	want := map[string]string{
		"disk/bob":      "accounts.root_equiv_group@suspect", // primary GID 6
		"docker/alice":  "accounts.root_equiv_group@notable",
		"docker/erin":   "accounts.root_equiv_group@suspect", // primary GID 999
		"docker/ghost":  "accounts.root_equiv_group@notable", // listed, no passwd entry
		"libvirt/carol": "accounts.root_equiv_group@notable",
		"shadow/alice":  "accounts.shadow_group@notable",
		"shadow/dave":   "accounts.shadow_group@notable",
		"sudo/alice":    "",
		"sudo/carol":    "accounts.privileged_primary_group@notable", // primary GID 27
		"root/frank":    "accounts.privileged_primary_group@notable", // primary GID 0
	}
	for k, w := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: not listed", k)
			continue
		}
		if rules[k] != w {
			t.Errorf("%s: %q, want %q", k, rules[k], w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected %s (%+v)", k, got[k])
		}
	}
	if !got["disk/bob"].primary || got["sudo/alice"].primary || got["docker/ghost"].uid != -1 {
		t.Errorf("membership details: %+v %+v %+v", got["disk/bob"], got["sudo/alice"], got["docker/ghost"])
	}
	if f := got["disk/bob"].findings()[0]; !strings.Contains(f.Detail, "primary group") || !strings.Contains(f.Detail, "raw disks") {
		t.Errorf("detail: %s", f.Detail)
	}
	if got["disk/bob"].fields()["primary"] != true {
		t.Error("record must say primary")
	}
}
