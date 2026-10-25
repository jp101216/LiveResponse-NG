package collector

import (
	"testing"
	"unicode/utf16"
)

const sampleTaskXML = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>EVIL\mallory</Author>
    <Description>definitely legit</Description>
    <Date>2026-10-01T12:00:00</Date>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <BootTrigger/>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\Public\update.exe</Command>
      <Arguments>-q -beacon</Arguments>
      <WorkingDirectory>C:\Users\Public</WorkingDirectory>
    </Exec>
  </Actions>
</Task>`

func TestParseTaskXML_UTF8(t *testing.T) {
	def, err := parseTaskXML([]byte(sampleTaskXML))
	if err != nil {
		t.Fatal(err)
	}
	if def.Author != `EVIL\mallory` {
		t.Errorf("author = %q", def.Author)
	}
	if !def.Enabled || !def.Hidden {
		t.Errorf("enabled=%v hidden=%v", def.Enabled, def.Hidden)
	}
	if def.RunAs != "S-1-5-18" || def.RunLevel != "HighestAvailable" || def.LogonType != "Password" {
		t.Errorf("principal = %+v", def)
	}
	if len(def.Execs) != 1 || def.Execs[0].Command != `C:\Users\Public\update.exe` ||
		def.Execs[0].Arguments != "-q -beacon" {
		t.Fatalf("execs = %+v", def.Execs)
	}
	if len(def.Triggers) != 2 || def.Triggers[0] != "LogonTrigger" || def.Triggers[1] != "BootTrigger" {
		t.Errorf("triggers = %v", def.Triggers)
	}
}

// Task files on disk are UTF-16LE with a BOM and declare encoding="UTF-16";
// the parser must decode them the same as the UTF-8 form.
func TestParseTaskXML_UTF16LE_BOM(t *testing.T) {
	u := utf16.Encode([]rune(sampleTaskXML))
	b := make([]byte, 0, 2+len(u)*2)
	b = append(b, 0xFF, 0xFE) // UTF-16LE BOM
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	def, err := parseTaskXML(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(def.Execs) != 1 || def.Execs[0].Command != `C:\Users\Public\update.exe` {
		t.Fatalf("utf-16 decode failed: %+v", def)
	}
	if def.RunAs != "S-1-5-18" {
		t.Errorf("runAs = %q", def.RunAs)
	}
}

func TestParseTaskXML_EnabledDefaultsTrue(t *testing.T) {
	const noSettings = `<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	  <Actions><Exec><Command>cmd.exe</Command></Exec></Actions></Task>`
	def, err := parseTaskXML([]byte(noSettings))
	if err != nil {
		t.Fatal(err)
	}
	if !def.Enabled {
		t.Error("a task with no <Settings><Enabled> should default to enabled")
	}
}
