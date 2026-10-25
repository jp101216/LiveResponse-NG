package collector

import (
	"net/netip"
	"testing"
)

func TestAnalyzeConnection(t *testing.T) {
	pub := netip.MustParseAddr("198.51.100.20")
	cases := []struct {
		name string
		c    connView
		want []string
	}{
		{"bind shell", connView{State: "LISTEN", Local: netip.MustParseAddr("0.0.0.0"), LocalPort: 4444, PID: 9, Process: "powershell.exe"},
			[]string{"network.script_host_listener"}},
		{"loopback listener is fine", connView{State: "LISTEN", Local: netip.MustParseAddr("127.0.0.1"), LocalPort: 8080, PID: 9, Process: "powershell.exe"},
			nil},
		{"rundll32 beacon", connView{State: "ESTABLISHED", Remote: pub, RemotePort: 443, PID: 9, Process: "rundll32.exe"},
			[]string{"network.lolbin_outbound"}},
		{"rundll32 to LAN is fine", connView{State: "ESTABLISHED", Remote: netip.MustParseAddr("10.0.0.8"), RemotePort: 445, PID: 9, Process: "rundll32.exe"},
			nil},
		{"powershell outbound is a note", connView{State: "SYN_SENT", Remote: pub, RemotePort: 80, PID: 9, Process: "PowerShell.exe"},
			[]string{"network.script_host_outbound"}},
		{"temp binary to internet", connView{State: "ESTABLISHED", Remote: pub, RemotePort: 8443, PID: 9, Process: "upd.exe",
			ImagePath: `C:\Users\a\AppData\Local\Temp\upd.exe`}, []string{"network.unusual_path_outbound"}},
		{"closed state ignored", connView{State: "TIME_WAIT", Remote: pub, RemotePort: 443, PID: 9, Process: "rundll32.exe"}, nil},
		{"browser is fine", connView{State: "ESTABLISHED", Remote: pub, RemotePort: 443, PID: 9, Process: "chrome.exe",
			ImagePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`}, nil},
		{"self ignored", connView{State: "ESTABLISHED", Remote: pub, RemotePort: 443, PID: 9, Process: "lrng.exe",
			ImagePath: `C:\Users\a\Downloads\lrng.exe`, Self: true}, nil},
	}
	for _, c := range cases {
		got := analyzeConnection(c.c)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, keys(rulesOf(got)), c.want)
			continue
		}
		for i, w := range c.want {
			if got[i].Rule != w {
				t.Errorf("%s: got %s, want %s", c.name, got[i].Rule, w)
			}
		}
	}
}
