package watch

import (
	"os"
	"path"
	"strings"
)

// Programs whose periodic traffic is expected: Windows' own services,
// Defender, browsers and their updaters, sync and chat clients. Each is
// pinned to the folder it installs to, so a copy dropped elsewhere under the
// same name isn't excused; a snapshot that finds the image unsigned or
// untrusted overrides the entry. Their flows are still recorded.
var builtinAllow = []struct{ pattern, why string }{
	{`{sys}/system32/svchost.exe`, "Windows service host"},
	{`{sys}/system32/lsass.exe`, "Windows security authority"},
	{`{sys}/system32/services.exe`, "Windows service control manager"},
	{`{sys}/system32/spoolsv.exe`, "Windows print spooler"},
	{`{sys}/system32/searchindexer.exe`, "Windows Search"},
	{`{sys}/system32/searchprotocolhost.exe`, "Windows Search"},
	{`{sys}/system32/mousocoreworker.exe`, "Windows Update"},
	{`{sys}/system32/usocoreworker.exe`, "Windows Update"},
	{`{sys}/system32/wuauclt.exe`, "Windows Update"},
	{`{sys}/system32/musnotification.exe`, "Windows Update"},
	{`{sys}/system32/waasmedicagent.exe`, "Windows Update"},
	{`{sys}/system32/compattelrunner.exe`, "Windows telemetry"},
	{`{sys}/system32/devicecensus.exe`, "Windows telemetry"},
	{`{sys}/system32/taskhostw.exe`, "Windows task host"},
	{`{sys}/system32/backgroundtaskhost.exe`, "Windows background tasks"},
	{`{sys}/system32/runtimebroker.exe`, "Windows runtime broker"},
	{`{sys}/system32/sihost.exe`, "Windows shell infrastructure"},
	{`{sys}/system32/smartscreen.exe`, "Windows SmartScreen"},
	{`{sys}/system32/sgrmbroker.exe`, "Windows System Guard"},
	{`{sys}/system32/securityhealthservice.exe`, "Windows Security"},
	{`{sys}/system32/wbem/wmiprvse.exe`, "WMI provider host"},
	{`{sys}/system32/conhost.exe`, "console host"},
	{`{pd}/microsoft/windows defender/platform/*/msmpeng.exe`, "Microsoft Defender"},
	{`{pd}/microsoft/windows defender/platform/*/mpdefendercoreservice.exe`, "Microsoft Defender"},
	{`{pd}/microsoft/windows defender/platform/*/nissrv.exe`, "Microsoft Defender"},
	{`{pd}/microsoft/windows defender/platform/*/mpcmdrun.exe`, "Microsoft Defender"},
	{`{pf}/windows defender/msmpeng.exe`, "Microsoft Defender"},
	{`{pf}/windows defender/mpcmdrun.exe`, "Microsoft Defender"},
	{`{pf86}/microsoft/edge/application/msedge.exe`, "Microsoft Edge"},
	{`{pf}/microsoft/edge/application/msedge.exe`, "Microsoft Edge"},
	{`{pf86}/microsoft/edgeupdate/microsoftedgeupdate.exe`, "Microsoft Edge updater"},
	{`{pf86}/microsoft/edgewebview/application/*/msedgewebview2.exe`, "Microsoft Edge WebView2"},
	{`{pf}/google/chrome/application/chrome.exe`, "Google Chrome"},
	{`{pf86}/google/chrome/application/chrome.exe`, "Google Chrome"},
	{`{users}/*/appdata/local/google/chrome/application/chrome.exe`, "Google Chrome"},
	{`{pf86}/google/update/googleupdate.exe`, "Google updater"},
	{`{pf}/google/googleupdater/*/updater.exe`, "Google updater"},
	{`{pf}/mozilla firefox/firefox.exe`, "Mozilla Firefox"},
	{`{pf86}/mozilla firefox/firefox.exe`, "Mozilla Firefox"},
	{`{pf}/microsoft onedrive/onedrive.exe`, "Microsoft OneDrive"},
	{`{users}/*/appdata/local/microsoft/onedrive/onedrive.exe`, "Microsoft OneDrive"},
	{`{pf}/windowsapps/msteams_*/ms-teams.exe`, "Microsoft Teams"},
	{`{users}/*/appdata/local/microsoft/teams/current/teams.exe`, "Microsoft Teams"},
	{`{pf}/microsoft office/root/office16/*.exe`, "Microsoft Office"},
	{`{pf}/common files/microsoft shared/clicktorun/officeclicktorun.exe`, "Microsoft Office"},
	{`{users}/*/appdata/local/slack/app-*/slack.exe`, "Slack"},
}

// Allowlist decides which programs' periodic traffic is expected.
type Allowlist struct {
	patterns []struct{ pattern, why string }
	names    map[string]bool
}

// NewAllowlist expands the built-in entries against this system's folders
// (Windows defaults when the variables are unset, as when replaying a
// Windows stream elsewhere) and adds extra program names, matched on any path.
func NewAllowlist(extra []string) *Allowlist {
	root := func(env, def string) string {
		v := os.Getenv(env)
		if v == "" {
			v = def
		}
		return slashLower(v)
	}
	drive := root("SystemDrive", `C:`)
	repl := strings.NewReplacer(
		"{sys}", root("SystemRoot", `C:\Windows`),
		"{pf86}", root("ProgramFiles(x86)", `C:\Program Files (x86)`),
		"{pf}", root("ProgramFiles", `C:\Program Files`),
		"{pd}", root("ProgramData", `C:\ProgramData`),
		"{users}", drive+"/users",
	)
	a := &Allowlist{names: map[string]bool{}}
	for _, e := range builtinAllow {
		a.patterns = append(a.patterns, struct{ pattern, why string }{repl.Replace(e.pattern), e.why})
	}
	for _, n := range extra {
		if n = strings.TrimSpace(n); n != "" {
			a.names[strings.ToLower(path.Base(slashLower(n)))] = true
		}
	}
	return a
}

// Match returns why image is expected to be periodic, or "".
func (a *Allowlist) Match(image string) string {
	if image == "" {
		return ""
	}
	p := slashLower(image)
	if a.names[path.Base(p)] {
		return "allowed by -allow-beacon"
	}
	for _, e := range a.patterns {
		if ok, _ := path.Match(e.pattern, p); ok {
			return e.why
		}
	}
	return ""
}

func slashLower(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	return strings.TrimPrefix(p, "//?/")
}
