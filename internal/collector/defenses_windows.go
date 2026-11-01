//go:build windows

package collector

import (
	"context"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const (
	defenderKey       = `SOFTWARE\Microsoft\Windows Defender`
	defenderPolicyKey = `SOFTWARE\Policies\Microsoft\Windows Defender`
	lsaControlKey     = `SYSTEM\CurrentControlSet\Control\Lsa`
	wdigestKey        = `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
)

// exclusionKeys are the Exclusions subkeys (their value names are the
// exclusions), by kind.
var exclusionKeys = []struct{ kind, key string }{
	{"path", "Paths"}, {"extension", "Extensions"}, {"process", "Processes"}, {"ip", "IpAddresses"},
}

func collectDefenses(ctx context.Context) (Result, error) {
	res := NewResult("defenses")
	d := readDefender()
	defensesReport(res, d, readCredentials())
	amsiReport(res, readAMSI(), !d.NotInstalled)
	runtimeEnvReport(res, readRuntimeEnv())
	return res.Finish(), nil
}

const (
	amsiProvidersKey = `SOFTWARE\Microsoft\AMSI\Providers`
	sessionEnvKey    = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	servicesRegKey   = `SYSTEM\CurrentControlSet\Services`
)

// readAMSI lists the AMSI providers and the DLL each CLSID registers.
func readAMSI() amsiState {
	k, err := winreg.Open(winreg.LocalMachine, amsiProvidersKey)
	if err != nil {
		return amsiState{}
	}
	subs, _ := k.SubKeys()
	k.Close()
	a := amsiState{Present: true}
	for _, clsid := range subs {
		a.Providers = append(a.Providers, amsiProvider{CLSID: clsid, DLL: clsidServer("", clsid)})
	}
	return a
}

// clsidServer returns the DLL a COM class registers (its InprocServer32),
// looking in a user's own classes first when sid is given, as COM does for
// that user's processes, then in the machine's.
func clsidServer(sid, clsid string) string {
	c := "{" + strings.Trim(strings.TrimSpace(clsid), "{}") + "}"
	if sid != "" {
		if v, err := winreg.ReadValue(winreg.Users, sid+`_Classes\CLSID\`+c+`\InprocServer32`, ""); err == nil {
			if s, _ := regString(v, ""); s != "" {
				return s
			}
		}
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine, `SOFTWARE\Classes\CLSID\`+c+`\InprocServer32`, ""); err == nil {
		s, _ := regString(v, "")
		return s
	}
	return ""
}

// readRuntimeEnv finds the .NET runtime variables set in the system's
// environment, each loaded user's, and each service's (a service's
// Environment value is a list of NAME=value strings its processes start with).
func readRuntimeEnv() []envSource {
	var out []envSource
	fromKey := func(root winreg.Root, path, where, sid string) {
		k, err := winreg.Open(root, path)
		if err != nil {
			return
		}
		vals, err := k.Values()
		k.Close()
		if err != nil {
			return
		}
		env := map[string]string{}
		for _, v := range vals {
			if runtimeEnvVar(v.Name) {
				s, _ := regString(v, "")
				env[strings.ToUpper(v.Name)] = s
			}
		}
		if len(env) > 0 {
			out = append(out, envSource{Where: where, Env: env, Resolve: func(c string) string { return clsidServer(sid, c) }})
		}
	}
	fromKey(winreg.LocalMachine, sessionEnvKey, `the system environment (HKLM\`+sessionEnvKey+`)`, "")
	hives, _ := loadedUserHives()
	for _, sid := range hives {
		fromKey(winreg.Users, sid+`\Environment`, `user `+sid+`'s environment (HKU\`+sid+`\Environment)`, sid)
	}
	if k, err := winreg.Open(winreg.LocalMachine, servicesRegKey); err == nil {
		svcs, _ := k.SubKeys()
		k.Close()
		for _, svc := range svcs {
			v, err := winreg.ReadValue(winreg.LocalMachine, servicesRegKey+`\`+svc, "Environment")
			if err != nil {
				continue
			}
			if env := parseEnvBlock(v.Strings()); len(env) > 0 {
				out = append(out, envSource{Where: `service ` + svc + `'s environment (HKLM\` + servicesRegKey + `\` + svc + `\Environment)`,
					Env: env, Resolve: func(c string) string { return clsidServer("", c) }})
			}
		}
	}
	return out
}

func readDefender() defenderState {
	var d defenderState
	if k, err := winreg.Open(winreg.LocalMachine, defenderKey); err != nil {
		if winreg.IsNotExist(err) {
			d.NotInstalled = true
			return d
		}
		d.Unreadable = append(d.Unreadable, defenderKey+": "+err.Error())
	} else {
		k.Close()
	}
	for _, base := range []struct {
		key    string
		policy bool
	}{{defenderKey, false}, {defenderPolicyKey, true}} {
		for _, ek := range exclusionKeys {
			path := base.key + `\Exclusions\` + ek.key
			k, err := winreg.Open(winreg.LocalMachine, path)
			if err != nil {
				if !winreg.IsNotExist(err) {
					d.Unreadable = append(d.Unreadable, path+": "+err.Error())
				}
				continue
			}
			vals, err := k.Values()
			k.Close()
			if err != nil {
				d.Unreadable = append(d.Unreadable, path+": "+err.Error())
				continue
			}
			for _, v := range vals {
				if v.Name != "" {
					d.Exclusions = append(d.Exclusions, exclusion{Kind: ek.kind, Value: v.Name, Policy: base.policy})
				}
			}
		}
		for _, s := range defenderSettings {
			path := base.key
			if s.Key != "" {
				path += `\` + s.Key
			}
			if v, err := winreg.ReadValue(winreg.LocalMachine, path, s.Name); err == nil {
				if n, ok := v.Uint32(); ok {
					d.Settings = append(d.Settings, setting{Path: path, Name: s.Name, Value: n, Policy: base.policy})
				}
			}
		}
	}
	if v, err := winreg.ReadValue(winreg.LocalMachine, defenderKey+`\Features`, "TamperProtection"); err == nil {
		if n, ok := v.Uint32(); ok {
			d.Tamper = &n
		}
	}
	sort.Slice(d.Exclusions, func(i, j int) bool {
		a, b := d.Exclusions[i], d.Exclusions[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
	return d
}

func readCredentials() credentialState {
	u := func(path, name string) *uint32 {
		if v, err := winreg.ReadValue(winreg.LocalMachine, path, name); err == nil {
			if n, ok := v.Uint32(); ok {
				return &n
			}
		}
		return nil
	}
	return credentialState{
		WDigest:         u(wdigestKey, "UseLogonCredential"),
		RunAsPPL:        u(lsaControlKey, "RunAsPPL"),
		LsaCfgFlags:     u(lsaControlKey, "LsaCfgFlags"),
		RestrictedAdmin: u(lsaControlKey, "DisableRestrictedAdmin"),
		LmCompat:        u(lsaControlKey, "LmCompatibilityLevel"),
		DsrmLogon:       u(lsaControlKey, "DsrmAdminLogonBehavior"),
	}
}
