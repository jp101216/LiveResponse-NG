//go:build windows

package collector

import (
	"context"
	"sort"

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
	defensesReport(res, readDefender(), readCredentials())
	return res.Finish(), nil
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
	}
}
