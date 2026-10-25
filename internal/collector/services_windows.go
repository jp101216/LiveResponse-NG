//go:build windows

package collector

import (
	"context"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const servicesKey = `SYSTEM\CurrentControlSet\Services`

// collectServices walks every service subkey and records its configuration,
// then judges it (see judgeService).
func collectServices(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("services")

	root, err := winreg.Open(winreg.LocalMachine, servicesKey)
	if err != nil {
		return res.Finish(), err
	}
	names, err := root.SubKeys()
	root.Close()
	if err != nil && len(names) == 0 {
		return res.Finish(), err
	}
	if err != nil {
		res.Fail(err.Error())
	}
	res.SetMeta("services_key", `HKLM\`+servicesKey)
	res.SetMeta("service_count", len(names))
	sysRoot := systemRoot()

	for _, name := range names {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		k, err := winreg.Open(winreg.LocalMachine, servicesKey+`\`+name)
		if err != nil {
			res.Fail(name + ": " + err.Error())
			continue
		}
		vals := map[string]winreg.Value{}
		if vs, err := k.Values(); err == nil {
			for _, v := range vs {
				vals[strings.ToLower(v.Name)] = v
			}
		}
		lastWrite := k.LastWrite()
		k.Close()

		svc := serviceConfig{Name: name}
		svc.Command, svc.CommandRaw = regString(vals["imagepath"], "")
		svc.Image = normalizeImage(imageFromCommand(svc.Command))
		svc.Type, svc.HasType = vals["type"].Uint32()
		// svchost services carry their real code in a ServiceDll, normally
		// under Parameters, sometimes on the service key itself.
		if v, err := winreg.ReadValue(winreg.LocalMachine, servicesKey+`\`+name+`\Parameters`, "ServiceDll"); err == nil {
			svc.ServiceDLL, _ = regString(v, "")
		}
		if svc.ServiceDLL == "" {
			svc.ServiceDLL, _ = regString(vals["servicedll"], "")
		}
		svc.ServiceDLL = normalizeImage(svc.ServiceDLL)
		svc.FailureCommand, _ = regString(vals["failurecommand"], "")

		fields := map[string]any{"name": name}
		if !lastWrite.IsZero() {
			fields["key_last_write"] = lastWrite
		}
		if dn, _ := regString(vals["displayname"], ""); dn != "" {
			fields["display_name"] = dn
		}
		if svc.Command != "" {
			fields["image_path"] = svc.Command
			if svc.CommandRaw != svc.Command {
				fields["image_path_raw"] = svc.CommandRaw
			}
		}
		if svc.Image != "" {
			fields["image"] = svc.Image
		}
		if st, ok := vals["start"].Uint32(); ok {
			fields["start"] = serviceStart(st)
		}
		if d, ok := vals["delayedautostart"].Uint32(); ok && d != 0 {
			fields["delayed_autostart"] = true
		}
		if svc.HasType {
			fields["type"] = serviceType(svc.Type)
		}
		if obj, _ := regString(vals["objectname"], ""); obj != "" {
			fields["account"] = obj
		}
		if svc.ServiceDLL != "" {
			fields["service_dll"] = svc.ServiceDLL
		}
		if svc.FailureCommand != "" {
			fields["failure_command"] = svc.FailureCommand
		}

		findings := judgeService(svc, sysRoot)
		fields["suspicious_path"] = hasRule(findings, "persistence.service_unusual_path")

		// Hash third-party binaries, and anything flagged; Windows' own
		// drivers and services (hundreds of them) are left alone.
		if opts.Hasher != nil && ctx.Err() == nil {
			if svc.Image != "" && (len(findings) > 0 || !underDir(svc.Image, sysRoot)) {
				opts.Hasher.Fields(ctx, fields, "image", svc.Image)
			}
			if svc.ServiceDLL != "" && (len(findings) > 0 || !underDir(svc.ServiceDLL, sysRoot)) {
				opts.Hasher.Fields(ctx, fields, "service_dll", svc.ServiceDLL)
			}
		}
		res.Add(fields, findings...)
	}
	return res.Finish(), nil
}

func hasRule(fs []Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

// underDir reports whether path lies inside dir (case-insensitive).
func underDir(path, dir string) bool {
	p := strings.ToLower(path)
	d := strings.ToLower(strings.TrimRight(dir, `\`)) + `\`
	return strings.HasPrefix(p, d)
}
