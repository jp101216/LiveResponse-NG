//go:build windows

package collector

import (
	"context"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// COM class registrations live under a CLSID key whose children name the
// server. The machine store is HKLM\SOFTWARE\Classes\CLSID (with the 32-bit
// view under ...\Wow6432Node\CLSID); each user has their own store, the
// separately loaded HKU\<sid>_Classes hive (older systems keep it under
// HKU\<sid>\Software\Classes). The reader forces the 64-bit view, so the
// Wow6432Node paths are read explicitly.
const (
	clsidMachine      = `SOFTWARE\Classes\CLSID`
	clsidMachineWow64 = `SOFTWARE\Classes\Wow6432Node\CLSID`
)

// comWalker gathers COM class registrations into one result.
type comWalker struct {
	ctx     context.Context
	res     *Result
	opts    RunOptions
	machine map[string]string // lower-case CLSID present in HKLM -> its native server (may be "")

	machineCount int
	userCount    int
	emitted      int
}

func collectCOMHijack(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("comhijack")
	w := &comWalker{ctx: ctx, res: res, opts: opts, machine: map[string]string{}}

	// Pass 1 — machine CLSIDs. The native pass also records which CLSIDs exist
	// in HKLM, so per-user registrations that shadow them can be recognised.
	w.walk(winreg.LocalMachine, clsidMachine, "HKLM", "native", "")
	w.walk(winreg.LocalMachine, clsidMachineWow64, "HKLM", "wow64", "")

	// Pass 2 — each loaded user's own class store.
	profiles, err := userProfiles()
	if err != nil {
		res.Fail("profile list: " + err.Error())
	}
	hives, err := loadedUserHives()
	if err != nil {
		res.Fail("HKU: " + err.Error())
	}
	var userStores []string
	for _, sid := range hives {
		if w.done() {
			break
		}
		profile := profiles[sid]
		hive := `HKU\` + sid
		// Prefer the modern per-user class hive; fall back to the Software\Classes
		// path when it isn't loaded separately.
		if w.walk(winreg.Users, sid+`_Classes\`+`CLSID`, hive, "native", profile) {
			userStores = append(userStores, sid+"_Classes")
		} else if w.walk(winreg.Users, sid+`\Software\Classes\CLSID`, hive, "native", profile) {
			userStores = append(userStores, sid+`\Software\Classes`)
		}
		w.walk(winreg.Users, sid+`_Classes\Wow6432Node\CLSID`, hive, "wow64", profile)
	}

	sort.Strings(userStores)
	res.SetMeta("clsid_count_machine", w.machineCount)
	res.SetMeta("clsid_count_user", w.userCount)
	res.SetMeta("user_class_stores", userStores)
	res.SetMeta("emitted", w.emitted)
	res.SetMeta("note", "only CLSIDs that tripped a heuristic are recorded; the counts above are the totals scanned")
	return res.Finish(), nil
}

// done reports (and records, once) that the collector was cancelled.
func (w *comWalker) done() bool {
	if err := w.ctx.Err(); err != nil {
		w.res.Fail("cancelled: " + err.Error())
		return true
	}
	return false
}

// walk enumerates every CLSID subkey under one class store and judges it.
// It returns whether the store key existed (so the caller can fall back to
// another path for the same hive).
func (w *comWalker) walk(root winreg.Root, path, hive, view, profile string) bool {
	if w.done() {
		return false
	}
	parent, err := winreg.Open(root, path)
	if err != nil {
		if !winreg.IsNotExist(err) {
			w.res.Fail(path + ": " + err.Error())
		}
		return false
	}
	names, err := parent.SubKeys()
	parent.Close()
	if err != nil && len(names) == 0 {
		w.res.Fail(path + ": " + err.Error())
		return true
	}
	if err != nil {
		w.res.Fail(path + ": " + err.Error())
	}

	user := root == winreg.Users
	native := view == "native" && !user
	for _, guid := range names {
		if w.done() {
			return true
		}
		e := w.read(root, path+`\`+guid, guid, hive, view, user, profile)

		if user {
			w.userCount++
			if srv, in := w.machine[e.CLSID]; in {
				e.Shadows = true
				e.ShadowServer = srv
			}
		} else {
			w.machineCount++
			if native {
				// Record existence (value may be "" for a TreatAs-only entry).
				if _, seen := w.machine[e.CLSID]; !seen {
					w.machine[e.CLSID] = e.Server
				}
			}
		}

		findings := judgeCOM(e)
		if len(findings) == 0 {
			continue
		}
		w.emit(e, findings)
	}
	return true
}

// read builds a comEntry from one CLSID key: its friendly name, the server
// (InprocServer32 preferred, else LocalServer32) and any TreatAs redirect.
func (w *comWalker) read(root winreg.Root, base, guid, hive, view string, user bool, profile string) comEntry {
	e := comEntry{CLSID: strings.ToLower(guid), Hive: hive, View: view, User: user}

	if v, err := winreg.ReadValue(root, base, ""); err == nil {
		e.Name = strings.TrimSpace(v.String())
	}

	if srv, thread, ok := w.server(root, base+`\InprocServer32`); ok {
		e.ServerKind = comInproc
		e.ServerRaw = srv
		e.Server = comNormalize(srv, profile) // a bare DLL path
		e.Threading = thread
	} else if srv, _, ok := w.server(root, base+`\LocalServer32`); ok {
		e.ServerKind = comLocal
		e.ServerRaw = srv
		e.Server = comExpand(srv, profile) // a command line: keep arguments
	}

	if v, err := winreg.ReadValue(root, base+`\TreatAs`, ""); err == nil {
		if t := strings.TrimSpace(v.String()); t != "" {
			e.TreatAs = strings.ToLower(t)
		}
	}
	return e
}

// server reads a server key's default value (the path or command) and, for an
// inproc server, its ThreadingModel.
func (w *comWalker) server(root winreg.Root, keyPath string) (val, threading string, ok bool) {
	k, err := winreg.Open(root, keyPath)
	if err != nil {
		return "", "", false
	}
	defer k.Close()
	d, err := k.Value("")
	if err != nil {
		return "", "", false
	}
	val = strings.TrimSpace(d.String())
	if val == "" {
		return "", "", false
	}
	if t, err := k.Value("ThreadingModel"); err == nil {
		threading = strings.TrimSpace(t.String())
	}
	return val, threading, true
}

// emit records one flagged COM registration with its findings.
func (w *comWalker) emit(e comEntry, findings []Finding) {
	fields := map[string]any{
		"clsid": e.CLSID,
		"hive":  e.Hive,
		"view":  e.View,
	}
	if e.Name != "" {
		fields["name"] = e.Name
	}
	if e.User {
		fields["per_user"] = true
	}
	if e.ServerKind != "" {
		fields["server_kind"] = e.ServerKind
		fields["server"] = e.Server
		if e.ServerRaw != "" && e.ServerRaw != e.Server {
			fields["server_raw"] = e.ServerRaw
		}
		if e.Threading != "" {
			fields["threading_model"] = e.Threading
		}
	}
	if e.TreatAs != "" {
		fields["treat_as"] = e.TreatAs
	}
	if e.Shadows {
		fields["shadows_hklm"] = true
		if e.ShadowServer != "" {
			fields["shadowed_server"] = e.ShadowServer
		}
	}
	fields["suspicious_path"] = hasRule(findings, "persistence.com_server_unusual_path")

	// Hash the server image where it's the kind of third-party/flagged binary
	// worth a hash — not every System32 DLL.
	if w.opts.Hasher != nil && w.ctx.Err() == nil && e.Server != "" {
		img := e.Server
		if e.ServerKind == comLocal {
			img = imageFromCommand(e.Server)
		}
		if strings.ContainsAny(img, `\/`) {
			w.opts.Hasher.Fields(w.ctx, fields, "server", img)
		}
	}

	w.res.Add(fields, findings...)
	w.emitted++
}

// comNormalize expands a bare COM server DLL path (environment references and
// the NT/relative forms Windows stores) to an ordinary Win32 path, under the
// owning user's profile for a per-user entry and machine-wide otherwise.
func comNormalize(raw, profile string) string {
	if profile != "" {
		return normalizeImageWith(raw, systemRoot(), chain(userLookup(profile), machineLookup()))
	}
	return normalizeImage(raw)
}

// comExpand expands environment references in a LocalServer32 command line
// without splitting it, so the shared command analytics see the whole thing.
func comExpand(raw, profile string) string {
	if profile != "" {
		return expandForProfile(raw, profile)
	}
	return expandMachine(raw)
}
