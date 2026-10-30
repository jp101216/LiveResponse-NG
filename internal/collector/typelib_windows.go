//go:build windows

package collector

import (
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// Type-library class stores, alongside the CLSID stores walked in
// comhijack_windows.go. Registrations live under TypeLib\{libid}\{version}\
// {lcid}\{platform}; the reader forces the 64-bit view, so the Wow6432Node
// paths are read explicitly.
const (
	typeLibMachine      = `SOFTWARE\Classes\TypeLib`
	typeLibMachineWow64 = `SOFTWARE\Classes\Wow6432Node\TypeLib`
)

// typeLibPlatforms are the per-platform leaf keys whose default value holds
// the library path.
var typeLibPlatforms = []string{"win32", "win64", "win16"}

// walkTypeLibStores enumerates the machine and per-user TypeLib registrations,
// mirroring the CLSID walk: the native machine pass records which LibIDs exist
// so per-user entries that shadow them can be recognised.
func (w *comWalker) walkTypeLibStores(profiles map[string]string, hives []string) {
	w.walkTypeLib(winreg.LocalMachine, typeLibMachine, "HKLM", "native", false, "")
	w.walkTypeLib(winreg.LocalMachine, typeLibMachineWow64, "HKLM", "wow64", false, "")

	for _, sid := range hives {
		if w.done() {
			return
		}
		profile := profiles[sid]
		hive := `HKU\` + sid
		if !w.walkTypeLib(winreg.Users, sid+`_Classes\TypeLib`, hive, "native", true, profile) {
			w.walkTypeLib(winreg.Users, sid+`\Software\Classes\TypeLib`, hive, "native", true, profile)
		}
		w.walkTypeLib(winreg.Users, sid+`_Classes\Wow6432Node\TypeLib`, hive, "wow64", true, profile)
	}
}

// walkTypeLib enumerates every LibID under one TypeLib store and judges each
// platform leaf. It returns whether the store key existed (so the caller can
// fall back to another path for the same hive).
func (w *comWalker) walkTypeLib(root winreg.Root, path, hive, view string, user bool, profile string) bool {
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
	libIDs, err := parent.SubKeys()
	parent.Close()
	if err != nil && len(libIDs) == 0 {
		w.res.Fail(path + ": " + err.Error())
		return true
	}
	if err != nil {
		w.res.Fail(path + ": " + err.Error())
	}

	native := view == "native" && !user
	for _, libID := range libIDs {
		if w.done() {
			return true
		}
		lid := strings.ToLower(libID)
		if native {
			w.machineTypeLib[lid] = true
		}
		shadows := user && w.machineTypeLib[lid]
		w.readLibID(root, path+`\`+libID, lid, hive, view, user, profile, shadows)
	}
	return true
}

// readLibID walks the version / LCID / platform levels below one LibID and
// judges each platform leaf it finds.
func (w *comWalker) readLibID(root winreg.Root, base, libID, hive, view string, user bool, profile string, shadows bool) {
	verKey, err := winreg.Open(root, base)
	if err != nil {
		return
	}
	versions, _ := verKey.SubKeys()
	verKey.Close()

	for _, ver := range versions {
		if w.done() {
			return
		}
		// The version key's default value is the library's friendly name.
		name := ""
		if v, err := winreg.ReadValue(root, base+`\`+ver, ""); err == nil {
			name = strings.TrimSpace(v.String())
		}

		lcidKey, err := winreg.Open(root, base+`\`+ver)
		if err != nil {
			continue
		}
		lcids, _ := lcidKey.SubKeys()
		lcidKey.Close()

		for _, lcid := range lcids {
			// FLAGS and HELPDIR sit beside the LCID subkeys; the platform
			// probe below simply finds nothing under them.
			for _, plat := range typeLibPlatforms {
				val, ok := w.typeLibLeaf(root, base+`\`+ver+`\`+lcid+`\`+plat)
				if !ok {
					continue
				}
				e := typeLibEntry{
					LibID: libID, Version: ver, LCID: lcid, Platform: plat,
					Name: name, Hive: hive, User: user, View: view,
					PathRaw: val, Shadows: shadows,
				}
				// Keep a COM moniker verbatim; only path-normalise a real path.
				if typeLibScriptMoniker(val) != "" {
					e.Path = val
				} else {
					e.Path = comNormalize(val, profile)
				}

				if user {
					w.typeLibUserCount++
				} else {
					w.typeLibMachineCount++
				}

				if findings := judgeTypeLib(e); len(findings) > 0 {
					w.emitTypeLib(e, findings)
				}
			}
		}
	}
}

// typeLibLeaf reads the default value (the library path) of one platform key.
func (w *comWalker) typeLibLeaf(root winreg.Root, keyPath string) (string, bool) {
	k, err := winreg.Open(root, keyPath)
	if err != nil {
		return "", false
	}
	defer k.Close()
	d, err := k.Value("")
	if err != nil {
		return "", false
	}
	val := strings.TrimSpace(d.String())
	return val, val != ""
}

// emitTypeLib records one flagged type-library registration with its findings.
func (w *comWalker) emitTypeLib(e typeLibEntry, findings []Finding) {
	fields := map[string]any{
		"artifact": "typelib",
		"libid":    e.LibID,
		"hive":     e.Hive,
		"view":     e.View,
		"platform": e.Platform,
		"path":     e.Path,
	}
	if e.Version != "" {
		fields["version"] = e.Version
	}
	if e.LCID != "" {
		fields["lcid"] = e.LCID
	}
	if e.Name != "" {
		fields["name"] = e.Name
	}
	if e.User {
		fields["per_user"] = true
	}
	if e.PathRaw != "" && e.PathRaw != e.Path {
		fields["path_raw"] = e.PathRaw
	}
	if e.Shadows {
		fields["shadows_hklm"] = true
	}
	fields["suspicious_path"] = hasRule(findings, "persistence.typelib_unusual_path")

	// Hash a flagged library image where it is a concrete file path (not a
	// moniker), the way the CLSID walk hashes a flagged server.
	if w.opts.Hasher != nil && w.ctx.Err() == nil && e.Path != "" &&
		typeLibScriptMoniker(firstNonEmpty(e.PathRaw, e.Path)) == "" &&
		strings.ContainsAny(e.Path, `\/`) {
		w.opts.Hasher.Fields(w.ctx, fields, "path", e.Path)
	}

	w.res.Add(fields, findings...)
	w.typeLibEmitted++
}
