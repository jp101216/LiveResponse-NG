//go:build windows

package collector

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// runLocation is one Run-style key whose every value is an autostart entry.
type runLocation struct{ path, kind string }

// machineRunKeys are the per-machine Run-style locations. Wow6432Node is read
// explicitly because the reader forces the 64-bit view.
var machineRunKeys = []runLocation{
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "run"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "runonce"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, "runservices"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`, "runservicesonce"},
	{`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "policies_run"},
	{`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, "run_wow64"},
	{`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "runonce_wow64"},
}

// perUserRunKeys are the Run-style paths read under each user hive in HKU.
var perUserRunKeys = []runLocation{
	{`Software\Microsoft\Windows\CurrentVersion\Run`, "run"},
	{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, "runonce"},
	{`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "policies_run"},
}

const (
	ifeoKey        = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	ifeoKeyWow64   = `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	silentExitKey  = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`
	sessionMgrKey  = `SYSTEM\CurrentControlSet\Control\Session Manager`
	lsaKey         = `SYSTEM\CurrentControlSet\Control\Lsa`
	printMonKey    = `SYSTEM\CurrentControlSet\Control\Print\Monitors`
	maxLNKBytes    = 1 << 20
	flgMonitorExit = 0x200 // FLG_MONITOR_SILENT_PROCESS_EXIT
)

// asepWalker gathers autostart entries into one result.
type asepWalker struct {
	ctx       context.Context
	res       *Result
	opts      RunOptions
	sysRoot   string
	count     int
	cancelled bool
}

func collectAutoruns(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("autoruns")
	a := &asepWalker{ctx: ctx, res: res, opts: opts, sysRoot: systemRoot()}

	profiles, err := userProfiles()
	if err != nil {
		res.Fail("profile list: " + err.Error())
	}
	hives, err := loadedUserHives()
	if err != nil {
		res.Fail("HKU: " + err.Error())
	}

	for _, loc := range machineRunKeys {
		a.runKey(winreg.LocalMachine, loc.path, loc.kind, `HKLM\`+loc.path, "", "")
	}
	a.winlogon()
	a.appInit()
	a.ifeo()
	a.sessionManager()
	a.lsa()
	a.cmdAutoRun(winreg.LocalMachine, `SOFTWARE\Microsoft\Command Processor`, `HKLM\`, "", "")
	a.cmdAutoRun(winreg.LocalMachine, `SOFTWARE\Wow6432Node\Microsoft\Command Processor`, `HKLM\`, "", "")
	a.printMonitors()
	a.netshHelpers()

	for _, sid := range hives {
		if a.done() {
			break
		}
		profile := profiles[sid]
		for _, loc := range perUserRunKeys {
			a.runKey(winreg.Users, sid+`\`+loc.path, loc.kind, `HKU\`+sid+`\`+loc.path, profile, sid)
		}
		a.userValues(sid, profile)
	}
	a.startupFolders(profiles)

	var notLoaded []string
	for sid := range profiles {
		if !contains(hives, sid) {
			notLoaded = append(notLoaded, sid)
		}
	}
	sort.Strings(notLoaded)
	res.SetMeta("user_hives_checked", hives)
	if len(notLoaded) > 0 {
		res.SetMeta("profiles_without_loaded_hive", notLoaded)
		res.SetMeta("note", "per-user registry autostarts are read from loaded hives only; profiles listed in "+
			"profiles_without_loaded_hive were not checked (their Startup folders were)")
	}
	res.SetMeta("entry_count", a.count)
	return res.Finish(), nil
}

// done reports (and records, once) that the collector's time is up.
func (a *asepWalker) done() bool {
	if a.cancelled {
		return true
	}
	if err := a.ctx.Err(); err != nil {
		a.res.Fail("cancelled: " + err.Error())
		a.cancelled = true
	}
	return a.cancelled
}

// emit records one entry with its findings.
func (a *asepWalker) emit(e autorunEntry, raw string, keyWrite time.Time, sid string, extra map[string]any) {
	fields := map[string]any{
		"kind":     e.Kind,
		"location": e.Location,
		"name":     e.Name,
		"command":  e.Command,
	}
	if raw != "" && raw != e.Command {
		fields["command_raw"] = raw
	}
	if sid != "" {
		fields["user_sid"] = sid
	}
	if !keyWrite.IsZero() {
		fields["key_last_write"] = keyWrite
	}
	img, payload := "", ""
	if e.Command != "" {
		img = normalizeImage(imageFromCommand(e.Command))
		if strings.ContainsAny(img, `\/`) {
			fields["image"] = img
		}
		payload = proxyPayload(e.Command)
		if payload != "" {
			fields["payload"] = payload
		}
	}
	for k, v := range extra {
		fields[k] = v
	}
	findings := judgeAutorun(e, a.sysRoot)
	fields["suspicious_path"] = hasRule(findings, "persistence.autorun_unusual_path")
	if a.opts.Hasher != nil && a.ctx.Err() == nil {
		if strings.ContainsAny(img, `\/`) && (len(findings) > 0 || !underDir(img, a.sysRoot)) {
			a.opts.Hasher.Fields(a.ctx, fields, "image", img)
		}
		if payload != "" {
			a.opts.Hasher.Fields(a.ctx, fields, "payload", payload)
		}
	}
	a.res.Add(fields, findings...)
	a.count++
}

// readKey opens a key and returns its values (by lower-case name) and
// last-write time. A missing key is normal for optional locations and is
// not reported; other failures are.
func (a *asepWalker) readKey(root winreg.Root, path, label string) (map[string]winreg.Value, []winreg.Value, time.Time, bool) {
	k, err := winreg.Open(root, path)
	if err != nil {
		if !winreg.IsNotExist(err) {
			a.res.Fail(label + ": " + err.Error())
		}
		return nil, nil, time.Time{}, false
	}
	defer k.Close()
	vals, err := k.Values()
	if err != nil {
		a.res.Fail(label + ": " + err.Error())
		return nil, nil, time.Time{}, false
	}
	m := make(map[string]winreg.Value, len(vals))
	for _, v := range vals {
		m[strings.ToLower(v.Name)] = v
	}
	return m, vals, k.LastWrite(), true
}

// runKey records every value under a Run-style key as one entry, noting
// entries switched off in Task Manager's Startup tab (StartupApproved).
func (a *asepWalker) runKey(root winreg.Root, path, kind, label, profile, sid string) {
	if a.done() {
		return
	}
	_, vals, lw, ok := a.readKey(root, path, label)
	if !ok {
		return
	}
	approved := a.startupApproved(root, path, sid)
	for _, v := range vals {
		cmd, raw := regString(v, profile)
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		var extra map[string]any
		if on, known := approved[strings.ToLower(v.Name)]; known {
			extra = map[string]any{"startup_approved": on}
		}
		a.emit(autorunEntry{Kind: kind, Location: label, Name: v.Name, Command: cmd, Enabled: true}, raw, lw, sid, extra)
	}
}

// startupApproved reads Explorer's StartupApproved state for a Run key: a
// value per entry whose first byte has bit 0 set when the user disabled it.
func (a *asepWalker) startupApproved(root winreg.Root, runPath, sid string) map[string]bool {
	sub := ""
	switch {
	case strings.HasSuffix(strings.ToLower(runPath), `wow6432node\microsoft\windows\currentversion\run`):
		sub = "Run32"
	case strings.HasSuffix(strings.ToLower(runPath), `currentversion\run`):
		sub = "Run"
	default:
		return nil
	}
	base := `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\` + sub
	if root == winreg.Users {
		base = sid + `\` + base
	}
	k, err := winreg.Open(root, base)
	if err != nil {
		return nil
	}
	defer k.Close()
	vals, _ := k.Values()
	out := map[string]bool{}
	for _, v := range vals {
		if len(v.Data) > 0 {
			out[strings.ToLower(v.Name)] = v.Data[0]&1 == 0
		}
	}
	return out
}

// winlogon records the Winlogon Shell and Userinit values (judged against
// their defaults) and the rarely used Taskman/AppSetup values.
func (a *asepWalker) winlogon() {
	const path = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	label := `HKLM\` + path
	vals, _, lw, ok := a.readKey(winreg.LocalMachine, path, label)
	if !ok {
		return
	}
	for _, c := range []struct{ name, kind string }{
		{"Shell", "winlogon"}, {"Userinit", "winlogon"}, {"Taskman", "winlogon_extra"}, {"AppSetup", "winlogon_extra"},
	} {
		cmd, raw := regString(vals[strings.ToLower(c.name)], "")
		if strings.TrimSpace(cmd) == "" {
			continue
		}
		a.emit(autorunEntry{Kind: c.kind, Location: label, Name: c.name, Command: cmd, Enabled: true}, raw, lw, "", nil)
	}
}

// appInit records AppInit_DLLs (native and WOW64), one entry per DLL.
func (a *asepWalker) appInit() {
	for _, path := range []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	} {
		label := `HKLM\` + path
		vals, _, lw, ok := a.readKey(winreg.LocalMachine, path, label)
		if !ok {
			continue
		}
		dlls, raw := regString(vals["appinit_dlls"], "")
		load, _ := vals["loadappinit_dlls"].Uint32()
		for _, dll := range strings.FieldsFunc(dlls, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			a.emit(autorunEntry{Kind: "appinit_dlls", Location: label, Name: "AppInit_DLLs", Command: dll, Enabled: load != 0},
				raw, lw, "", map[string]any{"enabled": load != 0})
		}
	}
}

// ifeo records Image File Execution Options debuggers (native and WOW64)
// and SilentProcessExit monitor processes. Where Windows shares the IFEO key
// between the two registry views, the WOW64 copy repeats the native entry;
// identical repeats are reported once.
func (a *asepWalker) ifeo() {
	globalFlags := map[string]uint32{}
	native := map[string]string{} // image name -> debugger, native view
	for _, base := range []string{ifeoKey, ifeoKeyWow64} {
		root, err := winreg.Open(winreg.LocalMachine, base)
		if err != nil {
			if !winreg.IsNotExist(err) {
				a.res.Fail(`HKLM\` + base + ": " + err.Error())
			}
			continue
		}
		names, err := root.SubKeys()
		root.Close()
		if err != nil {
			a.res.Fail(`HKLM\` + base + ": " + err.Error())
		}
		for _, name := range names {
			if a.done() {
				return
			}
			label := `HKLM\` + base + `\` + name
			vals, _, lw, ok := a.readKey(winreg.LocalMachine, base+`\`+name, label)
			if !ok {
				continue
			}
			if gf, ok := globalFlag(vals["globalflag"]); ok && base == ifeoKey {
				globalFlags[strings.ToLower(name)] = gf
			}
			if dbg, raw := regString(vals["debugger"], ""); strings.TrimSpace(dbg) != "" {
				key := strings.ToLower(name)
				if base == ifeoKey {
					native[key] = dbg
				} else if native[key] == dbg {
					continue // the shared key seen through the WOW64 view
				}
				a.emit(autorunEntry{Kind: "ifeo_debugger", Location: label, Name: name, Command: dbg, Enabled: true}, raw, lw, "", nil)
			}
		}
	}

	root, err := winreg.Open(winreg.LocalMachine, silentExitKey)
	if err != nil {
		if !winreg.IsNotExist(err) {
			a.res.Fail(`HKLM\` + silentExitKey + ": " + err.Error())
		}
		return
	}
	names, _ := root.SubKeys()
	root.Close()
	for _, name := range names {
		label := `HKLM\` + silentExitKey + `\` + name
		vals, _, lw, ok := a.readKey(winreg.LocalMachine, silentExitKey+`\`+name, label)
		if !ok {
			continue
		}
		mon, raw := regString(vals["monitorprocess"], "")
		if strings.TrimSpace(mon) == "" {
			continue
		}
		active := globalFlags[strings.ToLower(name)]&flgMonitorExit != 0
		a.emit(autorunEntry{Kind: "silent_process_exit", Location: label, Name: name, Command: mon, Enabled: active},
			raw, lw, "", map[string]any{"enabled": active})
	}
}

// globalFlag decodes an IFEO GlobalFlag, stored as a DWORD or a hex string.
func globalFlag(v winreg.Value) (uint32, bool) {
	if d, ok := v.Uint32(); ok {
		return d, true
	}
	s := strings.TrimSpace(v.String())
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// sessionManager records BootExecute/SetupExecute/Execute (programs run
// before Windows starts) and AppCertDLLs.
func (a *asepWalker) sessionManager() {
	label := `HKLM\` + sessionMgrKey
	vals, _, lw, ok := a.readKey(winreg.LocalMachine, sessionMgrKey, label)
	if ok {
		for _, name := range []string{"BootExecute", "SetupExecute", "Execute"} {
			for _, cmd := range vals[strings.ToLower(name)].Strings() {
				if strings.TrimSpace(cmd) == "" {
					continue
				}
				a.emit(autorunEntry{Kind: "boot_execute", Location: label, Name: name, Command: cmd, Enabled: true}, "", lw, "", nil)
			}
		}
	}
	certLabel := label + `\AppCertDlls`
	_, certs, clw, ok := a.readKey(winreg.LocalMachine, sessionMgrKey+`\AppCertDlls`, certLabel)
	if ok {
		for _, v := range certs {
			cmd, raw := regString(v, "")
			if strings.TrimSpace(cmd) != "" {
				a.emit(autorunEntry{Kind: "appcert_dlls", Location: certLabel, Name: v.Name, Command: cmd, Enabled: true}, raw, clw, "", nil)
			}
		}
	}
}

// lsa records the packages LSASS loads: authentication packages, security
// support providers and password filters.
func (a *asepWalker) lsa() {
	for _, path := range []string{lsaKey, lsaKey + `\OSConfig`} {
		label := `HKLM\` + path
		vals, _, lw, ok := a.readKey(winreg.LocalMachine, path, label)
		if !ok {
			continue
		}
		for _, c := range []struct{ value, kind string }{
			{"Authentication Packages", "lsa_authentication_packages"},
			{"Security Packages", "lsa_security_packages"},
			{"Notification Packages", "lsa_notification_packages"},
		} {
			for _, pkg := range vals[strings.ToLower(c.value)].Strings() {
				pkg = strings.TrimSpace(pkg)
				if pkg == "" || pkg == `""` {
					continue
				}
				a.emit(autorunEntry{Kind: c.kind, Location: label, Name: c.value, Command: pkg, Enabled: true}, "", lw, "", nil)
			}
		}
	}
}

// cmdAutoRun records a Command Processor AutoRun value.
func (a *asepWalker) cmdAutoRun(root winreg.Root, path, prefix, profile, sid string) {
	label := prefix + path
	vals, _, lw, ok := a.readKey(root, path, label)
	if !ok {
		return
	}
	if cmd, raw := regString(vals["autorun"], profile); strings.TrimSpace(cmd) != "" {
		a.emit(autorunEntry{Kind: "cmd_autorun", Location: label, Name: "AutoRun", Command: cmd, Enabled: true}, raw, lw, sid, nil)
	}
}

// printMonitors records the DLL of every print monitor (loaded by the
// spooler, as SYSTEM).
func (a *asepWalker) printMonitors() {
	root, err := winreg.Open(winreg.LocalMachine, printMonKey)
	if err != nil {
		return
	}
	names, _ := root.SubKeys()
	root.Close()
	for _, name := range names {
		label := `HKLM\` + printMonKey + `\` + name
		vals, _, lw, ok := a.readKey(winreg.LocalMachine, printMonKey+`\`+name, label)
		if !ok {
			continue
		}
		if dll, raw := regString(vals["driver"], ""); strings.TrimSpace(dll) != "" {
			a.emit(autorunEntry{Kind: "print_monitor", Location: label, Name: name, Command: dll, Enabled: true}, raw, lw, "", nil)
		}
	}
}

// netshHelpers records the helper DLLs netsh loads.
func (a *asepWalker) netshHelpers() {
	const path = `SOFTWARE\Microsoft\NetSh`
	label := `HKLM\` + path
	_, vals, lw, ok := a.readKey(winreg.LocalMachine, path, label)
	if !ok {
		return
	}
	for _, v := range vals {
		if dll, raw := regString(v, ""); strings.TrimSpace(dll) != "" {
			a.emit(autorunEntry{Kind: "netsh_helper", Location: label, Name: v.Name, Command: dll, Enabled: true}, raw, lw, "", nil)
		}
	}
}

// userValues records the per-user autostart values outside Run keys:
// Winlogon Shell, the legacy Windows Load/Run values, Command Processor
// AutoRun and the screensaver.
func (a *asepWalker) userValues(sid, profile string) {
	base := `HKU\` + sid + `\`
	if vals, _, lw, ok := a.readKey(winreg.Users, sid+`\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		base+`Software\Microsoft\Windows NT\CurrentVersion\Winlogon`); ok {
		if cmd, raw := regString(vals["shell"], profile); strings.TrimSpace(cmd) != "" {
			a.emit(autorunEntry{Kind: "winlogon", Location: base + `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,
				Name: "Shell", Command: cmd, Enabled: true}, raw, lw, sid, nil)
		}
	}
	winPath := `Software\Microsoft\Windows NT\CurrentVersion\Windows`
	if vals, _, lw, ok := a.readKey(winreg.Users, sid+`\`+winPath, base+winPath); ok {
		for _, name := range []string{"Load", "Run"} {
			if cmd, raw := regString(vals[strings.ToLower(name)], profile); strings.TrimSpace(cmd) != "" {
				a.emit(autorunEntry{Kind: "windows_load", Location: base + winPath, Name: name, Command: cmd, Enabled: true}, raw, lw, sid, nil)
			}
		}
	}
	a.cmdAutoRun(winreg.Users, sid+`\Software\Microsoft\Command Processor`, `HKU\`, profile, sid)
	deskPath := `Control Panel\Desktop`
	if vals, _, lw, ok := a.readKey(winreg.Users, sid+`\`+deskPath, base+deskPath); ok {
		if scr, raw := regString(vals["scrnsave.exe"], profile); strings.TrimSpace(scr) != "" {
			a.emit(autorunEntry{Kind: "screensaver", Location: base + deskPath, Name: "SCRNSAVE.EXE", Command: scr, Enabled: true}, raw, lw, sid, nil)
		}
	}
}

// startupFolders records what sits in the all-users and per-user Startup
// folders. Shortcuts are judged by what they launch (target and arguments);
// programs and scripts dropped there directly are flagged as such.
func (a *asepWalker) startupFolders(profiles map[string]string) {
	var folders []string
	common := ""
	if v, err := winreg.ReadValue(winreg.LocalMachine,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, "Common Startup"); err == nil {
		common, _ = regString(v, "")
	}
	if common == "" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		common = filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`)
	}
	folders = append(folders, common)
	for _, p := range profileDirs(profiles) {
		folders = append(folders, filepath.Join(p, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
	}

	for _, dir := range folders {
		if a.done() {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // a profile without a Startup folder is normal
		}
		for _, d := range entries {
			if d.IsDir() || strings.EqualFold(d.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(dir, d.Name())
			extra := map[string]any{"path": full}
			if info, err := d.Info(); err == nil {
				addFileTimes(extra, "file_", info)
				extra["size"] = info.Size()
			}
			e := autorunEntry{Kind: "startup_folder", Location: dir, Name: d.Name(), Command: full, Enabled: true}
			switch strings.ToLower(filepath.Ext(d.Name())) {
			case ".lnk":
				l, err := readLNK(full)
				if err != nil {
					extra["shortcut_error"] = err.Error()
					break
				}
				e.Command = l.Command()
				extra["shortcut_target"] = l.Target
				extra["shortcut_target_source"] = l.TargetSource
				if l.Arguments != "" {
					extra["shortcut_arguments"] = l.Arguments
				}
				if l.WorkingDir != "" {
					extra["shortcut_working_dir"] = l.WorkingDir
				}
			case ".url":
				if u := readURLShortcut(full); u != "" {
					extra["url"] = u
					e.Command = u
				}
			default:
				e.Direct = true
			}
			a.emit(e, "", time.Time{}, "", extra)
		}
	}
}

// readLNK reads and parses a shortcut, bounded in size.
func readLNK(path string) (lnkInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return lnkInfo{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxLNKBytes))
	if err != nil {
		return lnkInfo{}, err
	}
	return parseLNK(b)
}

// readURLShortcut returns the URL= line of an Internet shortcut.
func readURLShortcut(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	for _, line := range strings.Split(string(b), "\n") {
		if l := strings.TrimSpace(line); len(l) > 4 && strings.EqualFold(l[:4], "url=") {
			return l[4:]
		}
	}
	return ""
}
