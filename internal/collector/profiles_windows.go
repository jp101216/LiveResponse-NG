//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

// isUserSID reports whether a SID belongs to a real interactive account:
// local or domain (S-1-5-21-...) or Microsoft Entra ID / Azure AD
// (S-1-12-1-...). Service SIDs and the _Classes hive companions are not.
func isUserSID(sid string) bool {
	if strings.HasSuffix(sid, "_Classes") {
		return false
	}
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// userProfiles maps user SIDs to their profile directories, from the
// registry's ProfileList.
func userProfiles() (map[string]string, error) {
	root, err := winreg.Open(winreg.LocalMachine, profileListKey)
	if err != nil {
		return nil, err
	}
	sids, err := root.SubKeys()
	root.Close()
	out := map[string]string{}
	for _, sid := range sids {
		if !isUserSID(sid) || strings.HasSuffix(sid, ".bak") {
			continue // ".bak" keys are leftovers of a profile Windows rebuilt
		}
		v, verr := winreg.ReadValue(winreg.LocalMachine, profileListKey+`\`+sid, "ProfileImagePath")
		if verr != nil {
			continue
		}
		if p, _ := regString(v, ""); p != "" {
			out[sid] = p
		}
	}
	return out, err
}

// loadedUserHives lists the user hives currently loaded under HKU (the users
// logged on, or with processes running). Per-user registry autostarts of
// anyone else can't be read without loading their NTUSER.DAT, which lrng
// deliberately doesn't do (it would modify the live registry).
func loadedUserHives() ([]string, error) {
	root, err := winreg.Open(winreg.Users, "")
	if err != nil {
		return nil, err
	}
	subs, err := root.SubKeys()
	root.Close()
	var out []string
	for _, s := range subs {
		if isUserSID(s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, err
}

// profileDirs returns every user profile directory: those in ProfileList
// plus any folder under <SystemDrive>\Users that looks like a profile (an
// account deleted from the registry can leave its folder — and its Startup
// folder — behind).
func profileDirs(profiles map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		k := strings.ToLower(filepath.Clean(p))
		if p == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, p)
	}
	for _, p := range profiles {
		add(p)
	}
	root := systemRoot()
	usersDir := `C:\Users`
	if len(root) >= 2 && root[1] == ':' {
		usersDir = root[:2] + `\Users`
	}
	if entries, err := os.ReadDir(usersDir); err == nil {
		for _, e := range entries {
			switch strings.ToLower(e.Name()) {
			case "public", "default", "default user", "all users":
				continue
			}
			if e.IsDir() {
				add(filepath.Join(usersDir, e.Name()))
			}
		}
	}
	sort.Strings(out)
	return out
}
