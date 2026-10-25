package collector

import (
	"strconv"
	"strings"
	"time"

	"github.com/jp101216/liveresponse-ng/internal/winreg"
)

// AmCache extraction. Amcache.hve records programs that were present on the
// host — and, for many entries, that ran — with a SHA-1, the PE link date, the
// publisher and the file's own path. It survives a binary's deletion, which is
// why it's prized in DFIR. The hive navigation is done by the offline reader in
// internal/winreg; the mapping of hive entries to records and findings lives
// here, tag-free and unit-tested on any OS.
//
// Two layouts are covered: InventoryApplicationFile (Windows 10 1709+ and
// Server 2019+), the rich current format; and the legacy Root\File\{volume}\
// {fileref} layout (Windows 8 through early Windows 10 / Server 2016), whose
// numbered values are mapped conservatively — the path (15) and SHA-1 (101),
// the two that are well established.

type amcacheEntry struct {
	Key        string
	Source     string
	Path       string
	Name       string
	SHA1       string
	Publisher  string
	Version    string
	BinaryType string
	LinkDate   string
	ProgramID  string
	Size       int64
	HasSize    bool
	LastWrite  time.Time
}

// extractAmcache reads the entries from a parsed hive and returns them with
// collection metadata. Missing subtrees are normal (which layout is present
// depends on the Windows version), so they're noted, not errors.
func extractAmcache(h *winreg.Hive) ([]amcacheEntry, map[string]any) {
	meta := map[string]any{}
	var out []amcacheEntry

	if k, err := h.KeyAt("InventoryApplicationFile"); err == nil {
		subs, _ := k.SubKeys()
		meta["inventory_application_file_count"] = len(subs)
		for _, s := range subs {
			out = append(out, iafEntry(s.Name, s.LastWrite, s.ValueMap()))
		}
	} else {
		meta["inventory_application_file_present"] = false
	}

	if fk, err := h.KeyAt("File"); err == nil {
		n := 0
		vols, _ := fk.SubKeys()
		for _, vol := range vols {
			files, _ := vol.SubKeys()
			for _, f := range files {
				if e := legacyFileEntry(f.Name, f.LastWrite, f.ValueMap()); e.Path != "" || e.SHA1 != "" {
					out = append(out, e)
					n++
				}
			}
		}
		meta["file_entry_count"] = n
	}
	return out, meta
}

func iafEntry(name string, lw time.Time, vm map[string]winreg.Value) amcacheEntry {
	e := amcacheEntry{Key: name, Source: "InventoryApplicationFile", LastWrite: lw}
	e.Path = vm["lowercaselongpath"].String()
	e.Name = vm["name"].String()
	e.Publisher = vm["publisher"].String()
	e.Version = vm["version"].String()
	e.BinaryType = vm["binarytype"].String()
	e.LinkDate = vm["linkdate"].String()
	e.ProgramID = vm["programid"].String()
	e.SHA1 = amcacheSHA1(vm["fileid"].String())
	if n, ok := vm["size"].Uint64(); ok {
		e.Size, e.HasSize = int64(n), true
	} else if s := strings.TrimSpace(vm["size"].String()); s != "" {
		if n, err := strconv.ParseInt(s, 0, 64); err == nil {
			e.Size, e.HasSize = n, true
		}
	}
	return e
}

func legacyFileEntry(name string, lw time.Time, vm map[string]winreg.Value) amcacheEntry {
	return amcacheEntry{
		Key:       name,
		Source:    "File",
		LastWrite: lw,
		Path:      vm["15"].String(),               // full path
		SHA1:      amcacheSHA1(vm["101"].String()), // SHA-1 (often "0000"+hash)
	}
}

// amcacheSHA1 normalises an AmCache FileId to a 40-hex SHA-1. AmCache stores it
// as a 44-character string with a four-zero prefix; a bare 40-hex value is
// accepted too. Anything else yields "".
func amcacheSHA1(fileID string) string {
	s := strings.ToLower(strings.TrimSpace(fileID))
	if len(s) == 44 && strings.HasPrefix(s, "0000") {
		s = s[4:]
	}
	if len(s) == 40 && isHexStr(s) {
		return s
	}
	return ""
}

func isHexStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func amcacheFields(e amcacheEntry) map[string]any {
	f := map[string]any{"key": e.Key, "source": e.Source}
	if e.Path != "" {
		f["path"] = e.Path
		f["suspicious_path"] = suspiciousPath(e.Path)
	}
	if e.Name != "" {
		f["name"] = e.Name
	}
	if e.SHA1 != "" {
		f["sha1"] = e.SHA1
	}
	if e.Publisher != "" {
		f["publisher"] = e.Publisher
	}
	if e.Version != "" {
		f["version"] = e.Version
	}
	if e.BinaryType != "" {
		f["binary_type"] = e.BinaryType
	}
	if e.LinkDate != "" {
		f["link_date"] = e.LinkDate
	}
	if e.ProgramID != "" {
		f["program_id"] = e.ProgramID
	}
	if e.HasSize {
		f["size"] = e.Size
	}
	if !e.LastWrite.IsZero() {
		f["key_last_write"] = e.LastWrite
	}
	return f
}

func amcacheFindings(e amcacheEntry) []Finding {
	if e.Path == "" {
		return nil
	}
	lvl, why := pathRisk(e.Path)
	if lvl != riskHigh {
		return nil
	}
	detail := "AmCache recorded a program in " + why + " (it was present, and may have run): " + e.Path
	if e.SHA1 != "" {
		detail += " [sha1 " + e.SHA1 + "]"
	}
	return []Finding{{
		Rule:       "execution.amcache_unusual_path",
		Severity:   SevNotable,
		Technique:  "T1204.002",
		Confidence: 45,
		Detail:     detail,
	}}
}
