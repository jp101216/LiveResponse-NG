package collector

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func commandDigest(cmd string) string {
	// Preserve case and arguments. Whitespace normalization inside quoted
	// strings would invent command equivalence. Remove only surrounding space.
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(cmd))))
}

// correlateModern uses live process creation times before making ancestry or
// module joins. A bare PID from separate snapshots is never enough.
func correlateModern(results []Result) {
	pr := findResult(results, "processes")
	if pr == nil {
		return
	}
	index := map[string][]int{}
	for i, rec := range pr.Records {
		if p := graphPID(rec.Fields["pid"]); p != "" {
			index[p] = append(index[p], i)
		}
	}
	resultIndex := func(name string) int {
		for i := range results {
			if results[i].Collector == name {
				return i
			}
		}
		return -1
	}
	pi := resultIndex("processes")
	parent := func(rec *Record) (int, bool) {
		if rec.Fields["parent_pid_reused"] == true {
			return 0, false
		}
		ids := index[graphPID(rec.Fields["ppid"])]
		if len(ids) != 1 {
			return 0, false
		}
		p := pr.Records[ids[0]]
		a, b := graphTime(p.Fields["created_at"]), graphTime(rec.Fields["created_at"])
		return ids[0], !a.IsZero() && !b.IsZero() && a.Before(b)
	}
	for i := range pr.Records {
		rec := &pr.Records[i]
		if rec.Fields["lrng_component"] == true {
			continue
		}
		cmd, img := stringField(rec.Fields, "command_line"), stringField(rec.Fields, "image_path")
		identity := firstNonEmpty(stringField(rec.Fields, "original_file_name"), img)
		if isIDETunnel(identity, cmd) && !hasRule(rec.Findings, "remote.ide_tunnel") {
			rec.Findings = mergeFindings(rec.Findings, Finding{"remote.ide_tunnel", SevNotable, "T1219.001", 40, "remote-tunnel arguments and executable identity metadata indicate VS Code-style tunneling; version-resource names are self-reported and legitimate developer use is possible"})
		}
		pidx, verified := parent(rec)
		if !verified {
			continue
		}
		p := pr.Records[pidx]
		pn := baseName(firstNonEmpty(stringField(p.Fields, "image_path"), stringField(p.Fields, "name")))
		c := prepareCommand(img, cmd)
		if (pn == "explorer.exe" || pn == "windowsterminal.exe" || pn == "wt.exe") && c.ps && cradle(c) && executes(c) {
			rec.Findings = mergeFindings(rec.Findings, Finding{"correlate.interactive_payload", SevSuspect, "T1204.004", 65,
				"OS-reported interactive-shell ancestry and a download/execute command coincide; consistent with paste-and-run delivery, but user intent and lure origin are unknown"})
			rec.Fields["detection_source_refs"] = []EvidenceRef{{pi, pidx}}
		}
		if isIDETunnel(identity, cmd) && (pn == "wscript.exe" || pn == "cscript.exe" || recordHasSeverity(&p, SevSuspect)) {
			rec.Findings = mergeFindings(rec.Findings, Finding{"remote.ide_tunnel_suspicious_context", SevSuspect, "T1219.001", 70,
				"remote-tunnel arguments accompany a verified script-host or suspicious parent; validate approved automation and the tunnel's owner"})
			rec.Fields["detection_source_refs"] = []EvidenceRef{{pi, pidx}}
		}
	}
	// Exact command + exact account links RunMRU to a live observation. The
	// shared registry timestamp deliberately plays no part in this match.
	if rh := findResult(results, "runhistory"); rh != nil {
		byCommand := map[string][]int{}
		for i, rec := range rh.Records {
			if sid := stringField(rec.Fields, "user_sid"); sid != "" {
				byCommand[sid+":"+stringField(rec.Fields, "command_sha256")] = append(byCommand[sid+":"+stringField(rec.Fields, "command_sha256")], i)
			}
		}
		for i := range pr.Records {
			rec := &pr.Records[i]
			cmd := stringField(rec.Fields, "command_line")
			sid := stringField(rec.Fields, "user_sid")
			if cmd == "" || sid == "" || !recordHasSeverity(rec, SevSuspect) {
				continue
			}
			ids := byCommand[sid+":"+commandDigest(cmd)]
			if len(ids) != 1 {
				continue
			}
			rec.Findings = mergeFindings(rec.Findings, Finding{"correlate.run_dialog_command", SevSuspect, "T1204.004", 70,
				"the same exact command is present in this account's RunMRU and in a suspicious live process; this is command correspondence, not proof of when or how it was launched"})
			refs, _ := rec.Fields["detection_source_refs"].([]EvidenceRef)
			ref := EvidenceRef{resultIndex("runhistory"), ids[0]}
			found := false
			for _, old := range refs {
				if old == ref {
					found = true
					break
				}
			}
			if !found {
				rec.Fields["detection_source_refs"] = append(refs, ref)
			}
		}
	}
	mods := findResult(results, "modules")
	if mods == nil {
		return
	}
	for mi := range mods.Records {
		m := &mods.Records[mi]
		if !hasRule(m.Findings, "modules.side_load_candidate") {
			continue
		}
		ids := index[graphPID(m.Fields["pid"])]
		if len(ids) != 1 {
			continue
		}
		pidx := ids[0]
		p := pr.Records[pidx]
		a, b := graphTime(m.Fields["process_created_at"]), graphTime(p.Fields["created_at"])
		if a.IsZero() || !a.Equal(b) || graphPathKey(stringField(m.Fields, "image_path")) != graphPathKey(stringField(p.Fields, "image_path")) {
			continue
		}
		for ci := range pr.Records {
			child := &pr.Records[ci]
			parentID, ok := parent(child)
			if !ok || parentID != pidx || !recordHasSeverity(child, SevSuspect) {
				continue
			}
			m.Findings = mergeFindings(m.Findings, Finding{"correlate.dll_sideload_context", SevSuspect, "T1574.001", 75,
				"a signed-host/adjacent-DLL candidate has a suspicious child, joined using exact process creation times and image path; the observations support investigation but do not establish which DLL caused the child"})
			m.Fields["detection_source_refs"] = []EvidenceRef{{pi, pidx}, {pi, ci}}
			break
		}
	}
}
