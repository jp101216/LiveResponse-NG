package collector

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// EvidenceRef addresses an original observation, never a copy of its findings.
type EvidenceRef struct {
	Result int `json:"result"`
	Record int `json:"record"`
}

const graphMaxNodes = 5000
const graphMaxEdges = 15000

type evidenceNode struct {
	id        string
	ref       EvidenceRef
	collector string
	rec       Record
}

// BuildEvidenceGraph derives a bounded graph without reading the host. An
// observed edge means the source explicitly reports the relationship; it does
// not authenticate that source or prove causation. Matching paths/PIDs are
// always inferences. Record indices refer to the unchanged input results.
func BuildEvidenceGraph(results []Result, host string) Result {
	res := NewResult("evidence_graph")
	var nodes []evidenceNode
	processes := map[string][]int{}
	spans := map[string][]int{}
	paths := map[string]int{}
	accounts := map[string][]int{}
	services := map[string]int{}
	tasks := map[string]int{}
	total := 0
	var selected []EvidenceRef
	for _, r := range results {
		if graphDerived(r.Collector) {
			continue
		}
		total += len(r.Records)
	}
	// Preserve high-severity evidence and process context when a large event
	// log would otherwise consume the whole graph before live state appears.
	for priority := 0; priority < 4; priority++ {
		for ri, r := range results {
			if graphDerived(r.Collector) {
				continue
			}
			for i, rec := range r.Records {
				if len(selected) < graphMaxNodes && graphPriority(r.Collector, rec) == priority {
					selected = append(selected, EvidenceRef{ri, i})
				}
			}
		}
	}
	byRef := map[EvidenceRef]int{}
	for _, ref := range selected {
		ri, i := ref.Result, ref.Record
		r := results[ri]
		rec := r.Records[i]
		n := evidenceNode{fmt.Sprintf("r%d:%d", ri, i), EvidenceRef{ri, i}, r.Collector, rec}
		idx := len(nodes)
		byRef[ref] = idx
		nodes = append(nodes, n)
		rule, sev := topFinding(rec)
		res.Add(map[string]any{
			"kind": "node", "id": n.id, "node_type": r.Collector,
			"label": graphLabel(r.Collector, rec), "source_ref": n.ref,
			"source_collector": r.Collector, "top_rule": rule, "severity": sev,
		})
		if r.Collector == "processes" {
			if pid := graphPID(rec.Fields["pid"]); pid != "" {
				processes[pid] = append(processes[pid], idx)
			}
		}
		if r.Collector == "agenttrace" {
			if k := graphSpanKey(rec.Fields, "span_id"); k != "" {
				spans[k] = append(spans[k], idx)
			}
		}
		if r.Collector == "localaccounts" {
			if k := graphAccount(rec.Fields); k != "" {
				accounts[k] = append(accounts[k], idx)
			}
		}
		if r.Collector == "services" {
			if name := stringField(rec.Fields, "name"); name != "" {
				services[strings.ToLower(name)] = idx
			}
		}
		if r.Collector == "scheduledtasks" {
			if name := stringField(rec.Fields, "task_path"); name != "" {
				tasks[normTaskName(name)] = idx
			}
		}
	}
	edges, inferred, missingParents := 0, 0, 0
	seen := map[string]bool{}
	addEdge := func(from, to int, relation, basis, explanation string) {
		if from == to || edges >= graphMaxEdges {
			return
		}
		a, b := nodes[from], nodes[to]
		key := a.id + "\x00" + b.id + "\x00" + relation
		if seen[key] {
			return
		}
		seen[key] = true
		res.Add(map[string]any{
			"kind": "edge", "from": a.id, "to": b.id, "relation": relation,
			"basis": basis, "explanation": explanation,
			"source_refs": []EvidenceRef{a.ref, b.ref},
		})
		edges++
		if basis == "inferred" {
			inferred++
		}
	}
	for i, n := range nodes {
		f := n.rec.Fields
		if refs, ok := f["detection_source_refs"].([]EvidenceRef); ok {
			for _, ref := range refs {
				if source, ok := byRef[ref]; ok {
					addEdge(source, i, "corroborates_detection", "inferred", "This source observation contributed to a contextual detection. The finding explains the match and its attribution limits.")
				}
			}
		}
		if indices, ok := f["supporting_events"].([]int); ok && n.collector == "cloudaudit" {
			for _, idx := range indices {
				if source, ok := byRef[EvidenceRef{n.ref.Result, idx}]; ok {
					addEdge(source, i, "contributes_to_analysis", "inferred", "This supplied cloud event contributes to a bounded heuristic window. This does not authenticate the log or establish compromise.")
				}
			}
		}
		if n.collector == "eventlog" {
			if name := eventDataField(&n.rec, "ServiceName"); name != "" {
				if target, ok := services[strings.ToLower(name)]; ok {
					addEdge(i, target, "same_service_name", "inferred", "An event names a service with this current name. The service may have been removed and recreated.")
				}
			}
			if name := eventDataField(&n.rec, "TaskName"); name != "" {
				if target, ok := tasks[normTaskName(name)]; ok {
					addEdge(i, target, "same_task_name", "inferred", "An event names a task with this current path. The task may have changed since the event.")
				}
			}
		}
		if refs, ok := f["source_refs"].([]EvidenceRef); n.collector == "adaptive" && ok {
			for _, ref := range refs {
				if source, ok := byRef[ref]; ok {
					addEdge(source, i, "triggered_follow_up", "observed", "The source finding selected this later file observation for bounded follow-up; file identity may have changed.")
				}
			}
		}
		if n.collector == "processes" && f["parent_pid_reused"] != true {
			if ps := processes[graphPID(f["ppid"])]; len(ps) == 1 {
				p := ps[0]
				pt, ct := graphTime(nodes[p].rec.Fields["created_at"]), graphTime(f["created_at"])
				if !pt.IsZero() && !ct.IsZero() && !pt.After(ct) {
					addEdge(p, i, "reported_parent", "observed", "OS-reported parent PID; both process start times checked. Parent spoofing remains possible.")
				} else if pt.IsZero() || ct.IsZero() {
					addEdge(p, i, "candidate_parent", "inferred", "Parent PID matches; missing start times prevent ruling out PID reuse.")
				}
			}
		}
		if n.collector == "network" || n.collector == "udp" || n.collector == "memory" || n.collector == "modules" {
			if ps := processes[graphPID(f["pid"])]; len(ps) == 1 {
				addEdge(ps[0], i, "same_pid", "inferred", "PID matches observations taken by separate collectors; PID reuse between snapshots is possible.")
			}
		}
		if n.collector == "agenttrace" {
			if key := graphSpanKey(f, "parent_span_id"); key != "" {
				if ps := spans[key]; len(ps) == 1 {
					addEdge(ps[0], i, "reported_trace_parent", "observed", "The imported trace declares this parent span; telemetry is not independent proof of execution.")
				} else {
					missingParents++
				}
			}
			// Never join an arbitrary imported PID to this machine's process.
			if host != "" && strings.EqualFold(host, stringField(f, "host")) {
				if ps := processes[graphPID(f["pid"])]; len(ps) == 1 {
					start := graphTime(f["process_created_at"])
					if !start.IsZero() && start.Equal(graphTime(nodes[ps[0]].rec.Fields["created_at"])) {
						addEdge(ps[0], i, "trace_process", "inferred", "Imported host, PID and process start time match this snapshot; trace claims remain unverified.")
					}
				}
			}
		}
		if n.collector != "localaccounts" {
			if as := accounts[graphAccount(f)]; len(as) == 1 {
				addEdge(as[0], i, "same_account", "inferred", "Account SID or UID matches; this is identity context, not proof that the account initiated the action. Container user namespaces may differ.")
			}
		}
		for _, path := range graphPaths(f) {
			key := graphPathKey(path)
			if anchor, ok := paths[key]; ok {
				// A star per path avoids quadratic expansion for common images.
				a, b := graphImageHash(nodes[anchor].rec.Fields), graphImageHash(f)
				if a == "" || b == "" || a == b {
					addEdge(anchor, i, "same_path", "inferred", "Recorded absolute paths match. Contents, mount namespaces and file identity may differ; this does not prove execution.")
				}
			} else {
				paths[key] = i
			}
		}
	}
	// Shared destinations provide a pivot without claiming a common operator.
	destinations := map[string]int{}
	for i, n := range nodes {
		if n.collector != "network" {
			continue
		}
		ip, err := netip.ParseAddr(stringField(n.rec.Fields, "remote_addr"))
		port := graphNumber(n.rec.Fields["remote_port"])
		if err != nil || ip.IsUnspecified() || port == "" || port == "0" {
			continue
		}
		key := ip.Unmap().String() + ":" + port
		if a, ok := destinations[key]; ok {
			addEdge(a, i, "same_destination", "inferred", "Remote IP and port match; shared infrastructure does not establish a common attacker.")
		} else {
			destinations[key] = i
		}
	}
	res.SetMeta("graph_version", "1")
	res.SetMeta("nodes", len(nodes))
	res.SetMeta("edges", edges)
	res.SetMeta("inferred_edges", inferred)
	res.SetMeta("missing_trace_parents", missingParents)
	res.SetMeta("source_records", total)
	res.SetMeta("truncated", total > len(nodes) || edges >= graphMaxEdges)
	res.SetMeta("node_limit", graphMaxNodes)
	res.SetMeta("edge_limit", graphMaxEdges)
	res.SetMeta("note", "Observed means explicitly reported by a source, not independently verified. Edges do not prove causation. Findings remain on original records.")
	return res.Finish()
}

func graphDerived(name string) bool {
	switch name {
	case "evidence_graph", "timeline", "iocs", "intel":
		return true
	}
	return false
}

func graphPriority(name string, rec Record) int {
	_, sev := topFinding(rec)
	if SeverityRank(sev) >= SeverityRank(SevSuspect) {
		return 0
	}
	if name == "processes" {
		return 1
	}
	switch name {
	case "agenttrace", "adaptive", "network", "localaccounts":
		return 2
	}
	return 3
}

func graphLabel(name string, rec Record) string {
	if name == "agenttrace" {
		identity := stringField(rec.Fields, "tool")
		if identity == "" {
			identity = stringField(rec.Fields, "agent")
		}
		return excerpt(stringField(rec.Fields, "operation")+": "+identity, 180)
	}
	if name == "network" {
		return excerpt("network: "+stringField(rec.Fields, "remote_addr")+":"+graphNumber(rec.Fields["remote_port"]), 180)
	}
	for _, k := range []string{"tool", "agent", "name", "task_path", "image_path", "image", "path", "remote_addr", "operation", "kind"} {
		if v := stringField(rec.Fields, k); v != "" {
			if pid := graphPID(rec.Fields["pid"]); pid != "" && name == "processes" {
				v += " (PID " + pid + ")"
			}
			return excerpt(name+": "+v, 180)
		}
	}
	return name
}

func graphNumber(v any) string {
	var s string
	switch x := v.(type) {
	case int:
		if x < 0 {
			return ""
		}
		s = strconv.Itoa(x)
	case uint32:
		s = strconv.FormatUint(uint64(x), 10)
	case uint16:
		s = strconv.FormatUint(uint64(x), 10)
	case uint:
		s = strconv.FormatUint(uint64(x), 10)
	case uint64:
		s = strconv.FormatUint(x, 10)
	case int64:
		if x < 0 {
			return ""
		}
		s = strconv.FormatInt(x, 10)
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || x < 0 || x > 1<<53 || math.Trunc(x) != x {
			return ""
		}
		s = strconv.FormatFloat(x, 'f', 0, 64)
	case json.Number:
		s = string(x)
	case string:
		s = x
	default:
		return ""
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return ""
	}
	return strconv.FormatUint(n, 10)
}

func graphPID(v any) string {
	s := graphNumber(v)
	if s == "0" {
		return ""
	}
	return s
}

func graphTime(v any) time.Time {
	if t, ok := v.(time.Time); ok {
		return t
	}
	t, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(v))
	return t
}

func graphSpanKey(f map[string]any, span string) string {
	t, s := stringField(f, "trace_id"), stringField(f, span)
	if t == "" || s == "" {
		return ""
	}
	return t + ":" + s
}

func graphAccount(f map[string]any) string {
	for _, k := range []string{"user_sid", "sid"} {
		if s := stringField(f, k); s != "" {
			return "sid:" + strings.ToLower(s)
		}
	}
	if u := graphNumber(f["uid"]); u != "" {
		return "uid:" + u
	}
	return ""
}

func graphPaths(f map[string]any) []string {
	var out []string
	for _, k := range []string{"image_path", "image", "executable", "file_path", "path"} {
		if p := stringField(f, k); graphAbsolutePath(p) {
			out = append(out, p)
		}
	}
	for _, k := range []string{"Image", "NewProcessName", "ImageLoaded", "TargetFilename", "SourceImage", "TargetImage"} {
		rec := Record{Fields: f}
		if p := eventDataField(&rec, k); graphAbsolutePath(p) {
			out = append(out, p)
		}
	}
	// Task actions and loaded modules are nested in live Go values.
	for _, key := range []string{"actions", "modules"} {
		switch as := f[key].(type) {
		case []map[string]any:
			for _, a := range as {
				out = append(out, graphPaths(a)...)
			}
		case []any:
			for _, a := range as {
				if m, ok := a.(map[string]any); ok {
					out = append(out, graphPaths(m)...)
				}
			}
		}
	}
	return out
}

func graphAbsolutePath(p string) bool {
	return strings.HasPrefix(p, "/") || len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

func graphPathKey(p string) string {
	if len(p) > 2 && p[1] == ':' {
		return strings.ToLower(strings.ReplaceAll(p, "/", "\\"))
	}
	return p
}

func graphImageHash(f map[string]any) string {
	for _, k := range []string{"image_sha256", "sha256"} {
		if s := stringField(f, k); s != "" {
			return strings.ToLower(s)
		}
	}
	return ""
}
