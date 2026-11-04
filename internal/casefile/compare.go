package casefile

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

// Ref is always qualified by an imported file's digest. Run-local graph node
// IDs, hostnames and PIDs cannot accidentally join evidence between reports.
type Ref struct {
	Source string `json:"source_id"`
	Result int    `json:"result"`
	Record int    `json:"record"`
}

type Comparison struct {
	Before     string                `json:"before_source"`
	After      string                `json:"after_source"`
	Identity   string                `json:"identity_basis"`
	Notes      []string              `json:"notes"`
	Collectors []CollectorComparison `json:"collectors"`
}

type CollectorComparison struct {
	Collector     string   `json:"collector"`
	Coverage      string   `json:"coverage"`
	Reasons       []string `json:"reasons"`
	BeforeRecords int      `json:"before_records"`
	AfterRecords  int      `json:"after_records"`
	UnkeyedBefore int      `json:"unkeyed_before"`
	UnkeyedAfter  int      `json:"unkeyed_after"`
	Unchanged     int      `json:"unchanged"`
	Uncompared    int      `json:"uncompared"`
	Changes       []Change `json:"changes"`
}

type Change struct {
	Key         string   `json:"key"`
	Kind        string   `json:"kind"`
	Before      []Ref    `json:"before"`
	After       []Ref    `json:"after"`
	Fields      []string `json:"changed_fields,omitempty"`
	Unavailable []string `json:"unavailable_fields,omitempty"`
}

// Projection deliberately excludes timestamps, PIDs, findings, signature/hash
// availability and detector annotations. A different rule set isn't a host
// configuration change. Missing fields are reported separately from changed
// values; lack of evidence isn't a default value.
var comparedFields = map[string][]string{
	"services":       {"display_name", "image_path", "image_path_raw", "start", "delayed_autostart", "type", "account", "service_dll", "failure_command"},
	"scheduledtasks": {"enabled", "hidden", "author", "description", "run_as", "logon_type", "run_level", "triggers", "com_handlers", "actions"},
	"autoruns":       {"command", "command_raw", "exec", "exec_start", "masked", "library", "md5"},
	"drivers":        {"loaded", "start", "service_type", "image_path", "services"},
}

func compare(before, after Source) (Comparison, error) {
	a, b := before.decoded, after.decoded
	if a.Host == "(offline)" || b.Host == "(offline)" || !strings.EqualFold(a.Host, b.Host) || a.OS != b.OS || a.Arch != b.Arch {
		return Comparison{}, errors.New("comparison needs matching reported hostnames, OS and architecture; offline log reports cannot establish a machine scope")
	}
	if !a.Collected.Before(b.Collected) {
		return Comparison{}, errors.New("comparison inputs must be chronological: before report first, then a later after report")
	}
	c := Comparison{Before: before.ID, After: after.ID, Identity: "operator_attested_same_machine", Notes: []string{
		"The operator attested these reports describe the same machine. Matching hostnames do not establish machine identity.",
		"Only-before and only-after mean observed in one supplied report. They do not establish installation, removal, remediation or a clean host.",
		"Comparison covers selected persistent artifact keys and configuration fields, not processes, network connections, every artifact or changes to detection rules.",
	}}
	if a.Version != b.Version || a.Commit != b.Commit {
		c.Notes = append(c.Notes, "Tool versions or commits differ; collection and detection coverage may differ.")
	}
	for _, name := range []string{"services", "scheduledtasks", "autoruns", "drivers"} {
		c.Collectors = append(c.Collectors, compareCollector(before, after, name))
	}
	return c, nil
}

func resultFor(s Source, name string) (*collector.Result, int, bool) {
	var result *collector.Result
	index := -1
	for i := range s.decoded.Results {
		if s.decoded.Results[i].Collector == name {
			if result != nil {
				return nil, -1, true
			}
			result, index = &s.decoded.Results[i], i
		}
	}
	return result, index, false
}

func compareCollector(before, after Source, name string) CollectorComparison {
	c := CollectorComparison{Collector: name, Coverage: "observations", Reasons: []string{}, Changes: []Change{}}
	a, ai, adup := resultFor(before, name)
	b, bi, bdup := resultFor(after, name)
	if a != nil {
		c.BeforeRecords = len(a.Records)
	}
	if b != nil {
		c.AfterRecords = len(b.Records)
	}
	if adup || bdup {
		c.Coverage, c.Reasons = "ambiguous", []string{"duplicate collector results; no artifact pairing attempted"}
		return c
	}
	if a == nil || b == nil {
		c.Coverage = "unavailable"
		if a == nil {
			c.Reasons = append(c.Reasons, "collector not present in before report")
		}
		if b == nil {
			c.Reasons = append(c.Reasons, "collector not present in after report")
		}
		return c
	}
	if a.Records == nil || b.Records == nil {
		c.Coverage, c.Reasons = "unavailable", []string{"a collector's records array is null; no artifact pairing attempted"}
		return c
	}
	for _, side := range []struct {
		label string
		s     Source
		r     *collector.Result
	}{{"before", before, a}, {"after", after, b}} {
		if side.s.decoded.Run.Interrupted || len(side.r.Errors) > 0 || side.s.decoded.Run.Elevated != nil && !*side.s.decoded.Run.Elevated {
			c.Coverage = "partial"
			c.Reasons = append(c.Reasons, side.label+" run interrupted, not elevated or collector has errors; review source coverage")
		}
		for _, key := range []string{"truncated", "partial", "limit_reached"} {
			if side.r.Meta[key] == true {
				c.Coverage = "partial"
				c.Reasons = append(c.Reasons, side.label+" collector reports "+key)
			}
		}
	}
	left, unkeyedA := indexRecords(before.ID, ai, a, before.decoded.OS)
	right, unkeyedB := indexRecords(after.ID, bi, b, after.decoded.OS)
	c.UnkeyedBefore, c.UnkeyedAfter = unkeyedA, unkeyedB
	keys := make([]string, 0, len(left)+len(right))
	for k := range left {
		keys = append(keys, k)
	}
	for k := range right {
		if _, ok := left[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		x, y := left[key], right[key]
		change := Change{Key: key, Before: refs(x), After: refs(y)}
		switch {
		case len(x) > 1 || len(y) > 1:
			change.Kind = "ambiguous"
		case len(x) == 0:
			change.Kind = "only_after"
			if c.Coverage == "partial" {
				change.Kind = "unresolved_after"
			}
		case len(y) == 0:
			change.Kind = "only_before"
			if c.Coverage == "partial" {
				change.Kind = "unresolved_before"
			}
		default:
			observed := 0
			for _, field := range comparedFields[name] {
				av, aok := a.Records[x[0].Record].Fields[field]
				bv, bok := b.Records[y[0].Record].Fields[field]
				if aok && bok && av != nil && bv != nil {
					observed++
				}
				if aok != bok || aok && (av == nil || bv == nil) && !reflect.DeepEqual(av, bv) {
					change.Unavailable = append(change.Unavailable, field)
				} else if aok && !reflect.DeepEqual(av, bv) {
					change.Fields = append(change.Fields, field)
				}
			}
			if len(change.Fields) > 0 {
				change.Kind = "changed"
			} else if len(change.Unavailable) > 0 {
				change.Kind = "field_coverage"
			} else if observed == 0 {
				c.Uncompared++
				continue
			} else {
				c.Unchanged++
				continue
			}
		}
		c.Changes = append(c.Changes, change)
	}
	return c
}

func refs(in []Ref) []Ref {
	if in == nil {
		return []Ref{}
	}
	return in
}

func indexRecords(source string, result int, r *collector.Result, platform string) (map[string][]Ref, int) {
	index, unkeyed := map[string][]Ref{}, 0
	for i, rec := range r.Records {
		key := artifactKey(r.Collector, rec.Fields, platform)
		if key == "" {
			unkeyed++
			continue
		}
		index[key] = append(index[key], Ref{Source: source, Result: result, Record: i})
	}
	return index, unkeyed
}

func artifactKey(name string, f map[string]any, platform string) string {
	str := func(key string) string {
		v, _ := f[key].(string)
		return v
	}
	var parts []string
	switch name {
	case "services":
		if platform == "windows" && str("name") != "" {
			parts = []string{str("name")}
		}
	case "scheduledtasks":
		if platform == "windows" && str("task_path") != "" {
			parts = []string{str("task_path")}
		}
	case "drivers":
		if platform == "windows" && str("kind") == "driver" && str("path") != "" {
			parts = []string{str("path")}
		}
	case "autoruns":
		if platform == "windows" && str("kind") != "" && str("location") != "" && str("name") != "" {
			parts = []string{str("kind"), str("location"), str("name"), str("user_sid")}
		} else if platform == "linux" {
			switch str("kind") {
			case "systemd_unit", "systemd_user_unit", "systemd_dropin", "systemd_user_dropin", "systemd_timer", "systemd_user_timer":
				if str("source") != "" && str("unit") != "" {
					parts = []string{str("kind"), str("source"), str("unit"), str("file")}
				}
			case "xdg_autostart":
				if str("source") != "" && str("name") != "" {
					parts = []string{str("kind"), str("source"), str("name")}
				}
			case "pam_module":
				if str("path") != "" {
					parts = []string{str("kind"), str("path")}
				}
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	for i, p := range parts {
		if len(p) > 4096 {
			return ""
		}
		if platform == "windows" {
			parts[i] = strings.ToLower(p)
		}
	}
	// Encoding a tuple avoids delimiter collisions in hostile names.
	key, _ := json.Marshal(parts) // a slice of strings is always serializable
	return string(key)
}
