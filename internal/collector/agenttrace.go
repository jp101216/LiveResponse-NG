package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const traceMaxBytes = 32 << 20
const traceMaxTotalBytes = 64 << 20
const traceMaxRecords = 10000
const traceMaxFiles = 16

var traceIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var spanIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// ParseAgentTraceFiles imports existing telemetry. It does not instrument an
// agent or recover unrecorded history. Only allowlisted metadata survives;
// prompts, responses, tool arguments, headers and unknown attributes are never
// copied to the report. Known content fields get a digest and encoded length.
func ParseAgentTraceFiles(ctx context.Context, paths []string) Result {
	res := NewResult("agenttrace")
	var sources []map[string]any
	total, rejected, ignored := 0, 0, 0
	truncated := false
	if len(paths) > traceMaxFiles {
		paths = paths[:traceMaxFiles]
		truncated = true
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			res.Fail("trace import interrupted: " + ctx.Err().Error())
			break
		}
		if total >= traceMaxTotalBytes || len(res.Records) >= traceMaxRecords {
			truncated = true
			break
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			res.Fail(fmt.Sprintf("trace file %q: unreadable or not a regular file", path))
			continue
		}
		limit := min(int64(traceMaxBytes), int64(traceMaxTotalBytes-total))
		data, err := readAgentTrace(path, limit)
		total += len(data)
		if err != nil {
			res.Fail(fmt.Sprintf("trace file %q: %v", path, err))
			continue
		}
		digest := sha256.Sum256(data)
		source := map[string]any{"path": path, "sha256": hex.EncodeToString(digest[:]), "bytes": len(data)}
		sources = append(sources, source)
		add := func(raw map[string]any, locator string, index int, attrs map[string]any) {
			if ctx.Err() != nil {
				return
			}
			if len(res.Records) >= traceMaxRecords {
				truncated = true
				return
			}
			fields, recognized := normalizeAgentSpan(raw, attrs)
			if !recognized {
				ignored++
				return
			}
			if fields == nil {
				rejected++
				return
			}
			fields["source_file"] = path
			fields["source_sha256"] = source["sha256"]
			fields[locator] = index
			res.Add(fields)
		}
		var document any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		decodeErr := dec.Decode(&document)
		var extra any
		if decodeErr == nil && dec.Decode(&extra) == io.EOF {
			if root, ok := document.(map[string]any); ok {
				if resources, ok := root["resourceSpans"].([]any); ok {
					index := 0
					for _, value := range resources {
						r, ok := value.(map[string]any)
						if !ok {
							rejected++
							continue
						}
						resource, _ := r["resource"].(map[string]any)
						attrs := traceAttributes(resource["attributes"])
						scopes, _ := r["scopeSpans"].([]any)
						for _, value := range scopes {
							scope, ok := value.(map[string]any)
							if !ok {
								rejected++
								continue
							}
							spans, _ := scope["spans"].([]any)
							for _, value := range spans {
								index++
								span, ok := value.(map[string]any)
								if !ok {
									rejected++
									continue
								}
								add(span, "source_span", index, attrs)
							}
						}
					}
				} else {
					add(root, "source_line", 1, nil)
				}
			} else {
				rejected++
			}
		} else {
			// JSONL: preserve line numbers and report malformed rows without
			// copying parser errors that could quote sensitive input.
			scanner := bufio.NewScanner(bytes.NewReader(data))
			scanner.Buffer(make([]byte, 4096), 4<<20)
			line := 0
			for scanner.Scan() {
				line++
				if ctx.Err() != nil || len(res.Records) >= traceMaxRecords {
					truncated = true
					break
				}
				if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
					continue
				}
				var raw map[string]any
				d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
				d.UseNumber()
				if d.Decode(&raw) != nil || raw == nil || d.Decode(&extra) != io.EOF {
					rejected++
					continue
				}
				add(raw, "source_line", line, nil)
			}
			if scanner.Err() != nil {
				rejected++
				truncated = true
			}
		}
	}
	if ctx.Err() != nil && len(res.Errors) == 0 {
		res.Fail("trace import interrupted: " + ctx.Err().Error())
	}
	if rejected > 0 {
		res.Fail(fmt.Sprintf("%d malformed or invalid trace record(s) omitted; original files retain their contents", rejected))
	}
	if len(res.Records) == 0 {
		res.Fail("no supported agent spans imported; input must be normalized JSONL or OTLP/JSON resourceSpans")
	}
	if truncated {
		res.Fail("trace input limit reached; import covers only retained spans")
	}
	res.SetMeta("sources", sources)
	res.SetMeta("content_policy", "metadata only; known content fields have SHA-256 and JSON-encoded byte length; original content and unknown fields are omitted")
	res.SetMeta("coverage", "only supplied telemetry; missing spans and absent content are unknown, not evidence of no activity")
	res.SetMeta("records", len(res.Records))
	res.SetMeta("rejected_records", rejected)
	res.SetMeta("ignored_spans", ignored)
	res.SetMeta("truncated", truncated)
	res.SetMeta("bytes_read", total)
	return res.Finish()
}

func readAgentTrace(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("not a readable regular file")
	}
	if before.Size() > limit {
		return nil, fmt.Errorf("file exceeds the %d-byte input limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return data, err
	}
	after, err := f.Stat()
	if err != nil || after.Size() != int64(len(data)) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return data, fmt.Errorf("file changed while reading; import omitted")
	}
	return data, nil
}

func normalizeAgentSpan(raw, resource map[string]any) (map[string]any, bool) {
	otel := raw["traceId"] != nil || raw["spanId"] != nil
	attrs := traceAttributes(raw["attributes"])
	op := stringField(raw, "operation")
	if otel {
		op = stringField(attrs, "gen_ai.operation.name")
	}
	switch op {
	case "invoke_agent", "execute_tool", "chat", "generate_content":
	default:
		return nil, false
	}
	get := func(normal, otlp string) string {
		if otel {
			return stringField(raw, otlp)
		}
		return stringField(raw, normal)
	}
	tid, sid, parent := get("trace_id", "traceId"), get("span_id", "spanId"), get("parent_span_id", "parentSpanId")
	if !traceIDPattern.MatchString(tid) || !spanIDPattern.MatchString(sid) || strings.Trim(sid, "0") == "" || strings.Trim(tid, "0") == "" {
		return nil, true
	}
	if parent != "" && parent != "0000000000000000" && !spanIDPattern.MatchString(parent) {
		return nil, true
	}
	f := map[string]any{"operation": op, "trace_id": strings.ToLower(tid), "span_id": strings.ToLower(sid)}
	if parent != "" && parent != "0000000000000000" {
		f["parent_span_id"] = strings.ToLower(parent)
	}
	metadata := map[string]string{
		"agent": "gen_ai.agent.name", "tool": "gen_ai.tool.name", "model": "gen_ai.request.model",
		"host": "host.name", "process_created_at": "process.creation.time", "file_path": "file.path",
	}
	for key, attr := range metadata {
		value := stringField(raw, key)
		if otel {
			value = stringField(attrs, attr)
			if value == "" {
				value = stringField(resource, attr)
			}
		}
		if value != "" {
			f[key] = excerpt(redactSecrets(value), 1024)
		}
	}
	pid := raw["pid"]
	if otel {
		pid = resource["process.pid"]
		if p := attrs["process.pid"]; p != nil {
			pid = p
		}
	}
	if p := graphPID(pid); p != "" {
		f["pid"], _ = strconv.ParseUint(p, 10, 32)
	}
	start, end := graphTime(raw["timestamp"]), graphTime(raw["ended_at"])
	if otel {
		start, end = traceNanoTime(raw["startTimeUnixNano"]), traceNanoTime(raw["endTimeUnixNano"])
	}
	if !start.IsZero() {
		f["timestamp"] = start.UTC()
	}
	if !end.IsZero() {
		f["ended_at"] = end.UTC()
	}
	if !start.IsZero() && !end.IsZero() && end.Before(start) {
		return nil, true
	}
	content := map[string]string{"input": "gen_ai.input.messages", "output": "gen_ai.output.messages", "arguments": "gen_ai.tool.call.arguments"}
	for key, attr := range content {
		v, ok := raw[key]
		if otel {
			v, ok = attrs[attr]
		}
		if !ok {
			continue
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(encoded)
		f[key+"_sha256"] = hex.EncodeToString(sum[:])
		f[key+"_json_bytes"] = len(encoded)
	}
	f["telemetry_format"] = "normalized-jsonl"
	if otel {
		f["telemetry_format"] = "otlp-json"
	}
	return f, true
}

func traceAttributes(value any) map[string]any {
	attrs := map[string]any{}
	values, _ := value.([]any)
	for _, entry := range values {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		key := stringField(m, "key")
		v, ok := m["value"].(map[string]any)
		if key == "" || !ok {
			continue
		}
		for _, kind := range []string{"stringValue", "intValue", "boolValue", "doubleValue", "arrayValue", "kvlistValue"} {
			if x, ok := v[kind]; ok {
				attrs[key] = x
				break
			}
		}
	}
	return attrs
}

func traceNanoTime(v any) time.Time {
	s := fmt.Sprint(v)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
