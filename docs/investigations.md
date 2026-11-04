# Evidence graphs and guided investigation

These opt-in features extend the existing report envelope (schema 1.2). They
add `evidence_graph`, `agenttrace` and `adaptive` results, each using the normal
`records`, `meta` and `errors` contract. They require no new agent dependencies.

## Evidence graph

```sh
lrng -no-dns -graph -format html -out case.html
```

Open **Evidence graph** in the offline report viewer. Search observations,
select a node to inspect its neighbors, filter observed/inferred relationships,
and open the original source record. The drawing shows at most ten neighbors;
the adjacent table shows up to 200 relationships. All source records remain
available in the collector views. Old reports open normally and explain how to
include graph data in a later run.

A node is an original observation, with a `source_ref` containing zero-based
`result` and `record` indices. An edge names its `from` and `to` node IDs,
`relation`, `basis`, `explanation` and endpoint `source_refs`. IDs are local to
one report. The graph does not duplicate findings or change their severities.

| Relationship | Basis and limits |
|---|---|
| `reported_parent` | Observed OS-reported parent PID, with both start times checked. Parent spoofing remains possible. |
| `candidate_parent` | Inferred parent PID match when start times are missing. A known reused PID is never linked. |
| `same_pid` | Inferred match between live process, network, UDP, module or memory snapshots; reuse between collectors remains possible. |
| `same_path` | Inferred absolute-path match, case-sensitive for Unix and folded for Windows paths even during offline parsing. Conflicting image hashes suppress a link. Paths do not establish file identity or execution. |
| `same_account` | Inferred unique SID/UID match. User namespaces can differ. |
| `same_destination` | Inferred remote IP/port match. Shared infrastructure does not establish a common attacker. |
| `same_service_name`, `same_task_name` | Inferred match of an event's service/task name against current inventory; an object can be recreated. |
| `reported_trace_parent` | Observed parent declaration within the same trace ID. Missing/duplicate parents are counted, not guessed. |
| `trace_process` | Inferred match requiring the imported host, PID and exact process creation time to match the live snapshot. A PID alone is insufficient. |
| `triggered_follow_up` | Observed link from a triggering source finding to a later adaptive file observation. |

**Observed means explicitly reported by a source.** It does not authenticate
that source or establish causation. Graph generation reads only report data.
It retains at most 5,000 nodes and 15,000 edges, prioritizing suspect/critical
observations and process context over ordinary records from large logs. Caps
and missing trace parents are visible in metadata and the viewer.

## Existing agent telemetry

```sh
# Import telemetry alongside this host's normal live collection:
lrng -no-dns -agent-trace spans.jsonl -format html -out case.html

# Import only supplied telemetry; do not collect this workstation:
lrng -agent-trace demo/agent-trace.jsonl -trace-only -format html -out trace.html
```

`-agent-trace` accepts up to 16 comma-separated file paths and implies `-graph`.
It reads normalized JSONL or an OTLP/JSON trace-export object with
`resourceSpans[].scopeSpans[].spans[]`. It imports up to 10,000 supported spans,
32 MiB per file and 64 MiB in total. Files must be regular files. A changing
file is rejected. Malformed rows are counted without quoting their contents.
Binary protobuf, collector-specific transcript formats and OTLP/JSONL export
envelopes are not supported by this first version.

The normalized JSONL format uses one span per line:

```json
{"trace_id":"11111111111111111111111111111111","span_id":"2222222222222222","parent_span_id":"1111111111111111","operation":"execute_tool","tool":"read_file","timestamp":"2026-11-01T12:00:01Z"}
```

Trace IDs are 32 hexadecimal characters; span and optional parent IDs are 16.
All-zero trace/span IDs are invalid; an all-zero parent denotes no parent.
Supported operations are `invoke_agent`, `execute_tool`, `chat` and
`generate_content`. Additional spans are ignored and counted.

| Normalized field | OTLP source |
|---|---|
| `trace_id`, `span_id`, `parent_span_id` | Span `traceId`, `spanId`, `parentSpanId` |
| `operation` | `gen_ai.operation.name` attribute |
| `agent`, `tool`, `model` | `gen_ai.agent.name`, `gen_ai.tool.name`, `gen_ai.request.model` |
| `host`, `pid`, `process_created_at` | `host.name`, `process.pid`, `process.creation.time` on the span or resource |
| `file_path` | `file.path` attribute; a trace claim, not independent proof of file access |
| `timestamp`, `ended_at` | Span `startTimeUnixNano`, `endTimeUnixNano` |
| `input`, `output`, `arguments` | `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.tool.call.arguments` |

`process_created_at` is optional RFC 3339 metadata supplied by the exporter;
instrumentation may not emit it. Without it, no trace-to-live-process join is
made. The parser uses an explicit field allowlist and the existing credential
shape redaction on string metadata. Raw content, headers, environment values
and unknown attributes are omitted. Known content fields become SHA-256
digests and JSON-encoded byte lengths, retaining a comparison handle without
copying their text into the report. These hashes describe the encoded field,
not an assertion that an instruction caused an action.

Each imported row names its source file, source SHA-256 and JSONL line number
or one-based OTLP span index. Original files retain the full evidence. The
importer does not enable instrumentation, recover missing history, classify an
agent as compromised, or execute recorded actions. Missing telemetry remains
unknown. For exporter conventions, see
[OpenTelemetry GenAI](https://opentelemetry.io/docs/specs/semconv/gen-ai/).

## Bounded adaptive file collection

```sh
lrng -no-dns -adaptive -adaptive-budget 15s -adaptive-max-files 20 \
  -format html -out case.html
```

After initial live collection and correlation, one deterministic pass selects
executable paths on suspect/critical records from processes, services,
autoruns, tasks, modules and drivers. It orders critical targets first,
deduplicates paths, and records the triggering rules and source references.
It collects regular-file size and modification time, a bounded SHA-256, and
offline Authenticode information on Windows. Symlinks, device namespaces,
UNC paths and Unix `/dev`, `/proc` and `/sys` targets are excluded. File identity
and metadata are checked around hashing; a detected change suppresses the digest.

Defaults are 20 files and a 15-second dispatcher budget, plus the dispatcher's
normal cancellation grace. The file limit accepts 1–200. Hash reads are capped
at 8 MiB per target and 64 MiB in total, reserved conservatively before each
read. Signature checks apply only to files up to 8 MiB. `-no-hash` and
`-no-sign` apply. Per-file statuses and aggregate uncollected counts explain
gaps. A blocked syscall can outlast cancellation; the dispatcher abandons it
and reports the gap, as for other collectors.

The targets come only from supported live inventories. Imported agent spans
and event bodies cannot schedule file reads. Adaptive mode is rejected with
`-trace-only` or `-evtx`. A follow-up is a later observation of a host path,
which may differ from a process's container mount namespace. It does not
execute commands, perform memory scans, modify the target, or remediate it.
