# Modern delivery, remote access and model-resource abuse

These additions retain report schema 1.2 and add no agent dependencies.
Findings describe observed behavior and explain attribution limits.

## Endpoint collection and detections

On Windows, `runhistory` and `wfp` join the default collectors:

```sh
lrng -no-dns -collectors runhistory,wfp -out supplemental.json
lrng -no-dns -graph -format html -out host.html
```

| Rule | Evidence and limits |
|---|---|
| `exec.clickfix_lure` | Verification/repair lure text plus PowerShell download and execution primitives, including decoded encoded-command content. Shared analytics also apply to saved EVTX process-creation and script-block records. Website origin and social engineering remain unverified. |
| `execution.run_dialog_payload` | A RunMRU command matches execution rules. Only loaded user hives are read; no hive loading or clipboard collection. Entered commands do not prove execution. Command text and finding excerpts receive credential-shape redaction; an exact-command SHA-256 permits comparison. |
| `correlate.interactive_payload` | Live PowerShell download/execute behavior with an OS-reported Explorer/Terminal parent checked using both creation times. Parent spoofing and authorized use remain possible. |
| `correlate.run_dialog_command` | Exact command digest and SID match between a suspicious live process and one unambiguous RunMRU entry. Case and quoted spaces are preserved. The shared registry key last-write time is never treated as an individual execution time. |
| `remote.ide_tunnel` | VS Code-family executable identity and a `tunnel` command, or tunnel arguments with distinctive CLI flags. Notable context for legitimate developer use. Windows version-resource inspection can recognize renamed executables; original names are self-reported metadata. |
| `remote.ide_tunnel_suspicious_context` | Tunnel evidence plus a script-host or suspect parent, with creation-time-verified ancestry. Missing creation times cannot establish this match. |
| `modules.side_load_candidate` | A trusted executable has loaded an adjacent system-DLL-named module whose disk file is unsigned/untrusted, in an unusual location. Valid application packaging can have this shape. |
| `correlate.dll_sideload_context` | The candidate's host also has a suspicious child. Module-to-process matching requires PID, exact creation time and image path. This does not establish which DLL caused the child. |
| `defense.wfp_security_agent_block` | An enabled BLOCK filter at an outbound ALE authorization layer has an equality condition for a security-agent-named executable. Agent identity is inferred from its basename. Other conditions and filter precedence affect the outcome; communication loss is not tested. |

WFP collection uses read-only `fwpuclnt.dll` APIs; it never modifies filters
or invokes `netsh`. Limits are 16,384 enumerated filters and 4,096 retained
app-specific block observations. Records preserve filter/provider GUIDs,
layer, flags, application path and condition descriptors. Non-app condition
values are omitted. Rights failures, cancellation, invalid fields and limits
are reported. Removed dynamic filters cannot be recovered from a snapshot.

Module analysis keeps at most eight adjacent system-DLL candidates per process
and makes at most 128 signature checks per run, on regular files up to 8 MiB.
`-no-sign` leaves signature evidence unknown and prevents the new signed-host
finding. These are later checks of disk files, not an attestation of bytes
previously mapped into memory. The optional memory-integrity scanner supplies
separate evidence. Record fields and metadata expose check limits and gaps.
Tunnel identity inspection checks at most 128 version resources per process
collector run, each capped at 4 MiB.

## Offline LLMjacking analysis

```sh
# Analyze supplied logs without live collection, DNS queries or cloud calls.
lrng -cloud-audit audit.json -cloud-only -format html -out cloud.html

# Include cloud evidence with an ordinary endpoint investigation.
lrng -no-dns -cloud-audit cloudtrail.json,gcp.jsonl -graph -out host.json

# Harmless synthetic demo with a deliberately small threshold.
lrng -cloud-audit demo/cloud-audit.jsonl -cloud-only -llm-burst 3 -out demo.json
```

`-cloud-audit` implies `-graph`. `-cloud-only` requires it and rejects live
collector, memory, Sigma and adaptive options. Saved EVTX analysis can be
combined with `-cloud-audit` without `-cloud-only`. Imported resource names
never schedule host reads or model calls. Standard JSON/JSONL/HTML output,
checksums, timeline and `-fail-on` handling apply.

Inputs are explicit uncompressed regular files: at most 16 files, 32 MiB each,
64 MiB total and 10,000 retained unique events. JSONL lines are capped at 4 MiB.
Changing files are rejected. Retained events identify their source file,
SHA-256 and line number or one-based document event index. Malformed input is
counted without echoing its contents. Limits and cancellation are reported.

| Input | Supported evidence |
|---|---|
| AWS CloudTrail `Records` envelopes or individual JSON/JSONL events | Bedrock invocations, model discovery/access configuration and invocation-logging changes. Only `AwsApiCall` records are retained; stream-completion `AwsServiceEvent` records are excluded. Matching request IDs collapse management/data copies and repeated exports. Account, principal and region are required for rate correlation. |
| GCP arrays, `entries` envelopes or individual JSON/JSONL AuditLog records | Vertex AI/Gemini calls and discovery; enablement of their APIs through Service Usage. Project and principal are required for correlation. |
| Azure arrays, `records` envelopes or individual Activity Log events | Cognitive Services deployment writes/reads and account reads. Unfinished operations are excluded. Subscription, caller and account resource scope are required for correlation. |
| Normalized JSONL | Explicit provider, service, operation and status metadata. Can represent Azure invocation diagnostics after an analyst adapts the export. Unsupported operations are counted and omitted. |

Azure diagnostic schemas vary. This version does not infer successful
invocations or principals from arbitrary diagnostic payloads; adapt those
exports into normalized JSONL. Management logs alone do not provide complete
invocation counts on every provider. Data-plane logging must have existed
before collection. Missing telemetry remains unknown.

Normalized example (one event per line):

```json
{"provider":"aws","tenant":"111122223333","principal":"arn:aws:iam::111122223333:user/example","region":"us-east-1","service":"bedrock.amazonaws.com","operation":"InvokeModel","timestamp":"2026-11-01T12:00:00Z","status":"success","request_id":"example-request","resource":"example-model"}
```

`provider` is `aws`, `gcp` or `azure`. `tenant` identifies the AWS account, GCP
project or Azure subscription. `status` is `success`, `failure` or `unknown`;
timestamps use RFC 3339. Optional fields are `event_id`, `request_id`,
`resource` and `source_ip` (an IP literal). Only allowlisted metadata survives:
no prompts, responses, request/response bodies, API keys, headers or unknown
fields. Strings receive credential-shape redaction and length caps.
Correlation uses a digest of original identities so redacted names cannot
merge distinct principals. Imported logs are not authenticated.

Recognized operations are enumerated in `cloudCategory` in
`internal/collector/cloudaudit.go`. AWS uses native Bedrock API names. GCP uses
fully qualified audit methods ending in `GenerateContent`,
`StreamGenerateContent`, `Predict`, `RawPredict`, `StreamRawPredict`,
`ListModels`, `ListEndpoints` or `ListPublisherModels`. Azure uses deployment
write/read and account-read operation IDs; normalized inference records use
`ChatCompletions_Create` or `Completions_Create`, service
`Microsoft.CognitiveServices` and a full account resource ID.

### Findings

- `llm.service_or_deployment_enabled`: notable context for successful service
  enablement, access configuration or a deployment write (including updates).
- `llm.logging_disabled`: a successful Bedrock invocation-logging deletion.
  Logging configuration writes with unknown contents do not imply deletion.
- `llm.invocation_burst`: a fixed threshold of successful unique calls in five
  minutes (default 100; `-llm-burst` accepts 1–100,000). At most the busiest
  window per scope is emitted. Normal batches can meet this threshold; no
  historical baseline or billing impact is inferred.
- `llm.possible_resource_hijack`: a burst with logging deletion, or enablement
  or identity configuration changes plus at least three discovery calls,
  within the window or preceding 30
  minutes for the same provider/account/principal/region (and Azure account
  resource). A suspect investigation lead requiring authorization checks.

Identity context includes AWS access-key creation and user/role policy
attachment or inline policy writes, GCP service-account key creation and
project IAM writes, and Azure role assignments scoped to a Cognitive Services
account. These events record the actor making a change, not proof of which
credential subsequently invoked a model. AWS IAM changes are global and may
corroborate that same account/principal's model activity in another region.
Identity changes alone do not generate an LLMjacking finding; secret values
and policy bodies are omitted.

Failures and unknown outcomes do not count as successful invocations.
Supporting event indices are local to `cloudaudit`: at most 32 invocation and
32 context references, with omissions counted. Graph edges link evidence to
analysis without duplicating findings. Endpoint contextual detections also
retain source references. These heuristics do not prove stolen credentials,
resale or unauthorized resource consumption.

## References

- [Microsoft: TerminalFix](https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/)
- [Telekom Security: VS Code tunnel abuse](https://github.security.telekom.com/2026/09/IDE-Tunneling-via-VSCode.html)
- [Microsoft: FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)
- [Google/Mandiant: LLMjacking](https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models/)
- [AWS: Bedrock CloudTrail semantics](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
