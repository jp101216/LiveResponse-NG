# Offline case workspaces and report comparisons

Combine existing LRNG JSON reports into one JSON workspace or self-contained
HTML page. This is an offline investigation workflow: it neither collects the
analyst's computer nor sends jobs to endpoints. It needs no server or sidecar.

```powershell
# Different hosts, or several runs from the same reported host.
.\lrng.exe -case-report HOST01.json -case-report HOST02.json -case-name IR-42 -format html -out case.html

# Explicit order: before, then after. Attest the same physical/virtual machine.
.\lrng.exe -case-report before.json -case-report after.json -compare -same-host -format html -out comparison.html

# JSON cases open in viewer/lrng-viewer.html too.
.\lrng.exe -case-report HOST01.json -case-report HOST02.json -out case.json
```

Repeat `-case-report` rather than using a comma-separated path list. Inputs
must be regular files, not symlinks, containing one LRNG schema 1.2 JSON
envelope. JSONL, HTML and nested cases are not case inputs in this version.
The standalone viewer continues to open an individual JSON or JSONL report.

The case overview keeps source reports separate, lists their collector errors
and interrupted/non-elevated status, and searches findings across all sources.
Each finding opens its original record in its original report. The comparison
view opens either the before or after record. Existing report views, including
the evidence graph, stay within the selected run. There is no automatic
cross-host entity merge, PID join or assertion of attacker movement.

## Provenance and boundaries

Case schema `1.0` has `kind: "lrng_case"`, a new `case_id`, and `sources`.
Every source records the basename, byte count, SHA-256 of the **original input
file**, the report envelope and a freshly computed summary. Source IDs are
`sha256:<original-file-digest>`; record references use
`{source_id, result, record}` with original zero-based report indices.
Unknown envelope and artifact fields are retained. Reports aren't flattened
into a new host or rewritten to claim the analyst's machine collected them.

The outer case is re-serialized JSON: the original digest is not the digest of
a newly formatted embedded report. Retain the original evidence files and
their checksums. Digests record byte identity, not authenticity, signatures or
an independently verified chain of custody. An imported case's comparison and
digest fields are recorded claims. HTML embedding escapes data and the viewer
uses text-only rendering under its existing network-blocking CSP.

Duplicate file bytes, conflicting exports with the same run ID, duplicate
collector names, ambiguous JSON member names (including case variants), invalid
UTF-8 and nesting beyond 64 levels fail import. Errors reject the entire case;
there is no silent partial import. `-force` can replace an output, but the CLI
refuses to replace an input report with the case or its checksum.

## Comparison semantics

`-compare` requires exactly two reports, chronological collection timestamps,
matching reported hostname/OS/architecture, and `-same-host`. **A hostname is
not a durable machine identifier.** The flag records the operator's assertion
that these snapshots describe the same machine. A reused hostname, cloned
machine or reinstated VM requires independent identity verification. Reports
whose host is `(offline)` cannot establish this scope. The CLI does not infer
identity or choose a baseline automatically.

Comparison currently covers selected persistent artifacts and configuration
fields:

| Collector | Stable key | Compared configuration |
| --- | --- | --- |
| Windows `services` | Service name | Image/command, start/type, account, service DLL, failure command and display name |
| Windows `scheduledtasks` | Task path | Actions, triggers, enabled/hidden state, principal, logon/run level, author and description |
| Windows `autoruns` | Kind + location + entry name + user SID | Command and raw command |
| Windows `drivers` | Driver path, for `kind: driver` records | Loaded state, service bindings and registered start/type/image |
| Linux `autoruns` | Systemd kind + source + unit + drop-in file; XDG source + name; PAM module path | ExecStart/exec, masking and module MD5 where reported |

Windows keys compare without case; Linux keys preserve case. Unsupported or
incomplete keys count as **unkeyed** and remain in the source report. Processes,
network connections and other collectors are not compared. Selected-field
comparison does not claim every property was checked. Timestamp changes and
detection-rule/annotation changes do not become configuration changes.

| Kind | Meaning |
| --- | --- |
| `changed` | Different values for a selected field observed on both sides |
| `field_coverage` | Selected field present on one side only; no default value inferred |
| `only_before`, `only_after` | Key observed in only one supplied report; does not establish removal or installation |
| `unresolved_before`, `unresolved_after` | Unmatched key with known partial collection coverage |
| `ambiguous` | Multiple records share a key; all references retained, no arbitrary pairing |

Missing collectors or null record arrays produce **unavailable** coverage and
no artifact differences for that collector. Interrupted runs, non-elevated
runs, collector errors and explicit truncation flags produce **partial**
coverage. Otherwise coverage is labeled **observations**, never "complete".
Collector selection, selective enumeration, privilege and unreported gaps can
still affect visibility. Tool-version differences are called out. Neither a
missing observation nor an unchanged comparison proves remediation or a clean
host. Existing source findings remain visible independently of the comparison.
Paired keys with no mutually observed selected fields count as **uncompared**,
not unchanged.

## Limits and verification

- 1–16 sources, at most 16 MiB each and 64 MiB in total.
- At most 100,000 records and 200,000 findings across the case; at most 256
  collector results per report. Excesses fail before output is created.
- No imported paths trigger local reads; only explicit CLI inputs are opened.
- Output supports JSON and HTML, with the existing private-file permissions,
  no-overwrite default and adjacent `.sha256` file. JSONL still means one run.
- Live/collection flags are rejected in case mode. Output flags and `-fail-on`
  remain available; the latter uses actual imported findings.
- The viewer paginates findings and changes, limits displayed ambiguous-key
  references, validates comparison reference scope and accepts files up to
  192 MiB. It does not verify original-file digests embedded in a case.

Harmless repeatable examples (any supported OS):

```sh
go run ./cmd/lrng -case-report demo/case-before.json -case-report demo/case-after.json -case-report demo/case-other-host.json -case-name IR-DEMO -format html -out case.html
go run ./cmd/lrng -case-report demo/case-before.json -case-report demo/case-after.json -compare -same-host -format html -out comparison.html
go test -race ./internal/casefile ./internal/output ./cmd/lrng ./viewer
node --test viewer/browsertest/parse_test.cjs viewer/browsertest/graph_test.cjs viewer/browsertest/case_test.cjs
go test ./internal/casefile -run '^$' -bench ComparePersistence -benchmem -count=3
```

The scale fixture compares 10,000 named services with 100 deliberate changes
and 9,900 unchanged configurations. It validates those counts while measuring
time and allocations. It is a regression/performance fixture, **not** a
head-to-head commercial accuracy benchmark. Chromium CI opens real CLI-generated
JSON/HTML cases, checks both comparison pivots, exercises search and confirms
hostile case text cannot execute, inject markup or request external content.
