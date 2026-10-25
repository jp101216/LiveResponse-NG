# Live Response NG (`lrng`)

A fast live-response triage agent for Windows and Linux DFIR, with two AI-aware
detection modules aimed at the current wave of AI-assisted malware. It's the
next-generation successor to a PowerShell live-response toolkit: a single
static binary, structured JSON output, parallel collection, and memory-safe
handling of hostile input. It builds from any OS; Windows has the full collector
set, and Linux now has a working core (processes, network, modules, accounts and
persistence) behind the same interface.

> **Status:** v0.10. On **Linux**, a default run covers processes, network
> (TCP + UDP, with per-socket process attribution via `/proc`), loaded modules,
> local accounts, and persistence (cron, systemd, ld.so.preload, rc.local, XDG
> autostart) — judged by Linux-specific path and command-line heuristics, with AI
> module A (LLM-callout detection) running too; see
> [Platform support](#platform-support).
>
> On **Windows**, a default run covers processes (with a process-tree,
> command-line analysis and offline Authenticode verification that names the
> signer), network (TCP + UDP, IPv4 + IPv6), services, ~20 autostart locations,
> scheduled tasks (cross-checked against the Task Scheduler's registry cache),
> WMI event subscriptions, COM CLSID hijacking, ShimCache, AmCache, prefetch
> (with decoded run counts and times), sessions, local accounts, loaded modules
> and the Windows event logs, which can also be triaged offline from saved
> `.evtx` files on any OS. A correlation pass lines the logs up against the live
> state. That's about 90 named detections, each mapped to MITRE ATT&CK, plus
> your own Sigma rules (or the bundled pack), an optional super-timeline,
> indicator (IOC) export and offline endpoint-intelligence attribution
> (ASN / country / cloud / CDN / hosting / Tor, air-gapped), AI
> module A (LLM-callout detection), the Rust sidecar with AI module B
> (embedded-prompt-artifact scanner), and opt-in live process-memory scanning
> with YARA and memory-structure heuristics. See [Roadmap](#roadmap).

---

## Why

Classic endpoint triage dumps artifacts; signatures then try to match known
bad. AI-assisted malware leans on code that's generated and mutated per-build,
which defeats signatures — so the right response is the one live response was
always built on: **collect behavior, not hashes.** This tool doubles down on
behavioral triage and adds two indicators specific to the AI-assisted class:

- **Runtime LLM callouts.** Some samples call a commercial LLM API mid-execution
  to generate commands or decide what to do next (LameHug asked a model hosted
  on Hugging Face for its commands). A connection to LLM inference
  infrastructure from a process with no business making one (a script host, a
  random service) is a real, current signal.
- **Embedded prompt artifacts.** Samples that carry LLM instructions, chat-API
  scaffolding, provider endpoints, or API keys as embedded strings — whether to
  call a model or because a model wrote them — leave scannable traces.

Everything else is classic triage done well. The "AI" framing is kept honest:
two concrete indicators, not a buzzword applied to the whole tool.

---

## Architecture

A **Go framework** does broad, concurrent artifact collection and emits one
report. A **Rust sidecar** does the work that benefits from memory safety on
attacker-controlled input. They speak newline-delimited JSON over a pipe.

```
                 ┌──────────────────────────────────────────┐
  CLI / config ─▶│                lrng (Go)                 │
                 │                                          │
                 │  dispatcher ─▶ collectors (parallel)     │
                 │          processes · services · autoruns │
                 │          scheduledtasks · shimcache      │
                 │          prefetch · amcache · sessions   │
                 │          modules · localaccounts · udp   │
                 │          comhijack · wmi                 │
                 │          network                         │
                 │            └─ AI module A (LLM callouts) │
                 │          eventlog (live, or -evtx)       │
                 │            └─ built-in rules + Sigma     │
                 │  shared analytics: command lines,        │
                 │  process tree, paths, shortcuts, hashes, │
                 │  signatures                              │
                 │                                          │
                 │  post-passes ─▶ correlation · timeline   │
                 │                                          │
                 │  results ─▶ JSON or JSONL + .sha256      │
                 └──────────────────────────────────────────┘
                        │ request             ▲ response
                        │ (one JSON line)     │ (one JSON line)
                        ▼                     │
                 ┌──────────────────────────────────────────┐
                 │           lrng-sidecar (Rust)            │
                 │                                          │
                 │  scan_prompts ← AI module B on files     │
                 │  scan_memory  ← YARA-X + module B +      │
                 │                 memory heuristics on     │
                 │                 live process memory      │
                 └──────────────────────────────────────────┘
```

**Why the split, and why a separate process (not cgo/FFI) for v1:**

- The sidecar parses hostile input. Rust's memory safety means a malformed
  sample can produce a wrong answer, but not memory corruption.
- A panic is still possible, and process isolation handles it: the scanner
  dies alone instead of taking down the whole collection run. (The sidecar
  also catches its own panics and returns them as an error line.)
- No cgo toolchain coupling; the boundary is a stable JSON schema either side
  can evolve. A future version can swap the transport for a static FFI library
  without touching the contract.

The Go framework has **zero third-party dependencies** — Windows calls go
through the standard-library `syscall` package (plus a small read-only
registry reader, `internal/winreg`), so the agent builds from a clean checkout
with just the Go toolchain.

Every collector runs in its own goroutine under its own timeout. A collector
that panics becomes an error result. A collector that hangs (stuck in a system
call, say) is abandoned after its timeout plus a short grace period. Either way
the run finishes and the report gets written; Ctrl+C writes whatever was
collected so far, and collectors that hadn't started are listed as not run.

---

## What gets collected

**`processes`** — PID, PPID, parent name, name, thread count, full image path
and its SHA-256, command line, start time, owner (SID and `DOMAIN\user`),
session, integrity level, a `suspicious_path` flag, and the Authenticode
`signature_state` (`trusted`/`untrusted`/`unsigned`) of the image with the
`signer` it names, verified offline against embedded signatures and security
catalogs (`-no-sign` skips it). The signer is the certificate's display name
(for a catalog-signed Windows binary, the catalog's: "Microsoft Windows"); it's
attacker-chosen text, so it is length-capped and any control or bidi-override
character is shown as a `\uXXXX` escape. When a parent was
created *after* its child, the PID has been reused, so the record is marked
`parent_pid_reused` instead of naming the wrong parent. Anything that couldn't
be read is listed per record in `query_errors`. Every process is judged as
part of a tree (see [Detections](#detections)).

**`network`** — every IPv4 and IPv6 TCP connection and listener with state,
local/remote endpoints and owning PID/process, plus module A's findings and
the generic network heuristics. With `dnscache` selected, each connection also
carries the hostnames the DNS cache holds for its remote address.

**`udp`** — IPv4 and IPv6 UDP endpoints with their owning PID/process.

**`services`** — every service from the registry: image path (raw and
expanded), the normalised program and its SHA-256, `ServiceDll`, start type,
service type, account, recovery `FailureCommand`, and the key's last-write
time (≈ when it was installed or changed).

**`autoruns`** — the auto-start extensibility points: per-machine and per-user
Run/RunOnce (+ WOW64 and policy) keys with Task Manager's enable/disable state,
Winlogon `Shell`/`Userinit`/`Taskman`/`AppSetup`, legacy `Windows\Load`/`Run`,
`AppInit_DLLs`, `AppCertDLLs`, Image File Execution Options debuggers (native
and WOW64), SilentProcessExit monitors, `BootExecute`, the LSA authentication
packages / security providers / password filters, Command Processor
`AutoRun`, print monitors, netsh helpers, the screensaver, and the Startup
folders — with `.lnk` shortcuts resolved to the target and arguments they
launch. Each entry carries the key's last-write time, the command (expanded
under the right user's profile, with the raw value kept), the image and its
SHA-256. User hives are read for local, domain and Microsoft Entra ID
(`S-1-12-1-…`) accounts.

**`scheduledtasks`** — the Task Scheduler store parsed from task XML
(principal, run level, logon type, triggers, each action), the task file's
timestamps, action image hashes, and a cross-check against the registry cache
(`TaskCache\Tree`): tasks hidden by deleting their security descriptor, tasks
whose file is gone, and task files never registered.

**`shimcache`** — the AppCompatCache (Windows 10/11 `10ts` format): path and
file last-modified time per entry. (The registry copy is written at shutdown.)

**`amcache`** — the AmCache hive (`Amcache.hve`): programs that were present on
the host, each with its path, SHA-1, PE link date, publisher, version and the
key's last-write time. Covers the current `InventoryApplicationFile` layout and
the legacy `Root\File` layout. AmCache outlives the binaries it records, so it
surfaces tools that ran and were deleted; a program in an unusual path is raised
as `execution.amcache_unusual_path`. The hive is read live and best-effort —
if it's locked, the collector says so rather than failing — and parsed by a
dependency-free offline hive reader, so no binary is shelled out to.

**`prefetch`** — the prefetch directory with per-file timestamps and the
executable name/path-hash decoded from each `.pf` filename, and whether the
prefetcher is enabled. Each `.pf` body is also decompressed (Xpress Huffman)
and decoded: format version, run count, the recent run times (up to eight), the
files the program referenced on its runs, and the volumes (device path, serial,
creation time). A program that ran from a temp, download or world-writable path
is raised as `execution.prefetch_unusual_path`.

**`sessions`** — terminal and RDP sessions: id, state, station, user, client
name and IPv4 address, logon/connect/disconnect/last-input times, and whether
RDP is enabled (and on which port).

**`localaccounts`** — local users with privilege, RID, flags, password last
set, last logon, logon and bad-password counts, account expiry, and whether the
sign-in screen hides them; and the members (with SIDs) of Administrators,
Remote Desktop Users, Remote Management Users and Backup Operators.

**`modules`** — the loaded modules of every process lrng can open, one record
per process. A DLL loaded from a user-writable or temporary path is flagged.

**`comhijack`** — COM class registrations (CLSID servers) across the machine
class store (`HKLM\…\Classes\CLSID`, native and WOW64) and each loaded user's
own store. For each it reads the `InprocServer32`/`LocalServer32` server, its
`ThreadingModel` and any `TreatAs` redirect, and judges the COM-hijacking
patterns (T1546.015): a per-user registration that shadows a machine one (a
user's class store is consulted first, so it wins), a server DLL/EXE in a
user-writable or temporary path, a scriptlet (`scrobj.dll`) or script-host /
LOLBin server, and `TreatAs` remaps. Detection is behavioural, not a list of
"known abused" CLSIDs. A host has tens of thousands of legitimate CLSIDs, so
only registrations that trip a heuristic are recorded; the totals scanned are
in the result metadata.

**`wmi`** — WMI permanent event subscriptions in `root\subscription` (and the
legacy `root\default`): the `__EventFilter` trigger queries, the
`__EventConsumer`s — including the `CommandLineEventConsumer` command and the
`ActiveScriptEventConsumer` engine and script text — and the
`__FilterToConsumerBinding`s that make them live (T1546.003). Read from the CIM
repository over COM through a hand-rolled, dependency-free client (nothing is
shelled out to `wmic` or PowerShell). A clean install carries essentially none,
so every object is surfaced; the fileless script consumers and the active
bindings rank highest, while the stock `SCM Event Log Consumer` is left quiet.

**`eventlog`** — the DFIR-relevant Windows event logs, parsed from `winevt\Logs`
with a dependency-free, read-only EVTX/binary-XML reader (no `wevtutil` or
PowerShell shelled out to). It targets the channels that matter — Security,
System, Application, Windows PowerShell and PowerShell/Operational,
TaskScheduler, WMI-Activity, Windows Defender, both TerminalServices logs and
Sysmon — and, within them, the events that matter: the security-relevant ones
(log cleared, service installed, account created, privileged-group change,
remote logon, Defender detection) are recorded in full, while high-volume command-bearing
events (process creation 4688, PowerShell script blocks 4104) are kept only when
a rule fires. Command lines inside events run through the same analytics as
processes, services and task actions, so an encoded-PowerShell or
download-cradle payload is caught whether it is running now or only logged. Each
record carries the normalised `System` fields (provider, event id, level, the
`TimeCreated` timestamp, computer, the actor SID, process/thread id) and the
`EventData`/`UserData` values. A log held open by the event-log service, or one
larger than the read cap, is reported and skipped — read it from a shadow copy
or image then. The same parser also runs **offline** on a supplied `.evtx` (or a
directory of them) with `-evtx`, on any OS, applying the identical
classification — for an exported log, a Volume Shadow Copy, or a file pulled
from a disk image.

**`memory`** *(opt-in)* — YARA rules, the module-B prompt scan and memory
structure heuristics over the live memory of every process (or the ones you
pick). See [Memory scanning](#memory-scanning-yara).

**`dnscache`** *(opt-in)* — the DNS resolver cache: each cached name, its
record types, and the addresses it resolved to (read with cache-only lookups,
so nothing goes on the network). Selecting it also turns on **DNS
correlation** in `network`. It's opt-in because it reads the cache through the
undocumented `DnsGetCacheDataTable` API. The cache is snapshotted once, before
module A resolves anything, so lrng never pollutes the evidence it reports.

---

## Detections

Every finding has a rule id, a severity (`notable` → `suspect` →
`critical`), a confidence (0–100), a MITRE ATT&CK technique and a sentence
saying what was seen. Rules are deliberately specific — they match a
technique's mechanics, not a program's name — and each one is unit-tested
against both malicious and ordinary examples.

| Area | Rule ids |
|---|---|
| **Command lines** (processes, services, autoruns, task actions) | `exec.powershell_encoded` (decodes the payload into the finding), `exec.download_execute`, `exec.download_cradle`, `exec.powershell_reflective_load`, `exec.mshta_script`, `exec.rundll32_script`, `exec.regsvr32_scriptlet`, `exec.certutil_decode`, `exec.lolbin_proxy`, `exec.wmic_process_create`, `cred.lsass_dump` (comsvcs MiniDump, procdump), `cred.hive_or_ntds_dump`, `impact.inhibit_recovery` (vssadmin/wbadmin/bcdedit), `defense.clear_event_logs`, `defense.disable_defender`, `defense.firewall_disabled`, `persistence.account_created`, `persistence.admin_group_add`; context at *notable*: `exec.powershell_hidden`, `exec.frombase64`, `exec.obfuscated_blob`, `exec.scheduled_task_create`, `exec.service_create` |
| **Process tree** | `process.masquerade_path` (a system binary name outside its Windows directory), `process.unexpected_parent` (e.g. `lsass.exe` not started by `wininit.exe`), `process.document_app_child` (Office → shell), `process.server_app_child` (w3wp → shell: web shell), `process.wmi_child`, `process.service_shell`, `process.name_typosquat` (`scvhost`, `Isass`), `process.unusual_path` |
| **Autostarts** | `persistence.autorun_unusual_path`, `persistence.startup_folder_program`, `persistence.policies_run`, `persistence.windows_load`, `persistence.winlogon_hijack`, `persistence.winlogon_extra`, `persistence.ifeo_debugger`, `persistence.silent_process_exit`, `persistence.appinit_dlls`, `persistence.appcert_dlls`, `persistence.lsa_authentication_package`, `persistence.lsa_security_package`, `persistence.password_filter`, `persistence.boot_execute`, `persistence.cmd_autorun`, `persistence.print_monitor`, `persistence.netsh_helper`, `persistence.screensaver` |
| **Services & scheduled tasks** | `persistence.service_unusual_path`, `persistence.service_script_host`, `persistence.service_unquoted_path`, `persistence.service_failure_command`, `lateral.service_in_windows_dir` (PsExec/Impacket), `persistence.scheduled_task_unusual_path`, `persistence.scheduled_task_hidden` (Tarrask), `persistence.scheduled_task_no_file`, `persistence.scheduled_task_unregistered` |
| **COM & WMI persistence** | `persistence.com_hijack_user_shadow` (a per-user CLSID overriding a machine one), `persistence.com_server_unusual_path`, `persistence.com_script_server` (`scrobj.dll` / script-host server), `persistence.com_treatas_redirect`; `persistence.wmi_script_consumer` (fileless `ActiveScriptEventConsumer`), `persistence.wmi_commandline_consumer`, `persistence.wmi_consumer_unusual_path`, `persistence.wmi_consumer`, `persistence.wmi_filter`, `persistence.wmi_subscription_active` (a binding — the persistence is live) |
| **Accounts & sessions** | `accounts.dollar_suffix_user`, `accounts.hidden_from_logon_screen`, `accounts.guest_enabled`, `accounts.password_not_required`, `sessions.remote_from_public_address` |
| **Network** | `network.lolbin_outbound`, `network.script_host_listener`, `network.unusual_path_outbound`, `network.script_host_outbound`; module A's `ai.llm_callout`, `ai.llm_callout_unattributed`, `ai.llm_callout_unusual_path`, `ai.llm_dns_cache` |
| **Execution evidence & modules** | `execution.shimcache_unusual_path`, `execution.prefetch_unusual_path`, `execution.amcache_unusual_path`, `modules.unusual_path` |
| **Signature integrity** | `integrity.unsigned_system_binary` (a process image in System32/SysWOW64 that is unsigned or carries an untrusted signature; the finding quotes who that signature claims to be from) |
| **Event logs** | `defense.clear_event_logs` (Security 1102 / System 104), `eventlog.service_installed` (7045), `persistence.account_created` (4720), `persistence.admin_group_add` (4728/4732/4756 to a privileged group), `eventlog.powershell_suspicious_block` (4104), `eventlog.defender_detection` (Defender 1116/1117) — plus the command-line rules above applied to 4688 command lines, 4104 script blocks and 7045 service ImagePaths |
| **Logon sessions** (event log) | `logon.remote_interactive` (4624 type 10 / RDP — suspect from a public source address, T1021.001), `logon.network_external` (4624 type 3 from an external address, T1021), `logon.failed_external` (4625 from an external address, T1110) |
| **Correlation** (event log × live state) | `correlate.service_installed_absent` (a 7045 service install with no matching live service — installed then removed, T1070.009), `correlate.task_registered_absent` (a 4698/106 task registration with no matching live task — deleted or hidden, T1070.009); and the `defense.clear_event_logs` finding is annotated with the surviving record-id/time range left by the clear |
| **Sigma** (`-sigma`) | `sigma.<rule>` for each matching Sigma rule, carrying the rule's level (→ severity) and first `attack.t*` tag (→ technique) — the analyst's own detections, run beside the built-in ones |
| **Memory** (opt-in) | `yara:<rule>`, `memory.pe_in_private` (reflective/manual-mapped PE), `memory.elf_in_anonymous`, `memory.memfd_exec`, `memory.deleted_file_exec`, and module B's `prompt.*`, `api.*`, `model.*` and `secret.*` (below) |
| **Endpoint intelligence** (`-intel`) | `intel.tor_endpoint` (a remote address that is Tor infrastructure, T1090.003), `intel.anonymizer_endpoint` (a known anonymising VPN/proxy, T1090.002) — from the offline ASN/country/category attribution of the run's public remote addresses |

**False-positive discipline.** Path heuristics grade locations: temporary,
download and world-writable directories are *high* risk, `ProgramData` and
drive roots *low* (a lower severity). Microsoft Defender's own home under
`ProgramData` is trusted. A path in an ordinary program's arguments (a log
file) is ignored; in a proxy host's arguments (`rundll32 C:\Users\Public\x.dll`)
it's the payload and is judged. `%TEMP%`-style references are resolved before
judging, so they can't hide a location. lrng never judges itself or its
sidecar, wherever you run it from.

`summary.top_findings` lists the most severe findings with pointers back to
their records, and a short summary is printed to stderr after every run.

---

## The two AI modules

### Module A — runtime LLM-callout detection (Go, `internal/aidetect`)

At run start it resolves the API hostnames of ~30 commercial LLM inference
providers (OpenAI, Anthropic, Google, Hugging Face, Mistral, Groq, DeepSeek,
xAI, Alibaba Qwen, NVIDIA, …), all at once with a 3-second limit per lookup,
so a network-contained host can't stall the run. It then checks each TCP
connection's remote address against that set — and, with DNS correlation, its
hostname, which also matches regional/per-tenant endpoints (Azure OpenAI and
AI Foundry, AWS Bedrock, Vertex AI).

| Situation | Finding |
|---|---|
| Script host or LOLBin (`powershell.exe`, `rundll32.exe`, `python.exe`, …) → LLM endpoint | `ai.llm_callout`, **critical** |
| Any other process not on the allowlist → LLM endpoint | `ai.llm_callout`, suspect |
| Allowlisted *name* (`chrome.exe`, `code.exe`, …) running from a temp/user-writable path → LLM endpoint | `ai.llm_callout_unusual_path`, suspect |
| Closed connection with no owning process (`TIME_WAIT`, PID 0) → LLM endpoint | `ai.llm_callout_unattributed`, notable |
| DNS cache holds an LLM endpoint name (`dnscache`) | `ai.llm_dns_cache`, notable |

It's a heuristic and says so. Know its limits before you rely on it:

- **Shared infrastructure.** Public LLM APIs sit behind shared CDNs and their
  IPs churn, so a match is a lead for an analyst, not a verdict.
- **Point-in-time.** It sees connections that exist at collection time. An API
  call that finished more than a few minutes ago is gone from the table (the
  DNS cache remembers longer — select `dnscache`).
- **DNS filtering.** If a provider resolves to a loopback, private or
  unspecified address (typical of DNS filters that block AI APIs), that answer
  is ignored and listed in the collector's `meta.non_public_answers_ignored`.

`results[].meta` for the network collector reports exactly what the detector
had to work with (hosts resolved, IPs loaded, failures), so "no findings" can
be told apart from "nothing to match against".

### Module B — embedded prompt-artifact scanner (Rust, `sidecar-rs/src/prompts.rs`)

Binary-safe pattern matching over a file or live memory for: prompt-injection
phrasing, system-role scaffolding, chat-API JSON shape (`"role":"system"`,
`"messages":[`, sampling params), model identifiers (GPT, Claude, Gemini,
Llama, Mistral, DeepSeek, Grok, Qwen, gpt-oss), provider endpoints (the same
list as module A), and API keys (OpenAI, Anthropic, Google, Hugging Face,
Groq, xAI, OpenRouter and other OpenAI-compatible hex keys).

- **ASCII and UTF-16LE.** Windows binaries and .NET assemblies store most
  string literals as UTF-16LE, so the scanner reads the input three ways (raw,
  and UTF-16LE at even and odd offsets) and tags each hit with its `encoding`.
- **Keys must look random.** Key matches need digits and letters (mixed case
  for base62 keys), which filters out look-alikes such as
  `sk-learn-preprocessing-pipeline`.
- **Secrets never leak.** Every key inside any hit's context snippet is
  redacted, including a key that merely sits next to another rule's match.
- **Bounded.** Files are read up to 64 MiB, never more, and are flagged
  `truncated` beyond that.

Each hit carries an offset, encoding, sanitized context, severity, ATT&CK
technique where one fits, and confidence. A run returns an aggregate score
(each rule counted once) and a verdict. Rule ids: `prompt.injection`,
`prompt.system_role`, `prompt.ai_disclaimer`, `api.chat_schema`,
`api.messages_array`, `api.sampling_params`, `api.endpoint`,
`model.identifier`, `secret.openai_key`, `secret.anthropic_key`,
`secret.google_key`, `secret.huggingface_token`, `secret.groq_key`,
`secret.xai_key`, `secret.openai_compatible_key`.

---

## Memory scanning (YARA)

The sidecar scans live process memory with
[YARA-X](https://virustotal.github.io/yara-x/), VirusTotal's pure-Rust YARA,
so the code reading attacker-controlled memory stays memory-safe end to end.

```powershell
.\lrng.exe -yara .\rules -out E:\case42\HOST01.json      # default collectors + memory
.\lrng.exe -collectors memory -yara .\rules -mem-pids 4242,5120
.\lrng.exe -mem-scan 4242 -yara .\rules                  # one process, to the console
```

**How it works.** For each process the sidecar opens the target read-only
(`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, nothing else), walks its
committed, readable regions with `VirtualQueryEx`, reads them in 16 MiB
chunks (with a 4 KiB overlap so nothing straddling a chunk boundary is
missed), and feeds each chunk to a YARA block scan *at its virtual address*.
This is the same model as `yara rules.yar <pid>`: rule conditions are
evaluated across the whole process, and match offsets are virtual addresses.
Each hit reports the region it's in: base, size, protection (`RX`, `RWX`, …),
type (`image` / `mapped` / `private`) and backing file (as a drive-letter
path). Private `RWX` memory holding a match is exactly what to look at first.

**Memory heuristics (no rules needed).** The start of every executable region
no image file backs is checked for a PE header (`memory.pe_in_private`,
including headers whose `MZ` was erased) — the footprint of reflective DLL
injection and manual mapping. On Linux, anonymous executable ELF images,
executable `memfd` mappings and executable mappings of deleted files are
flagged. Per-process counts of unbacked executable and RWX regions are in the
record.

**Rules.** Pass `-yara` a `.yar`/`.yara` file or a directory (searched
recursively). Each file gets its own namespace, so rule names from different
sets can't collide. Rule files that fail to compile are listed in
`meta.yara.rules_failed` and counted as collector errors instead of being
dropped silently. Severity, confidence and ATT&CK technique come from rule
metadata when present (`severity`, `score`, `mitre_attack`), so you can tune
them in your rules.

**What can't match in memory.** In block mode, as in classic YARA process
scanning, modules (`pe`, `hash`, …), `uint32()`-style reads and `filesize`
are undefined. String, hex and regex rules work fully. Files that import
modules are listed in `meta.yara.module_imports`.

**Module B in memory.** Unless `-mem-no-prompts` is given, every chunk also
goes through the prompt-artifact scanner (ASCII and UTF-16LE, keys redacted).
Expect more noise than on files: environment blocks and browser memory often
contain LLM endpoints or model names legitimately.

**Bounded and partial-safe.**

| Flag | Default | Meaning |
|---|---|---|
| `-mem-budget` | 60s | time per process; past it the result is `partial` with `stopped_early` |
| `-mem-timeout` | 15m | the whole memory collector |
| `-mem-workers` | 2 | sidecars scanning in parallel (each compiles the rules once) |
| `-mem-pids` | all | only these PIDs |
| `-mem-no-prompts` | off | YARA only (roughly 5× faster) |
| `-mem-include-lsass` | off | scan `lsass.exe` too |

Results stream back per process, so a timeout keeps everything already
scanned. Every process gets a record (`scanned`, `partial`, `skipped`,
`access_denied`, `not_found`, `not_reached`) with bytes scanned and
coverage, so gaps are visible.

**Safety defaults.**
- **No raw memory in the report.** YARA hits carry rule names, pattern
  identifiers and addresses, never matched bytes. Module-B snippets are the
  same sanitised, key-redacted text used for files.
- **`lsass.exe` is skipped** unless `-mem-include-lsass` is given. Reading it
  trips Defender/EDR credential-theft protection and pulls credential material
  into the scanner's buffers. Scan it on purpose, not by default.
- **lrng never scans itself or its sidecars.** Its own memory contains the
  very strings its rules look for.
- **Protected processes** (PPL: Defender, `csrss.exe`, LSASS with RunAsPPL)
  can't be opened even when elevated; they're recorded as `access_denied`.

**Throughput** (release build, 400 MB process, Linux test host): YARA only
≈1.4 GB/s; YARA plus the prompt scan ≈240 MB/s.

The same scanner works on Linux through `/proc/<pid>/mem` (as root), which is
also how it's tested end to end.

---

## Sigma rules

`-sigma` evaluates [Sigma](https://sigmahq.io) detection rules against every
parsed event, beside the built-in detections, in both live and offline
(`-evtx`) runs. A match is a `sigma.<rule>` finding carrying the rule's level
(mapped to severity) and first `attack.t*` tag (mapped to technique), and it
keeps an otherwise-dropped high-volume event. Rules are read with a
dependency-free YAML-subset parser, so the zero-dependency Go tree stands.

The flag takes a comma-separated spec where each entry is a `.yml`/`.yaml` file,
a directory, or **`builtin`** — a small curated starter pack embedded in the
binary and mapped to the channels lrng collects (encoded PowerShell, PsExec and
smbexec service installs, shadow-copy deletion, LSASS-dump command lines,
credential-tool keywords, a windowed failed-logon burst and password spray,
Defender real-time-protection changes, external RDP by source CIDR, and a log
clear that lands within minutes of a service install), so Sigma is useful with
nothing on disk.

```powershell
.\lrng.exe -sigma builtin -out E:\case42\HOST01.json        # the bundled pack
.\lrng.exe -sigma .\rules -out E:\case42\HOST01.json        # your own rules
.\lrng.exe -sigma builtin,.\rules -out E:\case42\HOST01.json   # both
.\lrng.exe -evtx E:\case42\winevt\Logs -sigma builtin       # offline, any OS
```

**Supported:** string matching with `*`/`?` wildcards; the `|contains`,
`|startswith`, `|endswith`, `|all`, `|re`, `|cased` and `|windash` (treats every
`-`/`/` as any Windows dash variant — `-`, `/`, en/em dash, horizontal bar)
modifiers; `|base64offset` (match a value as it appears base64-encoded at any
byte alignment); `|cidr` (match an IP-address field against a CIDR network, IPv4
or IPv6); `|fieldref` (compare a field to another field's value — on its own, or
with `|contains`/`|startswith`/`|endswith` and `|cased`); numeric
`|lt`/`|lte`/`|gt`/`|gte`, `|exists`, and null matches; list values (OR, or AND
with `|all`); a selection that is a list of maps; keyword lists; the condition
language (`and`/`or`/`not`, parentheses, and `N`/`all`/`1 of them` or
`… of <pattern>*`); the scalar aggregations
`<expr> | count|min|max|avg|sum([field]) [by <field>] <op> <n>` — evaluated
across the whole run and emitted as a synthetic record per over-threshold group.
A `count`, `count(field)` or `sum` with `>`/`>=` and a detection `timeframe:`
is instead evaluated as a **sliding window** of that width, firing if any window
crosses the threshold (a burst of failed logons, a spray across distinct
accounts, or a volume spike — not the same count spread thinly over a week).
And the temporal
`<expr> | near <expr>` with a detection `timeframe:` window, which fires when the
named selections co-occur inside one window (an install-then-wipe sequence, say).
`logsource` narrows a rule to a channel/event when its service or category is one
lrng maps; otherwise the rule is tried against every event.

**Not evaluated — skipped with a reason, never mis-scored:** the plain `|base64`
and `|utf16`/`|wide` encodings, a `| near` with no `timeframe` (it has no defined
window), a `timeframe` on `min`/`max`/`avg` or with an operator other than
`>`/`>=` (no sound sliding-window meaning), and a condition that names a
selection the rule doesn't define. Skipped
and failed-to-parse counts are printed to stderr. The eventlog result's
`meta.sigma` lists each skipped rule with its reason (`skipped`) and each file
that failed to parse (`failed`), the way YARA compile failures are listed — a
detection tool must say which rules it could not run rather than quietly
matching nothing.

---

## Super-timeline

`-timeline` adds a synthetic `timeline` result that merges every timestamped
artifact the other collectors gathered into one oldest-first view: prefetch run
times, service / autorun / registry key-last-write times, scheduled-task cache
writes, account last-logon and password-set times, ShimCache / AmCache times,
and event `TimeCreated`. Each entry names its source collector, the artifact
timestamp it came from, an identifying detail, and a pointer back to the source
record; when that record carries a finding, the entry shows the top rule and
severity, so detections sit in sequence with the activity around them. Timeline
entries hold no findings of their own, so the report's finding counts are
unchanged. It's a post-pass (run after correlation), works for live and `-evtx`
runs, and is bounded — past the cap the most recent entries are kept and the
truncation is noted in `meta`.

---

## Indicators (IOC export)

`-iocs` adds a synthetic `iocs` result: the indicators of compromise distilled
out of the run, deduplicated and ranked, so what an analyst does *after* triage
— block these addresses at the firewall, sweep these hashes across the fleet,
search these domains in the DNS logs — is a copy-and-go list rather than a
scrape through nested records.

Scope is deliberately tight: only records that **carry a finding** contribute,
so the result is the set of indicators tied to something the tool actually
flagged, not a full host inventory. Each indicator is deduplicated across every
record it appeared in — including across collectors, so the address a
connection beaconed to and the same address sitting in the DNS cache become one
entry — and ranked by the highest severity of the detections that referenced
it, so the ones worth acting on first sort to the top.

| Type | Drawn from | Kept when |
|---|---|---|
| `ipv4` / `ipv6` | any address field (a connection's `remote_addr`, a resolved `addresses`, a logon's `IpAddress`) | the address is **public** (same `aidetect.PublicAddr` test the rest of the tool uses) and not the socket's own local side — a host never lists itself or RFC1918 space |
| `domain` | fields that hold a hostname (the DNS cache's `name`, a connection's correlated `remote_hosts`) | it has the shape of a DNS name — so a process merely *named* like a domain isn't swept up |
| `sha256` / `sha1` | any field (`image_sha256`, AmCache `sha1`, …) | the value is bare hex of the exact length |
| `filepath` | path-bearing fields (`image_path`, `program`, COM `server`, …) | the value has a drive-letter or UNC shape — so a registry key or a task path is never mistaken for a file |

Each record carries the indicator's `type` and `value`, the `max_severity` and
the distinct `rules` of the detections that referenced it, a `source_count`, and
`sources` back-pointers into `results[result].records[record]` naming the field
each value came from — so an analyst can see *why* an indicator is on the list
before acting on it. The pass descends into the nested `event_data`/`user_data`
maps (an `IpAddress` behind a failed-logon event is captured under its leaf
field), runs after correlation so a cross-collector finding's indicators are
included, and skips the `timeline` and its own `iocs` result so no derived view
feeds back in. It works for live and `-evtx` runs, carries no findings of its
own (so finding counts are unchanged), and is bounded (50,000 indicators,
lowest-severity dropped past the cap). `meta.by_type` counts the set by type.

```powershell
.\lrng.exe -iocs -out E:\case42\HOST01.json                 # triage + an indicator set
.\lrng.exe -evtx E:\case42\winevt\Logs -iocs -out logs.json # offline, same pass
.\lrng.exe -timeline -iocs -out E:\case42\HOST01.json       # both post-passes
```

```jsonc
// one record of the "iocs" result
{ "fields": {
    "type": "ipv4", "value": "203.0.113.7",
    "max_severity": "suspect", "source_count": 2,
    "rules": ["ai.llm_dns_cache", "network.lolbin_outbound"],
    "sources": [ { "collector": "network",  "record": 41, "field": "remote_addr" },
                 { "collector": "dnscache", "record": 6,  "field": "addresses" } ] } }
```

---

## Endpoint intelligence (offline)

`-intel` adds a synthetic `intel` result that puts a name to the addresses the
run observed. The collectors tell you a host talked to `185.220.101.47`; this
pass tells you *what that is* — the AS and organisation that own it, the country
it's allocated in, and whether it's a cloud platform, a CDN, a hosting/VPS
provider, a public DNS resolver, Tor, or an anonymising VPN/proxy.

It is **wholly offline**: a dataset compiled ahead of time and bundled into the
binary, looked up by an in-memory longest-prefix match — no WHOIS, no geo-API, no
DNS. That is the point. By the time a responder reaches a box it is often
network-contained or air-gapped, and reaching out to a reputation service would
also tip off an attacker watching the wire. So the lookups are done once, in
advance, and the host does none at run time.

| Category | Means |
|---|---|
| `cloud` | IaaS / general cloud compute (AWS, Azure, GCP, Oracle, …) |
| `cdn` | content-delivery / edge (Cloudflare, Fastly, Akamai, …) |
| `hosting` | hosting / VPS / dedicated-server providers (OVH, Hetzner, DigitalOcean, …) — where throwaway C2 often lives |
| `dns` | public recursive DNS resolvers (Quad9, OpenDNS, Google/Cloudflare DNS) |
| `tor` | Tor network infrastructure (exit, relay, directory authority) |
| `anonymizer` | commercial VPN / open-proxy / anonymising egress |

**Scope** is every public remote address across the real collector records — not
only detection-linked ones, because attribution is useful context on all of a
host's external contacts. The socket's own local side and private/reserved space
are excluded (same `aidetect.PublicAddr` test the rest of the tool uses), and
addresses are deduplicated across the run. Each record carries the matched
`prefix`, the `asn`, `org`, `country` and `categories` when the dataset knows
them, `source_count` and `sources` back-pointers into
`results[result].records[record]`, and — when a finding sat on a record the
address appeared in — that record's `co_max_severity` and `co_rules`, so an
address that is both externally flagged *and*, say, a Tor node sorts to the top.
A miss is reported as `"attributed": false`, never guessed.

**Findings.** Two categories are high-signal enough to flag on their own: a
contact with Tor infrastructure raises `intel.tor_endpoint` (T1090.003,
*suspect*) and a contact with a known anonymising VPN/proxy raises
`intel.anonymizer_endpoint` (T1090.002, *notable*) — both classic anonymised-C2
and exfiltration channels. `cloud` / `cdn` / `hosting` / `dns` are context on the
record only; flagging them would drown the report.

**It enriches the IOC set.** With `-iocs` as well, each IP indicator in the
`iocs` result gains `intel_asn` / `intel_org` / `intel_country` /
`intel_categories` in place — so an exported blocklist ships with its "who /
where / what" attached.

**Freshness is explicit.** Attribution is only ever as current as the dataset,
so the result's `meta.dataset` records the dataset's source, generation date and
entry count, and the report's `run.intel_dataset` repeats it — a stale lookup is
visible as such.

```powershell
.\lrng.exe -intel -out E:\case42\HOST01.json                  # attribute the host's external contacts
.\lrng.exe -intel -iocs -out E:\case42\HOST01.json            # + an attributed blocklist
.\lrng.exe -intel-db .\endpoints.tsv -iocs -out HOST01.json   # use a refreshed dataset (implies -intel)
.\lrng.exe -evtx E:\case42\winevt\Logs -intel -out logs.json  # offline, same pass
```

```jsonc
// one record of the "intel" result — a flagged connection to a Tor node
{ "fields": {
    "address": "128.31.0.39", "version": "ipv4", "attributed": true,
    "prefix": "128.31.0.39/32", "asn": 3, "country": "US",
    "org": "Tor directory authority (moria1)", "categories": ["tor"],
    "co_max_severity": "suspect", "co_rules": ["net.beacon_regular"],
    "source_count": 1,
    "sources": [ { "collector": "network", "record": 0, "field": "remote_addr" } ] },
  "findings": [ { "rule": "intel.tor_endpoint", "severity": "suspect",
    "technique": "T1090.003", "confidence": 75,
    "detail": "remote address 128.31.0.39 is Tor network infrastructure …" } ] }
```

### The dataset, and refreshing it

The binary ships a real, generated dataset (`internal/intel/data/endpoints.tsv`,
~25k prefixes) built by `cmd/intelgen` from current, public sources: per-ASN CIDR
allocations for the major cloud / CDN / hosting / DNS providers, the live Tor
exit list, and a small built-in overlay of public resolvers and the Tor directory
authorities. Regenerate it on a networked workstation (never on the triaged
host), then rebuild `lrng` to embed the result.

**From GitHub-hosted feeds** (works behind a restrictive egress allowlist — only
`raw.githubusercontent.com` is needed):

```sh
# per-ASN CIDRs from ipverse/asn-ip, for the ASNs intelgen categorises
mkdir asndir
for asn in 16509 8075 15169 13335 54113 20940 14061 16276 24940 63949 20473 31898 19281 36692; do
  for fam in ipv4 ipv6; do
    curl -fsS "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/$asn/$fam-aggregated.txt" \
      -o "asndir/$asn-$fam.txt" || true
  done
done
# the TorProject exit list, mirrored by firehol
curl -fsS "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset" -o tor_exits.lst

go run ./cmd/intelgen -asn-cidrs asndir -tor tor_exits.lst \
  -out internal/intel/data/endpoints.tsv
```

**From iptoasn.com** (adds a country to every prefix, and full ASN coverage;
larger, and needs direct access to iptoasn.com):

```sh
curl -LO https://iptoasn.com/data/ip2asn-combined.tsv.gz
curl -L  https://check.torproject.org/torbulkexitlist -o torbulkexitlist
make intel-data        # intelgen -ip2asn … -tor …  (add -countries for per-prefix country)
```

`intelgen` tags ASNs by a built-in, overridable map (`-cats`), marks the Tor list
as `tor`, and overlays the known public resolvers (so `8.8.8.8` reads as `dns`,
not just its host ASN's category) and Tor directory authorities. The dataset
format is plain tab-separated text — `CIDR  ASN  CC  CATEGORIES  ORG` — so it
diffs cleanly and can be hand-edited. Point `-intel-db` at a file to use one
without rebuilding.

---

## Demo

`demo/linux-detection-demo.sh` stages benign stand-ins for six common Linux
attacker TTPs — a payload run from `/tmp`, a process masquerading as a kernel
thread, cron and systemd persistence, a fetch-and-run cradle and a reverse-shell
one-liner — then runs a triage and prints what fired. Every "payload" is `sleep`,
the only addresses are the documentation range, and everything is removed on exit.
It's a one-command way to see the Linux detections work (and a good screen
recording). See [`demo/README.md`](demo/README.md).

```sh
make build && sudo ./demo/linux-detection-demo.sh
```

---

## Platform support

| | Supported |
|---|---|
| **OS** | Windows 10 / Windows Server 2016 or later; Linux (kernel with `/proc` — the release binaries are fully static, so any distro, glibc or musl) |
| **Arch** | x64, ARM64 (Windows and Linux), x86 (32-bit Windows only — see below) |
| **Privileges** | Run elevated (Windows) or as root (Linux). The report records whether it was (`run.elevated`); without it, other users' processes, their open sockets, `/proc/<pid>/exe` targets and `/etc/shadow` are unreadable and those details are incomplete. |

### Collectors by OS

The collection framework is portable; each collector is implemented per OS. The
set that compiles and runs is exactly the set `-list` shows on that host.

| Collector | Windows | Linux | Linux source |
|---|---|---|---|
| `processes` | ✅ | ✅ | `/proc/<pid>/{status,stat,exe,cmdline}`, `/etc/passwd` |
| `network` (TCP) | ✅ | ✅ | `/proc/net/tcp{,6}` + `/proc/<pid>/fd` for the owning PID |
| `udp` | ✅ | ✅ | `/proc/net/udp{,6}` |
| `modules` | ✅ | ✅ | `/proc/<pid>/maps` (executable, file-backed mappings) |
| `localaccounts` | ✅ | ✅ | `/etc/passwd`, `/etc/group`, `/etc/shadow`, and each user's `authorized_keys` (via sshd's `AuthorizedKeysFile`) |
| `autoruns` (persistence) | ✅ | ✅ | ld.so.preload, cron, systemd, rc.local, XDG autostart, shell profiles |
| AI module A (LLM callouts) | ✅ | ✅ | runs on the Linux `network` collector (OS-agnostic) |
| `memory` (opt-in) | ✅ | ✅ | the Rust sidecar reads `/proc/<pid>/{maps,mem}` |
| `eventlog`, `sigma`, `-timeline`, `-iocs`, `-intel` | ✅ | ✅ | portable (Sigma and the event log are fed Windows `.evtx`, live or via `-evtx`) |
| `amcache`, `authenticode`, `comhijack`, `prefetch`, `shimcache`, `wmi`, `dnscache`, `services`, `scheduledtasks` | ✅ | — | Windows-specific concepts; on Linux, service and scheduled-task persistence is covered by `autoruns` (systemd and cron) |

On Linux the heuristics are Linux-shaped: path risk grades `/tmp`, `/dev/shm`,
`memfd`, deleted images and home hidden dirs, and the command-line analytics
catch reverse shells (`/dev/tcp`, netcat `-e`, socat EXEC, interpreter
one-liners), fetch-and-run (`curl … | sh`), base64-pipe-to-shell and persistence
writes. `lrng` targets Windows and Linux; on any other OS the collectors are
stubbed out (so the tree still builds) and simply don't appear in `-list`.

- **Older hosts.** Go 1.21+ and Rust 1.78+ binaries don't run on Windows
  7/8/8.1 or Server 2008/2012/2012 R2. For those hosts, use the PowerShell
  predecessor.
- **Use the x86 build only on 32-bit Windows.** On 64-bit Windows a 32-bit
  process runs under WOW64: file-system and registry redirection give it a
  32-bit view of `System32` and parts of `HKLM\SOFTWARE`, and it can't
  enumerate 64-bit processes' modules or fully read their memory.
- **Logged-off users.** Per-user registry autostarts are read from the hives
  that are loaded (users who are signed in or have processes running). lrng
  doesn't load other users' `NTUSER.DAT` — that would modify the live
  registry — and lists those profiles in `meta.profiles_without_loaded_hive`.
  Their Startup folders are still checked.

---

## Forensic footprint

Live response changes the system it examines. Here is what `lrng` itself
leaves behind, so you can account for it in your notes:

- **DNS.** Module A's start-up resolution sends DNS queries for the LLM
  provider hostnames and adds them to the host's DNS client cache. Use
  `-no-dns` when that cache is evidence (module A then has no IPs to match;
  the report says so), or select `dnscache`, which snapshots the cache before
  any lookup (`meta.taken_before_module_a_lookups`).
- **File reads.** Hashing opens the binaries the report names (process
  images, third-party and flagged service/autostart binaries) — each file at
  most once, up to 128 MiB. Use `-no-hash` to skip it.
- **Signature checks.** Verifying a process image opens it (to hash it for a
  catalog lookup) and queries the system catalog database. Verification is
  offline — no revocation traffic, so no network footprint — and each distinct
  image is verified once. Use `-no-sign` to skip it.
- **Endpoint intelligence** (`-intel`) adds **no** footprint: the lookup is a
  pure in-memory match against the bundled dataset, with no network I/O, no DNS
  and no file writes — it is safe on a contained or air-gapped host.
- **Memory scanning** opens other processes with `PROCESS_VM_READ` and reads
  their memory. That's exactly what EDR products watch for, so expect alerts
  (and blocks, for protected processes) and tell the SOC before a sweep.
- **Execution artifacts.** Running `lrng.exe` and `lrng-sidecar.exe` can
  create Prefetch entries (on by default on client Windows) and process-creation
  events in whatever logging the host has.
- **Disk.** Run from external media or a read-only share where possible, and
  point `-out` off-host. `-out` refuses to overwrite an existing file unless
  you pass `-force`.
- **Integrity.** Each report is written with a `<report>.sha256` file, the
  report records the SHA-256 of the `lrng` binary that produced it and a
  `run_id`, and `make release` writes `dist/SHA256SUMS`. Record these in your
  case notes.

Everything else is read-only: registry keys are opened with `KEY_READ`,
processes with query-only rights (outside the opt-in memory scan), and the
DNS cache with cache-only lookups.

---

## Build

Requires Go 1.24+ (build releases with a currently supported Go release) and,
for the sidecar, Rust 1.93+ (YARA-X). `Cargo.lock` is committed and builds use
`--locked`. With YARA-X the release sidecar is about 21 MB and takes around
10 minutes to build (LTO); `cargo build --no-default-features` builds a small
sidecar without YARA (prompt scanning and memory heuristics only).

```bash
make help            # list all targets
make all             # agent + sidecar for this machine, side by side
make release         # every Windows and Linux build + dist/SHA256SUMS:
                     #   dist/windows-amd64/{lrng.exe,lrng-sidecar.exe}
                     #   dist/windows-386/{lrng.exe,lrng-sidecar.exe}
                     #   dist/windows-arm64/{lrng.exe,lrng-sidecar.exe (x64, emulated)}
                     #   dist/linux-amd64/{lrng,lrng-sidecar}        (all static)
                     #   dist/linux-arm64/{lrng,lrng-sidecar}        (all static, native aarch64)
make release-windows # just the Windows half (needs mingw-w64)
make release-linux   # just the Linux half (needs cargo-zigbuild; see below)
make check           # gofmt/rustfmt, go vet (all Windows arches), clippy
                     # (with and without YARA), Windows memory code type-check, tests
make test-race       # Go tests under the race detector
make wine-test       # optional: run the Windows test binary and a sweep under Wine
make audit           # govulncheck + cargo-audit
```

Agents are static (`CGO_ENABLED=0`), built with `-trimpath -ldflags "-s -w"`,
and stamped with the git tag and commit so every report says which build
produced it.

**CI** (`.github/workflows/ci.yml`) runs the Linux checks above, then the full
Go suite — including a sweep of every collector — on a real Windows runner,
and an integration job that builds the agent and sidecar on Windows and finds
a YARA marker in a live process's memory. A Linux release job builds the
Linux release set with the same `make` recipes `make release` uses, fails if any
artifact is dynamically linked or built for the wrong architecture, then runs
the static agent and sidecar together: a default triage, a prompt scan, and a
live memory scan that must find a YARA marker assembled at runtime in another
process's heap. Both runners' triage reports are kept as build artifacts: a
clean runner is a useful false-positive baseline.

**Linux release sidecars** are fully static musl binaries, so one build runs on
any distro — glibc of any age, or musl (Alpine) — for the same reason the
Windows sidecar links its C runtime statically. wasmtime (under YARA-X)
compiles a small C helper on Unix targets, so the build needs a C compiler for
each target; [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
supplies zig as the C compiler and linker for both, from any build host, with
no musl-tools or aarch64 cross toolchain. One-time setup:

```bash
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
cargo install --locked cargo-zigbuild
pip install ziglang                       # or put a zig release on PATH
make release-linux
```

The ARM64 build gets a native aarch64 sidecar: unlike Windows on ARM, Linux
won't run the x64 one under emulation. Memory scanning on Linux reads
`/proc/<pid>/mem`, so run it as root (or with `CAP_SYS_PTRACE`); with Yama's
default `ptrace_scope=1` an unprivileged user can't read another process's memory.

**Cross-compiling the sidecar for Windows** uses the `*-pc-windows-gnu`
targets, which need mingw-w64:

```bash
rustup target add x86_64-pc-windows-gnu i686-pc-windows-gnu
sudo apt install gcc-mingw-w64
make sidecar-windows sidecar-windows-x86
```

The x86 sidecar is built with `--features yara-pulley`: wasmtime's JIT has no
32-bit x86 backend, so YARA conditions run on its portable interpreter there
(same results, slower). `make check-windows-rs` type-checks and lints the
sidecar's Windows memory code from a non-Windows host.

To build the MSVC target instead, use
[cargo-xwin](https://github.com/rust-cross/cargo-xwin) or build on Windows. The
repo-root `.cargo/config.toml` links the C runtime statically for MSVC builds,
so the sidecar runs on hosts without the VC++ redistributable.

---

## Usage

Run from an elevated prompt. Keep `lrng-sidecar.exe` in the same folder as
`lrng.exe` (or pass `-sidecar <path>`; a bare name is never looked up on
`PATH`).

```powershell
.\lrng.exe -list                                  # collectors available here
.\lrng.exe -version
.\lrng.exe                                        # default collectors, JSON to stdout
.\lrng.exe -out E:\case42\HOST01.json             # + E:\case42\HOST01.json.sha256
.\lrng.exe -collectors default,dnscache -out E:\case42\HOST01.json   # + DNS cache & correlation
.\lrng.exe -no-dns -out E:\case42\HOST01.json     # don't touch the DNS cache
.\lrng.exe -format jsonl -out E:\case42\HOST01.jsonl   # one event per line, for a SIEM
.\lrng.exe -collectors network -allow myaiapp.exe,tools.exe
.\lrng.exe -collectors services,autoruns,scheduledtasks    # just persistence
.\lrng.exe -collectors eventlog -out E:\case42\HOST01-logs.json   # just the event-log triage
.\lrng.exe -evtx E:\case42\winevt\Logs -out E:\case42\HOST01-logs.json   # offline: a saved log dir (any OS)
lrng -evtx Security.evtx -fail-on critical       # offline triage of one exported log
.\lrng.exe -sigma .\rules -out E:\case42\HOST01.json       # + Sigma rules over the event log
.\lrng.exe -evtx E:\case42\winevt\Logs -sigma .\rules -timeline -out E:\case42\HOST01.json   # offline + Sigma + timeline
.\lrng.exe -timeline -out E:\case42\HOST01.json            # + a unified super-timeline
.\lrng.exe -iocs -out E:\case42\HOST01.json                # + a deduplicated indicator (IOC) set
.\lrng.exe -fail-on suspect -quiet -out \\share\sweep\%COMPUTERNAME%.json   # exit 3 on findings
.\lrng.exe -ping-sidecar
.\lrng.exe -prompt-scan C:\Users\x\Downloads\suspicious.bin
.\lrng.exe -yara .\rules -out E:\case42\HOST01.json        # adds the memory collector
.\lrng.exe -mem-scan 4242 -yara .\rules
```

| Flag | Default | Meaning |
|---|---|---|
| `-collectors` | `default` | comma-separated collectors; `default` is the default set |
| `-out` | stdout | report path; also writes `<path>.sha256` |
| `-format` | `json` | `json` (one envelope) or `jsonl` (one event per line) |
| `-force` | off | let `-out` overwrite an existing file |
| `-quiet` | off | don't print the findings summary to stderr |
| `-fail-on` | — | exit with status 3 if any finding is at or above this severity |
| `-no-dns` | off | skip module A's provider lookups |
| `-no-hash` | off | don't SHA-256 the binaries the report names |
| `-no-sign` | off | don't verify the Authenticode signatures of process images |
| `-allow` | — | extra LLM-caller process names (paths are reduced to names) |
| `-timeout` | 60s | per-collector budget |
| `-workers` | 6 | collectors run concurrently |
| `-pretty` | on | indent JSON (`-pretty=false` for one line per report) |
| `-sidecar` | next to `lrng` | sidecar binary path |
| `-yara` | — | YARA rules file/dir; enables the `memory` collector |
| `-evtx` | — | offline mode: triage the given `.evtx` file(s) or directory (comma-separated) and exit; works on any OS |
| `-sigma` | — | Sigma rules over the event log: a file, a directory, or `builtin` (the bundled starter pack); comma-separated, live and `-evtx` |
| `-timeline` | off | add a unified super-timeline of every timestamped artifact (a `timeline` result) |
| `-iocs` | off | add a deduplicated, ranked indicator set (IPs, domains, hashes, paths) from detection-linked records (an `iocs` result) |
| `-mem-scan` | — | scan one PID's memory and print the hits |
| `-mem-*` | | memory-scan options (see [Memory scanning](#memory-scanning-yara)) |

`-list` marks opt-in collectors; with no `-collectors`, the default set runs,
plus `memory` when `-yara` or `-mem-pids` is given. The sidecar commands
(`-ping-sidecar`, `-prompt-scan`) work on any OS; `-mem-scan` works on Windows
and Linux. Exit status: `0` success, `1` error, `2` bad usage, `3` `-fail-on` threshold met.

---

## Output

**`json`** (default): one envelope per run — tool, version and commit; a
`run_id`; `host_info` (OS name/version/build, edition, install and boot time,
time zone, domain/workgroup, FQDN); a `run` section (start/end, PID,
elevation, arguments, options, agent SHA-256); per-collector results with their
own `meta` and `errors`; and a `summary` with counts by severity and by rule,
the collectors with coverage gaps, and `top_findings` pointing back to their
records (`results[result].records[record]`).

**`jsonl`**: one event per line, all sharing the `run_id` — a `run` event
(envelope and summary), a `collector` event per collector, a `record` event
per record, and a `finding` event per finding — so a SIEM can alert on
findings without unpacking nested arrays.

The shape is in [`docs/architecture.md`](docs/architecture.md);
`schema_version` (now `1.2`) tracks format changes so a parser can adapt.

---

## Roadmap

- [x] More collectors: persistence (services / Run keys / scheduled tasks),
      ShimCache, prefetch, sessions, local accounts, loaded modules, UDP
      endpoints. *(v0.4)*
- [x] DNS-cache snapshot (the opt-in `dnscache` collector). *(v0.4)*
- [x] DNS-cache **correlation**: snapshot the cache before any resolution,
      attach hostnames to connections, match regional endpoints by name. *(v0.5)*
- [x] Behavioural analytics: command lines, process tree, ~20 ASEPs, the
      TaskCache cross-check, hashes, shortcut targets. *(v0.5)*
- [x] Memory heuristics beyond YARA: PE images in private executable memory;
      fileless ELF/memfd on Linux. *(v0.5)*
- [x] **AmCache** (`Amcache.hve`), via a dependency-free, read-only offline
      registry-hive parser (`internal/winreg/hive.go`). *(v0.6)*
- [x] **Prefetch body decode**: run count, the last eight run times and
      referenced files, via a dependency-free Xpress-Huffman decompressor.
      *(v0.6)*
- [x] Authenticode signature verification for process images (embedded and
      catalog, offline), surfaced as `signature_state` and the `signer` name,
      with an `integrity.unsigned_system_binary` finding. *(v0.6; signer name
      v0.7)*
- [x] **WMI event-subscription persistence** (`wmi`): the
      `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` objects
      in `root\subscription`, read live over a hand-rolled, dependency-free COM
      client. *(v0.6)*
- [x] **COM hijacking** (`comhijack`): CLSID servers across the machine and
      per-user class stores, flagging per-user shadowing, unusual-path and
      scriptlet servers, and `TreatAs` remaps. *(v0.6)*
- [x] **Windows event-log triage** (`eventlog`): the DFIR channels parsed from
      `winevt\Logs` through a dependency-free EVTX/binary-XML reader, with log
      clears, service installs, account and privileged-group changes, Defender
      detections, and the shared command-line analytics applied to 4688/4104/7045;
      plus **offline mode** (`-evtx <file|dir>`) that triages a supplied log on
      any OS through the same parser and rules. *(v0.7)*
- [x] **Event-log ↔ live-state correlation** (`correlate.go`): a 7045 service
      install cross-checked against the services present now (gone →
      `correlate.service_installed_absent`, T1070.009), a 4698/106 task
      registration cross-checked against the live Task Scheduler store (gone →
      `correlate.task_registered_absent`), and a 1102/104 log clear measured
      against the surviving record-id and time range (folded into the
      `defense.clear_event_logs` finding). *(v0.7)*
- [x] **Logon-session analysis**: remote-interactive (RDP, type 10) and
      network (type 3) 4624 logons and 4625 failures from external addresses
      (`logon.remote_interactive` / `logon.network_external` /
      `logon.failed_external`). *(v0.7)*
- [x] **Sigma-rule support** (`-sigma`): compile and evaluate Sigma detection
      rules against the event log (live and offline) with a dependency-free
      YAML-subset parser; a match is a `sigma.<rule>` finding, and a rule using
      an unsupported construct is skipped with a reason rather than mis-scored.
      Ships with an embedded starter pack (`-sigma builtin`). *(v0.7)*
- [x] **Unified super-timeline** (`-timeline`): merge every timestamped artifact
      (prefetch runs, service/autorun/registry key-last-write, task cache
      writes, account logons, shimcache/amcache, event times) into one
      oldest-first view, with detections anchored in time. *(v0.7)*
- [x] **Sigma, completed**: the `|cidr` and `|fieldref` modifiers, the
      `min`/`max`/`avg`/`sum` aggregations and the temporal `| near` (with a
      detection `timeframe` window), plus two new bundled rules — external RDP by
      source CIDR, and a log clear temporally correlated with a service install.
      *(v0.7)*
- [x] **Sigma, completed (windowing)**: `timeframe` now drives a sliding window
      for `count`/`count(field)`/`sum` aggregations (`>`/`>=`), so a burst, a
      spray or a volume spike is detected within its window rather than summed
      across the whole run; plus three more bundled rules (windowed failed-logon
      burst, password spray, Defender real-time-protection change). *(v0.7)*
- [x] **Indicator (IOC) export** (`-iocs`): a post-pass that distils the
      network addresses, hostnames, file hashes and on-disk paths out of every
      detection-linked record into one deduplicated, severity-ranked `iocs`
      result — each indicator carrying the rules and max severity that flagged
      it and back-pointers to its source records — so a triage report yields a
      copy-and-go blocklist / hunt list. *(v0.8)*
- [x] **Offline endpoint intelligence** (`-intel`): attribute the run's public
      remote addresses to their ASN / organisation, country and infrastructure
      category (cloud / CDN / hosting / DNS / Tor / anonymiser) through a bundled,
      air-gapped dataset and an in-memory longest-prefix match, with Tor- and
      anonymiser-contact findings, IOC-set enrichment, and a generator
      (`cmd/intelgen`) that refreshes the dataset from public sources. *(v0.9)*
- [x] **Linux collectors behind the same interface** (`*_linux.go`): processes,
      network (TCP + UDP, with per-socket process attribution), modules, local
      accounts and persistence (cron, systemd, ld.so.preload, rc.local, XDG
      autostart), read from `/proc` and the standard config files and judged by
      Linux-specific path and command-line heuristics; AI module A runs on Linux
      too. *(v0.10)*
- [ ] Memory: hollowed and module-stomped images (image regions whose bytes
      differ from the file on disk).
- [ ] Remaining Linux surfaces (journald triage, eBPF/kernel-module
      persistence).

---

## Lineage & license

Successor to an earlier PowerShell live-response suite — same triage
philosophy, rebuilt as a portable compiled agent with structured output and the
AI-aware modules. MIT licensed; see [`LICENSE`](LICENSE).
