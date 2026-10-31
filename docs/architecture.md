# Architecture

## Layout

```
cmd/lrng/              CLI entry point (flags, validation, exit codes)
cmd/intelgen/          Offline dataset generator for internal/intel (dev tool)
internal/
  collector/           Collector interface, registry, parallel dispatcher,
                       the Windows and Linux collectors and the portable
                       analytics they share (see "Analytics" below), the EVTX reader
                       and Sigma engine, and the post-collection passes
                       (correlation, super-timeline, indicator export,
                       endpoint-intelligence attribution)
    sigmarules/        The bundled Sigma starter pack (embedded, go:embed)
  aidetect/            AI module A — LLM-callout detection (OS-agnostic)
  intel/               Offline endpoint-intelligence engine (IP -> ASN /
                       country / category), with its go:embed'd dataset
  winreg/              Read-only registry reader (advapi32), value decoding,
                       and an offline hive-file (regf) parser (hive.go) for
                       hives the live API doesn't expose, such as Amcache.hve
  hostinfo/            The agent's context (elevation) and the host's
                       identity (OS build, boot time, domain)
  output/              JSON/JSONL envelope, summary rollup, hashed file
                       output, the console summary
  sidecar/             Go side of the Go<->Rust contract + client
  config/              Resolved run configuration
viewer/                The report viewer: lrng-viewer.html (one offline page:
                       HTML, CSS and JS, no dependencies), embedded by
                       viewer.go for -format html; browsertest/ opens hostile
                       and real reports in Chromium
sidecar-rs/            Rust sidecar
  src/prompts.rs       AI module B (prompt artifacts, files and memory)
  src/memscan/         scan_memory: region walk, YARA-X block scan,
                       memory heuristics, budgets
    integrity.rs       image integrity: diffing mapped code against its file,
                       change sites, verdicts and their findings
    pe.rs              bounds-checked PE reader (sections, relocations,
                       exports) and the per-module comparison
    windows.rs         VirtualQueryEx / ReadProcessMemory (read-only)
    linux.rs           /proc/<pid>/maps + /proc/<pid>/mem
    yara.rs            rule loading (file/dir, namespaces) and block scanning
.github/workflows/     CI: Linux checks, real-Windows sweep, integration
docs/                  This file
```

## Collector framework

A collector implements one interface:

```go
type Collector interface {
    Name() string
    Platforms() []string          // GOOS values it supports ("windows", ...)
    Collect(ctx context.Context) (Result, error)
}
```

Collectors self-register from `init()` in their source file, so the set
available at runtime is exactly the set that compiled for this `GOOS`. The
registry filters by platform; `Available()` returns only collectors that run on
the current OS, sorted by name.

A `Result` is a list of `Record`s plus `Meta` and `Errors`. Each record is a
`Fields` map (the collected data) plus any `Finding`s (heuristic annotations:
rule, severity, ATT&CK technique, confidence, detail). `Meta` describes the
collection itself (detector coverage, table sizes) and is kept out of
`Records`, so record counts and SIEM parsers only ever see real artifacts.

### Platform split

OS-specific code lives behind build tags. A cross-platform collector is up to
four files:

- `process.go` — the type, `Name()`/`Platforms()`, registration (all platforms)
- `process_windows.go` — `collectProcesses` with real syscalls (`//go:build windows`)
- `process_linux.go` — `collectProcesses` reading `/proc` (`//go:build linux`)
- `process_other.go` — a stub for the rest (`//go:build !windows && !linux`)

`Platforms()` lists exactly the OSes with a real implementation, so `Available()`
(which filters on `runtime.GOOS`) and `-list` show the working set per host. As
of v0.10 `processes`, `network`, `udp`, `modules`, `localaccounts` and `autoruns`
report `windows, linux`; the Windows-specific collectors (registry, catalog, COM
and WMI based) stay `windows`. The Linux implementations read `/proc` and the
standard config files; their text parsers follow the same "no build tag, bounds-
checked, unit-tested on any OS" rule as the Windows decoders — `procfs.go`
(`/proc/<pid>` status/stat, passwd/group/shadow), `procnet.go`
(`/proc/net/{tcp,udp}` hex rows), `procmaps.go` (`/proc/<pid>/maps`) and
`persist_unix.go` (cron, systemd, .desktop, ld.so.preload), and
`journalfile.go`, the systemd journal reader. The Linux heuristics live in
`paths_unix.go`, `cmdline_unix.go`, `netrules_unix.go`, `modulerules_unix.go`,
`accountrules_unix.go`, `kmodrules.go`, `ebpfrules.go` and `journaldrules.go`,
the counterparts to `paths.go`, `cmdline.go` and the `*rules.go` files; AI module A
(`internal/aidetect`) is OS-agnostic and the Linux `network` collector feeds it
directly. The Linux-only `kmod` and `journald` collectors read files only, so
each scan takes a root directory and is tested against fixture trees on any OS;
`ebpf` needs the `bpf(2)` syscall (`ebpf_linux.go`), but decoding a program's
helper calls, the kallsyms lookup and judging it are portable.

Two Linux specifics shape those collectors. A process's name (`comm`) is the
script's name for a `#!` script and can be set to anything with `prctl`, so the
heuristics judge a process by its executable's name as well, and module A's
allowlist by the executable. And the path `readlink /proc/<pid>/exe` returns is
only a label in the process's own mount namespace, so `procexe_linux.go` reads
through the magic links instead: images are hashed by opening
`/proc/<pid>/exe` (reaching a deleted or memfd payload, and a container's own
file), keyed by device and inode so a shared binary is read once, and "is there
a file at this path now?" — how an upgraded binary or library is told from a
self-deleting one — is asked under `/proc/<pid>/root`. Kernel threads are told
by the `PF_KTHREAD` flag in `/proc/<pid>/stat`, which every user can read and
which (unlike a missing exe link) a zombie doesn't have.

Anything that's pure data handling stays out of the `_windows.go` files so it
can be unit-tested on any OS: the TCP- and UDP-table decoders (`tcptable.go`,
`udptable.go`), the `UNICODE_STRING` decoder (`ustring.go`), the AppCompatCache
decoder (`shimcacheparse.go`), the task-XML parser (`tasksxml.go`, UTF-16/BOM
aware), the shortcut parser (`lnk.go`), the prefetch-filename parser
(`prefetchname.go`), the Xpress Huffman decompressor and SCCA prefetch-body
parser (`xpress.go`, `scca.go`), the AmCache parser (`amcacheparse.go`, over
the offline hive reader in `internal/winreg/hive.go`), the EVTX/binary-XML
event-log reader (`evtx.go`), the YAML subset Sigma rules are written in
(`yamllite.go`), and every heuristic (below). The decoders bounds-check every
count, length and pointer against the buffer, so a short or inconsistent input
yields an error, not an out-of-bounds read. The shortcut parser is also
fuzzed with random corruption in its tests and checked against fixtures from
an independent implementation, and the EVTX reader is fed hostile offsets and
sizes to show it never panics or reads out of range.

The Windows files themselves are compile-checked for every architecture
(`go vet` with `GOOS=windows GOARCH=amd64|386|arm64`), run for real on a
Windows CI runner (`windows_smoke_test.go` sweeps every collector), and can be
exercised on Linux under Wine (`make wine-test`).

### Analytics

The judgement lives in portable files, one per subject, each with tests
covering both malicious and ordinary input:

| File | What it judges |
|---|---|
| `paths.go` | Where a program runs from: risk level (high: temp, downloads, Public, Recycle Bin, world-writable Windows dirs; low: ProgramData, drive roots), with `%VAR%` and NT-path forms resolved first and Defender's home trusted. `commandPathRisk` also judges the payload paths in a proxy host's arguments. |
| `command.go` | Splitting a command line into program and arguments, including unquoted paths with spaces and comma-separated lists. |
| `envexpand.go` | Environment expansion: machine variables from the host, per-user ones only from a known profile. |
| `cmdline.go` | Command-line analytics (encoded PowerShell, cradles, LOLBins, credential theft, recovery inhibition, defence evasion, account changes). RE2 regexes, compiled once. |
| `proctree.go` | Process-tree checks: masquerading paths, impossible parents, shells under document/server/WMI/service parents, typosquats. |
| `servicerules.go`, `autorunrules.go`, `taskrules.go`, `accountrules.go`, `netrules.go`, `comrules.go`, `typelibrules.go`, `wmirules.go` | Per-collector rules, including comparisons against Windows defaults (Winlogon, BootExecute, LSA packages, print monitors, netsh helpers), the TaskCache cross-check, COM-hijack patterns (per-user shadowing, unusual-path/scriptlet servers, `TreatAs`), TypeLib hijacking (script monikers, unusual-path libraries, per-user shadows) and WMI subscription consumers/filters/bindings/timers (including `__TimerEvent` schedule triggers). |
| `filehash.go` | The shared SHA-256 hasher: one read per file per run, size-capped, cancellable. |
| `authenticode.go` | The signature verdict → record fields (state, catalog, and the `signer` name, sanitized because a certificate's subject is attacker-chosen) and the unsigned/untrusted system-binary finding, which quotes the claimed signer. The WinVerifyTrust embedded-plus-catalog verification, and reading the signer from its state before it is closed, are in `authenticode_windows.go`. |
| `eventlog.go` | Which events are kept (low-volume security events in full; high-volume command-bearing ones such as 4688 and 4104 only when a rule fires) and the built-in event rules: log clears, service installs, account and privileged-group changes, Defender detections and remote logons. Command lines inside events go through `cmdline.go`, so a running process and a logged one are judged alike. |
| `sigma.go` | The Sigma engine: rule compilation (through `yamllite.go`), the modifiers, the condition language, the `logsource` → channel/event mapping, and the aggregations and temporal `near`, which accumulate over the run and flush as synthetic records. A `count`/`count(field)`/`sum` with a `timeframe` is instead swept as a sliding window. A construct it can't evaluate faithfully (a `timeframe` on `min`/`max`/`avg`, a `near` without one, …) gets the rule skipped with a reason, never mis-scored. |

Rules return `Finding`s with an ATT&CK technique; a stronger rule suppresses
the weaker ones it implies on the same line (one encoded download cradle is
one critical finding, not four).

The Windows collectors use the standard-library `syscall` package plus
`LazyDLL` bindings for the rest, so there are no third-party Go dependencies:
Toolhelp process and module snapshots, `QueryFullProcessImageNameW`,
`NtQueryInformationProcess`, `GetProcessTimes` and token queries;
`GetExtendedTcpTable`/`GetExtendedUdpTable` (`iphlpapi.dll`); the registry
(`advapi32.dll`: `RegOpenKeyExW`, `RegEnumKeyExW`, `RegEnumValueW`,
`RegQueryValueExW`) and SID resolution (`CreateWellKnownSid`,
`LookupAccountSidW`); sessions (`wtsapi32.dll`); local accounts and groups
(`netapi32.dll`); and the DNS resolver cache (`dnsapi.dll`: the undocumented
`DnsGetCacheDataTable` lists names, and documented `DnsQuery_W` with
`DNS_QUERY_NO_WIRE_QUERY` reads their cached answers without touching the
network). The process collector opens each process once with
`PROCESS_QUERY_LIMITED_INFORMATION`; apart from the opt-in memory scan,
nothing reads another process's memory.

### DNS snapshot ordering

The DNS cache is read at most once per run (`sync.Once`), by whichever of
`dnscache` and `network` (with correlation) asks first, and `network` waits
for it — bounded, so a wedged DNS Client service can't stall the run —
before module A resolves anything. So lrng's own lookups never appear as
evidence, and the `dnscache` result says whether the snapshot was taken
before them (`taken_before_module_a_lookups`).

### Self-exclusion

`RunOptions.SelfPID`/`SelfPaths` name lrng and its sidecar. Their processes
are marked `lrng_component` and never judged — an analyst who runs lrng from a
Downloads folder must not get findings about lrng.

### Dispatcher

The dispatcher runs collectors through a bounded worker pool and returns
results in the order the collectors were requested, so reports diff cleanly.

Each collector runs in its own goroutine under its own `context` deadline
(Ctrl+C and SIGTERM cancel the shared context; a second signal exits at once):

1. If it returns in time, its result is used.
2. If the deadline passes, it gets a grace period (default 2s) to return
   partial results; well-behaved collectors check `ctx` and do.
3. If it still hasn't returned (blocked in a system call, say), it's
   abandoned with an error result and the run moves on.

A panic is recovered inside the collector's goroutine, logged with a stack to
stderr, and becomes an error result. Ctrl+C cancels the shared context, so a
report with whatever was collected is still written and marked
`run.interrupted`; collectors that hadn't started by then are recorded as not
run rather than started against a cancelled context.

### Opt-in collectors and their own timeouts

A collector implementing `OptIn()` (`memory`, `dnscache`) is listed by
`-list` but left out of the default set; it runs when named — on its own or
as `-collectors default,<name>` — and `memory` also when `-yara`/`-mem-pids`
is given. A collector implementing `Timeout()`
gets that budget instead of the dispatcher-wide `-timeout` (memory scanning
takes minutes, not seconds).

### Memory collector

1. List processes (Toolhelp + image paths on Windows, `/proc` on Linux).
2. Skip lrng itself, its sidecar binary (by path), kernel-only processes and
   (Linux) zombies, which have exited and hold no memory; honour `-mem-pids`.
3. Split the targets round-robin across `-mem-workers` sidecars. Each gets one
   `scan_memory` request with its PID list, compiles the rules once, and
   streams back one line per PID.
4. Turn every target and every skip into a record (status, bytes, coverage,
   errors) and every hit into a finding, in PID order.

In the sidecar, each region is read in 16 MiB chunks that repeat the previous
chunk's last 4 KiB. YARA-X accepts overlapping blocks; the prompt scan is
given the whole block plus the offset where new bytes start, and ignores
matches that end inside the repeated tail (already counted), so a match that
straddles a boundary is found exactly once. The first chunk of each
executable region no image backs is also checked for a PE (or ELF) header.

Before the region walk, with up to a third of the per-process budget, the
sidecar checks **image integrity** (`integrity.rs`): each image's executable
code in memory is compared with its file, 64 bytes at a time with equal blocks
skipped whole. On Windows, `pe.rs` parses the file, applies the base
relocations the loader applied (HIGHLOW and DIR64; any other kind's bytes are
masked), masks the IAT, leaves out the `fothk` section (function-override
thunks the loader rewrites), and compares the mapped header's identity fields —
timestamp, image size, section layout; not the machine or entry point, which an
ARM64X image changes for x64 callers — with the file's. The same region walk
records each module's executable stretches; any outside the sections the file
marks as code (headers, data sections, past the last section) is reported and
its bytes compared with what the file maps there, so stomping that leaves
`.text` intact is still seen. The executable page recent Windows builds map
just past the end (`SizeOfImage`) of images with a `fothk` section has no file
bytes to compare with; it is the same in every module, so each copy is compared
with the others in the process instead (`Report::settle_loader_pages`). A file no drive letter reaches is read through
its `\\?\GLOBALROOT` device path. On Linux each
executable file mapping is compared with `/proc/<pid>/map_files/<range>`, the
inode actually mapped, falling back to the path only when its inode matches.
Differing bytes merge into change sites across gaps of 16 bytes or less; a site
of 256 bytes or more is a rewrite, anything shorter a patch; on Windows each
site is named by the nearest export. The check stops at its deadline or byte
cap and says so (`stopped`); Linux streams each mapping in chunks rather than
holding it whole. With no YARA rules and no prompt scan, the region walk after
it reads only each region's first chunk, which is all the heuristics need.

### Event logs

The `eventlog` collector reads the targeted channels from
`%SystemRoot%\System32\winevt\Logs`: Security, System, Application, both
PowerShell logs, TaskScheduler, WMI-Activity, Defender, the two
TerminalServices logs and Sysmon. A channel the host doesn't have is counted
in `meta.logs_missing`, not reported as an error; one the EventLog service
won't let lrng open is reported and skipped (take it from a shadow copy or
image and parse it offline). The tag-free reader in `evtx.go` reads the file one
64 KiB chunk at a time through an `io.ReaderAt` — constant memory, whatever the
log's size — resolves templates and decodes each record's binary XML into a
normalised event. A full log is circular (the newest chunks overwrite the
oldest at the front of the file), so chunks are visited in the order of their
first record identifier, not file order; the live collector walks them newest
first, records reversed within each chunk too, and polls its context between
chunks, so a log its time budget can't finish yields its latest records plus a
`cancelled` error instead of nothing. A chunk with a bad signature is skipped,
not taken as the end of the log.

Every event is classified (`eventlog.go`) and, when `-sigma` loaded rules,
matched against them as well; a Sigma match keeps an event the built-in rules
would have dropped. Aggregation and `near` rules hold state across the whole
run and flush once the last log is read (they sort their observations, so the
chunk order doesn't matter). Retention is bounded, in two budgets so that
volume can't displace evidence: records without a finding (the always-kept
low-volume events — less the 4672s of SYSTEM, the service accounts and the
DWM/UMFD virtual accounts, which are skipped as noise) keep the most recent
50,000 per log and 100,000 across the run; records with a finding are kept
first, up to 100,000 across the run, and every log is still parsed after the
finding-less budget is spent. Kept records are reported oldest first
(`records_truncated`, `records_dropped`). The result's `meta` says what was read
(`logs_read`, `records_scanned`, `records_kept`, `records_with_findings`,
`parse_warnings`), each
channel's record-id and time span (`channel_ranges`, which correlation
measures a log clear against), and what the Sigma engine could and couldn't
run (`sigma`: counts, each skipped rule with its reason, and each file that
failed to parse).

**Offline mode.** `-evtx <file|dir>` skips the live collectors and feeds the
named files through the same reader and classifier (`ParseEventLogFiles`) on
any OS. The report has the same envelope; its `host` is `(offline)` and the
result's `meta.mode` is `offline`. A named file that doesn't exist is an error
here, unlike a channel missing from a live host.

### Journal

The `journald` collector reads journald's files itself (`journalfile.go`):
objects walked in append order, both the regular and the compact layout
(32-bit entry items; data payloads at offset 72 rather than 64), with
LZ4-compressed payloads decoded and zstd/xz ones counted. Every offset and size
is checked against the file without overflowing (it is fuzzed in both layouts), and
the reader is checked against `journalctl` on real files of each layout and
compression (`LRNG_JOURNAL_SAMPLES`). Files are read newest first within a byte
budget; each entry becomes a small normalised record (time, identifier, PID,
transport, message), and `journaldrules.go` keeps only the security-relevant
ones. SSH failures are aggregated per source address and joined to later
successful logons from the same address within a day.

### Post-collection passes

After the dispatcher returns, `main` runs up to four passes over the results
before summarising, for live and offline runs alike:

1. **Correlation** (`correlate.go`) cross-references the event log against the
   live state. A 7045 service install is checked against the services present
   now, and a 4698/106 task registration against the live Task Scheduler
   store: still there is annotated, gone is `correlate.service_installed_absent`
   or `correlate.task_registered_absent` (T1070.009). A 1102/104 log clear is
   measured against the record span that survived it, folded into the
   `defense.clear_event_logs` finding. Independent of the event log, a scheduled
   task's `IComHandlerAction` CLSID is cross-checked against the COM
   registrations `comhijack` flagged (`correlate.task_comhandler_hijacked`,
   T1546.015) — the schedule (trigger) joined to the hijacked object (payload).
   A cross-check whose inputs weren't collected is skipped, so missing data
   never turns into an "absent" finding.
2. **Timeline** (`timeline.go`, with `-timeline`) appends a synthetic
   `timeline` result: every timestamped artifact, oldest first, each entry
   pointing back to its source record and showing that record's top finding.
   It runs after correlation so those findings appear in it. Its entries
   carry no findings of their own, so the summary counts don't change. It
   keeps at most 100,000 entries (the most recent) and notes truncation in
   `meta`.
3. **Indicator export** (`iocs.go`, with `-iocs`) appends a synthetic `iocs`
   result: the indicators of compromise — IPv4/IPv6 addresses, DNS hostnames,
   SHA-256/SHA-1 hashes and file paths — drawn from every record that carries a
   finding, deduplicated across the run (and across collectors) and ranked by
   the highest severity of the detections that referenced each. Addresses are
   kept only when public (`aidetect.PublicAddr`) and never from a socket's local
   side; hostnames only from hostname-bearing fields; hashes by exact hex shape;
   paths only from path-bearing fields with a drive/UNC shape — so the set is
   precise rather than a text scrape. Each indicator records its `type`,
   `value`, `max_severity`, contributing `rules`, a `source_count` and `sources`
   back-pointers (collector/record/field). It runs after correlation (so a
   cross-collector finding's indicators are captured) and skips the `timeline`
   and `iocs` results so no derived view feeds back in. Its records carry no
   findings of their own, so the summary counts don't change; it is bounded at
   50,000 indicators (lowest-severity dropped past the cap).
4. **Endpoint intelligence** (`intel.go`, with `-intel`) appends a synthetic
   `intel` result: every public remote address across the real collector
   records, attributed against the bundled `internal/intel` dataset by an
   in-memory longest-prefix match (ASN, organisation, country, infrastructure
   category). The address walk reuses the IOC pass's helpers and the same
   `aidetect.PublicAddr` / local-side exclusion, so a host never attributes
   itself or private space; addresses are deduplicated with source back-pointers
   and carry the severity/rules of any findings on the records they appeared in.
   Unlike the timeline and IOC passes it *does* raise findings — but only for the
   two anonymised-transport categories (`intel.tor_endpoint` T1090.003,
   `intel.anonymizer_endpoint` T1090.002); cloud/CDN/hosting/DNS are context on
   the record. When an `iocs` result is present it also writes the attribution
   onto each IP indicator there. It runs last (after the IOC pass, so the
   blocklist can be enriched) and skips the derived views. The dataset's
   provenance (source, generation date, entry count) is recorded in
   `meta.dataset` and in `run.intel_dataset`.

Because these passes run before `output.Summarise`, the findings correlation and
endpoint intelligence add roll up into `summary` like any other.

### Adding a collector

1. Create `yourthing.go` with the type, `Name()`, `Platforms()`, and
   `func init() { Register(&yourThing{}) }`.
2. Put the real logic in `yourthing_windows.go` (and `yourthing_linux.go`)
   and a stub in `yourthing_other.go` for the remaining OSes. Keep parsing in
   a tag-free file with tests.
3. Check `ctx.Err()` in loops and return partial results on cancellation.
4. If it needs run options (the hasher, the LLM allowlist, self-exclusion),
   implement `Configurable`.
5. Put judgement in a portable `*rules.go` file returning `[]Finding`, with
   tests for both malicious and ordinary input.

That's it — it shows up in `-list` and runs by default.

## Report viewer

`viewer/lrng-viewer.html` is the whole viewer: one page, no build step, no
framework, nothing fetched. It reads a report from a dropped or chosen file
(JSON, or JSONL rebuilt into the envelope from its `run`, `collector` and
`record` events), or from the `<script type="application/json"
id="lrng-report">` block that `viewer.Render` fills for `-format html`. It
builds one model (results with prototype-less field maps, findings flattened
and ranked, ATT&CK tactic counts), then renders views from it; the process
tree and timeline are built the first time they're needed. The hash names the
view (`#findings`, `#collector/<name>`), and anything it names is looked up in
the model, never inserted.

Safety rests on two independent layers. The first is that nothing from a report
is parsed as markup: the `h()` helper turns every string into a Text node or an
attribute value, and the page uses no API that parses HTML or code (checked by
`viewer_test.go`). The second is the content security policy, which allows the
page's own script and stylesheet by SHA-256 hash and nothing else, so inline
code can't run and no connection can leave the page. The Go test fails if the
hashes are stale; `go test ./viewer -update` rewrites them.
`viewer/browsertest/browser_test.cjs` is the end-to-end check, in Chromium
(through Playwright). It opens a hostile report embedded, as JSON and as JSONL,
plus real Windows and Linux reports, and walks every view. In CI it runs
against the reports the Windows and Linux runners produce.

## Go <-> Rust sidecar contract

Newline-delimited JSON over stdin/stdout. Go writes one `Request`; Rust writes
one `Response` line per result and exits. Every op answers with one line
except `scan_memory` with `pids`, which streams one line per PID, flushed as
each finishes. The agent finds the sidecar next to its own
executable unless `-sidecar` is given, always resolves it to an absolute path,
and never searches `PATH`.

```jsonc
// Request
{ "op": "scan_prompts", "path": "C:\\samples\\x.bin" }
{ "op": "scan_prompts", "data": "inline UTF-8 text" }
{ "op": "scan_memory", "pids": [4821, 5120], "rules_path": "C:\\rules",
  "prompts": true, "budget_ms": 60000, "max_bytes": 4294967296,
  "include_sensitive": false }
{ "op": "ping" }   // answers with version and capabilities
                  // (scan_prompts, scan_memory, yara, memory_heuristics)

// Response
{
  "op": "scan_prompts",
  "ok": true,
  "hits": [
    { "rule": "api.endpoint", "severity": "suspect", "technique": "T1071.001",
      "offset": 19, "encoding": "utf-16le",
      "context": "https://api.openai.com/v1/chat/complet  (x1)",
      "confidence": 30 }
  ],
  "meta": { "source": "file:C:\\samples\\x.bin", "file_size": 143,
            "bytes_scanned": 143, "truncated": false,
            "encodings": ["ascii", "utf-16le"],
            "matched_rules": 2, "score": 55, "verdict": "medium" }
}
```

A `scan_memory` line (one per PID):

```jsonc
{
  "op": "scan_memory", "ok": true,
  "hits": [
    { "rule": "yara:shellcode_loader", "severity": "critical", "technique": "T1055",
      "offset": 2203318222848, "confidence": 90,
      "context": "ruleset vendor_mem | 3 match(es): $a(2) $b(1) | tags: loader",
      "region": { "base": 2203318222848, "size": 262144, "protect": "RWX",
                  "kind": "private" } }
  ],
  "meta": { "pid": 4821, "image": "C:\\Users\\x\\AppData\\Local\\Temp\\upd.exe",
            "status": "scanned", "stopped_early": null,
            "regions_total": 412, "regions_scanned": 409,
            "bytes_total": 187432960, "bytes_scanned": 187432960,
            "coverage_pct": 100.0, "read_failures": 3, "elapsed_ms": 812,
            "yara": { "rules_loaded": 214, "rule_files": 19, "rules_failed": [],
                      "module_imports": [], "matched_rules": 1 },
            "prompt_verdict": "none",
            "unbacked_exec_regions": 3, "unbacked_rwx_regions": 1,
            "memory_heuristic_hits": 0 }
}
```

A memory-heuristic hit has the same shape as a YARA hit, with a rule such as
`memory.pe_in_private`, the region it describes and, like YARA hits, no raw
bytes.

`status` is `scanned`, `partial` (budget or byte cap hit; `stopped_early` says
why), or, with `ok: false`, `skipped`, `access_denied`, `not_found` or
`error`. YARA hits never contain matched bytes. A process that couldn't be
scanned is never reported as clean.

A `Hit` maps directly onto a collector `Finding` on the Go side. The transport
is intentionally dumb: one process per call, crash-isolated, with stdout/stderr
capped on the Go side. Swapping it for a long-lived streaming client, or a
static FFI library, is a later change that leaves these types untouched.

## Output envelope (schema 1.2)

```jsonc
{
  "schema_version": "1.2",
  "tool": "liveresponse-ng",
  "tool_version": "0.7.0",
  "tool_commit": "737cab9",
  "run_id": "4c1d7e0a-2f8b-4d3e-9a51-0c6b2f7e9d10",
  "host": "WORKSTATION-01",
  "os": "windows",
  "arch": "amd64",
  "collected_at": "2026-10-14T18:00:00Z",
  "host_info": {
    "os_name": "Windows 11 Enterprise", "os_version": "23H2", "os_build": "22631.4317",
    "edition": "Enterprise", "installation_type": "Client",
    "installed_at": "2025-02-03T09:12:44Z", "boot_time": "2026-10-14T07:58:03Z",
    "time_zone": "Eastern Standard Time", "join_type": "domain", "domain": "CORP",
    "dns_domain": "corp.example.com", "fqdn": "workstation-01.corp.example.com"
  },
  "run": {
    "started_at": "2026-10-14T18:00:00Z", "finished_at": "2026-10-14T18:00:09Z",
    "pid": 5120, "elevated": true, "args": ["-out", "E:\\case42\\WS01.json"],
    "collectors": ["amcache", "autoruns", "comhijack", "eventlog", "localaccounts", "modules",
                   "network", "prefetch", "processes", "scheduledtasks", "services", "sessions",
                   "shimcache", "udp", "wmi"],
    "workers": 6, "timeout": "1m0s", "dns_lookups": true, "dns_correlation": false,
    "hashing": true, "exe_path": "E:\\tools\\lrng.exe", "exe_sha256": "…"
  },
  "results": [
    {
      "collector": "processes",
      "started_at": "…", "duration_ns": 2100000000,
      "records": [ { "fields": { "pid": 4242, "name": "svchost.exe",
                                 "image_path": "C:\\Users\\Public\\svchost.exe",
                                 "image_sha256": "…", "integrity_level": "high",
                                 "signature_state": "untrusted", "signer": "Microsoft Windows",
                                 "session_id": 1, "parent_name": "explorer.exe", "…": "…" },
                     "findings": [ { "rule": "process.masquerade_path", "severity": "critical",
                                     "technique": "T1036.005", "confidence": 85,
                                     "detail": "svchost.exe (pid 4242) has the name of a Windows system binary but runs from …" } ] } ],
      "meta": { "system_root": "C:\\Windows", "images_hashed": 187, "hashing": true,
                "signature_checks": true },
      "errors": []
    }
  ],
  "summary": {
    "collectors": 15, "records": 4312, "findings": 3, "errors": 1,
    "by_severity": { "critical": 1, "suspect": 1, "notable": 1 },
    "by_rule": { "process.masquerade_path": 1, "persistence.service_unquoted_path": 1, "…": 1 },
    "collectors_with_errors": ["shimcache"],
    "top_findings": [
      { "rule": "process.masquerade_path", "severity": "critical", "technique": "T1036.005",
        "confidence": 85, "detail": "…", "collector": "processes", "result": 5, "record": 112 }
    ]
  }
}
```

`top_findings[].result`/`record` index into `results[].records[]`.

With `-format jsonl` the same content is written one event per line, every
event carrying `run_id` and `host`:

```jsonc
{"type":"run","schema_version":"1.2","run_id":"…","host":"WS01","run":{…},"summary":{…}, …}
{"type":"collector","run_id":"…","collector":"processes","duration_ns":…,"record_count":243,"meta":{…},"errors":[]}
{"type":"record","run_id":"…","collector":"processes","record":112,"fields":{…},"findings":[…]}
{"type":"finding","run_id":"…","collector":"processes","record":112,"rule":"process.masquerade_path","severity":"critical",…}
```

Schema 1.2 also covers the memory collector: one record per process with
`status`, `bytes_scanned`, `coverage_pct`, `unbacked_exec_regions` and so on,
plus `results[].meta.yara` for the rule set. Findings from YARA have rules
named `yara:<rule>`.

v0.7 through v0.10 keep schema 1.2: everything they add fits inside the envelope.
That covers the `eventlog` result (with `meta.sigma` and `meta.channel_ranges`),
Sigma findings (`sigma.<rule>`, and synthetic records with `source_log`
`sigma:aggregation`), correlation findings and annotations, the `timeline`
result, the process `signer` field, (v0.8) the `iocs` result — one record
per indicator (`type`, `value`, `max_severity`, `rules`, `source_count`,
`sources`), carrying no findings of its own — and (v0.9) the `intel` result
(one record per attributed address, with its own `intel.tor_endpoint` /
`intel.anonymizer_endpoint` findings and `meta.dataset` provenance), the
`intel_*` fields added onto IP indicators in `iocs`, and the `run.intel` /
`run.intel_dataset` fields. An offline (`-evtx`) report has `host` set to
`(offline)`.

Changes from 1.1: `run_id`, `host_info`, `run.dns_correlation`,
`run.hashing`, `summary.by_rule`, `summary.collectors_with_errors` and
`summary.top_findings` added; many collectors gained fields (hashes,
last-write times, session/integrity, account and session times — see the
CHANGELOG); `dnscache` records are one per name (`types`, `addresses`).

Changes from 1.0: `run` added; collector metadata moved from a `_meta` record
into `results[].meta`; `summary.errors` added; network records gained
`family`; process records gained `command_line`, `created_at`, `user`,
`user_sid`, `parent_name`, `parent_pid_reused` and `query_errors`; sidecar hits
gained `encoding`.
