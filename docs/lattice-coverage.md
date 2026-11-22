# Project Lattice coverage

Project Lattice is an adversary-emulation C2 written by this tool's author: a
Rust agent ("Wraith"), a Go team server and a Tauri operator console. Most of
its advertised tradecraft is still on its roadmap. This page maps every
feature on that roadmap to the lrng rules that detect it, so the detections
are in place before the features are, whoever finishes them.

Status:

- **Covered:** an existing rule detects the behavior.
- **New:** added for this mapping.
- **Partial:** a rule catches part of it or a side effect.
- **Out of reach:** not visible to a user-mode responder; the reason is given.

Rules marked *memory* come from the memory scanner, which is opt-in:
`lrng -collectors default,memory` (or pass `-yara`). Rules marked *watch* come
from watch mode (`lrng -watch 15m`, Windows), which records the host before
the snapshot.

## The agent itself

| Feature | Status | Rules |
|---|---|---|
| Agent or team-server binary, running or dropped | New | `malware.lattice_agent` (implants collector, Windows and Linux: running images outside system folders, deleted ones through `/proc/<pid>/exe`, executables in Temp, `/tmp`, `/var/tmp`, `/dev/shm`) |
| HTTP check-in from an unusual folder | Covered | `network.unusual_path_outbound` |
| Sleep and jitter between check-ins | New *watch* | `network.beacon`: a flow whose check-ins are too regular to be a person, *critical* with a second signal such as an unusual folder or `memory.stack_unbacked` on the same process |
| Transport and host rotation (HTTP, DNS, QUIC) | New *watch* | `network.beacon_rotating`: a process's check-ins regular across destinations or transports combined; `network.beacon` with transport `quic` for UDP 443 |
| DNS transport | New *watch* / Covered | `dns.tunnel_rate` (unique high-entropy names or TXT/NULL queries at rate), `dns.periodic_query`; in the snapshot, `network.dns_tunnel` |
| `sh -c` host fingerprint (`whoami 2>/dev/null \|\| id -un`), `net-enum`, default `shell` | New | `exec.c2_shell_recon` (Linux form: silent-fallback chains, or three or more discovery commands in one shell) |

The family markers come from the agent at commit `6cd2933`. Per-build string
encryption, also on the roadmap, would hide them; the behavioral rules below
don't depend on them.

## Call stack, syscall and memory evasion

| Feature | Status | Rules |
|---|---|---|
| Silent Moonwalk stack spoofing (synthetic `RtlUserThreadStart` / `BaseThreadInitThunk` frames) | Covered *memory* | `defense.stack_fake_thread_start`, `defense.stack_frame_no_call`, `defense.stack_jmp_gadget`, `defense.stack_truncated`, `memory.thread_start_spoofed` |
| Call-preceded gadgets (CET/LBR trampoline) that pass the "follows a call" check | New *memory* | `defense.stack_call_mismatch`: the first return address above a system call must follow a call that reaches the stub the thread waits in (directly, through an import or thunk, or by tail jumps). Judged when the call is direct or through an import and the target is in the caller's module or the core DLLs; deeper frames and calls through a register are left to the checks above |
| Indirect syscalls (Tartarus / Halo's / Hell's Hall gate) | Covered *memory* / New | `defense.indirect_syscall`, `defense.direct_syscall`, `memory.syscall_stub`; new from Sysmon 10: `defense.indirect_syscall` when LSASS is opened through an ntdll stub that unbacked code called directly |
| Sleep obfuscation: Ekko, Foliage, Zilean, Echo, TP-Wait-Pool, heap RC4 | Covered *memory* | `defense.stack_return_nonexec` (a waiting thread returning into memory made non-executable for the sleep), `memory.stack_unbacked`, `defense.stack_frame_no_call` (NtContinue/ROP chains) |
| Module stomping, module overloading, UDRL clean-VAD | Covered *memory* | `memory.image_code_modified`, `memory.image_exec_outside_code`, `memory.image_header_mismatch` |
| DripLoader (4 KB chunked allocations) | Partial *memory* | Execution from the resulting private memory: `memory.thread_start_unbacked`, `memory.stack_unbacked`. No rule judges the allocation pattern itself |
| Threadless export hijacking | Covered *memory* | `memory.image_inline_patch` |

## Self-healing, kernel and lifecycle

| Feature | Status | Rules |
|---|---|---|
| VEH self-healing | Covered *memory* | `memory.veh_unbacked` |
| Patchless HWBP AMSI/ETW bypass (`AmsiScanBuffer`, `EtwEventWrite`, `NtTraceEvent`) | Covered *memory* | `defense.amsi_hwbp`, `defense.etw_hwbp`, `defense.syscall_hwbp`, `memory.hardware_breakpoint` |
| BYOVD driver load | Covered | `privesc.vulnerable_driver_loaded`, `privesc.vulnerable_driver_installed`, `privesc.vulnerable_driver_blocked`, `defense.unsigned_driver_loaded`, `defense.driver_load_blocked`, `defense.driver_blocklist_disabled`, `defense.loaded_driver_file_missing` |
| Unlinking process, thread and image-load callbacks | Out of reach | The callback arrays live in kernel memory, which a user-mode responder can't read. The driver load that makes it possible is covered above |
| Zeroing `EtwThreatIntProvRegHandle` (ETW-TI) | Out of reach | Kernel memory, as above |
| Stripping `EPROCESS.Protection` (PPL) | New | `defense.ppl_stripped`: smss, csrss, wininit or services running unprotected (critical); LSASS unprotected while `Lsa\RunAsPPL` asks for protection; Defender's engine without PPL-Antimalware |
| Self-deletion through an NTFS stream rename (`:wtfbbq`) | New | `process.deleted_binary` on Windows (a running image no longer on disk), `defense.self_delete` (Sysmon 23/26: a process deleting its own executable) |
| Environmental keying, kill dates, sandbox checks | Out of reach | They decide whether the agent runs; they leave nothing on a host to inspect |

## Tradecraft primitives

| Opcode | Primitive | Status | Rules |
|---|---|---|---|
| 0x01 | `shell` | Covered | `exec.c2_shell_recon`, the command-line rules (download cradles, reverse shells, encoded payloads), `process.unexpected_parent` |
| 0x03 | `shinject-moonwalk` | Covered *memory* | `memory.remote_thread_unbacked`, `memory.thread_start_unbacked`, the stack-spoofing rules; Sysmon 8 through `memory.remote_thread_*` |
| 0x04 | `threadless-inject` | Covered *memory* | `memory.image_inline_patch` |
| 0x05 | `execute-assembly` | New | `modules.clr_in_native_process`: the .NET Framework runtime loaded into a process whose image has no CLR header (*suspect* in sacrificial hosts such as rundll32, notepad or wscript and in programs run from temporary folders; from Sysmon 7 for the sacrificial hosts). The bypasses it pairs with: `defense.amsi_hwbp`, `defense.etw_hwbp`, `defense.dotnet_etw_disabled` |
| 0x06 | `module-stomp` | Covered *memory* | `memory.image_code_modified` |
| 0x07 | `token-steal` | New | `privesc.thread_impersonation`: a thread wearing another account's token in a sacrificial host, a program in a temporary folder or a shell (servers, which impersonate clients, pass); `privesc.stolen_token_process`: a process running as a different account from its parent when the parent isn't a Windows broker, *suspect* for a user's process starting a SYSTEM one |
| 0x08 | `pth` (overpass-the-hash) | Covered | `cred.pass_the_hash` (logon type 9 through Secondary Logon) |
| 0x09 | `net-enum` | New / Partial | LDAP: `discovery.ldap_unusual_process` (a domain controller's LDAP, LDAPS or global catalog port from a sacrificial host or a temporary-folder program; Windows, Linux, Sysmon 3). Linux shell form: `exec.c2_shell_recon`. Share and session enumeration over SMB looks like any other connection to port 445 and isn't judged |
| 0x0A | `bof-exec` | Partial *memory* | Execution from private memory: `memory.thread_start_unbacked`, `memory.stack_unbacked` |
| 0x0B | `dcsync` | Covered | `cred.dcsync`, `cred.dcsync_machine_account` |
| 0x0C | `lsass-nanodump` (`PssCaptureSnapshot`) | Covered / New | Sysmon 10 LSASS access from unbacked code: `defense.direct_syscall`, and new `defense.indirect_syscall` for the indirect form; `process.unexpected_parent` for the snapshot clone (an LSASS whose parent isn't wininit) while it exists; `cred.lsass_dump` for dump-tool command lines |
| 0x0D | `byovd-blind-edr` | Partial | Driver-load rules above; the callback unlinking itself is out of reach |
| 0x0E | `byovd-etwti-disable` | Partial | As above |
| 0x0F | `byovd-ppl-strip` | New | `defense.ppl_stripped` |
| 0x10 | `unhook-ntdll` (`\KnownDlls` remap) | Covered *memory* | `defense.ntdll_second_copy` |
| 0x11 | `earlybird-apc` with PPID spoofing | Partial | `memory.thread_start_unbacked`, `memory.stack_unbacked`; `process.unexpected_parent` for implausible parents of system processes. A spoofed parent that is plausible passes |
| 0x12 | `pe-reflect` (headerless sRDI) | Partial *memory* | `memory.pe_in_private` needs a header; execution from the region is caught by the unbacked-execution rules |
| 0x13 | `sleep-hotswap` | Covered *memory* | As for sleep obfuscation |
| 0x14 | `veh-audit` | Covered *memory* | `memory.veh_unbacked`, `memory.hardware_breakpoint` |
| 0x15 | `graceful-shutdown` | New | `process.deleted_binary`, `defense.self_delete` |
| 0x16 | `socks5` | New | `network.unusual_path_listener` (a program in a temporary or public folder accepting connections; loopback-only listeners rate notable) |

## Transports

| Transport | Status | Rules |
|---|---|---|
| Plain HTTP (live) | Covered | `network.unusual_path_outbound`, `malware.lattice_agent` |
| HTTPS / HTTP/2 with JA3/JA4 camouflage | Partial | `network.unusual_path_outbound`; TLS fingerprints are a network sensor's job |
| HTTP/3 over QUIC | Covered | `network.quic_outbound` |
| DNS over HTTPS | New | `network.doh_outbound` (a public DoH resolver's port 443, or DNS over TLS on 853, from a program that isn't a browser, resolver or DNS privacy tool) |
| Authoritative DNS TXT/AAAA tunnel | Covered | `network.dns_tunnel`, `network.direct_dns` |
| SMB named pipes (`mojo.*`) | Covered / New | `network.c2_named_pipe` for Cobalt Strike's own mojo default; `network.mojo_pipe_impostor` for any other mojo.* pipe a non-Chromium program creates (Sysmon 17), or one open on the host not in Chromium's `mojo.<pid>.<tid>.<n>` form |
| WebSockets, gRPC with mTLS | Partial | `network.unusual_path_outbound`; the protocols themselves are a network sensor's job |
| P2P pivoting over SMB or TCP | Covered / New | The pipe rules above, `network.unusual_path_listener` |

## Team server and console

The team server's malleable listeners, decoy redirects, IIS-style headers,
TLS/HTTP multiplexing and JA4 camouflage are network-facing: Suricata or Zeek
on the wire is where they show. On a host, lrng reports the team-server binary
through `malware.lattice_agent` (it carries the agent's protocol strings) and
a listener run from a temporary or public folder through
`network.unusual_path_listener`. The operator console runs on the operator's
machine, not a target's.

## What's left

Everything on the roadmap now has a rule, apart from these:

- **Kernel tampering** (callback unlinking, ETW-TI, the `byovd-*` payloads
  themselves): out of reach for a user-mode responder. The driver load that
  makes it possible is covered.
- **DripLoader's allocation pattern** and **headerless reflective images**:
  the memory scanner sees the code running from private memory, not the
  4 KB reservations or the image without its header.
- **A plausible spoofed parent**: `process.unexpected_parent` catches
  impossible parents of system processes, not a believable one.
- **SMB share and session enumeration**, and the transports' wire formats
  (JA3/JA4, WebSockets, gRPC): a network sensor's job.
- **Keying, kill dates and sandbox checks**: they leave nothing on a host.
