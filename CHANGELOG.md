# Changelog

## 0.14.0

Adds detection of NIK C2, the AI-enabled Go remote-access tool Cisco Talos
described in October 2026, and of the tricks it shares with other implants:
making itself unkillable, working on a hidden desktop, back-dating its files,
bypassing UAC through the registry, and the commands it runs.

No new dependencies; the report schema is unchanged at 1.2 (new fields, a new
collector and rules only).

### Added
- **`implants` collector (Windows, on by default).** Specific implant
  families, found by their own strings and the files they stage.
  - `malware.nik_c2` (*critical*): a Go program holding NIK C2's strings (at
    least one only its code carries, and two in all), running from outside the
    Windows and Program Files folders or sitting in a user's
    `AppData\Roaming\Microsoft\Network` or temporary folder, where it copies
    itself. Programs are read up to 64 MB each and 1 GB in all.
  - `malware.nik_c2_artifact`: in the users' and Windows' temporary folders,
    its bootkit placeholder (by content) or its lock screen's page and batch
    file (*critical*); other pairs of its staged files, or a copy of the master
    boot record (*suspect*).
  - The marker strings are kept XOR-encoded in lrng's source, so lrng's own
    binary never holds them; a test checks that.
- **From each Windows process.**
  - `defense.critical_process` (*critical*): a process outside Windows' own core
    set marked critical (`IsProcessCritical`), so that ending it crashes
    Windows. The finding tells the responder to suspend it rather than kill it.
    A Windows program Windows doesn't mark is *notable*.
  - `defense.hidden_desktop`: the desktop a process started on, read from its
    process parameters with the environment. Explorer on a desktop of its own is
    *critical* (hidden VNC), browsers and shells *suspect*, anything else
    *notable*. Browser sandboxes' desktops (for their child processes) and
    Windows Search's are left alone.
  - Records gain `critical` and, when judged, `desktop`; `meta` gains
    `critical_flags_read`, `critical_processes` and `desktops`.
- **`defense.timestomp`.** An executable dated before 1980, which no file system
  or archive a program arrives through can record, is *suspect* (Unix's time
  zero, 1 January 1970, written by reproducible builds, is left alone); one
  dated in the future is *notable*. Checked on Windows process images,
  autostart programs and service files, and on Linux process images (through
  `/proc/<pid>/exe`).
- **`privesc.uac_bypass_key`.** A command in a user's `ms-settings`
  (fodhelper, computerdefaults), `mscfile` (eventvwr), `exefile\shell\runas`
  (sdclt), `Folder` with an empty `DelegateExecute` (sdclt), wsreset's AppX or
  `App Paths\control.exe` key, or a per-user `%windir%` (SilentCleanup), from
  each loaded user hive (`autoruns`) and from Sysmon's registry events (12, 13),
  which keep a key deleted two seconds later as NIK C2 deletes its own.
- **Command-line rules.** `cred.wifi_keys` (`netsh wlan … key=clear`),
  `defense.raw_disk_access` (a script opening `\\.\PhysicalDrive`: an MBR read
  or rewritten), `exec.mshta_local_file` (mshta running an HTML application
  from a temporary or download folder), and at *notable*
  `discovery.av_product` (SecurityCenter2 `AntiVirusProduct`) and
  `exec.c2_shell_recon` (`chcp 65001` with reconnaissance in the same line:
  the UTF-8 wrapper Go and Python implants put around each shell command).
  `bcdedit /enum` and `Confirm-SecureBootUEFI` on their own aren't judged:
  2026's Secure Boot certificate updates run them on many hosts.

### Changed
- **File times are converted without overflow.** A `FILETIME` before 1678
  (which a stomped time can be) overflowed the conversion the file records
  used, and an unset one showed as 1601; both now read correctly or are left
  out.

### Security
- `processes` reads one more field through the handle it already opens for
  the environment (the desktop name) and asks `IsProcessCritical` on its
  query-only handle. `implants` opens program files read-only.

### Tested
- On the Windows runner:
  - a desktop is created and ping started on it; the desktop is read back out
    of ping's process parameters and `defense.hidden_desktop` must be reported;
  - a copy of ping dated 1979 is run and `defense.timestomp` must be reported;
  - fodhelper's key is planted in the test user's hive, pointing at a program
    that doesn't exist, and `privesc.uac_bypass_key` must be reported (the key
    is removed after);
  - inert look-alikes of NIK C2's program (bytes shaped like a Go program, not
    a runnable one) and bootkit placeholder are written where it leaves them,
    and both must be reported;
  - the smoke test requires Windows' own critical processes to be read as such,
    and no critical-process, hidden-desktop, timestomp, UAC-bypass or implant
    finding on the clean runner.
- Talos's documented NIK C2 commands fire the new command-line rules, and
  look-alikes administrators run don't.
- Setting a process critical isn't tested live: if the test died before
  clearing it, the runner would crash.

## 0.13.0

Adds detection of:
- bring-your-own-vulnerable-driver (BYOVD), including attempts Windows blocked;
- the "patchless" AMSI and ETW bypasses, which use a hardware breakpoint and a
  vectored exception handler instead of changing any code;
- system calls made around ntdll's hooks: direct and indirect syscalls, the
  stubs that make them, and fresh copies of ntdll;
- where threads started and what the stacks of waiting threads show: injected
  threads, sleeping beacons, sleep masks and spoofed frames;
- what Impacket, NetExec and C2 frameworks leave behind;
- the settings an intruder weakens (Defender, AMSI, WDigest, LSA, .NET's ETW
  and profiler variables);
- attacks on Active Directory in a domain controller's and a certificate
  authority's logs (DCSync, Kerberoasting, AS-REP roasting, shadow
  credentials, delegation and ACL backdoors, AD CS abuse), and forged and
  stolen Kerberos tickets in the ticket caches;
- Cobalt Strike and Havoc configurations decoded out of memory, and more
  call-stack spoofing;
- AI agents' MCP servers, hooks and instruction files with hidden text, and
  programs driving a local LLM;
- covert channels: DNS tunnels, DNS past the resolver, QUIC;
- Linux rootkits (hidden processes and sockets) and PAM, sudo and udev
  backdoors.

No new dependencies; the report schema is unchanged at 1.2 (new fields,
collectors and rules only).

### Added
- **`drivers` collector (Windows, on by default).** Every module the kernel
  has loaded (from its own module list) and every driver registered as a
  service, one record per file, each hashed (SHA-256) and fingerprinted by its
  **Authenticode digest**, which stays the same when a driver is re-signed.
  Both are looked up in the bundled **LOLDrivers** list of known vulnerable
  and malicious drivers (712 drivers, 2,393 samples), offline. Only exact
  hashes match; LOLDrivers' file names are leads, not detections.
  - `persistence.malicious_driver` (*critical*), `privesc.vulnerable_driver_loaded`
    (*suspect*), `privesc.vulnerable_driver_installed` (*notable*; lower when
    HVCI is on and blocks that build). Each names the LOLDrivers entry, its
    CVEs and which hash matched, and links to its page.
  - For drivers no list names: `privesc.driver_unusual_path` (loaded from a
    temp, download or world-writable directory) and
    `defense.loaded_driver_file_missing` (loaded, then its file deleted: how
    BYOVD loaders, and some tools, clean up). Crash-dump copies of storage
    drivers are hashed as the file they came from, never reported missing.
  - The host's driver-loading policy as a record: kernel code integrity, test
    signing, kernel debugging, memory integrity (HVCI), and Microsoft's
    vulnerable driver blocklist, with `defense.driver_blocklist_disabled` and
    `defense.code_integrity_weakened`.
- **Sysmon driver loads in the event log.** Sysmon's event 6 is matched
  against the same list by its SHA-256 or SHA-1, so a vulnerable driver that
  was loaded and removed before lrng ran is still found; an unsigned driver
  load is `defense.unsigned_driver_loaded`. Works in offline `-evtx` triage on
  any OS.
- **Exception hooks in the memory scan (Windows).** Every thread's debug
  registers and both of ntdll's vectored handler lists are read:
  `defense.amsi_hwbp` and `defense.etw_hwbp` (*critical*: a hardware
  breakpoint on `amsi.dll` code or an ETW event writer; *suspect* when a
  debugger is attached), `memory.hardware_breakpoint` (any other armed
  breakpoint), and `memory.veh_unbacked` (*critical*: a vectored exception or
  continue handler in executable memory no image file backs). Each process's
  record gains `exception_hooks`: threads read, breakpoints, handlers walked,
  and the modules that registered handlers.
- **System calls in the memory scan (Windows x64).** A thread blocked in a
  system call shows where its `syscall` instruction is and where its stub
  returns:
  - `defense.direct_syscall`: the `syscall` is outside ntdll, win32u and (in a
    32-bit process) WoW64's wow64cpu
    (SysWhispers, Hell's, Halo's and Tartarus' Gate, FreshyCalls, Heaven's
    Gate). *Critical* from memory no image backs or from a second ntdll,
    *suspect* from another module, *notable* from a byte-for-byte copy of
    ntdll's stub (Chromium's sandbox keeps those for the calls it intercepts).
  - `defense.indirect_syscall`: through ntdll, returning into executable
    memory no image backs (SysWhispers3's jumper, RecycledGate, HellsHall).
  - `defense.syscall_return_nonexec` (*critical*): returning into memory that
    isn't executable, as sleep obfuscation leaves an implant, or where nothing
    is mapped (a forged stack).
  - `memory.syscall_stub`: direct, indirect and register-jumper stubs in
    executable memory no image backs, used or not. Hook trampolines (which
    jump back into ntdll's stub, not to its `syscall`) and copies of ntdll's
    stubs are counted, not reported.
  - `defense.ntdll_second_copy`: ntdll mapped again, as an image (found by its
    export name, so a renamed copy counts) or as an executable file view.
  - `defense.syscall_hwbp`: a hardware breakpoint on a system-call stub
    (TamperingSyscalls, LayeredSyscall).

  Each process's record gains `syscalls`: threads in a system call, the calls
  of each kind, stubs, copies and trampolines counted, bytes searched. ntdll's
  stubs are read from its file on disk.
- **Sysmon process access (event 10)** whose call trace starts in code no
  module backs is `defense.direct_syscall` too: the target was opened with a
  direct syscall. *Critical* when the target is LSASS (NanoDump, Dumpert).
- **Threads in the memory scan (Windows; stacks on x64).**
  - Start addresses (Windows records the routine each thread was created to
    run):
    - `memory.thread_start_unbacked`: started in memory no image backs.
      *Critical* while that memory is executable, *suspect* once it isn't.
    - `memory.thread_start_loadlibrary`: started at LoadLibrary, the classic
      CreateRemoteThread DLL injection, still running.
    - `memory.thread_start_spoofed`: started inside a function rather than at
      its start. Cobalt Strike's process-inject `CreateThread
      "module!function+0x.."` option does this.
  - Stacks: each thread blocked in a system call is unwound with its modules'
    own unwind data, read from their files, the way `RtlVirtualUnwind` does it
    (the new `unwind.rs`):
    - `memory.stack_unbacked`: a frame in code no image backs and no runtime
      registered as JIT code (a beacon sleeping in `Sleep` or
      `WaitForSingleObject`).
    - `defense.stack_return_nonexec` (*critical*): a frame in memory that
      isn't executable now (a sleep mask).
    - `defense.stack_frame_no_call`: a return address that follows no call
      instruction (a spoofed frame).
  - JIT code (.NET, V8, Java) is recognised from the ranges the process
    registered with ntdll (its dynamic function table list) and counted,
    not judged.
  - Each process's record gains `threads`: start addresses read, stacks
    walked and how each walk ended, JIT ranges and frames.
- **`lateral` collector (Windows, on by default).** Every named pipe is
  listed, without opening any, and those known tools use by default are
  reported:
  - `network.c2_named_pipe`: Cobalt Strike's defaults (*critical*) and the
    names published malleable profiles set (*suspect*), Covenant, PoshC2, and
    known malware families (SUNBURST, Turla, ...).
  - `lateral.remote_exec_pipe`: PsExec, PAExec and CSExec (*notable*); RemCom,
    as Impacket's psexec uses it (*suspect*).
  - `privesc.potato_pipe`: a pipe named after a path to another pipe, which a
    coerced SYSTEM service opens.
  - `cred.dump_tool_pipe`: cachedump, lsadump, WCE, Koh.

  `lateral.impacket_output_file` is an output file Impacket's wmiexec,
  dcomexec or smbexec didn't get to delete; its record keeps the start of the
  output. Sysmon's pipe events (17, 18) are judged by the same names, with the
  program that made the pipe.
- **`defenses` collector (Windows, on by default).** One record per area,
  with every value read:
  - Microsoft Defender's exclusions, from its preferences and group policy:
    `defense.defender_exclusion`, graded. A whole drive, a temporary,
    download or world-writable folder, an executable extension or a script
    host is *suspect*.
  - Defender's protection switched off: `defense.defender_protection_off`
    (real-time, behaviour or script scanning; cloud or tamper protection at
    *notable*).
  - `cred.wdigest_enabled` (WDigest keeping passwords in clear text in LSASS),
    `cred.lsa_protection_off`, `cred.restricted_admin_enabled` (RDP accepts a
    hash) and `cred.ntlmv1_allowed`.
- **Impacket and NetExec command lines.** `lateral.wmiexec`,
  `lateral.smbexec` and `lateral.atexec` (*critical*) match the shells their
  wmiexec, dcomexec, mmcexec, smbexec and atexec run, in the shapes their
  source builds. They apply wherever command lines are judged, now including
  the actions of tasks registered or updated (Security 4698, 4702). atexec's
  task survives there after it is deleted.
- **More of the event log.**
  - `cred.pass_the_hash`: a 4624 logon of type 9 through the Secondary Logon
    service (Mimikatz's `sekurlsa::pth`, Rubeus `createnetonly`; `runas
    /netonly` looks the same).
  - Defender's own events date its changes: 5001, 5010 and 5012 (protection
    off), 5007 (an exclusion added or a protection switched off) and 5013
    (`defense.defender_tamper_blocked`).
  - Code Integrity's log is now read. A driver it refused is matched against
    LOLDrivers by the event's hashes: `privesc.vulnerable_driver_blocked` (a
    failed BYOVD attempt), `persistence.malicious_driver` for a listed
    malicious one, and `privesc.vulnerable_driver_loaded` when the policy was
    only auditing. Any other refused driver is `defense.driver_load_blocked`
    (*notable*); a module LSA protection kept out of LSASS is
    `cred.lsa_plugin_blocked` (mimilib, an SSP or password-filter backdoor).
- **Active Directory attacks in a DC's and a CA's logs.**
  - Directory access (4662): `cred.dcsync` (replication rights used by an
    account that isn't a domain controller or Azure AD Connect's; *critical*
    for Get-Changes-All), `cred.dpapi_backup_key` (the domain's DPAPI backup
    key read), `persistence.domain_acl_changed` (the domain opened with
    WRITE_DAC: ntlmrelayx `--escalate-user`, PrivExchange).
  - Kerberos: `cred.kerberoasting` (one account asking for RC4 tickets to 4
    or more user-account services within 15 minutes — 4769s aggregated across
    the log; *critical* from 10), `cred.asrep_roasting` (4768 without
    pre-authentication; *suspect* when RC4), `cred.computer_certificate_logon`
    (PKINIT as a computer: a relayed DC certificate, PetitPotam + ESC8), and
    the KDC's event 41, `privesc.certificate_sid_mismatch`.
  - Directory changes (5136): `cred.shadow_credentials`,
    `privesc.rbcd_configured`, `privesc.constrained_delegation_configured`
    (also from 4738/4742), `cred.spn_added_to_user`, `defense.dcshadow`,
    `persistence.adminsdholder_modified`, and
    `persistence.dcsync_rights_granted` (the domain's new security descriptor
    parsed as SDDL; only trustees that don't hold replication rights by
    default are reported).
  - `persistence.sid_history_added` (4765, 4766, 4738; *critical* for a
    privileged SID), `persistence.dsrm_password_set` (4794), and
    `privesc.reflection_dns_record` (a DNS record named with a marshalled
    target-information blob, CVE-2025-33073; from 4662 and 5136/5137).
  - Certificate Services: `privesc.adcs_alternate_identity` (a request whose
    subject alternative name the requester supplied — as Certipy sends one for
    `-upn`, `-dns` and `-sid` — naming another user: ESC1, ESC6),
    `privesc.adcs_application_policies` (ESC15), and
    `privesc.adcs_vulnerable_template` (an ESC1-shaped template loaded, or a
    template changed into that shape: ESC4).
- **`kerberos` collector (Windows, on by default).** Each logon session's
  cached tickets from LSA, metadata only: `cred.golden_ticket` (a TGT valid
  for days or years), `cred.rc4_tgt` (*suspect* when other tickets are AES),
  `cred.pass_the_ticket` (another account's TGT in a session),
  `cred.kerberos_ticket_anomaly`. Every session needs SYSTEM; otherwise the
  agent's own is read and `meta.all_sessions` says so.
- **Evasion and persistence on Windows.**
  - The .NET runtime's variables, from every process's environment (only
    those variables are kept) and the system, user and service environments:
    `defense.dotnet_etw_disabled`, `persistence.clr_profiler`.
  - AMSI providers: `defense.amsi_provider_hijacked`,
    `defense.amsi_provider_missing`, `persistence.amsi_provider`.
  - `persistence.accessibility_backdoor` (an accessibility program replaced by
    a shell, by its bytes or its version resource), `network.portproxy_rule`
    (registry and command line), `cred.dsrm_network_logon`.
  - Command lines: `defense.powershell_downgrade` (also from Windows
    PowerShell's event 400), `cred.browser_remote_debugging`.
  - Sysmon: remote threads (8) as `memory.remote_thread_unbacked` and
    `memory.remote_thread_loadlibrary`; process tampering (25) as
    `memory.process_tampering`.
- **Covert channels.** `network.dns_tunnel` (many long, random-looking names
  under one domain: Sysmon's DNS events per program, aggregated across the log,
  and the DNS client cache), `network.direct_dns` (DNS sent straight to a
  public resolver: Sysmon's network events and live TCP connections, Windows
  and Linux), `network.quic_outbound` (QUIC from programs that aren't
  browsers), and `network.lolbin_outbound` from Sysmon's network events.
- **Beacon configurations in the memory scan.** `memory.cobalt_strike_config`
  (the packed settings, XOR-encoded or decoded, and a running beacon's
  settings table, 64- or 32-bit) and `memory.havoc_config` (a Havoc Demon
  payload still whole in executable memory), decoded: C2 hosts and URIs,
  ports, sleep and jitter, watermark, user agent, spawn-to, pipe names. The
  values ride in a new `extracted` field of the sidecar's hits; the memory
  record keeps them and the IOC export takes their C2 hosts.
- **More call-stack spoofing.** `defense.stack_jmp_gadget` (a return address
  on a `jmp [rbx]`-style gadget: SilentMoonwalk's desync),
  `defense.stack_truncated` (a stack that ends where no thread begins),
  `defense.stack_fake_thread_start` (BaseThreadInitThunk appearing to call a
  Windows API in a module the thread didn't start in).
- **`aiagents` collector (Windows and Linux, on by default).** Every AI
  client's MCP servers and Claude Code's hooks, credentials redacted:
  `ai.mcp_server_unusual_path`, `ai.mcp_server_remote_code`,
  `ai.mcp_server_url`, `ai.agent_hook_unusual_path`, and the command-line
  rules on each command. Agent instruction files and project configuration
  in the users' homes are checked for hidden text: `ai.hidden_instructions`
  (Unicode tag characters and variation-selector smuggling decoded,
  bidirectional controls, zero-width characters). The network collectors
  add `ai.local_llm_client` (a program that isn't an AI client talking to a
  local Ollama, LM Studio, GPT4All or Jan server, checked against the process
  listening) and `ai.remote_llm_server`.
- **`rootkit` collector (Linux, on by default)** and three more persistence
  surfaces. `defense.hidden_process` (answers at `/proc/<pid>`, missing from
  the listing), `defense.hidden_socket` (in netlink's socket table, missing
  from `/proc/net`); PAM (`persistence.pam_module`,
  `persistence.pam_module_modified` against dpkg's md5sums,
  `persistence.pam_module_unowned`, `persistence.pam_exec`), sudo
  (`persistence.sudo_nopasswd`) and udev (`persistence.udev_run`).

### Changed
- **The system-call checks re-read before reporting.** A call is reported
  only if the thread's registers and its stack slot read the same a second
  time (`threads_moved` counts the rest), and the sidecar's own thread is
  never judged. A call through ntdll that returns into JIT code a runtime
  registered is counted (`jit_returns`), not reported as an indirect syscall.
- **32-bit processes no longer read as tampered with.** The 32-bit .NET
  runtime patches its GC write-barrier helpers, which sit side by side, so its
  patches merge into one stretch of a few hundred bytes. Like the 64-bit
  runtime's smaller patches, that is now `memory.image_inline_patch` at *info*,
  not `memory.image_code_modified`. WoW64's wow64cpu.dll, whose `W64SVC` section
  Windows makes executable though its file marks it as data, is skipped when
  that section holds the file's own bytes.
- **`internal/pehash`**, the Authenticode digest (SHA-256 and SHA-1 in one
  streamed pass), and **`cmd/drivergen`**, which builds the dataset from
  LOLDrivers' `drivers.json` (`make driver-data`), sorted so a refresh diffs
  cleanly.

### Security
- **The sidecar asks for one new right**: `THREAD_GET_CONTEXT` (with
  `THREAD_QUERY_LIMITED_INFORMATION`) on the threads of a process it scans, to
  read their debug registers and instruction and stack pointers. Threads aren't suspended and nothing is set. To
  find ntdll's handler lists it registers a no-op handler of each kind in its
  own process for a moment and removes it; a target's lists are read twice and
  checked link by link, and a decoded handler that points at nothing
  executable is counted, not reported, so a list changing underneath can't
  produce a finding. Handlers are decoded with the target's pointer cookie,
  read from ntdll's own copy of it: `DecodeRemotePointer` would need more than
  read access to the process.
- **Thread start addresses** are read on the same thread handle, or on one
  opened with `THREAD_QUERY_INFORMATION` where Windows asks for that. Stack
  walks read the stack and each module's file only; a frame is reported only
  if the thread is still where it was. The integer registers a walk starts
  from come from the same `GetThreadContext` call.
- `lateral` lists pipes with `FindFirstFile`, which opens none of them, and
  `defenses` only reads registry values. Event data (hashes, names, task XML)
  is attacker-influenced text: it is matched, never executed or followed.
- **`processes` asks for one new right on Windows**: it opens each process
  (LSASS excepted) with `PROCESS_VM_READ` to read its environment block, and
  keeps only the .NET runtime's variables. `kerberos` reads ticket metadata,
  never a ticket or a key; as SYSTEM it registers a logon process, which
  Windows can log (4611). `aiagents` never records environment values, and
  redacts credential-shaped arguments, URL parameters and hook text.
- Beacon configurations are attacker-controlled bytes: every length and
  pointer is bounds-checked, a candidate is reported only if it parses whole,
  and Havoc proxy credentials are never reported.
- Driver files and `drivers.json` are hostile input: the Authenticode reader
  bounds-checks every offset (fuzzed), and the dataset parser rejects any
  malformed line.

### Tested
- The Authenticode digest matches LIEF's on 207 Windows binaries (34 signed)
  and LOLDrivers' recorded digest of a real vulnerable driver; on the Windows
  runner it matches Windows' own (`CryptCATAdminCalcHashFromFileHandle2`) for
  every loaded driver.
- On the Windows runner, entries planted in the list for drivers really loaded
  there (one by file hash, one by the digest Windows computed) and for a
  registered, never-started copy are reported loaded, malicious and installed.
- The sidecar's Windows self-test plants a handler on both lists and hardware
  breakpoints on `AmsiScanBuffer`, `EtwEventWrite` and `Sleep`, and requires
  each to be found at its address, after a clean pass that must find the test
  binary's own handler and report nothing.
- A second self-test plants system-call stubs of each shape (never run), poses
  suspended threads as stopped in a direct call, a call from a copied stub,
  and calls through ntdll returning into injected and into non-executable
  memory, and maps ntdll twice; each must be reported at its address. Nothing
  planted is executed.
- A third self-test walks a real waiting thread with both the new unwinder
  and Windows' `RtlVirtualUnwind`, and requires the same frames. It then:
  - runs a thread that waits from a page no image backs (it only calls
    `WaitForSingleObject`), makes the page non-executable while it waits,
    then registers it as JIT code;
  - parks threads at LoadLibraryW and inside `RtlUserThreadStart`;
  - poses one with a return address that follows no call.

  Each must be reported (or, as JIT code, not).
- The thread self-test also poses a return onto a `jmp [rbx]` gadget found
  in kernelbase, a stack that ends after `WaitForSingleObjectEx`, and a copy
  of the stack of a thread really started at `SleepEx` under a thread that
  started in the test's own code (the real one must not be reported).
- A live test runs the sidecar's test binary as a target holding a packed
  Cobalt Strike configuration and a running beacon's settings table on its
  heap (and, on Windows, a Havoc payload in executable memory), and requires
  every C2 host back out of a scan.
- The live scans of a 64-bit and a 32-bit PowerShell gate the new memory rules
  against false positives (twenty-one in all). The 64-bit one must also find
  .NET's registered JIT ranges.
- On the Windows runner: a child started with `COMPlus_ETWEnabled=0` and a
  profiler in its environment has them read back out of its memory (and a
  secret beside them isn't); the accessibility programs' version resources are
  read (Windows' own names for Magnify and Narrator came from there), AMSI's
  Defender provider must be found and judged ordinary, LSA must list the logon
  sessions and answer for the agent's own, and the AI-agent sweep must run.
- On Linux: PAM modules on a real Debian-family system match their packages'
  md5s, every PID is accounted for, and a listener opened by the test is in
  both netlink's and `/proc/net`'s socket tables.
- The Windows smoke test requires `lateral` to list the host's pipes and
  `defenses` to return its records, AMSI's among them, with no AMSI or .NET
  ETW finding on the clean runner.

### Third-party data
- LOLDrivers (Apache License 2.0). Its license ships beside the data and in
  every release archive, with `THIRD_PARTY_NOTICES.md`.

## 0.12.0

Adds the report viewer: one offline HTML page that reads lrng's reports, so an
analyst never has to read the JSON, plus `-format html`, which writes a report
already inside it: one file to open in a browser or attach to a ticket. The
agent itself stays command-line. No new dependencies (the page is plain HTML,
CSS and JavaScript, embedded in the agent with `go:embed`), and the report
schema is unchanged at 1.2.

### Added
- **Report viewer (`viewer/lrng-viewer.html`).** Drop a `.json` or `.jsonl`
  report onto it, or open one. It shows:
  - the run at a glance: the host and OS; when the report was collected; the
    run ID, agent version and elevation; the report's SHA-256, to compare with
    the `.sha256` lrng wrote; warnings for a non-elevated or interrupted run and
    for collector errors; and a strip of ATT&CK tactics in kill-chain order,
    each counting its findings and coloured by the worst of them (a click
    filters to that tactic);
  - findings, most severe first, filterable by severity, collector, tactic and
    text, each opening to the record behind it, with links to the process tree
    and the collector's table;
  - the process tree, with processes that have findings marked, collapsible
    branches, and a search that keeps the path down to each match;
  - the timeline: the `-timeline` result, or one built from the report's own
    timestamps, grouped by day, each entry linked to its source record;
  - indicators from `-iocs` with their `-intel` attribution, copyable as a list;
  - the run's settings, host details and every collector's errors;
  - every collector's records as a table that can be searched and sorted.

  It works in light and dark mode and at phone width, and opens a 43 MB report
  of 100,000 records in about a second. Monospace marks verbatim evidence from
  the host; everything else is the viewer's own words. The standalone page
  ships in every release archive, beside the agent.
- **`-format html`.** The `json` envelope inside the viewer, in one file; the
  `.sha256` beside it covers both. The report is HTML-escaped into a
  non-executable data block (`viewer.Render`), so no value in it can close the
  block or open markup.

### Security
- **The viewer treats every report as hostile.** Process names, command lines
  and event data are attacker-controlled, so no report string is ever parsed as
  markup or code: values only become Text nodes or attribute values, and the
  script uses none of `innerHTML`, `insertAdjacentHTML`, `document.write`,
  `eval` or `new Function` (a Go test checks). Field names are looked up on
  prototype-less objects, so keys like `__proto__` and `constructor` are just
  data. The only links it makes go to `attack.mitre.org`, for technique IDs it
  has validated, and a hash route can only name views and collectors that
  exist. The page's content security policy allows its one script and one
  stylesheet by SHA-256 hash and nothing else (`default-src 'none'`), so even
  a successful injection couldn't run inline code, and the page can't load or
  send anything: a report opened in it stays on the machine. A Go test keeps
  the hashes in step with the page (`go test ./viewer -update` after an edit).
- **Tested in a real browser with hostile reports** (`viewer/browsertest`, a
  new CI job). A report carrying markup, script, URL and template payloads in
  every field, prototype keys, malformed records, process cycles and a chain
  3,000 processes deep is opened embedded, as JSON and as JSONL. Real reports
  are also opened: the Windows runner's JSON and JSONL, and a Linux runner's.
  For each, the job walks every view in Chromium and opens every finding,
  process and record it shows. It fails on any dialog, page error, console
  error, element created from report markup, link outside ATT&CK, request
  leaving the page, or prototype pollution. It also checks that the policy is
  in force: an injected script doesn't run and `fetch` is refused. Making the
  viewer render report strings as markup fails this test thousands of times.

## 0.11.1

Closes the gap 0.11.0's image-integrity check left on Windows: module stomping
that writes its payload outside a module's code sections. One new rule id,
everything read-only, no new dependencies, schema unchanged at 1.2.

### Added
- **Executable pages outside a module's code sections (Windows,
  `memory.image_exec_outside_code`, T1055).** 0.11.0 compared the sections a
  module's file marks as code, so a stomper that leaves `.text` alone — writing
  its payload into a data section, the headers or past the last section, and
  making those pages executable — went unseen. The image walk now records every
  executable stretch of each loaded module and places it against the file's own
  layout; any outside the code sections is reported with the section it lies in
  and its protection, and its bytes are compared with what the file maps there
  (relocated, IAT masked, zero fill past the raw data): *critical* when a
  payload was written, *suspect* when only the protection changed. Images whose
  sections share pages (section alignment below a page, so the memory manager
  gives the whole image one protection) are counted under `skipped` instead.
  Recent Windows builds map an executable page of their own just past the end
  of every image with a `fothk` section (at `SizeOfImage`, so no section covers
  it) — in CI's test process 13 of 14 modules, byte-for-byte the same in all 13.
  Those are judged against each other instead of the file: a copy that differs
  from one two or more of the process's modules share is reported as
  *critical*, matching ones are counted under `skipped`.
  The expected bytes are checked against pefile on 188 real images (962 data
  sections and headers, byte for byte), and the real-Windows self-test now also
  makes a page of a loaded DLL's `.rsrc` executable, writes 1 KiB into it, and
  requires exactly that page to be reported — after a clean run that must report
  nothing. It also tries to write to that DLL's copy of Windows' own page: on
  CI's Windows build the page can't even be made writable (`VirtualProtect`
  fails with `ERROR_INVALID_ADDRESS`), so no payload can be written there from
  user mode; where it can be, the written copy must be reported. The live Windows sweep fails CI if the rule fires on the runner. Linux
  needed no change: it compares every executable mapping, wherever it lies.
  Counted per process as `image_integrity.exec_outside_code`.

### Fixed
- **A memory scan without YARA rules and without the prompt scan refused to
  run** ("nothing to do"), though image integrity and the memory heuristics
  need no rules. It now runs them, reading only each region's first chunk, so
  `-collectors memory -mem-no-prompts` is a quick integrity sweep. The
  `-mem-no-prompts` help no longer says "YARA only".

## 0.11.0

Closes the roadmap's open detection items. On Windows, the COM- and
WMI-persistence collectors from v0.6 reach three fileless surfaces they did not
yet cover (all T1546): COM type-library hijacking, timer-triggered WMI
subscriptions, and scheduled tasks that fire a hijacked COM handler. The memory
scan gains an image-integrity check on both OSes — mapped code and headers
compared with their files — for module stomping, hollowing and AMSI/ETW
patching. Linux gains three collectors (loaded kernel modules, loaded eBPF
programs, and a journal triage read straight from journald's files), and the
Unix command-line rules learn anti-forensics. 32 new rule ids, everything
read-only, no new dependencies, and the schema is unchanged at 1.2 — these are
new records and findings within the existing envelope.

### Added
- **COM type-library hijacking (`comhijack` collector).** The CLSID-server
  walk is joined by a walk of the TypeLib class stores —
  `HKLM\SOFTWARE\Classes\TypeLib` (native and the `Wow6432Node` 32-bit view)
  and each loaded user's `HKU\<sid>_Classes` — resolving the library path at
  each `{libid}\{version}\{lcid}\{platform}` leaf. A COM object loads its
  registered type library when it is instantiated, so a registration that
  names a COM script moniker instead of a `.tlb`/`.dll`, sits in a
  user-writable path, or (per-user) shadows a machine entry reaches code the
  same way a rewritten `InprocServer32` does — and the CLSID walk does not see
  it. New rules, all T1546.015: `persistence.typelib_script_moniker`,
  `persistence.typelib_unusual_path`, and `persistence.typelib_user_shadow`
  (*critical* when the shadowing entry is itself a moniker or an odd path).
  Reuses the read-only `internal/winreg` reader; the moniker and per-user-shadow
  judging is portable and unit-tested. The totals scanned go in the result's
  metadata (`typelib_count_machine` / `typelib_count_user`).
- **Timer-triggered WMI subscriptions (`wmi` collector).** The namespace sweep
  now also enumerates `__TimerInstruction` (the `__IntervalTimerInstruction`
  and `__AbsoluteTimerInstruction` subclasses) over the same hand-rolled COM
  client, and an `__EventFilter` whose WQL subscribes to `__TimerEvent` is
  called out as timer-triggered. A timer makes a subscription fire on a
  schedule, independent of any system event — a trigger legitimate software
  almost never uses. New rules, T1546.003: `persistence.wmi_timer` for the
  timer object and `persistence.wmi_timer_filter` for the filter that rides it.
  A clean host carries neither; a namespace that doesn't carry the class is
  noted, not failed, so the subscription records are never lost to it.
- **Scheduled task → COM-handler cross-check (`correlate.go`).** A scheduled
  task can act through an `IComHandlerAction` (a CLSID) rather than an exec; the
  scheduledtasks collector already records the ClassId and comhijack already
  flags hijacked or oddly-served COM registrations, but nothing joined the two.
  The post-pass now raises `correlate.task_comhandler_hijacked` (T1546.015) on a
  task whose ComHandler CLSID matches a registration comhijack flagged —
  *critical* when that registration was — tying the schedule (the trigger) to
  the hijacked object (the payload). Portable and unit-tested; like the other
  correlations, a no-op unless both collectors ran, so offline `-evtx` runs are
  unaffected.
- **Image integrity in the memory scan (sidecar, Windows and Linux).** Before
  the YARA walk, with up to a third of each process's budget, every image's
  executable code in memory is compared with its file. On Windows each loaded
  module's code sections are compared after applying the base relocations the
  loader applied (the import table, and the `fothk` section of function-override
  thunks the loader itself rewrites, are left out), and its header's identity
  fields — timestamp, image size, section layout — with the file's; on Linux
  each executable file mapping is compared with `/proc/<pid>/map_files/…`, the
  very inode that was mapped, so an upgraded package can't look like tampering.
  Differences merge into change sites judged by length: a long run is code
  rewritten in place, `memory.image_code_modified` (T1055, *critical* from
  16 KiB — module stomping); short runs are patches, `memory.image_inline_patch`
  (low severity, since security products hook too; the .NET runtime, which
  rewrites its own GC write barriers, is named as expected), except in `amsi.dll`
  (`defense.amsi_patched`, T1562.001) and at ntdll's ETW event writers
  (`defense.etw_patched`, T1562.006), named by export. A header that no longer
  matches its file is `memory.image_header_mismatch` (T1055.012 — hollowing and
  its relatives); an image whose file can't be read is
  `memory.image_file_unavailable`. The PE reader is bounds-checked, fuzzed, and
  checked byte-for-byte against pefile on 188 real images (relocations, section
  bytes and exports; `LRNG_PE_SAMPLES`, `sidecar-rs/scripts/pe_golden.py`).
  Results go in the memory record's `image_integrity`.
- **Loaded kernel modules (`kmod` collector, Linux).** Every module in
  `/proc/modules` with its size, users and taint flags; what loads at boot
  (`modules-load.d`, `/etc/modules`); modprobe `install`/`remove` hooks, which
  run a command as root whenever a module is requested; and the kernel taint,
  decoded. A cross-view of `/sys/module` against `/proc/modules` exposes a module
  hidden from the list. New rules (T1547.006 / T1014):
  `persistence.kmod_hidden`, `persistence.kmod_forced`,
  `persistence.kmod_unsigned`, `persistence.kmod_out_of_tree`,
  `persistence.kmod_boot_unknown`, `persistence.modprobe_hook` (stock
  blacklisting with `/bin/true` and modprobe chaining stay quiet) and
  `kernel.tainted`. Config files are resolved before reading, so a symlinked
  `modules.conf` or merged `/usr` is read once — and a dangling link isn't an
  error.
- **Loaded eBPF programs (`ebpf` collector, Linux, needs root).** Read with
  `bpf(2)` directly — no `bpftool`: each program's type, name, tag, loader uid,
  load time (a timestamp, so `-timeline` places it), maps and run count, and the
  bpffs paths that keep it alive after its loader exits (pinned itself, or by a
  pinned link). Each program's translated instructions are decoded and every
  helper call is named through `/proc/kallsyms`, the way `bpftool` does; programs
  that act on user space are flagged (T1014): `persistence.ebpf_write_user`
  (`bpf_probe_write_user`, the eBPF-rootkit helper),
  `persistence.ebpf_override_return` and `persistence.ebpf_send_signal`. Without
  root it fails with a clear message rather than an empty result.
- **Journal triage (`journald` collector, Linux).** The systemd journal, read
  straight from its files (persistent and volatile, newest first, within a byte
  budget) by a dependency-free reader for the regular and compact layouts, with
  LZ4 decoded; checked against `journalctl` on real journal files of every
  layout and compression (`LRNG_JOURNAL_SAMPLES`). Only security-relevant events
  become records: SSH failures aggregated per source address
  (`logon.ssh_bruteforce`), a logon after a burst of failures from the same
  address (`logon.ssh_bruteforce_success`, *critical*), logons from public
  addresses (`logon.ssh_external`), sudo refusals and authentication failures
  (`privesc.sudo_denied`, `privesc.sudo_auth_failure`), failed `su`
  (`privesc.su_failed`), account and group changes (`persistence.account_created`
  and `persistence.admin_group_add`, the ids the Windows event rules use, and
  `persistence.password_changed`), cron commands that trip the command-line
  rules, and the kernel's own warnings about unsigned modules
  (`persistence.kmod_unsigned_loaded`) and `bpf_probe_write_user` programs.
  Fields journald compressed with zstd or xz (only payloads over its 512-byte
  threshold) are counted, not decoded.
- **Linux anti-forensics in the command-line rules.** Shared by processes,
  cron, systemd units and the journal: `defense.clear_linux_logs` (T1070.002 —
  deleting, shredding, truncating or `/dev/null`-linking `/var/log` files, and
  `journalctl --vacuum-*`) and `defense.clear_shell_history` (T1070.003 —
  `history -c`, unsetting `HISTFILE` or pointing it at `/dev/null`, wiping a
  history file). Reading, rotating and appending to logs stays quiet.

### Fixed
- **A fetch-and-run wrapped in quotes was missed on Linux.** In
  `sh -c 'curl … | sh'` the closing quote stayed on the last program's name, so
  `sh'` wasn't recognised as a shell; the same went for `$(…)` and `{ …; }`
  wrappers, which is how cron jobs, units and modprobe hooks usually write it.
  Quotes, parentheses, braces and semicolons are now trimmed first.

### Changed
- **CI runs the image-integrity check against the real Windows loader.** A
  self-test loads a copy of a system DLL, checks a clean process (no rewrites,
  no header mismatches, nothing unreadable), overwrites 4 KiB of its code and
  requires that exact change to be found; its diagnostics surface as
  annotations on the pull request. The Windows and Linux sweeps also fail if
  image integrity compares nothing or raises a finding on the runner itself.

## 0.10.6

A pre-release correctness pass, mostly over the Linux side, found by running
the agent live as root on a Linux host and reviewing every collector. The
headline fixes: a patched-but-not-restarted server no longer floods the report
with *suspect* findings, Linux hashes are taken from the binary the process
actually runs, AI module A and the network heuristics see through a `#!`
script's name, and event-log retention can no longer drop a log clear in
favour of routine events. The first CI run on a real Windows host also found
that no Windows 10+ prefetch body had ever been decoded. Schema stays at 1.2.

### Fixed
- **Prefetch bodies weren't decoded on Windows 10 and later.** The Xpress
  Huffman decompressor misread two parts of the [MS-XCA] format. A match length
  of 18 or more continues in raw bytes of the byte stream, but it read them
  from the bit stream. And the reader keeps a 16-bit word of lookahead, which
  decides where those bytes and the next 64 KiB block's table sit, but it
  placed them at the next word boundary. Its tests used an encoder built on
  the same misreading, so they passed. On real files (every Windows 10+ `.pf`
  is compressed) decoding failed, and the collector listed prefetch files
  without run counts, run times, referenced files or
  `execution.prefetch_unusual_path`. The decompressor now follows the spec,
  including matches that run past a block and the 32-bit length form. It is
  checked against Windows' own codec: the Windows CI job decodes
  `RtlCompressBuffer` output, and a new test decodes a directory of real `.pf`
  files on any OS (`LRNG_PREFETCH_SAMPLES`). Six Windows 10 files, up to six
  blocks each, decode to the run counts and file and volume counts that PECmd
  reports for them.
- **The sidecar failed clippy on current Rust.** Rust 1.98's clippy added
  `chunks_exact_to_as_chunks`, which the UTF-16 scanner tripped, so CI's
  `-D warnings` failed on any toolchain from 1.98 on. It iterates `as_chunks`
  now.
- **Upgraded binaries and libraries are no longer "self-deleting malware".**
  After a package upgrade, every process still running the old copy maps it as
  `… (deleted)`; each such process raised `modules.deleted_file` *and*
  `modules.unusual_path` (and `process.deleted_binary` for an upgraded
  executable), all *suspect*. When a new file sits at the same system path
  (`/usr`, `/lib*`, `/bin`, `/sbin`, `/opt`, `/snap`, …, checked through
  `/proc/<pid>/root` so containers are judged on their own filesystem) the
  mapping is now `modules.replaced_on_disk` (*info*) and the executable
  `process.binary_replaced` (*notable*, T1554 — a trojanized binary is
  installed the same way, so it stays visible with a `dpkg -V` / `rpm -V`
  hint). A file deleted with nothing in its place is still *suspect*, and a
  deletion is no longer also counted as an unusual path. The memory scanner's
  `memory.deleted_file_exec` gets the same split (`memory.replaced_file_exec`,
  *info*).
- **Linux image hashes come from the running binary.** Process images were
  hashed by re-opening the path text `/proc/<pid>/exe` names, which lives in
  the process's mount namespace: a container's process was hashed from the
  host's file at that path (a different file, or none — reported as the
  misleading `image_exists: false`), and deleted or memfd payloads weren't
  hashed at all. Hashing now opens `/proc/<pid>/exe` itself, keyed by device
  and inode so a shared binary is still read once — a self-deleted or fileless
  payload now carries `image_sha256`, and so lands in the IOC export.
- **The hash cache was case-insensitive on Linux**, so `/tmp/A` and `/tmp/a`
  shared one hash. Paths are case-folded only on Windows now.
- **AI module A was half-blind on Linux.** Its allowlist and script-host lists
  held only Windows `.exe` names, so `firefox` or `code` calling an LLM API was
  a *suspect* finding and `python3`/`bash`/`curl` were never escalated to
  *critical*. And it judged the process by `comm`, which for a `#!` script is
  the script's name (`beacon.py`, its interpreter unseen) and which any
  process can set with `prctl` to an allowlisted name. It now judges by the
  executable's file name (still `comm` when the exe can't be read), knows the
  Linux executables of the allowed browsers and editors, treats versioned
  interpreters (`python3.12`, `perl5.36.0`) as interpreters, and counts only a
  high-risk location (not `~/.local`, where Linux desktop apps live) as an
  unusual place for an allowlisted name.
- **Linux network heuristics missed `#!` shells and misread servers.** A
  reverse shell launched as `./update.sh` (comm `update.sh`, exe `bash`) raised
  nothing; it's now `network.shell_outbound`. An interpreter *listening* (a
  gunicorn or node app server) was a *suspect* `network.shell_listener`; it's
  now `network.interpreter_listener` at *notable*. And every client connected
  to a local server was judged as an outbound connection by the server process;
  connections accepted on a listening port are now marked `direction: inbound`
  and not judged as outbound.
- **Event-log retention could drop the evidence.** Each log kept its most
  recent 50,000 recorded events whether or not they carried a finding, so on a
  busy server routine always-kept events (4672, task runs) could push a week-old
  log clear or service install out; and once 100,000 were kept the remaining
  logs — Defender, TerminalServices, Sysmon — weren't read at all. Records with
  a finding now have their own budget and are never displaced, and every log is
  still parsed (for findings, channel ranges and Sigma aggregations) after the
  routine budget is spent. The 4672s of SYSTEM, LocalService, NetworkService,
  the DWM/UMFD virtual accounts and computer accounts — the bulk of a server's
  Security log — are no longer kept as routine records.
- **A slow event-log parse lost everything.** Cancellation was only checked
  between files, so a large log still parsing at the collector's 3-minute
  deadline got the whole result abandoned. It is now checked between 64 KiB
  chunks, and the partial result is returned with a `cancelled` error.
- **Wrapped (circular) logs were read out of order.** Chunks were walked in
  file order, which for a full log that has wrapped is not time order, so "the
  most recent records" weren't. Chunks are now ordered by their first record
  identifier; a corrupt chunk is skipped instead of ending the walk.
- **Correlation could report a live service or task as removed** when the
  `services` or `scheduledtasks` collector ran out of time part-way: anything
  it hadn't reached became `correlate.*_absent`. A cancelled inventory now
  leaves those installs unjudged (`meta.*_correlation.unverified`).
- **Zombies were reported as kernel threads** (a zombie has no exe link, which
  was the kernel-thread test). Kernel threads are now told by the `PF_KTHREAD`
  flag in `/proc/<pid>/stat`, which also lets `process.kthread_masquerade` fire
  without root (another user's exe link is unreadable unprivileged). The memory
  collector skips zombies with their own reason.
- **A host with IPv6 disabled was reported as "incomplete coverage"** (no
  `/proc/net/tcp6`). A missing IPv6 table is now `meta.ipv6`, not an error.
- **`/etc/ld.so.preload` was parsed wrong.** Words of a commented-out line were
  raised as preloaded libraries, and `a.so:b.so` was one entry. It is now read
  as glibc reads it: `#` comments to end of line, entries split on whitespace
  and `:`.
- **memfd mappings raised two findings with a wrong message** ("deleted from
  disk" plus "unusual path"). They are now one `modules.memfd_exec`.
- **Module B's endpoint list had drifted from module A's** (no
  `*.models.ai.azure.com`). Fixed, and a Go test now reads the Rust pattern and
  fails if it misses any host or pattern module A knows.
- **`intelgen -out` truncated the dataset before reading its inputs**, so a
  failed refresh (a missing download) left `endpoints.tsv` empty — and the next
  build silently embedded an empty dataset. It now writes a temporary file and
  renames it into place only on success.
- **`-mem-scan` with `-mem-budget 0`** gave the sidecar its 60-second default
  but killed it after 30 seconds. A zero budget now means the default
  everywhere.
- The Linux path heuristics matched `/root` as a bare prefix, so `/rootfs/…`
  was treated as root's home. It is matched by whole component now.

### Changed
- **The event log streams.** Logs are read 64 KiB at a time (peak heap for a
  256 MiB log fell from 258 MiB to 4 MiB in testing, and parsing got faster),
  so the 512 MiB per-log cap is gone: a larger Security log is read rather than
  skipped. The live collector reads each log newest first, so if its budget runs
  out on a huge log, what it has is the latest activity. Kept records are still
  reported oldest first.
- **SIGTERM is handled like Ctrl+C** — what `timeout`, systemd and `kill` send
  on Linux now stops collection and still writes the report — and a second
  signal aborts immediately (exit status 130) instead of being swallowed.
- **The IOC export covers Linux.** Absolute POSIX paths are file indicators
  (case-sensitive; a ` (deleted)` marker is dropped, a memfd skipped), and
  `library`, `suspicious_modules` and `deleted_modules` are path fields — the
  last two also on Windows, where flagged DLL paths were never exported.
  Records whose only findings are *info* annotations no longer contribute.
- **Linux persistence coverage**: systemd drop-ins (`<unit>.d/*.conf`, which
  can override a legitimate unit's `ExecStart`), units in the vendor
  directories (`/usr/lib/systemd/system`, recorded only when one trips a
  heuristic, so an implant hiding among packaged units is caught without
  listing hundreds), system-wide user units, masked units; RHEL's
  `/etc/bashrc` and the zsh startup files (`zshenv` runs for every zsh, scripts
  included) and `~/.bash_login`/`.bash_logout`/`.zshenv`/`.zlogin`; and the
  homes of service accounts with an interactive shell (where a backdoor in
  `www-data`'s `~/.bashrc` would sit). Each persistence record names its
  `program`, and a flagged one's program (and every preloaded library) is
  hashed.
- **CI failures can be read from the pull request.** Test and lint steps pipe
  their output through `.github/scripts/ci-annotate.py`. It turns each failing
  Go test, rustc or clippy diagnostic, or PowerShell error into an annotation
  with its file and line, so a failure on the Windows runner no longer means
  digging through the raw log. Each Go test step also posts its pass and skip
  counts with every skip's reason: the test that decodes the runner's own
  prefetch files skips on Server SKUs, and that silence is how the prefetch
  bug stayed hidden. Actions moved to their Node 24 releases, and
  setup-go's module cache is off: it never restored for a stdlib-only module,
  and warned on every run.
- Report output is buffered (JSONL was one write per event — slow on USB media
  and network shares).
- Hashing reuses its 1 MiB read buffers.
- Linux host info reads `/usr/lib/os-release` when `/etc/os-release` is absent,
  and single-quoted values.

### Added
- Rule ids `process.binary_replaced`, `modules.replaced_on_disk`,
  `modules.memfd_exec`, `network.interpreter_listener`,
  `memory.replaced_file_exec`; record fields `image_replaced` (processes),
  `memfd_modules`/`replaced_modules` (modules), `direction` (network),
  `program`/`program_sha256`/`library_sha256`/`vendor`/`masked`/`file`
  (autoruns); meta `ipv6`, `processes_with_replaced_libraries`,
  `records_with_findings`, `records_dropped`.
- README: a Linux row set in the detections table, and a note that the bundled
  intel dataset has no anonymizer entries (how to add them).
- **A release workflow** (`.github/workflows/release.yml`). Publishing a GitHub
  release builds the full release set with `make release`, checks it, runs the
  Windows x64 and x86 builds on a Windows runner, and attaches per-platform
  archives with `SHA256SUMS` (the binaries) and `SHA256SUMS.archives`. A tag
  that doesn't match the code's version is refused.

## 0.10.5

Makes the Linux demo's "inert" cron lines inert on every host, not just the
ones without a cron daemon.

### Fixed
- **The demo's cron lines can no longer fire.** `demo/linux-detection-demo.sh`
  wrote its fetch-and-run and reverse-shell lines to `/etc/cron.d` with live
  schedules (every 5 minutes and every minute). The script itself never ran
  them, but on a host with `crond` running, cron could have, if the file was
  still there at the next matching minute — before cleanup, or indefinitely if
  the demo was killed with `kill -9`. Both lines are now scheduled for
  31 February (`0 0 31 2 *`), which never comes, and the file says so in a
  comment. They still target only the RFC 5737 documentation range, and the
  detections are unchanged: lrng rates the command, not the schedule.

## 0.10.4

Makes the Linux service-account rule evidence-based. A service account with an
interactive shell is common and usually benign — Debian's `postgres` user ships
with `/bin/bash` — so flagging every one buried the real lead: an account
someone has actually made *loginable*.

### Changed
- **`accounts.system_account_login_shell` now fires only on evidence of login
  capability**: a service account (UID 100–999) with an interactive shell *and*
  a usable password hash, an empty password, or an SSH key not pinned to a forced
  command. Distro defaults (shell set, password locked, no keys) stay quiet. The
  technique is now `T1098` (account manipulation), or `T1098.004` when an SSH key
  is the evidence, instead of `T1136.001`; confidence rose from 40 to 55.
- SSH keys are read from wherever sshd would look: `AuthorizedKeysFile` from the
  `sshd_config.d` drop-ins and `sshd_config` (first global value wins; `Match`
  blocks ignored; `%h`/`%u`/`%%` expanded; `none` honoured), defaulting to
  `~/.ssh/authorized_keys{,2}`. Keys with `command="…"` (GitLab/Gitea's `git`
  user) are counted but treated as non-interactive; `restrict`/`no-pty` alone
  don't pin the command, so those keys still count.
- Without root, `/etc/shadow` and other users' key files are unreadable: the rule
  then raises nothing and lists the accounts it couldn't verify in
  `meta.service_accounts_unverified`, with a note to re-run as root.

### Added
- Each `localaccounts` user record carries `password_state` (`usable`, `empty`,
  `locked`, `none`) when `/etc/shadow` is readable, and `ssh_keys` /
  `ssh_keys_unrestricted` when the account has keys, so the evidence behind the
  rule is visible. `meta.service_accounts_with_shell` counts the accounts it
  evaluated.

## 0.10.3

A correctness-and-polish pass over the Linux collectors.

### Fixed
- **`process.kthread_masquerade` now actually fires.** It previously only matched
  a comm with literal brackets (`[kworker/…]`), but the kernel stores kernel-thread
  names *without* brackets (ps adds them), so the common masquerade — a userland
  process using the bare name `kworker/0:1` — was missed. Detection now matches a
  curated set of distinctly-kernel comm prefixes (bare or bracketed) on any
  process that has an executable, which real kernel threads never do.
- **`readProcPIDs` returns PIDs in numeric order.** `os.ReadDir` sorts
  lexicographically (`"10"` before `"2"`), so process records and the
  shared-socket owner tie-break were ordered by PID *string*; they are now sorted
  numerically, giving a natural, deterministic record order (and making the
  lowest-PID owner win a shared socket).

### Changed
- The Linux `network` and `udp` collectors build the socket-inode→PID and
  PID→comm maps in a **single `/proc` walk** (`procSocketOwners`) instead of two,
  roughly halving the `/proc` enumeration cost of each.

### Added
- **`demo/linux-detection-demo.sh`**: a safe, self-cleaning demo that stages
  benign stand-ins for six common Linux TTPs (payload in `/tmp`, kernel-thread
  masquerade, cron + systemd persistence, fetch-and-run, reverse shell) and runs
  a triage so the Linux detections can be seen end-to-end. Every payload is
  `sleep`, addresses are the documentation range, and all artifacts are removed on
  exit.

## 0.10.2

Wires Linux into the release. `make release` now produces the Linux x64 and
ARM64 builds alongside the Windows ones — agent and sidecar for each, all fully
static — into `dist/linux-{amd64,arm64}/`, covered by the same `SHA256SUMS`. A
new CI job builds that set with the same recipes and exercises it live, so the
Linux release path is tested on every push rather than first at release time.

### Added
- **`make sidecar-linux` / `sidecar-linux-arm64`**: the sidecar as a fully
  static musl binary (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`),
  so a single build runs on any distro — glibc of any age, or musl (Alpine) — for
  the same reason the Windows sidecar links its C runtime statically. wasmtime
  (under YARA-X) compiles a small C helper on Unix targets, so the builds go
  through **cargo-zigbuild**, which supplies zig as the C compiler and linker for
  both targets from any build host (no musl-tools or aarch64 cross toolchain).
  ARM64 gets a native aarch64 sidecar, since Linux, unlike Windows on ARM, won't
  run the x64 one under emulation.
- **`make release-windows` / `release-linux`**: each half of the release on its
  own (with checksums), so a host without zig can still cut the Windows set and
  vice versa. `make release` builds both.
- **CI `linux-release` job**: builds the Linux release set via the `make`
  recipes (debug profile, for speed), fails if any artifact is dynamically linked
  (it checks the ELF program headers for an interpreter) or built for the wrong
  architecture, then runs the static agent and sidecar together: `-list`,
  `-ping-sidecar`, a prompt scan, a default triage, and a live memory scan that
  must find a YARA marker assembled at runtime in another process's heap (run
  under `sudo`, since Ubuntu's Yama `ptrace_scope=1` otherwise forbids reading
  another process's memory). The triage report is kept as a build artifact, as
  on Windows. The Go cross-compile check also covers `linux/amd64` and
  `linux/arm64`.

### Changed
- The sidecar `make` recipes copy from the cargo profile directory that
  `CARGO_FLAGS` selects (`release` by default, `debug` without `--release`), so
  they work with a debug override; the default release commands are unchanged.
- `.cargo/config.toml` states `+crt-static` for both musl targets explicitly
  (it is the musl default) and documents the zigbuild path.
- README: the Build section documents the Linux release outputs and one-time
  toolchain setup, CI coverage, and that Linux memory scanning needs root or
  `CAP_SYS_PTRACE`. Platform support notes the Linux binaries run on any distro.
  The last Homebrew pointer was dropped from the mingw-w64 instructions.

## 0.10.1

Refreshes the bundled endpoint-intelligence dataset from live sources and adds
the generator mode used to build it. The dataset was a hand-curated seed (~200
prefixes); it is now generated from current public feeds (~25k prefixes) —
per-ASN CIDR allocations for the major cloud/CDN/hosting/DNS providers, the live
Tor exit list, and a small built-in overlay for public resolvers and the Tor
directory authorities.

### Added
- **`intelgen -asn-cidrs <dir>`**: build the dataset from a directory of
  [ipverse/asn-ip](https://github.com/ipverse/asn-ip) aggregated files (each
  `# AS<n> (NAME)` header plus CIDRs), tagging every prefix by the ASN→category
  map and the AS's organisation. This path needs only `raw.githubusercontent.com`,
  so it works behind a restrictive egress allowlist where `iptoasn.com` is
  unreachable.
- **Built-in overlay** in `intelgen`: the public DNS resolvers (so `8.8.8.8`
  reads as `dns`, not just its host ASN's category) and the stable Tor directory
  authorities, layered on top of the live feeds via longest-prefix match.

### Changed
- **Bundled dataset regenerated** from `ipverse/asn-ip` + the firehol-mirrored
  TorProject exit list (`internal/intel/data/endpoints.tsv`, ~25k prefixes:
  ~12k cloud, ~6.5k hosting, ~5.6k CDN, ~1.2k Tor, ~320 DNS). Attribution is now
  broad and current rather than a representative sample; `meta.dataset` /
  `run.intel_dataset` record the new source and date.
- README documents both refresh paths — the GitHub-feed path (allowlist-friendly)
  and the iptoasn.com path (adds per-prefix country) — and the `intelgen` tor
  source label is now `tor-exit-list`.

## 0.10.0

Crosses the platform line. Until now the collectors were Windows-only; this
release gives `lrng` a real triage on Linux, behind the same collector
interface, the same `Collector`/`Result` types, and the same JSON envelope — the
"framework stays portable, collectors are platform-specific" split the project
was built around, finally exercised on a second OS. Six collectors read Linux's
own interfaces (`/proc`, `/etc/passwd`, cron, systemd, ld.so.preload) and are
judged by Linux-appropriate heuristics, and AI module A (LLM-callout detection),
being OS-agnostic, now runs on Linux too. The Go tree stays dependency-free, the
schema is unchanged at 1.2 (Linux results carry the same shape with
Linux-appropriate fields), and every text parser is portable and unit-tested on
any OS.

### Added
- **Linux `processes`** (`process_linux.go`): every process from `/proc` — PID,
  PPID and parent name, image path (with `(deleted)` and `memfd:` markers),
  command line, owning user (resolved through `/etc/passwd`), state and start
  time. Findings: `process.unusual_exec_path` (running from `/tmp`, `/dev/shm`,
  a home hidden dir, …), `process.deleted_binary` (self-deleting malware,
  T1070.004), `process.memfd_exec` (fileless execution, T1620),
  `process.kthread_masquerade` (a userland process wearing a `[kworker]`-style
  name), plus the shared Unix command-line analytics.
- **Linux `network`** (`netconn_linux.go`): IPv4/IPv6 TCP connections from
  `/proc/net/tcp{,6}`, each mapped to its owning process through
  `/proc/<pid>/fd`, run through **AI module A** (the LLM-callout detector) and
  the Linux network heuristics: `network.shell_listener` (a bind shell),
  `network.shell_outbound` / `network.interpreter_outbound`,
  `network.unusual_path_outbound`.
- **Linux `udp`** (`udp_linux.go`): UDP endpoints from `/proc/net/udp{,6}` with
  their owning process.
- **Linux `modules`** (`modules_linux.go`): the executable, file-backed mappings
  of each process from `/proc/<pid>/maps` (the image and its shared objects),
  flagging libraries loaded from unusual paths (`modules.unusual_path`,
  shared-object hijacking / LD_PRELOAD) and libraries deleted while still mapped
  (`modules.deleted_file`).
- **Linux `localaccounts`** (`localaccounts_linux.go`): users from
  `/etc/passwd`, privileged-group members from `/etc/group`, and (when
  `/etc/shadow` is readable) passwordless accounts. Findings:
  `accounts.uid0_nonroot` (a second superuser), `accounts.empty_password`,
  `accounts.system_account_login_shell`, `accounts.duplicate_uid`,
  `accounts.root_equiv_group` (docker/lxd membership).
- **Linux persistence** under the `autoruns` collector (`autoruns_linux.go`):
  `/etc/ld.so.preload` (a library-injection rootkit hook,
  `persistence.ld_preload`), cron (system, `/etc/cron.d`, the `cron.*` dirs, and
  per-user crontabs), systemd units and timers (system, runtime and per-user,
  with `ExecStart` graded), `/etc/rc.local`, XDG autostart entries, and shell
  startup files — each entry listed with its source, suspicious commands flagged
  via the shared analytics and `persistence.unusual_path`.
- **Linux heuristics** (`paths_unix.go`, `cmdline_unix.go`): a POSIX path-risk
  grader (tmp / shared-memory / memfd / deleted / home-hidden) and a Unix
  command-line analyzer — reverse shells (`/dev/tcp`, netcat `-e`, socat EXEC,
  interpreter one-liners), fetch-and-run (`curl … | sh`), base64-pipe-to-shell,
  `chmod +x` in a temporary location, and persistence writes (authorized_keys,
  shell profiles, crontab-from-stdin). Pure string logic, unit-tested on any OS.

### Changed
- The `processes`, `network`, `udp`, `modules`, `localaccounts` and `autoruns`
  collectors now report `Platforms()` of `windows, linux` and appear in `-list`
  and the default set on Linux; their off-platform stubs were narrowed to
  `!windows && !linux` so other platforms still compile.
- `-list` on Linux now shows a working default triage set instead of only the
  memory collector.
- Windows-specific collectors (amcache, authenticode, comhijack, prefetch,
  shimcache, wmi, eventlog, dnscache, services, scheduledtasks) remain
  Windows-only; on Linux their concepts are covered where they map — scheduled
  tasks and services as cron and systemd under `autoruns`.

## 0.9.0

Puts a name to the addresses. The collectors tell you a host talked to
185.220.101.47; this release tells you *what that is* — the AS and organisation
that owns it, the country it's allocated in, and whether it's a cloud platform, a
CDN, a hosting/VPS provider, a public DNS resolver, Tor, or an anonymising
VPN/proxy. The lookup is wholly offline: a bundled, compiled dataset and an
in-memory longest-prefix match, no WHOIS, no geo-API, no DNS — exactly what a
contained or air-gapped box needs, and what won't tip off an attacker watching
the wire. The attribution rides along onto the IOC set too, so an exported
blocklist carries its "who / where / what". The Go tree stays dependency-free and
the schema is unchanged at 1.2: the `intel` result is new records and metadata
inside the existing envelope, carrying findings only for the two anonymised-
transport categories, exactly as the other post-passes extend the report.

### Added
- **Offline endpoint intelligence (`-intel`).** A new post-pass
  (`internal/collector/intel.go`, `AnnotateIntel`) attributes every public remote
  address the run observed against a bundled dataset and emits a synthetic
  `intel` collector result. Each record carries the address, the matched
  `prefix`, and — when the dataset knows it — the `asn`, `org`, `country` and
  infrastructure `categories`; a miss is reported as `attributed: false` rather
  than guessed. Scope is every public remote address across the real collector
  records (the socket's local side and private/reserved space are excluded, via
  the same `aidetect.PublicAddr` test the network, sessions and logon rules use),
  deduplicated across the run, each pointing back to the records it appeared in
  and carrying the highest severity and the rules of any findings on those
  records (`co_max_severity` / `co_rules`), so an address that is both externally
  flagged and, say, a Tor node sorts to the top. Like the timeline and IOC
  passes it is portable (no build tag), runs after correlation and skips the
  derived views so nothing feeds back on itself.
- **Two intel findings.** A contact with Tor infrastructure raises
  `intel.tor_endpoint` (T1090.003, *suspect*) and a contact with a known
  anonymising VPN/proxy raises `intel.anonymizer_endpoint` (T1090.002,
  *notable*) — both classic anonymised-C2 and exfiltration channels. Cloud, CDN,
  hosting and DNS are reported as context on the record only, never a finding:
  far too common to flag.
- **IOC attribution.** When `-iocs` is also set, each IP indicator in the `iocs`
  result is enriched in place with `intel_asn` / `intel_org` / `intel_country` /
  `intel_categories`, so the copy-and-go blocklist ships with the attribution
  attached.
- **The intel engine (`internal/intel`).** A dependency-free, offline
  IP→intel lookup: a per-prefix-length longest-prefix-match table (IPv4 and IPv6,
  memory-proportional to the number of prefixes, not address bits) over a dataset
  bundled with `go:embed`. `Builtin()` returns the embedded dataset; `Load()`
  reads an external one. Every result records the dataset's provenance — source,
  generation date and entry count — in the `intel` result's `meta.dataset` and in
  the report's `run.intel_dataset`, so a stale lookup is visible as such.
- **`-intel-db <file>`** overrides the embedded dataset with one produced by the
  new generator; naming it implies `-intel`.
- **Dataset generator (`cmd/intelgen`).** A dependency-free tool that compiles
  the dataset from authoritative public sources — the iptoasn.com combined table
  (IP→ASN/country/org) and a Tor node list — tagging the major cloud / CDN /
  hosting / DNS ASNs by a built-in, overridable map. `make intel-data`
  regenerates the bundled dataset; the fetch step is the only part that needs a
  network, and it happens off the triaged host.
- **Bundled seed dataset** (`internal/intel/data/endpoints.tsv`): a hand-curated
  set of the major, stable cloud/CDN/hosting/DNS allocations plus Tor directory
  infrastructure — useful out of the box, and clearly marked as a seed to refresh
  with `intelgen`.

### Changed
- The report's `run` section gains `intel` (bool) and `intel_dataset` (the
  dataset's provenance string) when `-intel` is used; both are omitted otherwise.
  The schema version is unchanged (1.2).

## 0.8.0

Turns a triage report into an action list. A new post-collection pass distils
the indicators out of every detection-linked record — the addresses, domains,
file hashes and on-disk paths the findings referenced — into one deduplicated,
severity-ranked set, so the analyst's next move (block these at the firewall,
sweep these hashes across the fleet, search these domains in DNS logs) is a
copy-and-go list rather than a scrape through nested records. The Go tree is
still dependency-free and the schema is unchanged at 1.2: the `iocs` result is
new records and metadata inside the existing envelope, carrying no findings of
its own, exactly as the super-timeline does.

### Added
- **Indicator extraction (`-iocs`).** A new portable post-pass
  (`internal/collector/iocs.go`, `ExtractIOCs`) walks every record that carries
  a finding and pulls out the indicators of compromise it holds — IPv4/IPv6
  addresses, DNS hostnames, SHA-256 and SHA-1 hashes, and Windows file paths —
  then deduplicates them across the whole run and emits them as a synthetic
  `iocs` collector result. Each indicator records its `type` and `value`, the
  `max_severity` of the detections that referenced it, the distinct `rules` that
  did, a `source_count`, and `sources` back-pointers into
  `results[result].records[record]` (with the field each value came from), so an
  analyst can see why an indicator is on the list before acting on it, and the
  set sorts most-severe-first for a clean blocklist. Scope is deliberately tight
  — only records with a finding contribute, so the output is the set tied to
  something the tool actually flagged, not a full host inventory. Extraction is
  precise rather than a blind text scrape: addresses are kept only when
  **public** (via the same `aidetect.PublicAddr` test the network detector and
  the sessions and logon rules use) and never from the socket's local side, so a
  host never lists itself or RFC1918 space; hostnames are read only from
  fields that hold one (the DNS cache's `name`, a connection's correlated
  `remote_hosts`), so a process merely *named* like a domain isn't swept up;
  hashes are matched by exact hex shape; and file paths are taken only from
  path-bearing fields whose value has a drive-letter or UNC shape, so a registry
  key or a task path is never mistaken for a file. It descends into the nested
  `event_data`/`user_data` maps, so an `IpAddress` behind a failed-logon event is
  captured under its leaf field. It runs after correlation (so a cross-collector
  finding's indicators are included) and skips the `timeline` and its own `iocs`
  results so no derived view feeds back in; it works for live and `-evtx` runs
  alike and is bounded (50,000 indicators, lowest-severity dropped past the cap,
  with per-indicator source and rule caps). `meta.by_type` counts the set by
  indicator type. Portable and unit-tested on any OS (extraction, cross-record
  deduplication and severity escalation, public-only/local-excluded address
  scoping, hostname field-scoping, hash and path shape-matching, nested
  event-data descent, deterministic ranking). `-iocs` adds the pass, live or
  offline; the `iocs` result carries no findings of its own, so finding counts
  are unchanged.

## 0.7.0

Brings the Windows event log into the triage. A dependency-free EVTX reader
parses the DFIR channels live, or offline with `-evtx` on any OS. Built-in
detections and logon analysis run over the events, and a Sigma engine runs the
analyst's own rules beside them, with a 20-rule pack bundled in the binary. A
correlation pass lines the log up against the live host state (services and
tasks that were installed and then removed, and the gap a log clear left), and
a super-timeline puts every timestamped artifact in one sequence. Authenticode
verification now also names the signer. The Go-side detections now number
about 90 (over 110 rule ids counting the AI modules and memory heuristics), and
the Go tree is still dependency-free. The schema is unchanged at 1.2: these
additions are new collectors, records, findings and metadata within the
existing envelope.

### Added
- **Windows event-log triage (`eventlog` collector).** Parses the DFIR-relevant
  channels directly from `winevt\Logs` through a new dependency-free, read-only
  EVTX + binary-XML parser (`evtx.go`) — file header, 64 KiB chunks, record
  framing, the BinXML token stream, resident and referenced templates with their
  substitution arrays, and the full value-type set (strings, ints, FILETIME,
  SYSTEMTIME, GUID, SID, hex, embedded BinXML). Every offset and size in a record
  is attacker-controlled, so the reader is bounds-checked and a malformed record
  yields a warning and is skipped, never a panic. Rather than dump whole logs (a
  Security log holds millions of records), it targets the channels and events
  that matter, records the security-relevant ones in full, and keeps high-volume
  command-bearing events (process creation, PowerShell script blocks) only when a
  rule fires. Command lines inside events run through the **same** analytics as
  processes, services, autoruns and task actions, so one encoded-PowerShell or
  download-cradle rule covers a running process and a logged one alike. New
  findings: `defense.clear_event_logs` (Security 1102 / System 104, T1070.001),
  `eventlog.service_installed` (7045, T1543.003, with unusual-path grading and
  command analytics over the ImagePath), `persistence.account_created` (4720,
  T1136.001), `persistence.admin_group_add` (4728/4732/4756 to a privileged
  group, matched by RID, T1098), `eventlog.powershell_suspicious_block` (4104,
  T1059.001) plus whatever the shared analytics raise on the script-block text,
  process-creation command analysis (4688 with command-line auditing), and
  `eventlog.defender_detection` (Defender 1116/1117). Targeted channels: Security,
  System, Application, Windows PowerShell + PowerShell/Operational,
  TaskScheduler/Operational, WMI-Activity/Operational, Windows
  Defender/Operational, both TerminalServices/Operational logs and
  Sysmon/Operational. The parser and the classifier are portable and
  unit-tested on any OS (a spec-faithful BinXML encoder round-trips the reader,
  as the Xpress/SCCA decoders are tested; hostile offsets are fuzzed for no-OOB);
  `testdata/*.evtx` is parsed as a ground-truth check when present (Windows CI, or
  a copy of the host's own logs), and skipped otherwise.
- **Offline event-log triage (`-evtx`).** `lrng -evtx <file|dir>` (comma-separated
  files and/or directories) parses supplied `.evtx` logs — an exported log, a
  Volume Shadow Copy, or a file pulled from a disk image — and writes the same
  report envelope as a live run, so `-out`, `-format jsonl`, `-fail-on`, `-pretty`
  and the `.sha256` sidecar all apply. It runs on **any OS** (only reading a
  host's live logs needs Windows) through the same portable parser and
  classifier, so an analyst can triage a collected log on a non-Windows
  workstation. The live Windows collector and offline mode share one reader
  (`collectEventLogSources`); a directory expands to its `*.evtx`, and a named
  file that doesn't exist is reported as an error (versus the live sweep, where a
  channel a host simply lacks is silently counted).
- **Event-log ↔ live-state correlation (`correlate.go`).** A post-collection
  pass cross-references the event log against the host state gathered in the
  same run — where the separate collectors line up into one story. A 7045
  "service installed" event is checked against the services present now: one
  still there is annotated (`service_still_present`), one that is gone is raised
  as `correlate.service_installed_absent` (T1070.009 — the clean-up half of
  install-run-delete, *suspect* when the install's ImagePath was already risky,
  *notable* otherwise). A scheduled-task-registered event (4698 / 106) is checked
  against the live Task Scheduler store the same way: still present is annotated
  (`task_still_present`), gone is `correlate.task_registered_absent` (T1070.009 —
  registered then deleted or hidden, the reverse of the Tarrask check the
  scheduledtasks collector already does). A 1102/104 log clear is measured against the records that
  survived it: the surviving channel's record-id span, count and time range are
  added to the record and folded into the `defense.clear_event_logs` finding, so
  the evidence gap the clear left is quantified. It is a no-op for any cross-check
  whose inputs weren't collected, so a run without the `services` collector (or
  offline mode) never invents an "absent" finding from missing data. `main`
  runs it after collection and before summarising, for both live and `-evtx`
  runs. Portable and unit-tested.
- **Sigma rule support (`-sigma`).** `lrng -sigma <file|dir>` compiles Sigma
  detection rules and evaluates them against every parsed event, alongside the
  built-in detections and in both live and offline (`-evtx`) runs; a Sigma match
  is a `sigma.<rule>` finding carrying the rule's level (→ severity) and first
  `attack.t*` tag (→ technique), and it keeps an otherwise-dropped high-volume
  event. Rules are read with a new **dependency-free YAML-subset parser**
  (`yamllite.go`), keeping the zero-dependency Go tree. The engine
  (`sigma.go`) supports string matching with `*`/`?` wildcards, the `|contains`,
  `|startswith`, `|endswith`, `|all`, `|re`, `|cased` and `|windash` (dash-variant
  command-line flags) modifiers, `|base64offset` (match a value as base64 at any
  byte alignment), numeric `|lt/|lte/|gt/|gte`, `|exists` and null matches, list
  values (OR, or AND with `|all`), a selection that is a list of maps, keyword
  lists, the condition language (`and`/`or`/`not`, parentheses, and `N/all/1
  of them` or `… of <pattern>*`), and `count()` aggregation (`<expr> |
  count([field]) [by <field>] <op> <n>`, counted across the whole run and
  emitted as a synthetic record per over-threshold group — brute force / spray
  detection). A rule using a construct the engine does not implement faithfully
  (the plain `|base64` and `|utf16`/`|wide` encodings, a `| near` with no
  `timeframe`, or a condition naming an unknown selection) is **skipped with a
  reason**, never mis-evaluated. Counts are printed to stderr, and `meta.sigma`
  lists each skipped rule with its reason (`skipped`) and each file that failed
  to parse (`failed`), bounded at 200 entries each. `logsource` narrows a rule to a
  channel/event when its service or category is one we map, otherwise the rule
  is tried against every event. Ships with the `builtin` starter pack (now
  including a failed-logon-burst aggregation rule).
- **Unified super-timeline (`-timeline`).** `lrng -timeline` adds a synthetic
  `timeline` result (`timeline.go`) that merges every timestamped artifact the
  other collectors gathered — prefetch run times, service/autorun/registry
  key-last-write times, scheduled-task cache writes, account last-logon/
  password-set times, shimcache/amcache times, event `TimeCreated` — into one
  oldest-first view. Each entry names its source collector, the artifact
  timestamp it came from, an identifying detail, a pointer back to the source
  record, and (when the source record carries a finding) the top rule and
  severity, so detections are anchored in time. Entries carry no findings of
  their own, so finding counts are not inflated. It is a post-pass run after
  correlation for both live and `-evtx` runs, bounded (most-recent kept past the
  cap, truncation noted), portable and unit-tested.
- **Logon-session analysis (4624 / 4625).** The event-log triage now surfaces
  remote logons: a remote-interactive (RDP, logon type 10) 4624 is kept and
  raised as `logon.remote_interactive` (T1021.001) — *suspect* from a public
  source address (RDP exposed to the internet, or an attacker arriving over
  one), *notable* otherwise; a type-3 network logon from an external address by
  a non-machine account is `logon.network_external` (T1021); and a 4625 failed
  logon from an external address is `logon.failed_external` (T1110, a single
  data point for brute force / password spray). "External" uses the same
  public-address test as module A and the sessions collector
  (`aidetect.PublicAddr`), so it means one thing across the tool. High-volume
  local logons are not kept.
- **Bundled starter Sigma pack (`-sigma builtin`).** A small, curated set of
  Sigma rules is embedded in the binary (`go:embed`) and mapped to the channels
  lrng collects, so Sigma is useful out of the box with nothing on disk:
  encoded PowerShell, certutil download/decode, mshta remote script, PsExec and
  smbexec-style service installs, a service binary in a suspicious path, event
  log cleared via wevtutil, shadow-copy deletion, Defender disabled via
  PowerShell, LSASS-dump command lines, credential-tool script keywords, local
  admin added via net, and a hidden `$` account creation — each ATT&CK-tagged,
  using only the supported Sigma subset (a test asserts the pack compiles with
  zero skipped). `-sigma` now takes a comma-separated spec where each entry is
  `builtin` or a file/dir path (`-sigma builtin`, `-sigma ./rules`, or `-sigma
  builtin,./rules` to merge the pack with your own).
- **Sigma engine: CIDR / fieldref modifiers, more aggregations, temporal near.**
  Completes the Sigma roadmap. The engine now also evaluates `|cidr` (match an
  IP-address field inside a CIDR network, IPv4 or IPv6, through the
  standard-library `net/netip` — no new dependency) and `|fieldref` (compare a
  field to another field's value, on its own or combined with
  `|contains`/`|startswith`/`|endswith` and `|cased`); the scalar aggregations
  `min`/`max`/`avg`/`sum(<field>) [by <field>]` beside the existing `count()`
  (evaluated across the whole run, a synthetic record per over-threshold group;
  windowed by a `timeframe` as of the next entry);
  and the temporal `<expr> | near <expr>`, which fires when the referenced
  selections co-occur within the detection's `timeframe` (`s`/`m`/`h`/`d`),
  evaluated by a sliding window over the per-selection match timestamps. The
  near timestamps are bounded per selection so a broad selection on a large log
  can't grow without limit (the record is flagged `truncated` past the cap). A
  `| near` with no `timeframe` is still skipped — it has no defined window — as
  are the plain `|base64` and `|utf16`/`|wide` encodings.
- **Two new bundled Sigma rules.** `-sigma builtin` gains **External RDP Logon**
  (a logon-type-10 4624 whose source address is outside the RFC1918 / loopback /
  link-local ranges, via `|cidr`) and **Event Log Cleared Near A Service
  Install** (a 1102/104 log clear within five minutes of a 7045 service install,
  via `| near` — install-then-wipe anti-forensics). Both use only the supported
  subset, so the pack's zero-skipped compile test still holds.
- **Sigma aggregations windowed by `timeframe`.** A `count`, `count(field)` or
  `sum` aggregation with `>`/`>=` and a detection `timeframe:` is now evaluated
  as a sliding window of that width — it fires if any window crosses the
  threshold — rather than summing across the whole run. So a "> 10 failed logons
  by source" rule means ten within the window (a brute-force burst), not ten
  scattered over the whole log. The sweep is a two-pointer pass over each
  group's timestamped matches (`count`, distinct `count(field)` and non-negative
  `sum` are non-decreasing as a window grows, so the maximal window ending at
  each match is exact for `>`/`>=`); per-group observations are bounded like the
  `near` timestamps, flagged `truncated` past the cap. A `timeframe` on
  `min`/`max`/`avg`, or with an operator other than `>`/`>=`, has no sound
  sliding-window meaning and is **skipped with a reason** rather than silently
  summed across the run. Windowed records carry `timeframe`, `window_start` and
  `window_end`. This completes the Sigma roadmap's windowing item.
- **Three more bundled Sigma rules (20 in the pack).** `-sigma builtin` gains a
  windowed **Password Spray From Single Source** (one source failing against
  more than ten distinct accounts within five minutes, via `count(TargetUserName)
  by IpAddress`) and **Microsoft Defender Real-Time Protection Change** (Defender
  Operational event 5001, which otherwise went unflagged — the first builtin on
  that channel); and the existing **Failed Logon Burst From Single Source** gains
  a five-minute `timeframe`, so it now flags a burst rather than any source with
  ten failures over the life of the log. The pack's zero-skipped compile test
  still holds.
- **Authenticode signer name.** The `processes` collector's signature check now
  records who signed each image (`signer`): the display name of the primary
  signer's certificate, read from WinVerifyTrust's own verification state
  between its verify and close calls, so it costs no extra file access. For a
  catalog-signed Windows binary it is the catalog's signer ("Microsoft
  Windows"). An untrusted signature still names who it claims to be from, and
  `integrity.unsigned_system_binary` now quotes that name, since a Microsoft
  name on a signature that doesn't validate is itself the tell. The name is
  attacker-chosen text (anyone can sign a file with a certificate they made),
  so it is length-capped and every non-printable character, such as a control
  character or a bidi override that could make a name read as something it
  isn't, is written as a visible `\uXXXX` escape. The sanitizer and finding text
  are unit-tested on any OS. The Windows CI runner checks the real API path
  against kernel32.dll's catalog signer, and an opt-in test checks an embedded
  signature against a self-signed sample (`LRNG_SIGNED_SAMPLE`); it also runs
  under Wine.

## 0.6.0

Extends v0.5's AI-aware triage with four new persistence- and execution-focused
collectors plus signed-binary verification, all through dependency-free readers
that keep the zero-dependency Go tree. WMI permanent event subscriptions and COM
CLSID hijacking cover two of the most common fileless persistence techniques;
AmCache and decoded prefetch bodies add execution evidence that outlives the
binary on disk; and Authenticode verification flags system-binary lookalikes.
New rule families for WMI, COM, AmCache, prefetch and signature integrity bring
the Go-side detections to about 75 (over 90 rule ids counting the AI modules).
The schema is unchanged at 1.2 — these additions are new collectors, records
and findings within the existing envelope.

### Added
- **WMI event-subscription persistence (`wmi` collector).** Enumerates the
  permanent-subscription objects in `root\subscription` (and the legacy
  `root\default`) — `__EventFilter`, `__EventConsumer` and
  `__FilterToConsumerBinding` — live from the CIM repository over COM, through a
  hand-rolled client built directly on `ole32`/`oleaut32` with raw vtable
  dispatch, so lrng shells nothing out to `wmic` or PowerShell and keeps its
  zero-dependency Go tree. It raises the fileless script consumer
  (`persistence.wmi_script_consumer`, T1546.003), command-line consumers and a
  payload in an unusual path (`persistence.wmi_commandline_consumer`,
  `persistence.wmi_consumer_unusual_path`), the filters themselves
  (`persistence.wmi_filter`), and — highest-signal — a binding that makes a
  subscription live (`persistence.wmi_subscription_active`, *critical* when it
  binds a script consumer); a consumer's script or command also runs through the
  shared command-line analytics. The stock `SCM Event Log Consumer` is treated
  as benign, and a clean host carries none of these, so each object found is
  surfaced. The judging is portable and unit-tested; the COM path type-checks on
  every Windows arch and is exercised on the Windows CI runner (including a
  non-invasive `Win32_OperatingSystem` query that drives the whole
  ConnectServer → ExecQuery → VARIANT-decode path), and the `VARIANT` struct
  size is asserted against the real 16-byte (x86) / 24-byte (x64/arm64) layout.
- **COM-hijacking detection (`comhijack` collector).** Walks the COM class
  registrations (CLSID servers) in the machine class store
  (`HKLM\SOFTWARE\Classes\CLSID`, native and the `Wow6432Node` 32-bit view) and
  in each loaded user's own store (`HKU\<sid>_Classes`), reading each object's
  `InprocServer32`/`LocalServer32` server, its `ThreadingModel` and any
  `TreatAs` redirect. It raises the COM-hijack patterns (T1546.015): a per-user
  registration that shadows a machine one — a user's class store is consulted
  before HKLM, so it wins — (`persistence.com_hijack_user_shadow`, *critical*
  when that server is also in a temp or user-writable path), a server in a
  user-writable/temporary path (`persistence.com_server_unusual_path`), a
  scriptlet (`scrobj.dll`) or script-host/LOLBin server
  (`persistence.com_script_server`), and `TreatAs` remaps
  (`persistence.com_treatas_redirect`); `LocalServer32` commands also go through
  the shared command-line analytics. Detection is behavioural rather than a
  CLSID denylist. Only registrations that trip a heuristic are recorded (a host
  has tens of thousands of legitimate CLSIDs); the totals scanned are in the
  result's metadata. The judging is portable and unit-tested, and the walk
  reuses the read-only `internal/winreg` reader.
- **Authenticode signature verification of process images.** The `processes`
  collector now records each image's `signature_state` (`trusted`, `untrusted`
  or `unsigned`), verified with WinVerifyTrust against both embedded signatures
  and security catalogs (which is how most Windows binaries are signed).
  Verification is offline — revocation checking is off and URL retrieval is
  cache-only, so it adds no network footprint — and each distinct image is
  verified once per run. A process image in `System32`/`SysWOW64` that is
  unsigned (`notable`) or carries an untrusted signature (`suspect`) is raised
  as `integrity.unsigned_system_binary` (T1036.005): genuine system binaries
  there are signed, so a lookalike dropped into a trusted-looking path stands
  out. `-no-sign` turns it off. The trust decision, catalog fallback and
  struct layouts live in `authenticode_windows.go`; the result/field/finding
  logic is portable and unit-tested, and the real WinVerifyTrust path is
  exercised on the Windows CI runner. (The human-readable signer name is a
  planned follow-up.)
- **AmCache collector.** A new `amcache` collector reads `Amcache.hve` — the
  Microsoft Compatibility Appraiser's inventory of files that were present on
  the host, with a SHA-1, PE link date, publisher and the file's own path per
  entry, which survives the binary's deletion. It parses both the current
  `InventoryApplicationFile` layout (Windows 10 1709+ / Server 2019+) and the
  legacy `Root\File\{volume}\{fileref}` layout (through Server 2016), and raises
  `execution.amcache_unusual_path` (T1204.002) for a program recorded in a
  temporary, download or world-writable path. The hive is read live with the
  broad share mode the system holds it under and degrades cleanly to a reported
  error when it's locked (point it at a VSS or image copy then). Backed by a new
  dependency-free, read-only offline registry-hive (regf) parser in
  `internal/winreg/hive.go`, bounds-checked against hostile input and reusable
  for any other offline hive.
- **Prefetch bodies are decoded, not just listed.** The `prefetch` collector
  now decompresses each `.pf` (Xpress Huffman, the "MAM" container Windows 8+
  wraps the body in) and parses the SCCA structure: format version, run count,
  the recent run times (one on Windows 7, up to eight on Windows 8.1 and
  later), the referenced files, and the volumes (device path, serial number,
  creation time). A program that actually ran from a temporary, download or
  world-writable path is raised as `execution.prefetch_unusual_path`
  (T1204.002) — the execution-proof counterpart to the ShimCache existence
  signal, which only says a binary was present. The Xpress Huffman
  decompressor is dependency-free and bounds-checked against hostile input; it
  is validated by a spec-faithful encoder round trip on any OS and, on the
  Windows CI runner, against ntdll's own `RtlCompressBuffer` and whatever live
  `C:\Windows\Prefetch` files the host has. New tag-free
  `internal/collector/xpress.go` and `scca.go`.

## 0.5.0

Turns the v0.4 collection breadth into triage: about 70 named, ATT&CK-mapped
detections across the collectors (over 90 rule ids counting the AI modules
and memory heuristics), a review pass that fixes false positives and blind
spots in the existing heuristics, CI on real Windows, and a report that leads
with what matters. Report schema is now `1.2` (additive).

### Fixed
- **Winlogon hijacks raised no finding.** A Shell/Userinit value listing extra
  programs only set `unexpected_value`; the README promised a finding. It now
  raises `persistence.winlogon_hijack`, and the comparison is by file name and
  directory (a look-alike such as `notexplorer.exe` no longer passes).
- **Microsoft Entra ID (Azure AD) users were skipped.** Only `S-1-5-21-…`
  hives were read; `S-1-12-1-…` accounts — every user on an Entra-joined
  laptop — had their Run keys ignored.
- **Environment variables hid unusual paths.** `%TEMP%\x.exe`, `%PUBLIC%\…`
  and `%ProgramData%\…` never matched the path heuristic (it looked for
  `\temp\`). References are now resolved before judging.
- **Per-user values were expanded with the analyst's environment.** A
  `%APPDATA%` Run value under another user's hive was reported under the
  account running lrng (or SYSTEM's profile). Per-user variables now expand
  under that user's profile; anything unknown is left as written, and the raw
  value is kept (`command_raw`, `image_path_raw`).
- **False positives on every Windows host.** Microsoft Defender runs and loads
  its engine from `ProgramData`, so the WinDefend and MDCoreSvc services, the
  Defender scheduled tasks and every process with Defender's AMSI DLL loaded
  were flagged. Defender's home is now trusted; `ProgramData` and drive roots
  are graded *low* risk (notable), temp/download/world-writable paths *high*.
- **Arguments drove false positives.** `"C:\Program Files\App\svc.exe" --log
  C:\Windows\Temp\app.log` was flagged because the *whole* command line was
  searched. Only the program is judged now — plus the arguments of proxy
  hosts (`rundll32`, `regsvr32`, `mshta`, script hosts…), where a path in the
  arguments *is* the payload.
- **Every all-users Startup item was marked `suspicious_path`** (the folder
  itself lives under ProgramData). Startup entries are now judged by what
  they launch.
- **Unquoted paths with spaces were cut at the first space**
  (`C:\Program Files\x\svc.exe` became `C:\Program`), losing the image and
  any check on it. They're now resolved to the executable.
- **AWS Bedrock endpoints could never match**: the suffix
  `.bedrock-runtime.amazonaws.com` doesn't exist (endpoints are
  `bedrock-runtime.<region>.amazonaws.com`). Hostname matching now supports
  prefix + suffix patterns.
- **Module B missed prompt artifacts straddling 16 MiB chunk boundaries** in
  memory: the overlap was only fed to YARA. The prompt scan now covers it too,
  without double counting.
- **lrng flagged itself** (process path, loaded modules) when run from a
  Downloads or temp folder. lrng and its sidecar are never judged.
- Registry "not found" was detected by comparing localized error text; it now
  uses `errors.Is`. A `REG_MULTI_SZ` without its final terminator lost its
  last string. A registry value that grew between size probe and read failed
  instead of being retried. Toolhelp module snapshots now retry on
  `ERROR_BAD_LENGTH`, as documented.
- After Ctrl+C, collectors that hadn't started were still started against a
  dead context (each waiting out its grace period); they're now recorded as
  not run.
- A missing Prefetch directory (prefetch disabled, the Server default) was an
  error; it's now reported as such in `meta`.
- `-list` misaligned long collector names and told users `-yara` enables
  `dnscache`. NetApi errors showed bare numbers.
- The sidecar's version (0.3.0) had drifted from the agent's.

### Added
- **Command-line analytics** applied to processes, services, autoruns and task
  actions: encoded PowerShell (every `-EncodedCommand` prefix and the Unicode
  dashes PowerShell accepts, with the payload decoded into the finding, or
  reported as undecodable),
  download cradles and download-and-execute, reflective assembly loading,
  mshta/rundll32/regsvr32 script proxies, certutil decoding and other LOLBin
  proxies, LSASS dumping (comsvcs MiniDump, procdump), SAM/NTDS theft,
  shadow-copy/backup/recovery destruction, event-log clearing, Defender and
  firewall tampering, account creation and privileged-group changes, WMI
  process creation, task/service creation.
- **Process-tree analysis**: system binaries running from the wrong directory
  (`process.masquerade_path`), impossible parents (`lsass.exe` not started by
  `wininit.exe`, …), shells spawned by document readers, web/database servers,
  WMI or the service manager, one-character typosquats (`scvhost`, `Isass`).
  Processes now report session, integrity level and image SHA-256.
- **More autostart locations**: AppCertDLLs, SilentProcessExit monitors,
  WOW64 IFEO and RunOnce, Winlogon Taskman/AppSetup and per-user Shell,
  legacy `Windows\Load`/`Run`, BootExecute, LSA authentication packages,
  security providers and password filters, Command Processor AutoRun, print
  monitors, netsh helpers and screensavers — each compared to its Windows
  default where one exists. Run entries carry Task Manager's enable/disable
  state; every entry carries its key's last-write time.
- **Startup-folder shortcuts are resolved** (LinkInfo, environment block or
  shell ID list) to the target and arguments they launch; programs dropped
  into a Startup folder directly are flagged.
- **Scheduled tasks cross-checked against `TaskCache\Tree`**: tasks hidden by
  deleting their security descriptor (the HAFNIUM "Tarrask" technique),
  registered tasks whose file is gone, and task files never registered. Task
  file timestamps.
- **Services**: unquoted service paths (T1574.009), service binaries in the
  Windows directory (PsExec/Impacket), script hosts as service binaries
  (smbexec), recovery `FailureCommand`s, `ServiceDll` on the service key
  itself, per-user service instance types, key last-write times.
- **Network heuristics**: script hosts and LOLBins listening (bind shells) or
  talking to public addresses, and programs running from temp paths with
  internet connections. With `dnscache` selected, connections carry their
  cached hostnames and module A matches regional endpoints by name.
- **DNS cache**: addresses for each cached name via cache-only lookups (no
  network traffic); LLM endpoints in the cache are flagged; the snapshot is
  taken once, before module A resolves anything, and says so.
- **Accounts and sessions**: NetUserEnum level 3 (password last set, last
  logon, logon counts, RID, expiry), accounts hidden from the sign-in screen
  or with a `$` suffix, enabled Guest, `PASSWD_NOTREQD`; members of Remote
  Management Users and Backup Operators, with SIDs; RDP client addresses,
  logon/connect/idle times, sessions from public addresses, RDP enabled/port.
- **Module A**: ~30 providers (adds Hugging Face, Vertex AI, Azure AI
  Foundry, GitHub Models, Qwen/DashScope, NVIDIA, Moonshot, Cerebras, …);
  `PublicAddr` also excludes 0/8 and reserved ranges; more allowlisted
  browsers/editors.
- **Module B**: Hugging Face, Groq, xAI, OpenRouter and hex `sk-` keys;
  Qwen and gpt-oss model names; the endpoint list matches module A's.
- **Memory heuristics** (no rules needed): PE images in private executable
  memory, including erased-MZ headers (`memory.pe_in_private`); on Linux,
  anonymous ELF, memfd and deleted-file executable mappings; counts of
  unbacked executable/RWX regions. Mapped-file paths are reported with drive
  letters instead of `\Device\HarddiskVolumeN`.
- **SHA-256 of reported binaries** (process images, third-party or flagged
  service/autostart/task binaries), each file read once, capped at 128 MiB;
  a missing target is reported as `image_exists: false`. `-no-hash` turns it
  off.
- **Report**: `run_id`, `host_info` (OS build, edition, install/boot time, time
  zone, domain, FQDN), `summary.by_rule`, `summary.collectors_with_errors`,
  `summary.top_findings`; a human summary on stderr (`-quiet` to silence);
  `-format jsonl` for SIEM pipelines; `-fail-on <severity>` (exit status 3).
- `-collectors default,<name>` adds opt-in collectors to the default set;
  names are case-insensitive. Flags are validated (stray arguments, zero
  workers, bad formats) instead of being silently misread.
- `internal/winreg`: the read-only registry reader as its own package, with
  key last-write times, shared by the collectors and host info.
- CI on GitHub Actions: Linux checks (gofmt, vet for every Windows arch, race
  tests, clippy with and without YARA, rustfmt, Windows type-check, tests),
  the full Go suite and a collector sweep on a real Windows runner, and a
  Windows integration job that finds a YARA marker in a live process.
  `make test-race`, `make wine-test`.

### Changed
- Report schema `1.2` (additive): new top-level and summary fields as above;
  `dnscache` records are one per name (`types`, `addresses`) rather than one
  per name and type.
- Usage errors (a bad flag value, a stray argument) exit with status `2`, as
  unknown flags already did; `1` now always means the run itself failed.
  `-h` leads with common invocations and the exit statuses.

## 0.4.0

Ports the breadth of the PowerShell predecessor's live-response collector into
the Go framework: ten new Windows artifact collectors, so a default run now
covers processes, network, services, autoruns, scheduled tasks, execution
evidence, sessions and accounts, and loaded modules in one report. No envelope
change — the new collectors emit records under the existing schema (`1.1`).

### Added

- **Persistence**
  - **`services`** — every service from `HKLM\SYSTEM\CurrentControlSet\Services`
    (image path, ServiceDll, start type, service type, account), flagging an
    image or DLL in a user-writable/temporary path (T1543.003).
  - **`autoruns`** — per-machine and per-user Run/RunOnce keys, Winlogon
    Shell/Userinit (with a default-deviation flag), AppInit_DLLs, Image File
    Execution Options debuggers, and the Start Menu startup folders, each with
    its ASEP location and an unusual-path flag (T1547/T1546).
  - **`scheduledtasks`** — the Task Scheduler store under
    `%SystemRoot%\System32\Tasks`, parsed from the task XML (UTF-16 handled):
    principal, run level, triggers and each action's command, flagging tasks
    that run from unusual paths and hidden tasks (T1053.005).
- **Execution evidence**
  - **`shimcache`** — the AppCompatCache (ShimCache) value, Windows 10/11
    "10ts" format, with per-entry path and file last-modified time.
  - **`prefetch`** — the prefetch directory listed with per-file timestamps and
    the executable name/path-hash decoded from each `.pf` filename.
- **Sessions & accounts**
  - **`sessions`** — terminal/RDP sessions via the WTS API (id, state, station,
    signed-in user, connecting client).
  - **`localaccounts`** — local users (privilege and the account flags that
    matter: disabled, locked out, password-not-required, password-never-
    expires) and the members of the built-in Administrators and Remote Desktop
    Users groups (group names resolved from well-known SIDs for localized
    Windows).
- **Modules & endpoints**
  - **`modules`** — per-process loaded modules via Toolhelp, one record per
    process, flagging DLLs loaded from user-writable/temporary paths
    (T1574.002).
  - **`udp`** — IPv4 and IPv6 UDP endpoints with their owning process (the
    companion to the TCP `network` collector).
  - **`dnscache`** *(opt-in)* — a snapshot of the DNS resolver cache (names and
    record types) via the undocumented `DnsGetCacheDataTable`. Opt-in because
    module A's own lookups add to this cache; run it by name, ideally before a
    resolving run.
- Framework: a small read-only registry reader built directly on `advapi32`
  (still zero third-party Go dependencies), forcing the 64-bit view. New
  tag-free, unit-tested decoders for the AppCompatCache blob, the UDP tables,
  the task XML (UTF-16/BOM aware) and the prefetch filename.

### Notes

- **AmCache** is not yet collected: it lives in an offline registry hive
  (`Amcache.hve`) that needs a standalone hive parser. ShimCache covers
  live-registry execution evidence in the meantime.
- **Prefetch** is listed, not decoded: run count, the last eight run times and
  referenced files need an Xpress-Huffman decompressor (roadmap).

## 0.3.0

### Added
- **Live process-memory scanning with YARA** (`scan_memory`), using YARA-X
  (pure-Rust YARA) in the sidecar:
  - read-only region walk (`VirtualQueryEx` / `ReadProcessMemory` on Windows,
    `/proc/<pid>/mem` on Linux), 16 MiB chunks with a 4 KiB carry-over;
  - YARA block scanning at virtual addresses (`yara rules.yar <pid>`
    semantics), with region base/size/protection/type/backing file per hit;
  - module-B prompt scan of every chunk (`-mem-no-prompts` to skip);
  - per-process time budget and byte cap, partial results flagged with the
    reason; one result line streamed per PID;
  - rules from a file or directory, a namespace per file, compile failures and
    module imports reported, severity/score/ATT&CK taken from rule metadata;
  - no raw memory bytes in YARA hits; `lsass.exe` skipped unless
    `-mem-include-lsass`; lrng never scans itself or its sidecars.
- Opt-in **`memory` collector** with its own timeout (`-yara`, `-mem-pids`,
  `-mem-budget`, `-mem-timeout`, `-mem-workers`, `-mem-no-prompts`,
  `-mem-include-lsass`) and **`-mem-scan <pid>`** for a quick console scan.
- Framework: opt-in collectors (`OptIn`), per-collector timeouts
  (`TimeoutOverride`), streaming sidecar client (`Client.Stream`), sidecar
  `ping` reports capabilities.
- `make check-windows-rs`: type-checks and lints the Windows memory code from
  a non-Windows host (part of `make check`).
- x86 sidecar builds YARA with wasmtime's Pulley interpreter (`yara-pulley`).

### Fixed
- `model.identifier` matched non-model strings such as a `claude-0` directory
  name; versions must now be real (`claude-3`, `claude-2.1`, `gemini-1.5`).

### Changed
- Sidecar requires Rust 1.93+ and is ~21 MB with YARA-X
  (`--no-default-features` builds a small prompt-scan-only sidecar).

## 0.2.0

Report schema is now `1.1` (see `docs/architecture.md` for the full list of
format changes).

### Fixed
- **Sidecar read whole files into memory before applying the 64 MiB cap.** A
  1 GiB file took 10 s and 1.09 GB of RAM; it now takes 0.3 s and 100 MB.
- **`scan_memory` stub returned `ok: true`,** so a scan that never ran looked
  clean. It now returns `ok: false` with an explicit error.
- **Collector timeouts weren't enforced.** A collector blocked in a system call
  (or module A's DNS lookups on an isolated host) could hang the whole run.
  Collectors now run in their own goroutine, get a grace period to return
  partial results, and are abandoned after that.
- **TIME_WAIT connections (PID 0) were attributed to `[System Process]`.**
  They're now reported as `ai.llm_callout_unattributed`.
- **Network collector failed outright when the TCP table grew** between the
  sizing call and the fetch (busy servers). It now retries with headroom.
- **TCP rows were read through unchecked pointer arithmetic** driven by the
  table's own row count. Parsing is now bounds-checked and unit-tested.
- **A real OpenAI key was hidden whenever an Anthropic key appeared first** in
  the same file (the de-duplication removed the wrong match).
- **False "critical" key hits on ordinary words** (`task-…`, `disk-…`,
  `sk-learn-…`). Key matches now need a word boundary and a random-looking body.
- **Secrets could leak** through a neighbouring rule's context snippet. All
  keys in any snippet are now redacted.
- **Image paths longer than MAX_PATH were lost** (reported as an error).
- **Results came back in random order;** now in requested order.
- **Rust tests raced** on a shared temp file; they now scan in memory.
- `-X main.version` couldn't stamp a `const`; version is now a `var`.
- Report file `Close` errors were ignored (data loss on USB/shares went
  unnoticed); the file is now synced and checked.
- Go contract comment said inline `data` was base64; it's raw UTF-8.

### Added
- **IPv6** TCP connections (module A's biggest blind spot).
- **UTF-16LE** scanning in module B, with an `encoding` field per hit.
- Process **command line, start time, owner, parent name** (with a PID-reuse
  guard).
- Module A: parallel DNS lookups with per-lookup timeouts; `-no-dns`;
  non-public DNS answers (sinkholes) ignored and reported; allowlisted names
  running from temp/user-writable paths flagged
  (`ai.llm_callout_unusual_path`); `-allow` accepts full paths.
- Report `run` section: start/end, PID, elevation, arguments, options, agent
  SHA-256, interrupted flag. Collector metadata moved into `results[].meta`.
- `-out` writes `<path>.sha256` and refuses to overwrite without `-force`.
- Ctrl+C writes a partial report.
- Sidecar is found next to `lrng` by default, resolved to an absolute path,
  never via `PATH`; its output is size-capped.
- `-prompt-scan` prints verdict, score and truncation.
- `-version`.
- Sidecar patterns compiled once into a `RegexSet` (one pass to find candidate
  rules), ASCII-mode matching, hits sorted by offset, score counts each rule
  once. Endpoint list aligned with the Go provider list. Newer model names.
- Makefile: static stamped builds, per-arch `dist/` layout with matching
  sidecars, `SHA256SUMS`, Windows sidecar cross-compile, `check`/`lint`/`audit`.
- `.cargo/config.toml`: static CRT for MSVC sidecar builds.
- Release profile: `codegen-units = 1`, `overflow-checks = true`.
