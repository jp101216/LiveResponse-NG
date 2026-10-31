//! scan_memory: YARA rules and the module-B prompt scan over live process
//! memory.
//!
//! For each target PID:
//!   1. open the process read-only (Windows: QUERY_INFORMATION + VM_READ),
//!   2. walk its committed, readable regions,
//!   3. read each region in 16 MiB chunks (a 4 KiB tail is carried over so a
//!      pattern straddling a chunk boundary still matches),
//!   4. feed every chunk to a YARA-X block scan at its virtual address, and
//!      run the prompt-artifact scanner over it,
//!   5. check the start of each executable region that isn't backed by a
//!      normal file for a loaded-image header (reflective/manual-mapped code,
//!      fileless ELF), and executable mappings of memfd or deleted files,
//!   6. stop early, and say so, if the per-process time or byte budget runs out.
//!
//! This runs in the sidecar because it reads attacker-controlled memory: a
//! malformed region that panicked a parser would take down this process, not
//! the agent. Each PID is also wrapped in catch_unwind, so one bad process
//! doesn't lose the results of the others.
//!
//! Nothing here writes to the target, and YARA hits carry no raw memory bytes
//! (only rule, pattern identifiers and addresses). Prompt-scan contexts are the
//! same sanitised, secret-redacted snippets used for files.

pub mod integrity;
mod pe;
pub mod procmem;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(windows, lrng_typecheck_windows))]
mod windows;

#[cfg(feature = "yara")]
mod yara;
#[cfg(not(feature = "yara"))]
mod yara {
    //! Stand-in when built without the "yara" feature: rules are rejected,
    //! the prompt scan still works.
    use std::time::Duration;
    pub struct LoadedRules {
        pub path: String,
        pub files: usize,
        pub count: usize,
        pub failed: Vec<String>,
        pub module_imports: Vec<String>,
    }
    pub fn load(_: &str) -> Result<LoadedRules, String> {
        Err("this sidecar was built without YARA support (cargo feature \"yara\")".into())
    }
    #[derive(Default)]
    pub struct YaraMatch {
        pub rule: String,
        pub namespace: String,
        pub first_addr: Option<usize>,
        pub total_matches: usize,
        pub patterns: Vec<(String, usize)>,
        pub tags: Vec<String>,
        pub severity: Option<String>,
        pub technique: Option<String>,
        pub score: Option<i64>,
        pub description: Option<String>,
    }
    #[allow(dead_code)] // never constructed without YARA
    pub enum Stop {
        Timeout,
        Error(String),
    }
    pub struct Session;
    impl Session {
        pub fn new(_: &LoadedRules) -> Self {
            Session
        }
        pub fn feed(&mut self, _: usize, _: &[u8], _: Duration) -> Result<(), Stop> {
            Ok(())
        }
        pub fn finish(self) -> Result<Vec<YaraMatch>, String> {
            Ok(Vec::new())
        }
    }
}

use crate::contract::{Hit, HitRegion, Request, Response};
use crate::prompts;
use procmem::{file_name_lower, ProcessMemory, Region};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const OP: &str = "scan_memory";
const CHUNK: usize = 16 * 1024 * 1024;
const OVERLAP: usize = 4096;
const DEFAULT_BUDGET_MS: u64 = 60_000;
const DEFAULT_MAX_BYTES: u64 = 4 << 30;
const MAX_YARA_HITS: usize = 500;
/// Bounds the memory-heuristic hits reported per process.
const MAX_HEURISTIC_HITS: usize = 64;
/// Most image code compared per process by the integrity check.
const INTEGRITY_MAX_BYTES: u64 = 1 << 30;

/// Processes skipped unless the request sets include_sensitive. Reading
/// LSASS trips Defender/EDR credential-theft protections and pulls credential
/// material into this process's buffers; scan it only on purpose.
const SENSITIVE: &[&str] = &["lsass.exe"];

struct Opts {
    prompts: bool,
    budget: Duration,
    max_bytes: u64,
    include_sensitive: bool,
}

/// Handle a scan_memory request, emitting one response per PID as each
/// finishes so partial work survives if the caller stops waiting.
pub fn handle(req: &Request, emit: &mut dyn FnMut(Response)) {
    let pids: Vec<i64> = if req.pids.is_empty() {
        vec![req.pid]
    } else {
        req.pids.clone()
    };
    let opts = Opts {
        prompts: req.prompts.unwrap_or(true),
        budget: Duration::from_millis(req.budget_ms.unwrap_or(DEFAULT_BUDGET_MS).max(1)),
        max_bytes: req.max_bytes.unwrap_or(DEFAULT_MAX_BYTES).max(1),
        include_sensitive: req.include_sensitive,
    };

    // Rules compile once and are shared by every PID in the request.
    let rules = if req.rules_path.is_empty() {
        None
    } else {
        match yara::load(&req.rules_path) {
            Ok(r) => Some(r),
            Err(e) => {
                for &pid in &pids {
                    emit(failure(pid, "error", format!("rules: {e}")));
                }
                return;
            }
        }
    };
    // Without rules or the prompt scan there is still work: image integrity
    // and the memory heuristics need no rules.

    for &pid in &pids {
        let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scan_one(pid, &opts, rules.as_ref())
        }))
        .unwrap_or_else(|_| failure(pid, "error", "panic contained while scanning this process"));
        emit(resp);
    }
}

fn failure(pid: i64, status: &str, msg: impl Into<String>) -> Response {
    let mut r = Response::err(OP, msg);
    r.meta = Some(json!({ "pid": pid, "status": status }));
    r
}

/// Running total for one prompt rule across all regions of a process.
struct PromptAgg {
    raw: prompts::RawHit,
    addr: usize,
    count: usize,
    regions: usize,
    last_region: usize,
}

/// Per-process counts of executable memory that no image file backs.
#[derive(Default)]
struct ExecStats {
    private_exec: usize,
    private_rwx: usize,
}

fn is_exec(r: &Region) -> bool {
    r.protect.to_ascii_lowercase().contains('x')
}

/// Executable memory with no ordinary file behind it: Windows private
/// commits, Linux anonymous mappings.
fn is_unbacked(r: &Region) -> bool {
    matches!(r.kind.as_str(), "private" | "anon" | "heap" | "stack")
}

/// Does `b` start with a PE image (DOS header pointing at a valid NT header)?
/// The "MZ" may have been wiped by a loader that hides its image, so the NT
/// signature at e_lfanew, with a known machine type, is enough.
fn pe_header(b: &[u8]) -> Option<&'static str> {
    if b.len() < 0x40 {
        return None;
    }
    let lfanew = u32::from_le_bytes([b[0x3C], b[0x3D], b[0x3E], b[0x3F]]) as usize;
    if !(0x40..0x1000).contains(&lfanew) || lfanew + 6 > b.len() {
        return None;
    }
    if &b[lfanew..lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let machine = u16::from_le_bytes([b[lfanew + 4], b[lfanew + 5]]);
    if !matches!(machine, 0x014c | 0x8664 | 0xaa64 | 0x01c4) {
        return None;
    }
    Some(if &b[..2] == b"MZ" {
        "PE image"
    } else {
        "PE image with its MZ header erased"
    })
}

/// Package locations whose files upgrades replace in place (the new version is
/// renamed over the old, so a process still running the old one maps a
/// "deleted" file).
const SYSTEM_PREFIXES: &[&str] = &[
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/bin",
    "/sbin",
    "/opt",
    "/snap",
    "/nix/store",
    "/var/lib/flatpak",
    "/var/lib/snapd",
];

fn under_system_prefix(p: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|pre| {
        p == *pre
            || p.strip_prefix(pre)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Whether a regular file exists at `path` as process `pid` sees it (through
/// /proc/<pid>/root, so a container's own filesystem is the one consulted).
#[cfg(target_os = "linux")]
fn exists_in_process_root(pid: u32, path: &str) -> bool {
    std::fs::metadata(format!("/proc/{pid}/root{path}"))
        .map(|m| m.is_file())
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn exists_in_process_root(_pid: u32, _path: &str) -> bool {
    false
}

/// Memory-structure heuristics for one region, judged from its metadata and
/// the first bytes read from it. No bytes are copied into the hit.
#[cfg(test)]
fn region_heuristic(r: &Region, first: &[u8]) -> Option<Hit> {
    region_heuristic_with(r, first, &|_| false)
}

/// region_heuristic with `exists` saying whether a file is now at a path (in
/// the scanned process's view): a deleted mapping from a system location that
/// has a new file in its place is a package upgrade pending a restart, not a
/// self-deleting payload, and is reported at info level.
fn region_heuristic_with(r: &Region, first: &[u8], exists: &dyn Fn(&str) -> bool) -> Option<Hit> {
    if !is_exec(r) {
        return None;
    }
    let (rule, severity, technique, confidence, what) = if is_unbacked(r) {
        if let Some(what) = pe_header(first) {
            (
                "memory.pe_in_private",
                "suspect",
                "T1620",
                75,
                format!("{what} in executable memory no file backs: reflectively loaded or manually mapped code (classic injection)"),
            )
        } else if first.starts_with(b"\x7fELF") {
            (
                "memory.elf_in_anonymous",
                "suspect",
                "T1620",
                75,
                "ELF image in anonymous executable memory: a binary loaded without a file"
                    .to_string(),
            )
        } else {
            return None;
        }
    } else if r.file.starts_with("/memfd:") {
        (
            "memory.memfd_exec",
            "suspect",
            "T1620",
            65,
            format!(
                "executable mapping of a memfd ({}): fileless execution",
                r.file
            ),
        )
    } else {
        // Anything else worth a hit is a mapping of a deleted file.
        let orig = r.file.strip_suffix(" (deleted)")?;
        if under_system_prefix(orig) && exists(orig) {
            (
                "memory.replaced_file_exec",
                "info",
                "T1554",
                20,
                format!("executable mapping of a file since replaced on disk ({}): usually a package upgrade the process hasn't been restarted after; verify with the package manager", r.file),
            )
        } else {
            (
                "memory.deleted_file_exec",
                "notable",
                "T1070.004",
                45,
                format!("executable mapping of a deleted file ({})", r.file),
            )
        }
    };
    Some(Hit {
        rule: rule.to_string(),
        severity: severity.to_string(),
        technique: technique.to_string(),
        offset: r.base as i64,
        encoding: String::new(),
        context: what,
        confidence,
        region: None,
    })
}

fn scan_one(pid: i64, opts: &Opts, rules: Option<&yara::LoadedRules>) -> Response {
    let started = Instant::now();
    let deadline = started + opts.budget;

    let Ok(pid32) = u32::try_from(pid) else {
        return failure(pid, "error", format!("invalid pid {pid}"));
    };
    if pid32 == 0 {
        return failure(pid, "error", "invalid pid 0");
    }
    if pid32 == std::process::id() {
        return failure(
            pid,
            "skipped",
            "refusing to scan the sidecar's own memory (its rules would match themselves)",
        );
    }

    let mem = match procmem::open(pid32) {
        Ok(m) => m,
        Err(e) => return failure(pid, e.status(), e.message()),
    };
    let image = mem.image_path();
    let name = file_name_lower(&image);
    if !opts.include_sensitive && SENSITIVE.contains(&name.as_str()) {
        let mut r = failure(
            pid,
            "skipped",
            format!("{name} is excluded by default (credential material; trips EDR credential-theft protection); set include_sensitive to scan it"),
        );
        if let Some(m) = r.meta.as_mut() {
            m["image"] = json!(image);
        }
        return r;
    }

    let regions = match mem.regions() {
        Ok(r) => r,
        Err(e) => return failure(pid, "error", e),
    };
    let bytes_total: u64 = regions.iter().map(|r| r.size as u64).sum();

    // Image integrity first: it reads only code mapped from image files, and
    // gets at most a third of the budget so the YARA walk keeps the rest.
    let integrity = mem.image_integrity(
        started + opts.budget / 3,
        opts.max_bytes.min(INTEGRITY_MAX_BYTES),
    );

    let mut session = rules.map(yara::Session::new);
    let mut prompt_hits: BTreeMap<(&'static str, &'static str), PromptAgg> = BTreeMap::new();
    let mut scratch = prompts::Scratch::default();
    let mut heuristic_hits: Vec<Hit> = Vec::new();
    let mut heuristics_truncated = false;
    let mut stats = ExecStats::default();
    let mut buf = vec![0u8; CHUNK + OVERLAP];
    let (mut bytes_scanned, mut regions_scanned, mut read_failures) = (0u64, 0usize, 0usize);
    let mut stopped: Option<String> = None;

    'walk: for (ri, r) in regions.iter().enumerate() {
        let mut off = 0usize;
        let mut carry = 0usize; // bytes at buf[..carry] repeated from the previous chunk
        let mut any = false;
        if is_exec(r) && is_unbacked(r) {
            stats.private_exec += 1;
            if r.protect.to_ascii_lowercase().contains('w') {
                stats.private_rwx += 1;
            }
        }
        while off < r.size {
            if Instant::now() >= deadline {
                stopped = Some("time budget exhausted".into());
                break 'walk;
            }
            if bytes_scanned >= opts.max_bytes {
                stopped = Some("byte cap reached".into());
                break 'walk;
            }
            let want = (r.size - off).min(CHUNK);
            let n = mem.read(r.base + off, &mut buf[carry..carry + want]);
            if n == 0 {
                // Unreadable (decommitted since the walk, or special memory):
                // skip this chunk rather than probing it page by page.
                read_failures += 1;
                off += want;
                carry = 0;
                continue;
            }
            let block_base = r.base + off - carry;
            let block = &buf[..carry + n];

            if off == 0 {
                if let Some(h) =
                    region_heuristic_with(r, block, &|p| exists_in_process_root(pid32, p))
                {
                    if heuristic_hits.len() < MAX_HEURISTIC_HITS {
                        heuristic_hits.push(h);
                    } else {
                        heuristics_truncated = true;
                    }
                }
            }

            if let Some(s) = session.as_mut() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match s.feed(block_base, block, remaining) {
                    Ok(()) => {}
                    Err(yara::Stop::Timeout) => {
                        stopped = Some("time budget exhausted during YARA scan".into());
                        break 'walk;
                    }
                    Err(yara::Stop::Error(e)) => {
                        stopped = Some(format!("YARA scan error: {e}"));
                        break 'walk;
                    }
                }
            }
            if opts.prompts {
                // The whole block, so a match that starts in the carried tail
                // and runs into the new bytes is found; matches wholly inside
                // the tail were counted with the previous chunk and are skipped.
                for raw in prompts::analyze_raw_from(block, carry, &mut scratch) {
                    let addr = block_base + raw.offset;
                    let key = (raw.rule, raw.encoding);
                    match prompt_hits.get_mut(&key) {
                        Some(a) => {
                            a.count += raw.count;
                            if a.last_region != ri {
                                a.regions += 1;
                                a.last_region = ri;
                            }
                            if addr < a.addr {
                                a.addr = addr;
                                a.raw = raw;
                            }
                        }
                        None => {
                            let count = raw.count;
                            prompt_hits.insert(
                                key,
                                PromptAgg {
                                    raw,
                                    addr,
                                    count,
                                    regions: 1,
                                    last_region: ri,
                                },
                            );
                        }
                    }
                }
            }

            any = true;
            bytes_scanned += n as u64;
            if session.is_none() && !opts.prompts {
                // Only the heuristics read the bytes, and they look at each
                // region's first chunk.
                break;
            }
            off += n;
            if n < want {
                // Short read: the rest of this chunk is unreadable.
                read_failures += 1;
                off += want - n;
                carry = 0;
            } else {
                let total = carry + n;
                let keep = OVERLAP.min(total);
                buf.copy_within(total - keep..total, 0);
                carry = keep;
            }
        }
        if any {
            regions_scanned += 1;
        }
    }

    // Evaluate YARA conditions over everything that was fed.
    let mut hits: Vec<Hit> = Vec::new();
    let mut yara_error: Option<String> = None;
    let mut yara_matched = 0usize;
    let mut hits_truncated = false;
    if let Some(s) = session {
        match s.finish() {
            Ok(ms) => {
                yara_matched = ms.len();
                for m in ms.into_iter() {
                    if hits.len() >= MAX_YARA_HITS {
                        hits_truncated = true;
                        break;
                    }
                    hits.push(yara_hit(m, &regions, mem.as_ref()));
                }
            }
            Err(e) => yara_error = Some(e),
        }
    }
    let mut prompt_list: Vec<Hit> = prompt_hits
        .into_values()
        .map(|a| {
            let region = region_info(&regions, a.addr, mem.as_ref());
            let note = format!(" in {} region(s)", a.regions);
            let mut h = prompts::RawHit {
                count: a.count,
                ..a.raw
            }
            .into_hit(a.addr as i64);
            h.context.push_str(&note);
            h.region = region;
            h
        })
        .collect();
    let (prompt_rules, prompt_score, prompt_verdict) = prompts::tally(&prompt_list);
    hits.append(&mut prompt_list);
    let heuristic_count = heuristic_hits.len();
    for mut h in heuristic_hits.into_iter().chain(integrity.hits()) {
        h.region = region_info(&regions, h.offset as usize, mem.as_ref());
        hits.push(h);
    }
    hits.sort_by_key(|h| h.offset);

    let status = if stopped.is_some() || yara_error.is_some() {
        "partial"
    } else {
        "scanned"
    };
    let coverage = if bytes_total == 0 {
        100.0
    } else {
        (bytes_scanned as f64 * 1000.0 / bytes_total as f64).round() / 10.0
    };
    let yara_meta = rules.map(|l| {
        json!({
            "rules_path": l.path,
            "rule_files": l.files,
            "rules_loaded": l.count,
            "rules_failed": l.failed,
            "module_imports": l.module_imports,
            "matched_rules": yara_matched,
            "error": yara_error,
        })
    });

    Response {
        op: OP.to_string(),
        ok: true,
        hits,
        meta: Some(json!({
            "pid": pid,
            "image": image,
            "status": status,
            "stopped_early": stopped,
            "regions_total": regions.len(),
            "regions_scanned": regions_scanned,
            "bytes_total": bytes_total,
            "bytes_scanned": bytes_scanned,
            "coverage_pct": coverage,
            "read_failures": read_failures,
            "elapsed_ms": started.elapsed().as_millis() as u64,
            "budget_ms": opts.budget.as_millis() as u64,
            "yara": yara_meta,
            "prompts": opts.prompts,
            "prompt_matched_rules": prompt_rules,
            "prompt_score": prompt_score,
            "prompt_verdict": prompt_verdict,
            "hits_truncated": hits_truncated,
            "unbacked_exec_regions": stats.private_exec,
            "unbacked_rwx_regions": stats.private_rwx,
            "memory_heuristic_hits": heuristic_count,
            "memory_heuristics_truncated": heuristics_truncated,
            "image_integrity": integrity.meta(),
        })),
        ..Default::default()
    }
}

/// Region details for the region holding `addr` (regions are sorted).
fn region_info(regions: &[Region], addr: usize, mem: &dyn ProcessMemory) -> Option<HitRegion> {
    let i = regions.partition_point(|r| r.base <= addr).checked_sub(1)?;
    let r = &regions[i];
    if !r.contains(addr) {
        return None;
    }
    let file = if !r.file.is_empty() {
        r.file.clone()
    } else if r.kind == "image" || r.kind == "mapped" {
        mem.mapped_file(r.base)
    } else {
        String::new()
    };
    Some(HitRegion {
        base: r.base as u64,
        size: r.size as u64,
        protect: r.protect.clone(),
        kind: r.kind.clone(),
        file,
    })
}

const SEVERITIES: &[&str] = &["info", "notable", "suspect", "critical"];

/// Turn a rule match into a Hit. Severity and confidence come from the rule's
/// own metadata when it has them (severity/threat_level, score/confidence).
fn yara_hit(m: yara::YaraMatch, regions: &[Region], mem: &dyn ProcessMemory) -> Hit {
    let score = m.score.map(|s| s.clamp(0, 100));
    let severity = match m.severity.as_deref().map(str::to_ascii_lowercase) {
        Some(s) if SEVERITIES.contains(&s.as_str()) => s,
        Some(s) if s == "high" => "critical".into(),
        Some(s) if s == "medium" => "suspect".into(),
        Some(s) if s == "low" => "notable".into(),
        _ => match score {
            Some(s) if s >= 80 => "critical".into(),
            Some(s) if s < 50 => "notable".into(),
            _ => "suspect".into(),
        },
    };
    let addr = m.first_addr.unwrap_or(0);
    let mut ctx = format!("ruleset {}", m.namespace);
    if !m.patterns.is_empty() {
        let pats: Vec<String> = m
            .patterns
            .iter()
            .take(8)
            .map(|(id, n)| format!("{id}({n})"))
            .collect();
        ctx.push_str(&format!(
            " | {} match(es): {}",
            m.total_matches,
            pats.join(" ")
        ));
        if m.patterns.len() > 8 {
            ctx.push_str(" ...");
        }
    }
    if !m.tags.is_empty() {
        ctx.push_str(&format!(" | tags: {}", m.tags.join(",")));
    }
    if let Some(d) = &m.description {
        let d: String = d.chars().take(160).collect();
        ctx.push_str(&format!(" | {d}"));
    }
    Hit {
        rule: format!("yara:{}", m.rule),
        severity,
        technique: m.technique.unwrap_or_default(),
        offset: addr as i64,
        encoding: String::new(),
        context: ctx,
        confidence: score.unwrap_or(75),
        region: m.first_addr.and_then(|a| region_info(regions, a, mem)),
    }
}

#[cfg(test)]
mod tests;
