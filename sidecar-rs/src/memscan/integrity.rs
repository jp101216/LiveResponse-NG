//! Image integrity: does the code a process mapped from a file still match
//! the file?
//!
//! The loader maps an executable image (ELF on Linux, PE on Windows) from a
//! file and, for PE, applies base relocations; after that its code pages
//! should stay what the file says. This module compares the two and judges
//! what it finds:
//!
//! - a long run of differing bytes is code rewritten in place: the image's
//!   code was overwritten after it was mapped;
//! - only short runs are patches: inline hooks (security products install
//!   these), debugger breakpoints, uprobes, hot-patches. They are reported
//!   low, except in amsi.dll and at ntdll's ETW event writers, where a patch
//!   switches off this process's telemetry;
//! - a PE header that no longer matches its file means the mapped image was
//!   replaced (see pe.rs).
//!
//! Everything here is platform-neutral and unit-tested on any OS; linux.rs and
//! windows.rs supply the bytes. Nothing is written to the target, and hits
//! carry addresses, counts and symbol names, never memory contents.

use super::procmem::file_name_lower;
use crate::contract::Hit;
use serde_json::json;
use std::collections::BTreeMap;

/// Differences this close together are one change site: rewritten code
/// matches some original bytes by coincidence.
const MERGE_GAP: usize = 16;
/// A change site at least this long is rewritten code, not a patch. Hooks,
/// breakpoints and loader fixups are a few bytes each.
pub const REWRITE_MIN: usize = 256;
/// A rewrite this large is reported as critical.
const BIG_REWRITE: usize = 16 * 1024;
/// Change-site offsets kept per comparison, for symbol lookup.
const MAX_SITE_OFFSETS: usize = 32;
/// Comparisons proceed in blocks this size; equal blocks are skipped whole.
const BLOCK: usize = 64;

/// The result of comparing one stretch of mapped code with its file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiffStats {
    /// Bytes compared (masked bytes excluded).
    pub compared: u64,
    /// Bytes that differ.
    pub differing: u64,
    /// Change sites (differences merged across gaps of MERGE_GAP or less).
    pub sites: usize,
    /// Span of the largest change site, and its offset.
    pub largest: usize,
    pub largest_at: usize,
    /// Start offsets of the first MAX_SITE_OFFSETS change sites.
    pub site_offsets: Vec<usize>,
}

/// How a compared stretch of code reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Patched,
    Rewritten,
}

impl DiffStats {
    pub fn verdict(&self) -> Verdict {
        if self.differing == 0 {
            Verdict::Clean
        } else if self.largest >= REWRITE_MIN {
            Verdict::Rewritten
        } else {
            Verdict::Patched
        }
    }
}

/// Accumulates a comparison fed in chunks, so a large mapping never needs to
/// be held in memory whole. Offsets are relative to the start of the stretch.
#[derive(Debug, Default)]
pub struct DiffAcc {
    stats: DiffStats,
    /// The open change site: (start, last differing offset).
    run: Option<(usize, usize)>,
}

fn overlaps(a: usize, b: usize, mask: &[(usize, usize)]) -> bool {
    mask.iter().any(|&(s, e)| s < b && a < e)
}

fn masked(off: usize, mask: &[(usize, usize)]) -> bool {
    mask.iter().any(|&(s, e)| (s..e).contains(&off))
}

impl DiffAcc {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compare `mem` with `disk`, both holding the bytes at offset `at` of the
    /// stretch (the shorter length is compared). Offsets inside a `mask`
    /// range ([start, end), relative to the stretch) are not compared.
    pub fn feed(&mut self, at: usize, mem: &[u8], disk: &[u8], mask: &[(usize, usize)]) {
        let n = mem.len().min(disk.len());
        let mut i = 0;
        while i < n {
            let end = (i + BLOCK).min(n);
            let skip_mask = !overlaps(at + i, at + end, mask);
            if skip_mask && mem[i..end] == disk[i..end] {
                self.stats.compared += (end - i) as u64;
                i = end;
                continue;
            }
            for j in i..end {
                let off = at + j;
                if !skip_mask && masked(off, mask) {
                    continue;
                }
                self.stats.compared += 1;
                if mem[j] != disk[j] {
                    self.mark(off);
                }
            }
            i = end;
        }
    }

    fn mark(&mut self, off: usize) {
        self.stats.differing += 1;
        match self.run {
            Some((start, last)) if off - last <= MERGE_GAP => self.run = Some((start, off)),
            Some(_) => {
                self.close();
                self.run = Some((off, off));
            }
            None => self.run = Some((off, off)),
        }
    }

    fn close(&mut self) {
        if let Some((start, last)) = self.run.take() {
            let span = last - start + 1;
            self.stats.sites += 1;
            if self.stats.site_offsets.len() < MAX_SITE_OFFSETS {
                self.stats.site_offsets.push(start);
            }
            if span > self.stats.largest {
                self.stats.largest = span;
                self.stats.largest_at = start;
            }
        }
    }

    pub fn finish(mut self) -> DiffStats {
        self.close();
        self.stats
    }
}

/// One compared stretch of image code that isn't clean.
#[derive(Debug, Clone)]
pub struct Change {
    /// The image file the code was mapped from.
    pub path: String,
    /// What was compared: "section .text", "r-xp mapping".
    pub what: String,
    /// Address the compared stretch starts at.
    pub start: usize,
    pub stats: DiffStats,
    /// Nearest exported symbol for the first change sites ("" when unknown).
    pub near: Vec<String>,
}

/// A mapped PE image whose header no longer matches its file.
#[derive(Debug, Clone)]
pub struct HeaderMismatch {
    pub path: String,
    pub base: usize,
    pub fields: Vec<String>,
}

/// Executable image memory whose backing file can't be read back.
#[derive(Debug, Clone)]
pub struct Unavailable {
    pub path: String,
    pub base: usize,
    pub why: String,
}

/// The integrity pass over one process.
#[derive(Debug, Default)]
pub struct Report {
    pub supported: bool,
    /// Distinct images (PE modules, or ELF files) looked at.
    pub images: usize,
    /// Code stretches (PE sections, ELF mappings) compared.
    pub compared: usize,
    pub bytes: u64,
    pub skipped: BTreeMap<&'static str, usize>,
    pub changes: Vec<Change>,
    pub headers: Vec<HeaderMismatch>,
    pub unavailable: Vec<Unavailable>,
    pub stopped: Option<String>,
}

/// ntdll entry points that write ETW events. A patch at one of them blinds
/// event tracing for the process.
const ETW_WRITERS: &[&str] = &[
    "EtwEventWrite",
    "EtwEventWriteEx",
    "EtwEventWriteFull",
    "EtwEventWriteString",
    "EtwEventWriteTransfer",
    "NtTraceEvent",
    "ZwTraceEvent",
];

/// Windows modules whose patching matters most: the native API, the core
/// Win32 layers, networking, and the credential and crypto providers.
const CORE_PE: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "winhttp.dll",
    "sspicli.dll",
    "secur32.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "ncrypt.dll",
];

/// Linux libraries (by file-name prefix) whose patching matters most: the C
/// runtime and dynamic loader, authentication (PAM, NSS, crypt), TLS, and the
/// audit/logging clients.
const CORE_ELF: &[&str] = &[
    "libc.so",
    "libc-",
    "ld-linux",
    "ld-musl",
    "libpthread",
    "libdl.",
    "libpam.so",
    "pam_",
    "libnss_",
    "libcrypt.so",
    "libssl.so",
    "libcrypto.so",
    "libaudit.so",
    "libsystemd.so",
    "libselinux.so",
];

fn is_core(name: &str) -> bool {
    CORE_PE.contains(&name) || CORE_ELF.iter().any(|p| name.starts_with(p))
}

/// The export names in a `near` string: "NtTraceEvent/ZwTraceEvent+0x0" ->
/// NtTraceEvent, ZwTraceEvent.
fn symbol_names(s: &str) -> impl Iterator<Item = &str> {
    s.rsplit_once('+').map_or(s, |(names, _)| names).split('/')
}

fn hit(
    rule: &str,
    severity: &str,
    technique: &str,
    confidence: i64,
    addr: usize,
    context: String,
) -> Hit {
    Hit {
        rule: rule.to_string(),
        severity: severity.to_string(),
        technique: technique.to_string(),
        offset: addr as i64,
        encoding: String::new(),
        context,
        confidence,
        region: None,
    }
}

impl Change {
    fn first_site(&self) -> usize {
        self.start + self.stats.site_offsets.first().copied().unwrap_or(0)
    }

    fn near_list(&self) -> String {
        let known: Vec<&str> = self
            .near
            .iter()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect();
        if known.is_empty() {
            String::new()
        } else {
            format!(", near {}", known.join(", "))
        }
    }
}

impl Report {
    pub fn unsupported() -> Self {
        Report::default()
    }

    pub fn skip(&mut self, why: &'static str) {
        *self.skipped.entry(why).or_default() += 1;
    }

    /// The findings, as sidecar hits (regions are filled in by the caller).
    pub fn hits(&self) -> Vec<Hit> {
        let mut out = Vec::new();
        let mut patched: Vec<&Change> = Vec::new();
        for c in &self.changes {
            match c.stats.verdict() {
                Verdict::Clean => {}
                Verdict::Rewritten => out.push(rewrite_hit(c)),
                Verdict::Patched => match tamper_hit(c) {
                    Some(h) => out.push(h),
                    None => patched.push(c),
                },
            }
        }
        if !patched.is_empty() {
            out.push(patch_hit(&patched));
        }
        for m in &self.headers {
            out.push(hit(
                "memory.image_header_mismatch",
                "suspect",
                "T1055.012",
                70,
                m.base,
                format!(
                    "the image mapped at 0x{:x} from {} doesn't match that file on disk ({}): the mapped image was replaced (hollowing or a related technique)",
                    m.base,
                    m.path,
                    m.fields.join("; ")
                ),
            ));
        }
        for u in &self.unavailable {
            out.push(hit(
                "memory.image_file_unavailable",
                "notable",
                "T1055",
                40,
                u.base,
                format!(
                    "executable image at 0x{:x} is backed by {}, which can't be opened now ({}): the file was deleted or replaced after it was mapped",
                    u.base, u.path, u.why
                ),
            ));
        }
        out
    }

    /// Per-process summary for the response meta.
    pub fn meta(&self) -> serde_json::Value {
        if !self.supported {
            return json!({ "supported": false });
        }
        let count = |v: Verdict| {
            self.changes
                .iter()
                .filter(|c| c.stats.verdict() == v)
                .count()
        };
        json!({
            "supported": true,
            "images": self.images,
            "compared": self.compared,
            "bytes_compared": self.bytes,
            "rewritten": count(Verdict::Rewritten),
            "patched": count(Verdict::Patched),
            "header_mismatch": self.headers.len(),
            "unavailable": self.unavailable.len(),
            "skipped": self.skipped,
            "stopped": self.stopped,
        })
    }
}

fn rewrite_hit(c: &Change) -> Hit {
    let big = c.stats.largest >= BIG_REWRITE;
    hit(
        "memory.image_code_modified",
        if big { "critical" } else { "suspect" },
        "T1055",
        if big { 85 } else { 70 },
        c.start + c.stats.largest_at,
        format!(
            "{} of {}: {} contiguous byte(s) of code differ from the file on disk ({} differing byte(s) at {} site(s){}): the image's code was overwritten in memory after it was mapped",
            c.what,
            c.path,
            c.stats.largest,
            c.stats.differing,
            c.stats.sites,
            c.near_list()
        ),
    )
}

/// A patch that switches off this process's own telemetry.
fn tamper_hit(c: &Change) -> Option<Hit> {
    let name = file_name_lower(&c.path);
    if name == "amsi.dll" {
        return Some(hit(
            "defense.amsi_patched",
            "suspect",
            "T1562.001",
            75,
            c.first_site(),
            format!(
                "amsi.dll code is patched in memory ({} site(s){}): the Antimalware Scan Interface was tampered with in this process",
                c.stats.sites,
                c.near_list()
            ),
        ));
    }
    let etw = c
        .near
        .iter()
        .any(|s| symbol_names(s).any(|n| ETW_WRITERS.contains(&n)));
    if name == "ntdll.dll" && etw {
        return Some(hit(
            "defense.etw_patched",
            "suspect",
            "T1562.006",
            75,
            c.first_site(),
            format!(
                "ntdll.dll's ETW event-write code is patched in memory ({} site(s){}): event tracing from this process is blinded",
                c.stats.sites,
                c.near_list()
            ),
        ));
    }
    None
}

/// One hit for all of a process's short patches, grouped by module.
fn patch_hit(ps: &[&Change]) -> Hit {
    let mut by: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for c in ps {
        let e = by.entry(file_name_lower(&c.path)).or_default();
        e.0 += c.stats.sites;
        e.1.extend(c.near.iter().filter(|s| !s.is_empty()).take(3).cloned());
    }
    let core = by.keys().any(|n| is_core(n));
    let mut list: Vec<String> = by
        .iter()
        .take(8)
        .map(|(n, (sites, near))| {
            if near.is_empty() {
                format!("{n} ({sites} site(s))")
            } else {
                format!("{n} ({sites} site(s), near {})", near.join(", "))
            }
        })
        .collect();
    if by.len() > 8 {
        list.push(format!("and {} more", by.len() - 8));
    }
    hit(
        "memory.image_inline_patch",
        if core { "notable" } else { "info" },
        "T1055",
        if core { 45 } else { 30 },
        ps[0].first_site(),
        format!(
            "short in-memory patches to image code in {} module(s): {}. Inline hooks look like this (security products, debuggers, uprobes, hot-patches) and so does tampering; check which product owns them",
            by.len(),
            list.join("; ")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(mem: &[u8], disk: &[u8], mask: &[(usize, usize)]) -> DiffStats {
        let mut a = DiffAcc::new();
        a.feed(0, mem, disk, mask);
        a.finish()
    }

    #[test]
    fn identical_is_clean() {
        let d: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        let s = stats(&d, &d, &[]);
        assert_eq!(s.verdict(), Verdict::Clean);
        assert_eq!(s.compared, 10_000);
    }

    #[test]
    fn short_patches_merge_by_gap() {
        let disk = vec![0x90u8; 4096];
        let mut mem = disk.clone();
        // A 5-byte hook, a second byte 10 bytes after it (same site), and a
        // breakpoint far away (its own site).
        mem[100..105].copy_from_slice(&[0xE9, 1, 2, 3, 4]);
        mem[114] = 0xCC;
        mem[3000] = 0xCC;
        let s = stats(&mem, &disk, &[]);
        assert_eq!(s.verdict(), Verdict::Patched);
        assert_eq!(s.differing, 7);
        assert_eq!(s.sites, 2);
        assert_eq!((s.largest, s.largest_at), (15, 100));
        assert_eq!(s.site_offsets, vec![100, 3000]);
    }

    #[test]
    fn rewrite_survives_coincidental_matches() {
        let disk: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let mut mem = disk.clone();
        // Overwrite 2 KiB, leaving every 8th byte equal by chance.
        for (i, b) in mem[1024..3072].iter_mut().enumerate() {
            if i % 8 != 0 {
                *b ^= 0x5A;
            }
        }
        let s = stats(&mem, &disk, &[]);
        assert_eq!(s.verdict(), Verdict::Rewritten);
        assert_eq!(s.sites, 1);
        assert!(s.largest >= 2040, "largest {}", s.largest);
    }

    #[test]
    fn masked_bytes_are_not_compared() {
        let disk = vec![0u8; 512];
        let mut mem = disk.clone();
        mem[200..216].fill(0xFF); // an IAT slot the loader wrote
        let s = stats(&mem, &disk, &[(200, 216)]);
        assert_eq!(s.verdict(), Verdict::Clean);
        assert_eq!(s.compared, 512 - 16);
    }

    #[test]
    fn chunked_feed_matches_one_shot() {
        let disk: Vec<u8> = (0..20_000u32).map(|i| (i * 31 % 256) as u8).collect();
        let mut mem = disk.clone();
        mem[4095..4100].fill(0xAA); // a site straddling a chunk boundary
        mem[9000..9600].fill(0xBB);
        let whole = stats(&mem, &disk, &[]);
        let mut a = DiffAcc::new();
        for start in (0..mem.len()).step_by(4096) {
            let end = (start + 4096).min(mem.len());
            a.feed(start, &mem[start..end], &disk[start..end], &[]);
        }
        assert_eq!(a.finish(), whole);
        assert_eq!(whole.sites, 2);
    }

    fn change(path: &str, mem_diff: &[(usize, u8)], len: usize, near: &[&str]) -> Change {
        let disk = vec![0u8; len];
        let mut mem = disk.clone();
        for &(i, b) in mem_diff {
            mem[i] = b;
        }
        Change {
            path: path.into(),
            what: "section .text".into(),
            start: 0x7ff0_0000_1000,
            stats: stats(&mem, &disk, &[]),
            near: near.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn hits_by_kind() {
        let mut r = Report {
            supported: true,
            ..Default::default()
        };
        // A rewrite, an ETW patch, an AMSI patch and two ordinary hooks.
        let rewrite: Vec<(usize, u8)> = (0..4096).map(|i| (i, 0xCC)).collect();
        r.changes.push(change(
            r"C:\Windows\System32\version.dll",
            &rewrite,
            8192,
            &[],
        ));
        r.changes.push(change(
            r"C:\Windows\System32\ntdll.dll",
            &[(0, 0xC3)],
            64,
            &["EtwEventWrite+0x0"],
        ));
        r.changes.push(change(
            r"C:\Windows\System32\amsi.dll",
            &[(5, 0xB8)],
            64,
            &["AmsiScanBuffer+0x5"],
        ));
        r.changes.push(change(
            r"C:\Windows\System32\kernelbase.dll",
            &[(3, 0xE9)],
            64,
            &["CreateFileW+0x0"],
        ));
        r.changes
            .push(change("/usr/lib/libfoo.so.1", &[(9, 0xCC)], 64, &[]));
        r.headers.push(HeaderMismatch {
            path: "x.exe".into(),
            base: 0x400000,
            fields: vec!["SizeOfImage 0x5000 vs 0x9000 on disk".into()],
        });
        let hits = r.hits();
        let rules: Vec<&str> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert_eq!(
            rules,
            [
                "memory.image_code_modified",
                "defense.etw_patched",
                "defense.amsi_patched",
                "memory.image_inline_patch",
                "memory.image_header_mismatch"
            ]
        );
        let patch = &hits[3];
        assert_eq!(patch.severity, "notable", "kernelbase is a core module");
        assert!(
            patch
                .context
                .contains("kernelbase.dll (1 site(s), near CreateFileW+0x0)"),
            "{}",
            patch.context
        );
        assert!(patch.context.contains("libfoo.so.1 (1 site(s))"));
        assert_eq!(hits[0].severity, "suspect");
        let m = r.meta();
        assert_eq!(
            (m["rewritten"].as_u64(), m["patched"].as_u64()),
            (Some(1), Some(4))
        );
    }

    #[test]
    fn non_core_patches_are_info_and_big_rewrites_critical() {
        let mut r = Report {
            supported: true,
            ..Default::default()
        };
        r.changes
            .push(change("/opt/app/libplugin.so", &[(1, 0xCC)], 64, &[]));
        assert_eq!(r.hits()[0].severity, "info");

        let rewrite: Vec<(usize, u8)> = (0..BIG_REWRITE).map(|i| (i, 0x90)).collect();
        r.changes = vec![change(
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            &rewrite,
            BIG_REWRITE + 64,
            &[],
        )];
        let h = &r.hits()[0];
        assert_eq!(
            (h.rule.as_str(), h.severity.as_str()),
            ("memory.image_code_modified", "critical")
        );
    }

    #[test]
    fn etw_patch_is_found_under_any_alias() {
        let r = Report {
            supported: true,
            changes: vec![change(
                r"C:\Windows\System32\ntdll.dll",
                &[(0, 0xC3)],
                64,
                &["NtTraceEvent/ZwTraceEvent+0x0"],
            )],
            ..Default::default()
        };
        assert_eq!(r.hits()[0].rule, "defense.etw_patched");
        assert_eq!(symbol_names("A/B+0x10").collect::<Vec<_>>(), ["A", "B"]);
        assert_eq!(symbol_names("NoOffset").collect::<Vec<_>>(), ["NoOffset"]);
    }

    #[test]
    fn unsupported_meta() {
        assert_eq!(Report::unsupported().meta(), json!({ "supported": false }));
    }
}
