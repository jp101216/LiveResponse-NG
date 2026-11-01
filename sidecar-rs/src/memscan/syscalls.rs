//! System calls made around ntdll: direct and indirect syscalls, the stubs
//! that make them, and ntdll mapped a second time.
//!
//! On 64-bit Windows only ntdll.dll and win32u.dll hold the instruction that
//! enters the kernel (`syscall`), one small stub per system service:
//! `mov r10, rcx; mov eax, <service number>; ...; syscall; ret`. EDRs hook
//! those stubs in user mode, so malware goes around them:
//!
//! - **Direct syscalls** bring their own stub and run `syscall` from their own
//!   memory: SysWhispers 1 and 2, Hell's Gate and its successors Halo's Gate
//!   and Tartarus' Gate (which differ in how they find the service number when
//!   ntdll is hooked), FreshyCalls, and Heaven's Gate (32-bit code switching to
//!   64-bit mode to make 64-bit calls).
//! - **Indirect syscalls** set the registers up in their own stub but jump to
//!   ntdll's own `syscall` instruction, so the kernel sees the call come from
//!   ntdll: SysWhispers3's "jumper", RecycledGate, HellsHall, and the indirect
//!   modes of C2 frameworks. The return address gives them away: it leads
//!   back into the stub's caller, in injected code.
//! - **Unhooking by a fresh copy** maps ntdll a second time (from disk or
//!   KnownDlls) and calls the clean copy.
//!
//! The service-number lookups (the "gates") leave nothing behind once they
//! are done; what they produce is one of these calls. A thread blocked in a
//! system call has its user-mode instruction pointer just past the `syscall`
//! it ran and its stack pointer at the address the stub returns to, so:
//!
//! - a thread whose `syscall` lies outside ntdll and win32u made a direct call;
//! - one whose `syscall` is ntdll's but that returns into executable memory no
//!   image backs made an indirect call (or injected code called ntdll
//!   directly);
//! - one that returns into memory that isn't executable belongs to code that
//!   hid itself while it waits (sleep obfuscation), or to a forged stack.
//!
//! The stubs themselves are found in executable memory no image backs, used
//! or not: the direct and indirect shapes those tools emit. Hook trampolines,
//! which jump back into the middle of ntdll's stub rather than to its
//! `syscall`, and byte-for-byte copies of ntdll's stubs (Chromium's sandbox
//! keeps those for the calls it intercepts) are counted, not reported.
//!
//! Platform-neutral, unit-tested on any OS; windows_hooks.rs reads the
//! threads and memory.
#![cfg_attr(not(any(windows, lrng_typecheck_windows)), allow(dead_code))]

use super::pe;
use crate::contract::Hit;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// `syscall`, and the legacy `int 2Eh` ntdll falls back to.
pub fn is_syscall_insn(b: [u8; 2]) -> bool {
    b == [0x0F, 0x05] || b == [0xCD, 0x2E]
}

/// `mov r10, rcx`, in both its encodings: the first instruction of a stub.
fn is_mov_r10_rcx(b: &[u8]) -> bool {
    b.starts_with(&[0x4C, 0x8B, 0xD1]) || b.starts_with(&[0x49, 0x89, 0xCA])
}

/// `test byte ptr [7FFE0308h], 1; jne +3`: ntdll's check of SharedUserData
/// (int 2Eh or syscall), between the service number and the `syscall`.
const SHARED_USER_DATA_CHECK: [u8; 10] =
    [0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01, 0x75, 0x03];

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// ntdll's own system-call stubs, read from its file on disk, where no hook
/// reaches them: to name them and to recognise copies.
#[derive(Debug, Default)]
pub struct StubTable {
    /// Service number -> (export name, the stub's bytes through its `ret`).
    by_ssn: BTreeMap<u32, (String, Vec<u8>)>,
    names: BTreeSet<String>,
}

impl StubTable {
    /// The table for an ntdll image file: every Nt/Zw export that is a stub.
    pub fn from_ntdll(file: &[u8]) -> StubTable {
        let mut t = StubTable::default();
        let Ok(pe) = pe::parse(file) else {
            return t;
        };
        for (rva, name) in pe.exports(file).iter() {
            if !(name.starts_with("Nt") || name.starts_with("Zw")) || name.starts_with("Ntdll") {
                continue;
            }
            let Some(b) = pe.rva_to_off(rva).and_then(|o| file.get(o..o + 0x20)) else {
                continue;
            };
            let (Some(ssn), true) = (u32_at(b, 4), b.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8])) else {
                continue;
            };
            let Some(sc) = b.windows(2).position(|w| is_syscall_insn([w[0], w[1]])) else {
                continue;
            };
            t.names.insert(name.to_string());
            let stub = b[..(sc + 3).min(b.len())].to_vec();
            let e = t
                .by_ssn
                .entry(ssn)
                .or_insert_with(|| (name.to_string(), stub));
            if e.0.starts_with("Zw") && name.starts_with("Nt") {
                e.0 = name.to_string(); // Nt and Zw share one stub: use the Nt name
            }
        }
        t
    }

    /// For tests: a table of (name, stub bytes).
    #[cfg(test)]
    pub fn from_stubs(stubs: &[(&str, &[u8])]) -> StubTable {
        let mut t = StubTable::default();
        for (name, b) in stubs {
            t.names.insert(name.to_string());
            t.by_ssn
                .insert(u32_at(b, 4).unwrap(), (name.to_string(), b.to_vec()));
        }
        t
    }

    pub fn len(&self) -> usize {
        self.by_ssn.len()
    }

    /// Whether an ntdll export is a system-call stub.
    pub fn is_stub(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// The function whose stub `b` (from its first byte) copies byte for byte.
    pub fn copy_of(&self, b: &[u8]) -> Option<&str> {
        if !b.starts_with(&[0x4C, 0x8B, 0xD1, 0xB8]) {
            return None;
        }
        let (name, stub) = self.by_ssn.get(&u32_at(b, 4)?)?;
        (b.len() >= stub.len() && b[..stub.len()] == stub[..]).then_some(name.as_str())
    }
}

/// What a stub does with the call it set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StubKind {
    /// Runs `syscall` itself: a direct syscall.
    Direct,
    /// Jumps to a `syscall` instruction elsewhere (ntdll's): an indirect one.
    Indirect,
    /// `mov r10, rcx` straight into a jump through a register, the target
    /// computed at run time (SysWhispers3's jumper).
    Jumper,
}

impl StubKind {
    fn name(self) -> &'static str {
        match self {
            StubKind::Direct => "direct",
            StubKind::Indirect => "indirect",
            StubKind::Jumper => "jumper",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stub {
    pub addr: usize,
    pub kind: StubKind,
    /// The service number, when the stub sets it as an immediate.
    pub ssn: Option<u32>,
    /// Where an indirect stub jumps.
    pub target: Option<usize>,
}

/// The stubs in one stretch of memory.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Scan {
    pub stubs: Vec<Stub>,
    /// Byte-for-byte copies of ntdll's stubs.
    pub copies: usize,
    /// Hook trampolines: a stub's first instructions, then a jump back into
    /// ntdll's stub past them.
    pub trampolines: usize,
}

enum Shape {
    Direct(Option<u32>),
    Indirect(Option<u32>, usize),
    Jumper(Option<u32>),
    Trampoline,
}

/// Find system-call stubs in `bytes`, executable memory at `base`. `read`
/// reads the process's memory, for a jump's pointer or target outside
/// `bytes`.
pub fn scan(
    bytes: &[u8],
    base: usize,
    table: &StubTable,
    read: &mut dyn FnMut(usize, &mut [u8]) -> usize,
) -> Scan {
    let mut out = Scan::default();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let Some(k) = bytes[i..].iter().position(|&b| b == 0x4C || b == 0x49) else {
            break;
        };
        i += k;
        if is_mov_r10_rcx(&bytes[i..]) {
            match shape(bytes, i, base, read) {
                Some(Shape::Direct(ssn)) => {
                    if table.copy_of(&bytes[i..]).is_some() {
                        out.copies += 1;
                    } else {
                        out.stubs.push(Stub {
                            addr: base + i,
                            kind: StubKind::Direct,
                            ssn,
                            target: None,
                        });
                    }
                }
                Some(Shape::Indirect(ssn, target)) => out.stubs.push(Stub {
                    addr: base + i,
                    kind: StubKind::Indirect,
                    ssn,
                    target: Some(target),
                }),
                Some(Shape::Jumper(ssn)) => out.stubs.push(Stub {
                    addr: base + i,
                    kind: StubKind::Jumper,
                    ssn,
                    target: None,
                }),
                Some(Shape::Trampoline) => out.trampolines += 1,
                None => {}
            }
        }
        i += 1;
    }
    out
}

/// The stub starting with the `mov r10, rcx` at `b[i]`, if it is one.
fn shape(
    b: &[u8],
    i: usize,
    base: usize,
    read: &mut dyn FnMut(usize, &mut [u8]) -> usize,
) -> Option<Shape> {
    let mut j = i + 3;
    let mut ssn = None;
    // The service number: an immediate, a load from memory (Hell's Gate and
    // its family keep it in a variable), or set before `mov r10, rcx`.
    if b.get(j) == Some(&0xB8) {
        let v = u32_at(b, j + 1)?;
        if v > 0xFFFF {
            return None; // not a service number
        }
        ssn = Some(v);
        j += 5;
    } else if b.get(j..j + 2) == Some(&[0x8B, 0x05]) {
        j += 6;
    } else if i >= 5 && b[i - 5] == 0xB8 {
        ssn = u32_at(b, i - 4).filter(|&v| v <= 0xFFFF);
    }
    if b.get(j..j + SHARED_USER_DATA_CHECK.len()) == Some(&SHARED_USER_DATA_CHECK) {
        j += SHARED_USER_DATA_CHECK.len();
    }
    let rest = b.get(j..)?;
    if rest.len() >= 2 && is_syscall_insn([rest[0], rest[1]]) {
        return Some(Shape::Direct(ssn));
    }
    let next = base.wrapping_add(j);
    let rel = |o: usize| u32_at(rest, o).map(|v| v as i32 as isize);
    let target = match rest {
        // jmp qword ptr [rip+rel32]: the pointer is in the block or the process
        [0xFF, 0x25, ..] => {
            let slot = next.wrapping_add(6).wrapping_add_signed(rel(2)?);
            let mut p = [0u8; 8];
            let in_block = slot.checked_sub(base).and_then(|o| b.get(o..o + 8));
            match in_block {
                Some(v) => p.copy_from_slice(v),
                None if read(slot, &mut p) == 8 => {}
                None => return None,
            }
            u64::from_le_bytes(p) as usize
        }
        // mov r11, imm64; jmp r11
        [0x49, 0xBB, a, b2, c, d, e, f, g, h, 0x41, 0xFF, 0xE3, ..] => {
            u64::from_le_bytes([*a, *b2, *c, *d, *e, *f, *g, *h]) as usize
        }
        // jmp rel32
        [0xE9, ..] => next.wrapping_add(5).wrapping_add_signed(rel(1)?),
        // jmp <register>
        [0xFF, 0xE0..=0xE7, ..] | [0x41, 0xFF, 0xE0..=0xE7, ..] => return Some(Shape::Jumper(ssn)),
        _ => return None,
    };
    let mut insn = [0u8; 2];
    if read(target, &mut insn) == 2 && is_syscall_insn(insn) {
        Some(Shape::Indirect(ssn, target))
    } else {
        Some(Shape::Trampoline)
    }
}

/// Where an address lies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// ntdll.dll (the process's own) or win32u.dll: where system calls belong.
    System(String),
    /// A second copy of ntdll.
    NtdllCopy,
    /// Another image (lower-case file name).
    Image(String),
    /// Executable memory no image backs ("private" or "mapped").
    Unbacked { kind: String, protect: String },
    /// Committed memory that isn't executable.
    NotExecutable { kind: String, protect: String },
    /// Nothing committed there.
    Nothing,
}

impl Place {
    fn describe(&self) -> String {
        match self {
            Place::System(m) => m.clone(),
            Place::NtdllCopy => "a second copy of ntdll".into(),
            Place::Image(m) => m.clone(),
            Place::Unbacked { kind, protect } => {
                format!("{protect} {kind} memory no image file backs")
            }
            Place::NotExecutable { kind, protect } => {
                format!("{protect} {kind} memory, which isn't executable")
            }
            Place::Nothing => "memory where nothing is mapped".into(),
        }
    }
}

/// A thread in (or just back from) a system call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub tid: u32,
    /// The address just past its `syscall` instruction.
    pub rip: usize,
    /// Where that instruction lies.
    pub at: Place,
    /// The system module's export it is in ("NtWaitForSingleObject"), for a
    /// call made from ntdll or win32u.
    pub stub: String,
    /// The stub copies ntdll's stub of this function byte for byte.
    pub copy_of: Option<String>,
    /// The address the stub returns to, and where that lies.
    pub ret: Option<(usize, Place)>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Direct,
    Indirect,
    ReturnNotExecutable,
}

impl Call {
    /// What the call is, if it isn't an ordinary one: the rule, severity,
    /// confidence and the sentence about it.
    fn judge(&self) -> Option<(Verdict, &'static str, i64, String)> {
        let at = format!("thread {} (0x{:x})", self.tid, self.rip);
        match &self.at {
            Place::System(module) => {
                let (ret, place) = self.ret.as_ref()?;
                let from = if self.stub.is_empty() {
                    module.clone()
                } else {
                    format!("{module}!{}", self.stub)
                };
                match place {
                    Place::Unbacked { .. } => Some((
                        Verdict::Indirect,
                        "suspect",
                        75,
                        format!("{at}: a system call from {from} returns to 0x{ret:x}, in {}", place.describe()),
                    )),
                    Place::NotExecutable { .. } | Place::Nothing => Some((
                        Verdict::ReturnNotExecutable,
                        if *place == Place::Nothing { "suspect" } else { "critical" },
                        if *place == Place::Nothing { 65 } else { 80 },
                        format!("{at}: a system call from {from} returns to 0x{ret:x}, in {}", place.describe()),
                    )),
                    _ => None,
                }
            }
            Place::Unbacked { .. } => Some(match &self.copy_of {
                Some(name) => (
                    Verdict::Direct,
                    "notable",
                    40,
                    format!("{at}: a system call made from a byte-for-byte copy of ntdll's {name} stub, in {}", self.at.describe()),
                ),
                None => (
                    Verdict::Direct,
                    "critical",
                    85,
                    format!("{at}: a system call made from {}", self.at.describe()),
                ),
            }),
            Place::NtdllCopy => Some((
                Verdict::Direct,
                "critical",
                80,
                format!("{at}: a system call made from {}", self.at.describe()),
            )),
            Place::Image(m) => Some((
                Verdict::Direct,
                "suspect",
                70,
                format!("{at}: a system call made from inside {m}"),
            )),
            Place::NotExecutable { .. } | Place::Nothing => None, // a misread: nothing ran there
        }
    }
}

/// A second mapping of ntdll.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtdllCopy {
    pub base: usize,
    pub path: String,
    /// A view of the file made executable, rather than an image mapping.
    pub file_view: bool,
}

/// The stubs found in one region of executable memory no image backs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StubRegion {
    pub base: usize,
    pub size: usize,
    pub kind: String,
    pub protect: String,
    pub stubs: Vec<Stub>,
}

/// Everything found about one process.
#[derive(Debug, Default)]
pub struct Report {
    pub supported: bool,
    pub why: Option<String>,
    /// Threads in (or just back from) a system call, and those that weren't
    /// ordinary.
    pub in_syscall: usize,
    pub calls: Vec<Call>,
    /// Threads that looked out of the ordinary but had moved when read again
    /// (back from a short call, their stack slot reused): not reported.
    pub moved: usize,
    pub stub_regions: Vec<StubRegion>,
    pub stub_copies: usize,
    pub trampolines: usize,
    pub bytes_scanned: u64,
    pub scan_stopped: Option<String>,
    pub ntdll_copies: Vec<NtdllCopy>,
    /// ntdll stubs known from its file (0: copies can't be told apart).
    pub stub_table: usize,
}

fn hit(rule: &str, severity: &str, confidence: i64, addr: usize, context: String) -> Hit {
    Hit {
        rule: rule.to_string(),
        severity: severity.to_string(),
        technique: if rule == "defense.ntdll_second_copy" {
            "T1562.001"
        } else {
            "T1106"
        }
        .to_string(),
        offset: addr as i64,
        encoding: String::new(),
        context,
        confidence,
        region: None,
    }
}

const SEVERITY_ORDER: [&str; 4] = ["critical", "suspect", "notable", "info"];

fn listed(parts: &[String]) -> String {
    let mut s: Vec<String> = parts.iter().take(4).cloned().collect();
    if parts.len() > 4 {
        s.push(format!("and {} more", parts.len() - 4));
    }
    s.join("; ")
}

impl Report {
    pub fn unsupported(why: impl Into<String>) -> Self {
        Report {
            why: Some(why.into()),
            ..Default::default()
        }
    }

    pub fn hits(&self) -> Vec<Hit> {
        let mut out = Vec::new();
        // One hit per rule and severity, listing its threads.
        let mut groups: BTreeMap<(Verdict, usize), (usize, i64, Vec<String>)> = BTreeMap::new();
        for c in &self.calls {
            if let Some((v, sev, conf, line)) = c.judge() {
                let rank = SEVERITY_ORDER.iter().position(|s| *s == sev).unwrap_or(3);
                let g = groups.entry((v, rank)).or_insert((c.rip, conf, Vec::new()));
                g.1 = g.1.max(conf);
                g.2.push(line);
            }
        }
        for ((v, rank), (addr, conf, lines)) in groups {
            let sev = SEVERITY_ORDER[rank];
            let (rule, why) = match v {
                Verdict::Direct => (
                    "defense.direct_syscall",
                    "only ntdll and win32u make system calls: a direct syscall goes around the user-mode hooks EDR products place there (SysWhispers, Hell's, Halo's and Tartarus' Gate, FreshyCalls, Heaven's Gate)",
                ),
                Verdict::Indirect => (
                    "defense.indirect_syscall",
                    "ntdll's stubs return to their caller, here code no image backs: an indirect syscall (a stub in injected code jumping to ntdll's syscall instruction, as SysWhispers3's jumper, RecycledGate and HellsHall do) or injected code calling ntdll directly",
                ),
                Verdict::ReturnNotExecutable => (
                    "defense.syscall_return_nonexec",
                    "the code waiting on this call isn't executable now: sleep obfuscation hides an implant that way between callbacks, and a forged stack looks the same",
                ),
            };
            let mut detail = format!("{}. {why}", listed(&lines));
            if v == Verdict::Direct && rank >= 2 {
                detail.push_str(". Chromium's sandbox (Chrome, Edge, Electron apps) keeps copies like this for the calls it intercepts; a loader that copies stubs to dodge hooks looks the same");
            }
            out.push(hit(rule, sev, conf, addr, detail));
        }
        for r in &self.stub_regions {
            let worst = r.stubs.iter().any(|s| s.kind != StubKind::Jumper);
            let parts: Vec<String> = r
                .stubs
                .iter()
                .map(|s| {
                    let mut p = format!("{} at 0x{:x}", s.kind.name(), s.addr);
                    if let Some(n) = s.ssn {
                        p.push_str(&format!(" (service 0x{n:x})"));
                    }
                    if let Some(t) = s.target {
                        p.push_str(&format!(" -> syscall at 0x{t:x}"));
                    }
                    p
                })
                .collect();
            out.push(hit(
                "memory.syscall_stub",
                "suspect",
                if worst { 80 } else { 70 },
                r.stubs[0].addr,
                format!(
                    "{} {} memory at 0x{:x} ({} bytes), which no image file backs, holds {} system-call stub(s): {}. Stubs like these are what direct- and indirect-syscall tooling (SysWhispers, the Hell's Gate family, RecycledGate) places in injected code",
                    r.protect,
                    r.kind,
                    r.base,
                    r.size,
                    r.stubs.len(),
                    listed(&parts)
                ),
            ));
        }
        for c in &self.ntdll_copies {
            let (sev, conf, what) = if c.file_view {
                ("critical", 80, "a view of its file made executable")
            } else {
                ("suspect", 70, "a second image mapping")
            };
            out.push(hit(
                "defense.ntdll_second_copy",
                sev,
                conf,
                c.base,
                format!(
                    "ntdll is mapped a second time at 0x{:x} ({what}, {}): a clean copy to call, around the hooks in the loaded one (unhooking)",
                    c.base, c.path
                ),
            ));
        }
        out
    }

    pub fn meta(&self) -> serde_json::Value {
        if !self.supported {
            return json!({ "supported": false, "why": self.why });
        }
        let count = |v: Verdict| {
            self.calls
                .iter()
                .filter(|c| c.judge().is_some_and(|j| j.0 == v))
                .count()
        };
        json!({
            "supported": true,
            "threads_in_syscall": self.in_syscall,
            "threads_moved": self.moved,
            "direct": count(Verdict::Direct),
            "indirect": count(Verdict::Indirect),
            "return_not_executable": count(Verdict::ReturnNotExecutable),
            "stubs": self.stub_regions.iter().map(|r| r.stubs.len()).sum::<usize>(),
            "stub_copies": self.stub_copies,
            "trampolines": self.trampolines,
            "bytes_scanned": self.bytes_scanned,
            "scan_stopped": self.scan_stopped,
            "ntdll_copies": self.ntdll_copies.len(),
            "ntdll_stubs_known": self.stub_table,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ntdll's x64 stub for service `ssn` (Windows 10 and later).
    fn ntdll_stub(ssn: u32) -> Vec<u8> {
        let mut s = vec![0x4C, 0x8B, 0xD1, 0xB8];
        s.extend_from_slice(&ssn.to_le_bytes());
        s.extend_from_slice(&SHARED_USER_DATA_CHECK);
        s.extend_from_slice(&[0x0F, 0x05, 0xC3, 0xCD, 0x2E, 0xC3]);
        s
    }

    fn table() -> StubTable {
        let a = ntdll_stub(0x4);
        let b = ntdll_stub(0x18);
        StubTable::from_stubs(&[
            ("NtWaitForSingleObject", &a[..0x15]),
            ("NtAllocateVirtualMemory", &b[..0x15]),
        ])
    }

    /// A process whose memory is `mem` at `at`.
    fn reader(at: usize, mem: Vec<u8>) -> impl FnMut(usize, &mut [u8]) -> usize {
        move |addr: usize, buf: &mut [u8]| {
            let Some(o) = addr.checked_sub(at) else {
                return 0;
            };
            let Some(src) = mem.get(o..) else { return 0 };
            let n = buf.len().min(src.len());
            buf[..n].copy_from_slice(&src[..n]);
            n
        }
    }

    const NTDLL: usize = 0x7ffb_0000_0000;

    /// ntdll at NTDLL: the NtWaitForSingleObject stub at +0x1000 (its
    /// syscall at +0x1012).
    fn ntdll_memory() -> Vec<u8> {
        let mut m = vec![0xCCu8; 0x2000];
        m[0x1000..0x1018].copy_from_slice(&ntdll_stub(0x4));
        m
    }

    fn scan_of(code: &[u8]) -> Scan {
        let mut read = reader(NTDLL, ntdll_memory());
        scan(code, 0x1000_0000, &table(), &mut read)
    }

    #[test]
    fn finds_the_direct_stub_shapes() {
        let mut code = vec![0x90u8; 16];
        // SysWhispers 1: mov r10, rcx; mov eax, 18h; syscall; ret
        code.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0x0F, 0x05, 0xC3]);
        // SysWhispers 2 / 3 (direct): the number comes from a call; mov r10, rcx; syscall
        code.extend_from_slice(&[0x90, 0x4C, 0x8B, 0xD1, 0x0F, 0x05, 0xC3]);
        // Hell's Gate: mov r10, rcx; mov eax, [rip+x]; syscall
        code.extend_from_slice(&[
            0x90, 0x4C, 0x8B, 0xD1, 0x8B, 0x05, 1, 2, 3, 4, 0x0F, 0x05, 0xC3,
        ]);
        // The other encoding of mov r10, rcx, and int 2Eh; number set first
        code.extend_from_slice(&[0xB8, 0x55, 0, 0, 0, 0x49, 0x89, 0xCA, 0xCD, 0x2E, 0xC3]);
        let s = scan_of(&code);
        let kinds: Vec<(StubKind, Option<u32>)> = s.stubs.iter().map(|x| (x.kind, x.ssn)).collect();
        assert_eq!(
            kinds,
            [
                (StubKind::Direct, Some(0x18)),
                (StubKind::Direct, None),
                (StubKind::Direct, None),
                (StubKind::Direct, Some(0x55)),
            ]
        );
        assert_eq!(s.stubs[0].addr, 0x1000_0000 + 16);
        assert_eq!((s.copies, s.trampolines), (0, 0));
    }

    #[test]
    fn tells_indirect_stubs_from_trampolines_and_copies() {
        let syscall = NTDLL + 0x1012;
        let stub_plus_8 = NTDLL + 0x1008;
        let mut code = vec![0x90u8; 8];
        // RecycledGate / HellsHall: number from memory, jmp [rip+0] to ntdll's syscall
        code.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0x8B, 0x05, 9, 9, 9, 9, 0xFF, 0x25, 0, 0, 0, 0,
        ]);
        code.extend_from_slice(&(syscall as u64).to_le_bytes());
        // mov r11, imm64; jmp r11, to the syscall
        code.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0x49, 0xBB]);
        code.extend_from_slice(&(syscall as u64).to_le_bytes());
        code.extend_from_slice(&[0x41, 0xFF, 0xE3]);
        // SysWhispers3's jumper: mov r10, rcx; jmp r11
        code.extend_from_slice(&[0x90, 0x4C, 0x8B, 0xD1, 0x41, 0xFF, 0xE3]);
        // An EDR hook trampoline: the stub's first two instructions, then
        // jmp [rip+0] back into ntdll's stub past them (not its syscall)
        code.extend_from_slice(&[
            0x4C, 0x8B, 0xD1, 0xB8, 0x04, 0, 0, 0, 0xFF, 0x25, 0, 0, 0, 0,
        ]);
        code.extend_from_slice(&(stub_plus_8 as u64).to_le_bytes());
        // A byte-for-byte copy of ntdll's stub (Chromium's sandbox)
        code.extend_from_slice(&ntdll_stub(0x18));
        // A jump whose pointer can't be read: not judged
        code.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x40]);
        let s = scan_of(&code);
        let got: Vec<(StubKind, Option<usize>)> =
            s.stubs.iter().map(|x| (x.kind, x.target)).collect();
        assert_eq!(
            got,
            [
                (StubKind::Indirect, Some(syscall)),
                (StubKind::Indirect, Some(syscall)),
                (StubKind::Jumper, None),
            ]
        );
        assert_eq!((s.copies, s.trampolines), (1, 1));
    }

    #[test]
    fn ordinary_code_has_no_stubs() {
        // mov r10, rcx then ordinary code; a lone syscall-like byte pair;
        // an immediate too large to be a service number.
        let code = [
            0x4C, 0x8B, 0xD1, 0x48, 0x89, 0xC8, 0xC3, 0x90, 0x0F, 0x05, 0x4C, 0x8B, 0xD1, 0xB8,
            0x00, 0x00, 0x01, 0x00, 0x0F, 0x05, 0x4C, 0x8B,
        ];
        assert_eq!(scan_of(&code), Scan::default());
    }

    #[test]
    fn stub_table_from_an_ntdll_file() {
        // A PE32+ with exports NtWaitForSingleObject and ZwWaitForSingleObject
        // (one stub), NtdllDefWindowProc_A (not a stub) and RtlFoo.
        let f = tiny_ntdll();
        let t = StubTable::from_ntdll(&f);
        assert_eq!(t.len(), 1);
        assert!(t.is_stub("NtWaitForSingleObject") && t.is_stub("ZwWaitForSingleObject"));
        assert!(!t.is_stub("NtdllDefWindowProc_A") && !t.is_stub("RtlFoo"));
        assert_eq!(t.copy_of(&ntdll_stub(0x4)), Some("NtWaitForSingleObject"));
        let mut changed = ntdll_stub(0x4);
        changed[0x12] = 0x90;
        assert_eq!(t.copy_of(&changed), None);
        assert_eq!(StubTable::from_ntdll(b"not a pe").len(), 0);
    }

    fn tiny_ntdll() -> Vec<u8> {
        let mut f = vec![0u8; 0x800];
        f[..2].copy_from_slice(b"MZ");
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let fh = 0x84;
        f[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[fh + 2..fh + 4].copy_from_slice(&1u16.to_le_bytes());
        f[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes());
        let oh = fh + 20;
        f[oh..oh + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        f[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        f[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
        f[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        f[oh + 60..oh + 64].copy_from_slice(&0x200u32.to_le_bytes());
        f[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
        // export directory at RVA 0x1100
        f[oh + 112..oh + 116].copy_from_slice(&0x1100u32.to_le_bytes());
        f[oh + 116..oh + 120].copy_from_slice(&0x100u32.to_le_bytes());
        let s = oh + 0xF0;
        f[s..s + 5].copy_from_slice(b".text");
        f[s + 8..s + 12].copy_from_slice(&0x600u32.to_le_bytes());
        f[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        f[s + 16..s + 20].copy_from_slice(&0x600u32.to_le_bytes());
        f[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        f[s + 36..s + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let at = |rva: u32| (rva - 0x1000 + 0x200) as usize;
        // code: the stub at 0x1000, a non-stub at 0x1040
        f[at(0x1000)..at(0x1018)].copy_from_slice(&ntdll_stub(0x4));
        f[at(0x1040)..at(0x1043)].copy_from_slice(&[0x48, 0x31, 0xC0]);
        let names = [
            "NtWaitForSingleObject",
            "NtdllDefWindowProc_A",
            "RtlFoo",
            "ZwWaitForSingleObject",
        ];
        let rvas = [0x1000u32, 0x1040, 0x1040, 0x1000];
        let d = at(0x1100);
        f[d + 20..d + 24].copy_from_slice(&4u32.to_le_bytes()); // NumberOfFunctions
        f[d + 24..d + 28].copy_from_slice(&4u32.to_le_bytes()); // NumberOfNames
        f[d + 28..d + 32].copy_from_slice(&0x1140u32.to_le_bytes()); // functions
        f[d + 32..d + 36].copy_from_slice(&0x1160u32.to_le_bytes()); // names
        f[d + 36..d + 40].copy_from_slice(&0x1180u32.to_le_bytes()); // ordinals
        let mut name_rva = 0x1200u32;
        for (k, n) in names.iter().enumerate() {
            f[at(0x1140) + 4 * k..at(0x1140) + 4 * k + 4].copy_from_slice(&rvas[k].to_le_bytes());
            f[at(0x1160) + 4 * k..at(0x1160) + 4 * k + 4].copy_from_slice(&name_rva.to_le_bytes());
            f[at(0x1180) + 2 * k..at(0x1180) + 2 * k + 2]
                .copy_from_slice(&(k as u16).to_le_bytes());
            f[at(name_rva)..at(name_rva) + n.len()].copy_from_slice(n.as_bytes());
            name_rva += 0x20;
        }
        f
    }

    fn call(at: Place, ret: Option<(usize, Place)>) -> Call {
        Call {
            tid: 7,
            rip: 0x1234,
            at,
            stub: "NtWaitForSingleObject".into(),
            copy_of: None,
            ret,
        }
    }

    fn rules(r: &Report) -> Vec<(String, String)> {
        r.hits().into_iter().map(|h| (h.rule, h.severity)).collect()
    }

    fn unbacked(protect: &str) -> Place {
        Place::Unbacked {
            kind: "private".into(),
            protect: protect.into(),
        }
    }

    #[test]
    fn judges_threads_in_system_calls() {
        let ntdll = || Place::System("ntdll.dll".into());
        let image = || Place::Image("kernelbase.dll".into());
        let mut copy = call(unbacked("RX"), None);
        copy.copy_of = Some("NtCreateFile".into());
        let r = Report {
            supported: true,
            in_syscall: 9,
            moved: 2,
            calls: vec![
                call(ntdll(), Some((0x5000, image()))),        // ordinary
                call(unbacked("RWX"), None),                   // direct, injected
                call(Place::Image("game.exe".into()), None),   // direct, a module
                copy,                                          // Chromium-style copy
                call(Place::NtdllCopy, None),                  // from a fresh ntdll
                call(ntdll(), Some((0x6000, unbacked("RX")))), // indirect
                call(
                    ntdll(),
                    Some((
                        0x7000,
                        Place::NotExecutable {
                            kind: "private".into(),
                            protect: "RW".into(),
                        },
                    )),
                ), // sleeping, hidden
                call(ntdll(), Some((0x8000, Place::Nothing))), // forged
                call(ntdll(), None),                           // return unreadable
            ],
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [
                ("defense.direct_syscall", "critical"),
                ("defense.direct_syscall", "suspect"),
                ("defense.direct_syscall", "notable"),
                ("defense.indirect_syscall", "suspect"),
                ("defense.syscall_return_nonexec", "critical"),
                ("defense.syscall_return_nonexec", "suspect"),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let h = r.hits();
        assert!(
            h[0].context
                .contains("RWX private memory no image file backs")
                && h[0].context.contains("a second copy of ntdll")
        );
        assert!(h[1].context.contains("inside game.exe"));
        assert!(
            h[2].context.contains("copy of ntdll's NtCreateFile stub")
                && h[2].context.contains("Chromium")
        );
        assert!(h[3]
            .context
            .contains("ntdll.dll!NtWaitForSingleObject returns to 0x6000"));
        assert_eq!((h[0].technique.as_str(), h[3].offset), ("T1106", 0x1234));
        let m = r.meta();
        assert_eq!(
            (
                m["direct"].as_u64(),
                m["indirect"].as_u64(),
                m["return_not_executable"].as_u64()
            ),
            (Some(4), Some(1), Some(2))
        );
        assert_eq!(
            (
                m["threads_in_syscall"].as_u64(),
                m["threads_moved"].as_u64()
            ),
            (Some(9), Some(2))
        );
    }

    #[test]
    fn reports_stub_regions_and_ntdll_copies() {
        let r = Report {
            supported: true,
            stub_regions: vec![StubRegion {
                base: 0x1000_0000,
                size: 0x1000,
                kind: "private".into(),
                protect: "RX".into(),
                stubs: vec![Stub {
                    addr: 0x1000_0010,
                    kind: StubKind::Indirect,
                    ssn: Some(0x18),
                    target: Some(0x7ffb_0000_1012),
                }],
            }],
            ntdll_copies: vec![
                NtdllCopy {
                    base: 0x2000_0000,
                    path: r"C:\Windows\System32\ntdll.dll".into(),
                    file_view: false,
                },
                NtdllCopy {
                    base: 0x3000_0000,
                    path: r"C:\Windows\System32\ntdll.dll".into(),
                    file_view: true,
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [
                ("memory.syscall_stub", "suspect"),
                ("defense.ntdll_second_copy", "suspect"),
                ("defense.ntdll_second_copy", "critical"),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let h = r.hits();
        assert!(h[0]
            .context
            .contains("indirect at 0x10000010 (service 0x18) -> syscall at 0x7ffb00001012"));
        assert_eq!(h[0].offset, 0x1000_0010);
        assert_eq!(h[2].technique, "T1562.001");
        assert!(Report::unsupported("x64 only").hits().is_empty());
        assert_eq!(Report::unsupported("x64 only").meta()["supported"], false);
    }
}
