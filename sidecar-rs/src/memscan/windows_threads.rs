//! Reading where a Windows process's threads started, and walking the stacks
//! of those waiting in system calls (judged in threads.rs).
//!
//! - Start addresses: NtQueryInformationThread's Win32StartAddress, read in
//!   windows_hooks.rs with each thread's registers. Where one lies is looked
//!   up with VirtualQueryEx; a module's exports name it, and its unwind data
//!   says whether it begins a function.
//! - Stacks (x64): a thread whose instruction pointer is just past a
//!   `syscall` in ntdll or win32u is blocked in the kernel, so its stack holds
//!   still. It is unwound frame by frame (unwind.rs) with each module's unwind
//!   data, read from the module's file once per run. The walk stops at the
//!   first frame it can't go past: the end of the stack, code with no unwind
//!   data, a dispatcher's machine frame, or memory no image backs (judged
//!   there). A finding is kept only if the thread's registers and the stack
//!   slot it came from read the same a second time.
//! - JIT code: the ranges a runtime registered with ntdll as code
//!   (RtlAddFunctionTable, RtlInstallFunctionTableCallback,
//!   RtlAddGrowableFunctionTable) come from the process's list of dynamic
//!   function tables. The list's head is in ntdll's data, at the address
//!   RtlGetFunctionTableListHead gives in every process.
#![cfg_attr(not(windows), allow(dead_code))]

use super::pe;
use super::procmem::{file_name_lower, ProcessMemory};
use super::syscalls::is_syscall_insn;
use super::threads::{Frame, Report, StackFinding, Start, StartFinding};
use super::unwind::{self, UnwindTable, Unwound};
use super::windows::{read_image_file, WinProcess};
use super::windows_hooks::{locate, read_usize};
use super::windows_syscalls::{ntdll, still_in_call, Regs};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// Frames walked per stack, at most.
const MAX_FRAMES: usize = 64;
/// Stack read in one go from the stack pointer (deeper frames are read one
/// slot at a time).
const STACK_READ: usize = 64 << 10;
/// Modules whose unwind data and exports are kept for the run.
const MAX_MODULES: usize = 2048;
/// Dynamic function tables read per process, at most.
const MAX_TABLES: usize = 4096;
/// DYNAMIC_FUNCTION_TABLE (x64): MinimumAddress and MaximumAddress.
const TABLE_MIN: usize = 0x20;
const TABLE_MAX: usize = 0x28;
const LOADLIBRARY: [&str; 4] = [
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
];

/// A module's unwind data and exports, read from its file.
pub(super) struct Module {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) table: Option<UnwindTable>,
    pub(super) exports: pe::Exports,
}

impl Module {
    /// "module!Export+0x1c" ("module!Export" at its start, or without the
    /// offset when `offset` is false), or "module+0x1c3f0" when no export is
    /// near.
    pub(super) fn name(&self, base: usize, addr: usize, offset: bool) -> String {
        let rva = addr.wrapping_sub(base);
        let near = u32::try_from(rva)
            .map(|r| self.exports.near(r))
            .unwrap_or_default();
        match near.rsplit_once('+') {
            Some((names, off)) => {
                let first = names.split('/').next().unwrap_or(names);
                if off == "0x0" || !offset {
                    format!("{}!{first}", self.name)
                } else {
                    format!("{}!{first}+{off}", self.name)
                }
            }
            None => format!("{}+0x{rva:x}", self.name),
        }
    }
}

fn cache() -> &'static Mutex<HashMap<String, Arc<Module>>> {
    static C: OnceLock<Mutex<HashMap<String, Arc<Module>>>> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// The module mapped at `base` in `p`, its file read once per run.
pub(super) fn module(p: &WinProcess, base: usize) -> Arc<Module> {
    let path = p.mapped_file(base);
    let key = path.to_ascii_lowercase();
    if !key.is_empty() {
        if let Some(m) = cache().lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return m.clone();
        }
    }
    let file = read_image_file(&path).ok();
    let exports = file
        .as_deref()
        .and_then(|f| pe::parse(f).ok().map(|pe| pe.exports(f)))
        .unwrap_or_default();
    let table = file.as_deref().and_then(UnwindTable::from_image);
    let m = Arc::new(Module {
        name: file_name_lower(&path),
        path,
        table,
        exports,
    });
    if !key.is_empty() {
        let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
        if c.len() >= MAX_MODULES {
            c.clear();
        }
        c.insert(key, m.clone());
    }
    m
}

/// The modules of one process by base, so each is looked up once.
type Modules = HashMap<usize, Arc<Module>>;

fn module_at(p: &WinProcess, mods: &mut Modules, base: usize) -> Arc<Module> {
    mods.entry(base).or_insert_with(|| module(p, base)).clone()
}

/// Judge the threads `regs` (registers, x64) and `starts` (start addresses)
/// describe. Also returns the code ranges the process registered as JIT
/// code, for the system-call checks.
pub(super) fn read(
    p: &WinProcess,
    regs: &[Regs],
    starts: &[(u32, usize)],
    starts_unreadable: usize,
    deadline: Instant,
) -> (Report, Option<Vec<(usize, usize)>>) {
    let mut rep = Report {
        supported: true,
        starts_read: starts.len(),
        starts_unreadable,
        ..Default::default()
    };
    let mut mods = Modules::new();
    for &(tid, addr) in starts {
        if let Some(f) = judge_start(p, tid, addr, &mut mods) {
            rep.starts.push(f);
        }
    }
    let jit = jit_ranges(p);
    rep.jit_ranges = jit.as_ref().map(Vec::len);
    if cfg!(target_arch = "x86_64") {
        walk_all(
            p,
            regs,
            starts,
            jit.as_deref(),
            &mut mods,
            deadline,
            &mut rep,
        );
    }
    (rep, jit)
}

/// What is out of the ordinary about where a thread started, if anything.
fn judge_start(p: &WinProcess, tid: u32, addr: usize, mods: &mut Modules) -> Option<StartFinding> {
    let m = locate(p, addr)?;
    let start = match m.base {
        None => Start::Unbacked {
            kind: m.kind.into(),
            protect: m.protect.into(),
            exec: m.exec,
        },
        Some(base) => {
            let module = module_at(p, mods, base);
            let rva = u32::try_from(addr - base).ok()?;
            let near = module.exports.near(rva);
            let loadlibrary = matches!(module.name.as_str(), "kernel32.dll" | "kernelbase.dll")
                && near
                    .strip_suffix("+0x0")
                    .is_some_and(|names| names.split('/').any(|n| LOADLIBRARY.contains(&n)));
            if loadlibrary {
                Start::LoadLibrary {
                    symbol: module.name(base, addr, true),
                }
            } else if module.table.as_ref().and_then(|t| t.starts_function(rva)) == Some(false) {
                Start::MidFunction {
                    symbol: module.name(base, addr, true),
                }
            } else {
                return None;
            }
        }
    };
    Some(StartFinding { tid, addr, start })
}

/// RtlGetFunctionTableListHead in this process: ntdll's list head, at the
/// same address in every 64-bit process.
#[cfg(target_arch = "x86_64")]
fn table_list_head() -> Option<usize> {
    use super::windows_hooks::wide;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    static HEAD: OnceLock<Option<usize>> = OnceLock::new();
    // SAFETY: an ntdll export that takes nothing and returns a pointer.
    *HEAD.get_or_init(|| unsafe {
        let m = GetModuleHandleW(wide("ntdll.dll").as_ptr());
        let f = GetProcAddress(m, c"RtlGetFunctionTableListHead".as_ptr().cast())?;
        let get = core::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn() -> usize,
        >(f);
        Some(get()).filter(|&h| h != 0)
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn table_list_head() -> Option<usize> {
    None
}

/// The code ranges `p` registered with ntdll, or None when its list
/// couldn't be read consistently (it is read twice if it changed under the
/// first read).
pub(super) fn jit_ranges(p: &WinProcess) -> Option<Vec<(usize, usize)>> {
    let head = table_list_head()?;
    (0..2).find_map(|_| read_table_list(p, head))
}

fn read_table_list(p: &WinProcess, head: usize) -> Option<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    let (mut prev, mut cur) = (head, read_usize(p.h, head)?);
    for _ in 0..MAX_TABLES {
        if cur == head {
            return Some(out);
        }
        // Each entry's back link must lead to the one before it.
        if cur == 0 || read_usize(p.h, cur + core::mem::size_of::<usize>())? != prev {
            return None;
        }
        let (min, max) = (
            read_usize(p.h, cur + TABLE_MIN)?,
            read_usize(p.h, cur + TABLE_MAX)?,
        );
        if min < max {
            out.push((min, max));
        }
        prev = cur;
        cur = read_usize(p.h, cur)?;
    }
    None
}

/// How a walk ended.
#[derive(Debug)]
pub(super) enum Walked {
    /// At the end of the stack (a zero return address).
    Complete,
    /// In code a runtime registered (JIT).
    Jit,
    /// Somewhere it couldn't go past, for this reason.
    Stopped(&'static str),
    /// At a frame to report, read from this stack slot.
    Finding(StackFinding, usize),
}

/// The stack read once from the stack pointer, then slot by slot beyond.
struct Stack<'a> {
    p: &'a WinProcess,
    lo: usize,
    bytes: Vec<u8>,
}

impl<'a> Stack<'a> {
    fn new(p: &'a WinProcess, rsp: usize) -> Self {
        let mut bytes = vec![0u8; STACK_READ];
        let n = p.read(rsp, &mut bytes);
        bytes.truncate(n);
        Stack { p, lo: rsp, bytes }
    }

    fn u64(&self, a: u64) -> Option<u64> {
        let a = usize::try_from(a).ok()?;
        if let Some(b) = a
            .checked_sub(self.lo)
            .and_then(|o| self.bytes.get(o..o.checked_add(8)?))
        {
            return Some(u64::from_le_bytes(b.try_into().ok()?));
        }
        read_usize(self.p.h, a).map(|v| v as u64)
    }
}

/// Walk every thread blocked in a system call in ntdll or win32u.
fn walk_all(
    p: &WinProcess,
    regs: &[Regs],
    starts: &[(u32, usize)],
    jit: Option<&[(usize, usize)]>,
    mods: &mut Modules,
    deadline: Instant,
    rep: &mut Report,
) {
    let Ok(nt) = ntdll() else {
        *rep.stopped.entry("ntdll unreadable".into()).or_default() += regs.len();
        return;
    };
    for r in regs {
        let mut pre = [0u8; 2];
        if r.rip < 2 || p.read(r.rip - 2, &mut pre) != 2 || !is_syscall_insn(pre) {
            continue;
        }
        let Some(base) = locate(p, r.rip - 2).and_then(|m| m.base) else {
            continue;
        };
        let m = module_at(p, mods, base);
        let system = base == nt.base
            || (m.name == "win32u.dll"
                && m.path
                    .to_ascii_lowercase()
                    .ends_with(r"\system32\win32u.dll"));
        if !system {
            continue; // a direct system call: the system-call checks' finding
        }
        if Instant::now() >= deadline {
            *rep.stopped
                .entry("time budget exhausted".into())
                .or_default() += 1;
            continue;
        }
        rep.walked += 1;
        let (walked, frames) = walk(p, r, base, &m, jit, mods);
        rep.frames += frames.len();
        match walked {
            Walked::Complete => {
                rep.complete += 1;
                let start = starts.iter().find(|(t, _)| *t == r.tid).map(|&(_, a)| a);
                if let Some(f) = judge_ends(p, r, &frames, start, mods) {
                    // Still blocked where it was: the frames are the ones it waits with.
                    if still_in_call(p, r, None) {
                        rep.stacks.push(f);
                    } else {
                        rep.moved += 1;
                    }
                }
            }
            Walked::Jit => rep.jit_frames += 1,
            Walked::Stopped(why) => *rep.stopped.entry(why.into()).or_default() += 1,
            Walked::Finding(f, slot) => {
                // Still blocked where it was, the slot unchanged: a thread
                // that has run on may have reused that stack.
                if still_in_call(p, r, None) && read_usize(p.h, slot) == Some(f.addr) {
                    rep.stacks.push(f);
                } else {
                    rep.moved += 1;
                }
            }
        }
    }
}

/// Walk one thread's stack, from the system call its stub in the module at
/// `base0` (ntdll or win32u) is blocked in. Returns how the walk ended and
/// the frames' instruction pointers, innermost first.
pub(super) fn walk(
    p: &WinProcess,
    r: &Regs,
    base0: usize,
    m0: &Module,
    jit: Option<&[(usize, usize)]>,
    mods: &mut Modules,
) -> (Walked, Vec<usize>) {
    let stack = Stack::new(p, r.rsp);
    let mut read = |a: u64| stack.u64(a);
    let mut regs = unwind::Regs {
        rip: r.rip as u64,
        int: r.int,
    };
    let mut frames = vec![r.rip];
    let mut chain = vec![m0.name(base0, r.rip - 2, false)];

    // The stub: a leaf, unless its module gives it unwind data.
    let pc0 = (r.rip - base0) as u32;
    let first = match m0.table.as_ref() {
        Some(t) if t.function(pc0).is_some() => {
            t.unwind(pc0, pc0, &mut regs, &mut read).map(|_| ())
        }
        _ => unwind::pop_leaf(&mut regs, &mut read).ok_or("stack unreadable"),
    };
    if let Err(why) = first {
        return (Walked::Stopped(why), frames);
    }

    let mut below = r.rsp as u64;
    for depth in 1..=MAX_FRAMES {
        let pc = regs.rip as usize;
        if regs.rsp() <= below {
            return (Walked::Stopped("the stack didn't unwind upward"), frames);
        }
        below = regs.rsp();
        if pc == 0 {
            return (Walked::Complete, frames);
        }
        frames.push(pc);
        // The slot this return address was read from.
        let slot = regs.rsp().wrapping_sub(8) as usize;
        let Some(m) = locate(p, pc) else {
            return (Walked::Stopped("a return address leads nowhere"), frames);
        };
        let finding = |frame: Frame, mut chain: Vec<String>| {
            chain.push(frame.describe(pc));
            let f = StackFinding {
                tid: r.tid,
                addr: pc,
                depth,
                frame,
                chain,
            };
            Walked::Finding(f, slot)
        };
        match (m.base, m.exec) {
            (Some(base), true) => {
                let module = module_at(p, mods, base);
                if let Some(insn) = jump_gadget(p, pc) {
                    let symbol = module.name(base, pc, true);
                    return (finding(Frame::Gadget { symbol, insn }, chain), frames);
                }
                if let Some(false) = preceded_by_call(p, pc) {
                    let symbol = module.name(base, pc, true);
                    return (finding(Frame::NoCall { symbol }, chain), frames);
                }
                chain.push(module.name(base, pc, true));
                let Some(t) = module.table.as_ref() else {
                    return (Walked::Stopped("a module with no x64 unwind data"), frames);
                };
                let rva = (pc - base) as u32;
                match t.unwind(rva, rva.wrapping_sub(1), &mut regs, &mut read) {
                    Ok(Unwound::Return) => {}
                    Ok(Unwound::MachineFrame) => {
                        return (
                            Walked::Stopped("an exception, APC or callback dispatcher"),
                            frames,
                        )
                    }
                    Err(why) => return (Walked::Stopped(why), frames),
                }
            }
            (None, true) => {
                let Some(jit) = jit else {
                    return (Walked::Stopped("JIT code ranges unreadable"), frames);
                };
                if jit.iter().any(|&(lo, hi)| pc >= lo && pc < hi) {
                    return (Walked::Jit, frames);
                }
                if depth < 2 {
                    return (
                        Walked::Stopped(
                            "returns into memory no image backs (a system-call finding)",
                        ),
                        frames,
                    );
                }
                let frame = Frame::Unbacked {
                    kind: m.kind.into(),
                    protect: m.protect.into(),
                };
                return (finding(frame, chain), frames);
            }
            (_, false) => {
                if depth < 2 {
                    return (
                        Walked::Stopped(
                            "returns into memory that isn't executable (a system-call finding)",
                        ),
                        frames,
                    );
                }
                let frame = Frame::NotExecutable {
                    kind: m.kind.into(),
                    protect: m.protect.into(),
                };
                return (finding(frame, chain), frames);
            }
        }
    }
    (Walked::Stopped("deeper than 64 frames"), frames)
}

/// The indirect jump through a register calls preserve that `pc` points at,
/// if it does: what desynchronising stack spoofers return through.
fn jump_gadget(p: &WinProcess, pc: usize) -> Option<&'static str> {
    let mut b = [0u8; 2];
    if p.read(pc, &mut b) != 2 || b[0] != 0xff {
        return None;
    }
    Some(match b[1] {
        0x23 => "jmp qword ptr [rbx]",
        0xe3 => "jmp rbx",
        0x26 => "jmp qword ptr [rsi]",
        0xe6 => "jmp rsi",
        0x27 => "jmp qword ptr [rdi]",
        0xe7 => "jmp rdi",
        _ => return None,
    })
}

/// Modules a stack may legitimately end in: ntdll (RtlUserThreadStart,
/// LdrInitializeThunk, fiber starts), the WoW64 layer, and kernel32's and
/// kernelbase's fiber starts.
fn ends_where_threads_begin(module: &str, symbol: &str) -> bool {
    module == "ntdll.dll"
        || module.starts_with("wow64")
        || (matches!(module, "kernel32.dll" | "kernelbase.dll") && symbol.contains("FiberStart"))
}

/// Judge where a complete walk ended: early, at a frame that isn't where
/// threads begin (the stack truncated); or through BaseThreadInitThunk
/// calling a Windows API in a module the thread didn't start in (thread-start
/// frames forged beneath the real caller).
fn judge_ends(
    p: &WinProcess,
    r: &Regs,
    frames: &[usize],
    start: Option<usize>,
    mods: &mut Modules,
) -> Option<StackFinding> {
    let named = |mods: &mut Modules, pc: usize| -> Option<(usize, Arc<Module>, String)> {
        let base = locate(p, pc)?.base?;
        let m = module_at(p, mods, base);
        let name = m.name(base, pc, true);
        Some((base, m, name))
    };
    let chain = |mods: &mut Modules, upto: usize| -> Vec<String> {
        frames[..=upto]
            .iter()
            .enumerate()
            .map(
                |(i, &pc)| match named(mods, if i == 0 { pc - 2 } else { pc }) {
                    Some((_, _, n)) => n,
                    None => format!("0x{pc:x}"),
                },
            )
            .collect()
    };
    let last = frames.len().checked_sub(1)?;
    if last >= 1 {
        let (_, m, symbol) = named(mods, frames[last])?;
        if !ends_where_threads_begin(&m.name, &symbol) {
            let mut c = chain(mods, last - 1);
            c.push(
                Frame::Truncated {
                    symbol: symbol.clone(),
                }
                .describe(frames[last]),
            );
            return Some(StackFinding {
                tid: r.tid,
                addr: frames[last],
                depth: last,
                frame: Frame::Truncated { symbol },
                chain: c,
            });
        }
    }
    // The frame BaseThreadInitThunk called.
    let k = (1..frames.len()).find(|&i| {
        named(mods, frames[i]).is_some_and(|(_, m, n)| {
            m.name == "kernel32.dll" && n.contains("!BaseThreadInitThunk+")
        })
    })?;
    let start = start?;
    let (base1, m1, symbol) = named(mods, frames[k - 1])?;
    let start_base = locate(p, start)?.base?;
    let start_module = module_at(p, mods, start_base);
    let system = m1.path.to_ascii_lowercase().contains(r"\system32\");
    if !system
        || start_base == base1
        || matches!(
            start_module.name.as_str(),
            "kernel32.dll" | "kernelbase.dll"
        )
    {
        return None;
    }
    let start_name = start_module.name(start_base, start, true);
    let frame = Frame::FakeThreadStart {
        symbol,
        start: start_name,
    };
    let mut c = if k >= 2 {
        chain(mods, k - 2)
    } else {
        Vec::new()
    };
    c.push(frame.describe(frames[k - 1]));
    Some(StackFinding {
        tid: r.tid,
        addr: frames[k - 1],
        depth: k - 1,
        frame,
        chain: c,
    })
}

/// Whether the code just before `pc` ends with a call instruction; None when
/// those bytes can't be read.
fn preceded_by_call(p: &WinProcess, pc: usize) -> Option<bool> {
    let mut before = [0u8; 15];
    let start = pc.checked_sub(before.len())?;
    if p.read(start, &mut before) == before.len() {
        return Some(unwind::follows_call(&before));
    }
    // The page before may be unreadable: what there is of this one.
    let page = pc & !0xfff;
    let n = pc - page;
    (n >= 2 && p.read(page, &mut before[..n.min(15)]) == n.min(15) && n <= 15)
        .then(|| unwind::follows_call(&before[..n]))
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use crate::memscan::windows::{open, SELFTEST};
    use crate::memscan::windows_hooks::{wide, AlignedContext};
    use core::ffi::c_void;
    use core::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetThreadContext, RtlAddFunctionTable, RtlDeleteFunctionTable, RtlLookupFunctionEntry,
        RtlVirtualUnwind, SetThreadContext, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_FULL_AMD64,
        CONTEXT_INTEGER_AMD64, IMAGE_RUNTIME_FUNCTION_ENTRY, UNW_FLAG_NHANDLER,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, VirtualProtect, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateThread, GetCurrentThreadId, OpenThread, ResumeThread, SetEvent,
        WaitForSingleObject, CREATE_SUSPENDED, INFINITE, THREAD_GET_CONTEXT,
    };

    unsafe extern "system" fn idle(_: *mut c_void) -> u32 {
        0
    }

    fn export(module: &str, name: &core::ffi::CStr) -> usize {
        // SAFETY: lookups in modules this process has loaded.
        unsafe {
            let m = GetModuleHandleW(wide(module).as_ptr());
            GetProcAddress(m, name.as_ptr().cast()).expect("export") as usize
        }
    }

    /// A thread's full context, read while it is blocked.
    fn context(h: HANDLE) -> AlignedContext {
        // SAFETY: an aligned context of a thread of ours.
        unsafe {
            let mut c: AlignedContext = core::mem::zeroed();
            c.0.ContextFlags = CONTEXT_FULL_AMD64;
            assert_ne!(GetThreadContext(h, &mut c.0), 0);
            c
        }
    }

    fn regs_of(tid: u32, c: &CONTEXT) -> Regs {
        Regs {
            tid,
            rip: c.Rip as usize,
            rsp: c.Rsp as usize,
            int: [
                c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi, c.R8, c.R9, c.R10, c.R11,
                c.R12, c.R13, c.R14, c.R15,
            ],
        }
    }

    /// The frames Windows' own unwinder finds from a context of a thread in
    /// this process.
    fn windows_frames(c: &CONTEXT) -> Vec<usize> {
        let mut c = *c;
        let mut out = vec![c.Rip as usize];
        for _ in 0..MAX_FRAMES {
            // SAFETY: unwinding a blocked thread's stack in this process.
            unsafe {
                let mut base = 0u64;
                let f = RtlLookupFunctionEntry(c.Rip, &mut base, null_mut());
                if f.is_null() {
                    c.Rip = *(c.Rsp as *const u64);
                    c.Rsp += 8;
                } else {
                    let (mut data, mut frame) = (null_mut(), 0u64);
                    RtlVirtualUnwind(
                        UNW_FLAG_NHANDLER,
                        base,
                        c.Rip,
                        f,
                        &mut c,
                        &mut data,
                        &mut frame,
                        null_mut(),
                    );
                }
            }
            if c.Rip == 0 {
                break;
            }
            out.push(c.Rip as usize);
        }
        out
    }

    /// Wait until the thread `h` is blocked in the system call whose stub
    /// starts at `stub`: just past that stub's `syscall`, at the same place on
    /// two reads 20 ms apart. (A thread caught in a short call on its way
    /// there, such as the wake-up a channel send makes, has moved on by the
    /// time its stack is read.)
    fn until_blocked(h: HANDLE, stub: usize) -> AlignedContext {
        let mut last = None;
        for _ in 0..300 {
            let c = context(h);
            let rip = c.0.Rip as usize;
            let pre = rip
                .checked_sub(2)
                .map(|a| unsafe { *(a as *const [u8; 2]) });
            let here = pre.is_some_and(is_syscall_insn) && rip > stub && rip < stub + 0x20;
            if here && last == Some((c.0.Rip, c.0.Rsp)) {
                return c;
            }
            last = here.then_some((c.0.Rip, c.0.Rsp));
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the thread never blocked in the stub at 0x{stub:x}");
    }

    /// Read memory of this process the way the scan does (bytes read).
    fn p_read(addr: usize, buf: &mut [u8]) -> usize {
        let p = WinProcess {
            h: unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
        };
        let n = p.read(addr, buf);
        core::mem::forget(p); // the pseudo-handle isn't closed
        n
    }

    /// A suspended thread (start routine `idle`) shown as blocked in a system
    /// call: Rip just past a stub's `syscall`, Rsp at a stack we laid out.
    /// Its own context goes back before it runs.
    struct Posed(HANDLE, AlignedContext);

    impl Posed {
        fn new(rip: usize, rsp: usize) -> Posed {
            // SAFETY: a suspended thread of our own, never run while posed.
            unsafe {
                let h = CreateThread(null(), 0, Some(idle), null(), CREATE_SUSPENDED, null_mut());
                assert!(!h.is_null());
                let mut s: AlignedContext = core::mem::zeroed();
                s.0.ContextFlags = CONTEXT_CONTROL_AMD64;
                assert_ne!(GetThreadContext(h, &mut s.0), 0);
                let mut c = AlignedContext(s.0);
                c.0.Rip = rip as u64;
                c.0.Rsp = rsp as u64;
                assert_ne!(SetThreadContext(h, &c.0), 0);
                Posed(h, s)
            }
        }

        fn release(self) {
            // SAFETY: the thread's own context back, then it runs `idle`.
            unsafe {
                SetThreadContext(self.0, &self.1 .0);
                ResumeThread(self.0);
                WaitForSingleObject(self.0, INFINITE);
                CloseHandle(self.0);
            }
        }
    }

    /// A thread created suspended at `start`, never run from there: its start
    /// routine is replaced by `idle` before it runs (and exits at once).
    struct Parked(HANDLE);

    impl Parked {
        fn at(start: usize) -> Parked {
            // SAFETY: a suspended thread of our own, never resumed at `start`.
            unsafe {
                let start = core::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(start);
                let h = CreateThread(null(), 0, Some(start), null(), CREATE_SUSPENDED, null_mut());
                assert!(!h.is_null());
                Parked(h)
            }
        }

        fn release(self) {
            // SAFETY: RtlUserThreadStart calls the routine in Rcx: `idle`.
            unsafe {
                let mut c: AlignedContext = core::mem::zeroed();
                c.0.ContextFlags = CONTEXT_INTEGER_AMD64;
                assert_ne!(GetThreadContext(self.0, &mut c.0), 0);
                c.0.Rcx = idle as unsafe extern "system" fn(*mut c_void) -> u32 as usize as u64;
                assert_ne!(SetThreadContext(self.0, &c.0), 0);
                ResumeThread(self.0);
                WaitForSingleObject(self.0, INFINITE);
                CloseHandle(self.0);
            }
        }
    }

    /// End to end on this process. A clean pass finds nothing and walks a
    /// waiting thread's stack exactly as Windows' own unwinder does. Then:
    /// a thread that waits from code in memory no image backs (started
    /// there), the same with that memory made non-executable while it waits
    /// (as a sleep mask leaves it), the same with the memory registered as
    /// JIT code (not judged), threads parked at LoadLibraryW and inside a
    /// function, and one posed with a return address that follows no call.
    /// The waiting code only calls WaitForSingleObject; nothing evasive runs.
    #[test]
    fn walks_stacks_and_finds_planted_threads() {
        let _serial = SELFTEST.lock();
        let me = open(std::process::id()).unwrap();
        let soon = || Instant::now() + Duration::from_secs(60);
        let wait_fn = export("kernel32.dll", c"WaitForSingleObject");

        // SAFETY: an event of our own, signalled to end the waits below.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null());

        // A Rust thread waiting on the event: its stack, walked both ways.
        let ev = event as usize;
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        // SAFETY: the thread only waits on our event.
        let waiter = std::thread::spawn(move || unsafe {
            tid_tx.send(GetCurrentThreadId()).unwrap();
            WaitForSingleObject(ev as HANDLE, INFINITE)
        });
        let tid = tid_rx.recv().unwrap();
        // SAFETY: a handle to our own thread, closed below.
        let th = unsafe { OpenThread(THREAD_GET_CONTEXT, 0, tid) };
        let wait = export("ntdll.dll", c"NtWaitForSingleObject");
        let c = until_blocked(th, wait);
        let theirs = windows_frames(&c.0);
        let p = WinProcess {
            h: unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
        };
        let nt = ntdll().as_ref().expect("ntdll");
        let mut mods = Modules::new();
        let m0 = module_at(&p, &mut mods, nt.base);
        let (walked, ours) = walk(&p, &regs_of(tid, &c.0), nt.base, &m0, Some(&[]), &mut mods);
        core::mem::forget(p); // the pseudo-handle isn't closed
        unsafe { CloseHandle(th) };
        eprintln!(
            "lrng-selftest: stack walk: ours {} frames ({walked:?}), Windows' {} frames",
            ours.len(),
            theirs.len()
        );
        assert!(
            matches!(walked, Walked::Complete),
            "{walked:?}: {ours:x?} vs {theirs:x?}"
        );
        assert_eq!(ours, theirs, "our unwinder and RtlVirtualUnwind disagree");

        let clean = me.thread_checks(soon()).unwrap().threads;
        eprintln!("lrng-selftest: threads, clean: {}", clean.meta());
        assert!(
            clean.walked >= 2 && clean.complete >= 2 && clean.jit_ranges.is_some(),
            "{}",
            clean.meta()
        );
        assert!(clean.hits().is_empty(), "{:?}", clean.hits());

        // The waiting code: sub rsp,28h; mov rcx,event; mov edx,INFINITE;
        // mov rax,WaitForSingleObject; call rax; add rsp,28h; ret. Its unwind
        // data (for the JIT pass) follows it in the page.
        let mut code = vec![0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9];
        code.extend_from_slice(&(event as u64).to_le_bytes());
        code.extend_from_slice(&[0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0xB8]);
        code.extend_from_slice(&(wait_fn as u64).to_le_bytes());
        code.extend_from_slice(&[0xFF, 0xD0]);
        let ret_off = code.len();
        code.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28, 0xC3]);
        let len = code.len() as u32;
        // SAFETY: a fresh page of our own: written, then RX; freed below.
        let page = unsafe {
            let page =
                VirtualAlloc(null(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize;
            assert_ne!(page, 0);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
            // UNWIND_INFO at +0x100: prolog 4 bytes, one code (ALLOC_SMALL 0x28).
            core::ptr::copy_nonoverlapping(
                [0x01u8, 0x04, 0x01, 0x00, 0x04, 0x42, 0, 0].as_ptr(),
                (page + 0x100) as *mut u8,
                8,
            );
            let mut old = 0u32;
            assert_ne!(
                VirtualProtect(page as *const c_void, 0x1000, PAGE_EXECUTE_READ, &mut old),
                0
            );
            page
        };
        let ret = page + ret_off;
        // SAFETY: a thread started in that page; it waits on the event.
        let sleeper = unsafe {
            let start =
                core::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(page);
            CreateThread(null(), 0, Some(start), null(), 0, null_mut())
        };
        assert!(!sleeper.is_null());
        until_blocked(sleeper, wait);

        let loadlibrary = export("kernel32.dll", c"LoadLibraryW");
        let rtl_start = export("ntdll.dll", c"RtlUserThreadStart");
        let f = m0
            .table
            .as_ref()
            .and_then(|t| t.function((rtl_start - nt.base) as u32))
            .expect("RtlUserThreadStart has unwind data");
        let inside = nt.base + (f.begin + (f.end - f.begin) / 2) as usize;
        let parked = [Parked::at(loadlibrary), Parked::at(inside)];

        // A return address that follows no call: the first of these exports
        // whose preceding bytes aren't a call.
        let no_call = [
            c"RtlAllocateHeap",
            c"RtlFreeHeap",
            c"NtClose",
            c"RtlUserThreadStart",
            c"LdrLoadDll",
        ]
        .iter()
        .map(|n| export("ntdll.dll", n))
        .find(|&a| !unwind::follows_call(unsafe { &*((a - 15) as *const [u8; 15]) }))
        .expect("an export not preceded by a call");
        let sc = (0..0x20)
            .find(|&k| unsafe { *((wait + k) as *const [u8; 2]) } == [0x0F, 0x05])
            .expect("syscall");
        let data = unsafe {
            VirtualAlloc(null(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize
        };
        assert_ne!(data, 0);
        unsafe { *((data + 0x800) as *mut u64) = no_call as u64 };
        // SAFETY: a suspended thread of our own, shown as blocked in
        // NtWaitForSingleObject with `no_call` as its return address; its own
        // context goes back before it runs.
        let posed =
            unsafe { CreateThread(null(), 0, Some(idle), null(), CREATE_SUSPENDED, null_mut()) };
        let saved = unsafe {
            let mut s: AlignedContext = core::mem::zeroed();
            s.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            assert_ne!(GetThreadContext(posed, &mut s.0), 0);
            let mut c = AlignedContext(s.0);
            c.0.Rip = (wait + sc + 2) as u64;
            c.0.Rsp = (data + 0x800) as u64;
            assert_ne!(SetThreadContext(posed, &c.0), 0);
            s
        };

        // Call-stack spoofing, posed the same way. A return address on a
        // "jmp [rbx]" gadget in kernelbase's code:
        let kb = export("kernelbase.dll", c"SleepEx");
        let gadget = (kb..kb + 0x40000)
            .find(|&a| {
                let mut b = [0u8; 2];
                p_read(a, &mut b) == 2 && b == [0xFF, 0x23]
            })
            .expect("a jmp [rbx] gadget in kernelbase");
        unsafe { *((data + 0xC00) as *mut u64) = gadget as u64 };
        // A stack that ends after WaitForSingleObjectEx (its caller's return
        // address zeroed), from the real waiter's first frame:
        unsafe { *((data + 0xA00) as *mut u64) = theirs[1] as u64 };
        let gadget_pose = Posed::new(wait + sc + 2, data + 0xC00);
        let truncated_pose = Posed::new(wait + sc + 2, data + 0xA00);
        // A thread really started at SleepEx (a Windows API: not judged),
        // and a copy of its stack under a thread that started elsewhere
        // (here, in this test's own code): BaseThreadInitThunk then appears
        // to have called SleepEx itself.
        let delay = export("ntdll.dll", c"NtDelayExecution");
        let dsc = (0..0x20)
            .find(|&k| unsafe { *((delay + k) as *const [u8; 2]) } == [0x0F, 0x05])
            .expect("syscall");
        // SAFETY: a thread of our own that sleeps until terminated below.
        let sleepy = unsafe {
            let start = core::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(
                export("kernel32.dll", c"SleepEx"),
            );
            CreateThread(
                null(),
                0,
                Some(start),
                INFINITE as usize as *const c_void,
                0,
                null_mut(),
            )
        };
        assert!(!sleepy.is_null());
        let sc_ctx = until_blocked(sleepy, delay);
        let mut copy = vec![0u8; 0x400];
        let n = p_read(sc_ctx.0.Rsp as usize, &mut copy);
        assert!(n >= 0x100, "read {n} bytes of the sleeping thread's stack");
        // The data page holds four stacks that mustn't overlap: this copy at
        // the bottom (at most 0x40F bytes in), then the posed stacks at 0x800
        // (no call), 0xA00 (truncated) and 0xC00 (gadget), each with zeros
        // above it where its walk ends.
        let forged = data + (sc_ctx.0.Rsp as usize & 0xF);
        assert!(forged + n <= data + 0x800);
        unsafe { core::ptr::copy_nonoverlapping(copy.as_ptr(), forged as *mut u8, n) };
        let forged_pose = Posed::new(delay + dsc + 2, forged);

        let planted = me.thread_checks(soon()).unwrap().threads;
        // While it waits, the waiting code is made non-executable.
        let mut old = 0u32;
        unsafe { VirtualProtect(page as *const c_void, 0x1000, PAGE_READWRITE, &mut old) };
        let hidden = me.thread_checks(soon()).unwrap().threads;
        unsafe { VirtualProtect(page as *const c_void, 0x1000, PAGE_EXECUTE_READ, &mut old) };
        // And registered as code, as a JIT would.
        let rf = Box::new([IMAGE_RUNTIME_FUNCTION_ENTRY {
            BeginAddress: 0,
            EndAddress: len,
            Anonymous:
                windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY_0 {
                    UnwindInfoAddress: 0x100,
                },
        }]);
        assert!(unsafe { RtlAddFunctionTable(rf.as_ptr(), 1, page as u64) });
        let jitted = me.thread_checks(soon()).unwrap().threads;
        assert!(unsafe { RtlDeleteFunctionTable(rf.as_ptr()) });

        // Undo it all: the waiting thread returns, the others run `idle`.
        for posed in [gadget_pose, truncated_pose, forged_pose] {
            posed.release();
        }
        unsafe {
            windows_sys::Win32::System::Threading::TerminateThread(sleepy, 0);
            WaitForSingleObject(sleepy, INFINITE);
            CloseHandle(sleepy);
            SetEvent(event);
            assert_eq!(WaitForSingleObject(sleeper, 10_000), WAIT_OBJECT_0);
            CloseHandle(sleeper);
            SetThreadContext(posed, &saved.0);
            ResumeThread(posed);
            WaitForSingleObject(posed, INFINITE);
            CloseHandle(posed);
        }
        for t in parked {
            t.release();
        }
        waiter.join().unwrap();
        unsafe {
            CloseHandle(event);
            VirtualFree(page as *mut c_void, 0, MEM_RELEASE);
            VirtualFree(data as *mut c_void, 0, MEM_RELEASE);
        }

        let show = |label: &str, r: &Report| {
            eprintln!(
                "lrng-selftest: threads, {label}: {} | {:?}",
                r.meta(),
                r.hits()
                    .iter()
                    .map(|h| (h.rule.clone(), h.severity.clone(), h.offset))
                    .collect::<Vec<_>>()
            );
        };
        show("planted", &planted);
        show("hidden", &hidden);
        show("jit", &jitted);
        let find = |r: &Report, rule: &str, sev: &str| {
            r.hits()
                .into_iter()
                .find(|h| h.rule == rule && h.severity == sev)
                .unwrap_or_else(|| panic!("no {rule} [{sev}]: {:?}", r.hits()))
        };
        assert_eq!(
            find(&planted, "memory.thread_start_unbacked", "critical").offset as usize,
            page
        );
        assert_eq!(
            find(&planted, "memory.thread_start_loadlibrary", "suspect").offset as usize,
            loadlibrary
        );
        assert_eq!(
            find(&planted, "memory.thread_start_spoofed", "suspect").offset as usize,
            inside
        );
        let s = find(&planted, "memory.stack_unbacked", "suspect");
        assert_eq!(s.offset as usize, ret);
        assert!(
            s.context.contains(
                "waiting in ntdll.dll!NtWaitForSingleObject, called from kernelbase.dll!"
            ),
            "{}",
            s.context
        );
        assert_eq!(
            find(&planted, "defense.stack_frame_no_call", "suspect").offset as usize,
            no_call
        );
        assert_eq!(
            find(&planted, "defense.stack_jmp_gadget", "suspect").offset as usize,
            gadget
        );
        assert_eq!(
            find(&planted, "defense.stack_truncated", "suspect").offset as usize,
            theirs[1]
        );
        let fake = find(&planted, "defense.stack_fake_thread_start", "suspect");
        assert!(
            fake.context.contains("kernelbase.dll!SleepEx")
                && fake.context.contains("BaseThreadInitThunk"),
            "{}",
            fake.context
        );
        assert_eq!(
            find(&hidden, "defense.stack_return_nonexec", "critical").offset as usize,
            ret
        );
        assert_eq!(
            find(&hidden, "memory.thread_start_unbacked", "suspect").offset as usize,
            page
        );
        assert!(
            !jitted
                .hits()
                .iter()
                .any(|h| h.rule == "memory.stack_unbacked")
                && jitted.jit_frames >= 1,
            "{}",
            jitted.meta()
        );
    }
}
