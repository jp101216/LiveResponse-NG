//! Reading a Windows process's system calls (judged in syscalls.rs).
//!
//! - Threads: the instruction and stack pointers windows_hooks.rs read with
//!   each thread's debug registers (GetThreadContext, read-only). A thread
//!   whose two bytes before its instruction pointer are a `syscall` is in (or
//!   just back from) a system call; where that instruction lies, and where the
//!   address at its stack pointer leads, are looked up with VirtualQueryEx.
//!   A call out of the ordinary is reported only if the thread's registers
//!   and that address read the same a second time: a thread blocked in the
//!   kernel stays put, one back from a short call has moved on and may have
//!   reused the slot. The sidecar's own calling thread is never judged.
//! - Stubs: executable memory no image backs is read with ReadProcessMemory
//!   (capped, and within the scan's time budget) and searched for stubs.
//! - ntdll copies: every image mapping whose export directory names it
//!   ntdll.dll (so a renamed copy counts) at an address other than ntdll's,
//!   and every executable view of ntdll's file.
//!
//! ntdll's own stubs come from its file on disk, once, to name them and to
//! recognise copies. 64-bit only: the stubs and calls judged here are x64's,
//! which a 32-bit process reaches only through Heaven's Gate (and its
//! threads' 64-bit context is what is read).
#![cfg_attr(not(windows), allow(dead_code))]

use super::pe;
use super::procmem::{file_name_lower, ProcessMemory};
use super::syscalls::{self, Call, NtdllCopy, Place, Report, StubRegion, StubTable};
use super::windows::{read_image_file, WinProcess};
use super::windows_hooks::{locate, read_usize, wide};
use core::ffi::c_void;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Instant;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// A thread's registers, as the syscall checks need them.
#[derive(Clone, Copy, Debug)]
pub(super) struct Regs {
    pub(super) tid: u32,
    pub(super) rip: usize,
    pub(super) rsp: usize,
    /// The integer registers in unwind-code order (RAX, RCX, RDX, RBX, RSP,
    /// RBP, RSI, RDI, R8-R15), where a stack walk starts from.
    pub(super) int: [u64; 16],
}

/// Unbacked executable memory searched per process, at most.
const MAX_STUB_SCAN: u64 = 256 << 20;
const CHUNK: usize = 1 << 20;
/// Bytes carried into the next chunk, so a stub across a boundary is seen.
const OVERLAP: usize = 64;

/// ntdll as this (64-bit) process has it: where it is mapped, which is where
/// every 64-bit process has it, and its stubs and exports from its file.
pub(super) struct Ntdll {
    pub(super) base: usize,
    pub(super) size: usize,
    pub(super) stubs: StubTable,
    exports: pe::Exports,
}

pub(super) fn ntdll() -> &'static Result<Ntdll, String> {
    static NTDLL: OnceLock<Result<Ntdll, String>> = OnceLock::new();
    NTDLL.get_or_init(|| {
        // SAFETY: lookups on this process's own ntdll, which stays loaded.
        unsafe {
            let h = GetModuleHandleW(wide("ntdll.dll").as_ptr());
            let mut mi: MODULEINFO = core::mem::zeroed();
            if h.is_null()
                || K32GetModuleInformation(
                    GetCurrentProcess(),
                    h,
                    &mut mi,
                    core::mem::size_of::<MODULEINFO>() as u32,
                ) == 0
            {
                return Err("ntdll's address range is unknown".into());
            }
            let mut buf = vec![0u16; 1024];
            let n = GetModuleFileNameW(h, buf.as_mut_ptr(), buf.len() as u32) as usize;
            let path = String::from_utf16_lossy(&buf[..n.min(buf.len())]);
            let file = read_image_file(&path).map_err(|e| format!("{path}: {e}"))?;
            let exports = pe::parse(&file)
                .map(|pe| pe.exports(&file))
                .unwrap_or_default();
            Ok(Ntdll {
                base: mi.lpBaseOfDll as usize,
                size: mi.SizeOfImage as usize,
                stubs: StubTable::from_ntdll(&file),
                exports,
            })
        }
    })
}

impl Ntdll {
    /// The export a code address in ntdll belongs to, by its first name.
    fn function(&self, addr: usize) -> String {
        let Some(rva) = addr
            .checked_sub(self.base)
            .and_then(|r| u32::try_from(r).ok())
        else {
            return String::new();
        };
        let near = self.exports.near(rva);
        near.split(['/', '+']).next().unwrap_or("").to_string()
    }

    /// Whether `name+0xoff` is inside one of ntdll's system-call stubs.
    pub(super) fn in_stub(&self, symbol: &str) -> bool {
        let Some((names, off)) = symbol.rsplit_once("+0x") else {
            return false;
        };
        usize::from_str_radix(off, 16).is_ok_and(|o| o < 0x20)
            && names.split('/').any(|n| self.stubs.is_stub(n))
    }
}

/// Read the system calls of the process `p` has open, given its threads'
/// registers and the code ranges it registered as JIT code (None when they
/// couldn't be read; see windows_threads.rs).
pub(super) fn read(
    p: &WinProcess,
    regs: &[Regs],
    jit: Option<&[(usize, usize)]>,
    deadline: Instant,
) -> Report {
    if !cfg!(target_arch = "x86_64") {
        return Report::unsupported(
            "system calls are judged in 64-bit processes, by the 64-bit sidecar",
        );
    }
    let nt = match ntdll() {
        Ok(n) => n,
        Err(e) => return Report::unsupported(e.clone()),
    };
    let mut rep = Report {
        supported: true,
        stub_table: nt.stubs.len(),
        ..Default::default()
    };
    let mut copies: BTreeMap<usize, bool> = BTreeMap::new(); // image base -> is ntdll
    let mut is_copy = |base: usize| {
        *copies
            .entry(base)
            .or_insert_with(|| image_is_ntdll(p, base))
    };

    for r in regs {
        let mut pre = [0u8; 2];
        if r.rip < 2 || p.read(r.rip - 2, &mut pre) != 2 || !syscalls::is_syscall_insn(pre) {
            continue;
        }
        rep.in_syscall += 1;
        let at = place(p, r.rip - 2, nt, &mut is_copy);
        let mut call = Call {
            tid: r.tid,
            rip: r.rip,
            at,
            stub: String::new(),
            copy_of: None,
            ret: None,
        };
        match &call.at {
            Place::System(m) => {
                if m == "ntdll.dll" {
                    call.stub = nt.function(r.rip - 2);
                }
                if let Some(ret) = read_usize(p.h, r.rsp) {
                    let at = place(p, ret, nt, &mut is_copy);
                    // A runtime's JIT code calling ntdll (a P/Invoke straight
                    // into an Nt function) is where managed code waits.
                    if matches!(at, Place::Unbacked { .. })
                        && jit.is_some_and(|j| j.iter().any(|&(lo, hi)| ret >= lo && ret < hi))
                    {
                        rep.jit += 1;
                        continue;
                    }
                    call.ret = Some((ret, at));
                }
            }
            Place::Unbacked { .. } => call.copy_of = copied_stub(p, r.rip, &nt.stubs),
            _ => {}
        }
        // Keep what isn't an ordinary call: made outside ntdll and win32u,
        // or returning anywhere but into an image.
        let ordinary = matches!(call.at, Place::System(_))
            && !matches!(
                call.ret,
                Some((
                    _,
                    Place::Unbacked { .. } | Place::NotExecutable { .. } | Place::Nothing
                ))
            );
        if !ordinary {
            // The registers were read a while ago. A thread back from a short
            // call has run on, and may have reused the stack slot read above:
            // report only a thread still where it was.
            if !still_in_call(p, r, call.ret.as_ref().map(|(ret, _)| *ret)) {
                rep.moved += 1;
                continue;
            }
            rep.calls.push(call);
        }
    }

    scan_memory(p, nt, deadline, &mut rep);
    for (base, path) in images(p) {
        if base != nt.base && is_copy(base) {
            rep.ntdll_copies.push(NtdllCopy {
                base,
                path,
                file_view: false,
            });
        }
    }
    rep
}

/// Whether a thread is still at the instruction and stack pointers it was
/// read with, and (when given) the address at its stack pointer is still
/// `ret`. A thread blocked in a system call stays put.
pub(super) fn still_in_call(p: &WinProcess, r: &Regs, ret: Option<usize>) -> bool {
    registers_now(r.tid) == Some((r.rip, r.rsp))
        && ret.is_none_or(|v| read_usize(p.h, r.rsp) == Some(v))
}

/// A thread's instruction and stack pointers, read now.
#[cfg(target_arch = "x86_64")]
fn registers_now(tid: u32) -> Option<(usize, usize)> {
    use super::windows_hooks::AlignedContext;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT_CONTROL_AMD64};
    use windows_sys::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};
    // SAFETY: the handle is closed below; the context is aligned and only its
    // control registers are asked for.
    unsafe {
        let th = OpenThread(THREAD_GET_CONTEXT, 0, tid);
        if th.is_null() {
            return None;
        }
        let mut c: AlignedContext = core::mem::zeroed();
        c.0.ContextFlags = CONTEXT_CONTROL_AMD64;
        let ok = GetThreadContext(th, &mut c.0) != 0;
        CloseHandle(th);
        ok.then_some((c.0.Rip as usize, c.0.Rsp as usize))
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn registers_now(_: u32) -> Option<(usize, usize)> {
    None
}

/// Where an address lies, for the syscall checks.
fn place(p: &WinProcess, addr: usize, nt: &Ntdll, is_copy: &mut dyn FnMut(usize) -> bool) -> Place {
    let Some(m) = locate(p, addr) else {
        return Place::Nothing;
    };
    if !m.exec {
        return Place::NotExecutable {
            kind: m.kind.into(),
            protect: m.protect.into(),
        };
    }
    let Some(base) = m.base else {
        return Place::Unbacked {
            kind: m.kind.into(),
            protect: m.protect.into(),
        };
    };
    if base == nt.base {
        return Place::System("ntdll.dll".into());
    }
    let path = p.mapped_file(base);
    let name = file_name_lower(&path);
    // win32u holds the win32k system calls; in a 32-bit process, wow64cpu
    // makes the calls WoW64 dispatches itself, and wow64win makes the win32k
    // ones (its own stubs for the 32-bit user32 and gdi32).
    if matches!(
        name.as_str(),
        "win32u.dll" | "wow64cpu.dll" | "wow64win.dll"
    ) && path
        .to_ascii_lowercase()
        .ends_with(&format!(r"\system32\{name}"))
    {
        return Place::System(name);
    }
    if is_copy(base) {
        return Place::NtdllCopy;
    }
    Place::Image(name)
}

/// The ntdll stub a `syscall` just before `rip` belongs to, when it is a
/// byte-for-byte copy of one.
fn copied_stub(p: &WinProcess, rip: usize, table: &StubTable) -> Option<String> {
    let mut w = [0u8; 0x30];
    let start = rip.checked_sub(0x28)?;
    if p.read(start, &mut w) < 0x28 {
        return None;
    }
    // The last `mov r10, rcx; mov eax, imm32` before the syscall (at 0x26).
    let k = (0..0x26 - 3)
        .rev()
        .find(|&k| w[k..].starts_with(&[0x4C, 0x8B, 0xD1, 0xB8]))?;
    table.copy_of(&w[k..]).map(str::to_string)
}

/// Whether the image mapped at `base` is ntdll: a 64-bit image whose export
/// directory names it ntdll.dll (a renamed copy still does).
fn image_is_ntdll(p: &WinProcess, base: usize) -> bool {
    let mut h = [0u8; 0x400];
    let n = p.read(base, &mut h);
    let h = &h[..n];
    let u16_at = |o: usize| h.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| {
        h.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(nt) = u32_at(0x3c).map(|v| v as usize) else {
        return false;
    };
    if h.get(nt..nt + 4) != Some(b"PE\0\0") || u16_at(nt + 4) != Some(0x8664) {
        return false;
    }
    let opt = nt + 24;
    if u16_at(opt) != Some(0x20b) {
        return false;
    }
    let Some(export) = u32_at(opt + 112).filter(|&v| v != 0) else {
        return false;
    };
    let mut dir = [0u8; 16];
    if p.read(base + export as usize, &mut dir) != 16 {
        return false;
    }
    let name_rva = u32::from_le_bytes([dir[12], dir[13], dir[14], dir[15]]) as usize;
    let mut name = [0u8; 10];
    p.read(base + name_rva, &mut name) == 10 && name.eq_ignore_ascii_case(b"ntdll.dll\0")
}

/// The process's image mappings: allocation base and file.
fn images(p: &WinProcess) -> Vec<(usize, String)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    walk(p, |mbi| {
        if mbi.Type == MEM_IMAGE && seen.insert(mbi.AllocationBase as usize) {
            out.push((
                mbi.AllocationBase as usize,
                p.mapped_file(mbi.AllocationBase as usize),
            ));
        }
        true
    });
    out
}

/// Visit every committed region; `f` returns false to stop.
fn walk(p: &WinProcess, mut f: impl FnMut(&MEMORY_BASIC_INFORMATION) -> bool) {
    let mut addr = 0usize;
    for _ in 0..1_000_000 {
        // SAFETY: mbi is a plain-data struct VirtualQueryEx fills in.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
        let n = unsafe {
            VirtualQueryEx(
                p.h,
                addr as *const c_void,
                &mut mbi,
                core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            return;
        }
        if mbi.State == MEM_COMMIT && !f(&mbi) {
            return;
        }
        match (mbi.BaseAddress as usize).checked_add(mbi.RegionSize) {
            Some(next) if next > addr => addr = next,
            _ => return,
        }
    }
}

fn executable(protect: u32) -> bool {
    protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        && matches!(
            protect & 0xff,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
}

/// Search executable memory no image backs for stubs, and note executable
/// views of ntdll's file.
fn scan_memory(p: &WinProcess, nt: &Ntdll, deadline: Instant, rep: &mut Report) {
    let mut regions = Vec::new();
    walk(p, |mbi| {
        if mbi.Type != MEM_IMAGE && executable(mbi.Protect) {
            regions.push((
                mbi.BaseAddress as usize,
                mbi.RegionSize,
                mbi.Type,
                super::windows::protect_name(mbi.Protect),
                mbi.AllocationBase as usize,
            ));
        }
        true
    });
    let mut views = BTreeSet::new();
    let mut buf = vec![0u8; CHUNK + OVERLAP];
    'regions: for (base, size, ty, protect, alloc) in regions {
        let kind = if ty == MEM_MAPPED {
            "mapped"
        } else {
            "private"
        };
        if ty == MEM_MAPPED && views.insert(alloc) {
            let path = p.mapped_file(base);
            if file_name_lower(&path) == "ntdll.dll" {
                rep.ntdll_copies.push(NtdllCopy {
                    base: alloc,
                    path,
                    file_view: true,
                });
            }
        }
        let mut found = Vec::new();
        let mut off = 0usize;
        while off < size {
            if Instant::now() >= deadline {
                rep.scan_stopped = Some("time budget exhausted".into());
                break 'regions;
            }
            if rep.bytes_scanned >= MAX_STUB_SCAN {
                rep.scan_stopped = Some("byte cap reached".into());
                break 'regions;
            }
            let want = (size - off).min(CHUNK + OVERLAP);
            let n = p.read(base + off, &mut buf[..want]);
            if n == 0 {
                off += CHUNK;
                continue;
            }
            rep.bytes_scanned += n as u64;
            let mut read = |a: usize, b: &mut [u8]| p.read(a, b);
            let s = syscalls::scan(&buf[..n], base + off, &nt.stubs, &mut read);
            // A match starting in the overlap is the next chunk's.
            let limit = base + off + CHUNK;
            found.extend(s.stubs.into_iter().filter(|x| x.addr < limit));
            rep.stub_copies += s.copies;
            rep.trampolines += s.trampolines;
            off += CHUNK;
        }
        if !found.is_empty() {
            found.dedup_by_key(|x| x.addr);
            rep.stub_regions.push(StubRegion {
                base,
                size,
                kind: kind.into(),
                protect: protect.into(),
                stubs: found,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memscan::windows::{open, SELFTEST};
    use crate::memscan::windows_hooks::AlignedContext;
    use core::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_EXECUTE, GENERIC_READ, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, OPEN_EXISTING};
    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetThreadContext, SetThreadContext, CONTEXT_CONTROL_AMD64,
    };
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualAlloc, VirtualFree,
        VirtualProtect, FILE_MAP_EXECUTE, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MEM_RELEASE,
        MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE, SEC_IMAGE,
    };
    use windows_sys::Win32::System::Threading::{
        CreateThread, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED, INFINITE,
    };

    unsafe extern "system" fn idle(_: *mut c_void) -> u32 {
        0
    }

    /// A thread created suspended, never run while the test poses it, and
    /// its own context to put back before it runs (and exits at once).
    struct Posed {
        h: HANDLE,
        saved: AlignedContext,
    }

    impl Posed {
        fn new() -> Posed {
            // SAFETY: a suspended thread of our own; its context is aligned.
            unsafe {
                let h = CreateThread(null(), 0, Some(idle), null(), CREATE_SUSPENDED, null_mut());
                assert!(!h.is_null());
                let mut saved: AlignedContext = core::mem::zeroed();
                saved.0.ContextFlags = CONTEXT_CONTROL_AMD64;
                assert_ne!(GetThreadContext(h, &mut saved.0), 0);
                Posed { h, saved }
            }
        }

        /// Show the thread as stopped at `rip` with its stack at `rsp`.
        fn pose(&self, rip: usize, rsp: usize) {
            let mut c = AlignedContext(self.saved.0);
            c.0.Rip = rip as u64;
            c.0.Rsp = rsp as u64;
            // SAFETY: the thread is suspended and has never run.
            assert_ne!(unsafe { SetThreadContext(self.h, &c.0) }, 0);
        }

        fn release(self) {
            // SAFETY: its own context back, then it runs `idle` and exits.
            unsafe {
                SetThreadContext(self.h, &self.saved.0);
                ResumeThread(self.h);
                WaitForSingleObject(self.h, INFINITE);
                CloseHandle(self.h);
            }
        }
    }

    /// ntdll mapped once more: an image view of its file, and a plain view
    /// of it made executable. Neither is ever run.
    fn map_ntdll(executable: bool) -> (usize, HANDLE, HANDLE) {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let path = wide(&format!(r"{root}\System32\ntdll.dll"));
        // SAFETY: plain handles and a read-only (or read-execute) view, closed by the caller.
        unsafe {
            let access = if executable {
                GENERIC_READ | GENERIC_EXECUTE
            } else {
                GENERIC_READ
            };
            let f = CreateFileW(
                path.as_ptr(),
                access,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            assert_ne!(f, windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE);
            let (protect, view) = if executable {
                (PAGE_EXECUTE_READ, FILE_MAP_READ | FILE_MAP_EXECUTE)
            } else {
                (PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ)
            };
            let m = CreateFileMappingW(f, null(), protect, 0, 0, null());
            assert!(!m.is_null(), "CreateFileMappingW");
            let v = MapViewOfFile(m, view, 0, 0, 0);
            assert!(!v.Value.is_null(), "MapViewOfFile");
            (v.Value as usize, f, m)
        }
    }

    /// End to end on this process: a clean pass finds nothing; then inert
    /// stubs of the shapes direct- and indirect-syscall tools emit (with a
    /// hook trampoline and a copy of ntdll's stub, which aren't reported),
    /// threads posed as stopped in system calls (direct from injected memory,
    /// from a copied stub, and through ntdll returning into injected or
    /// non-executable memory), and two extra mappings of ntdll must each be
    /// found at the right address. Nothing planted is ever executed.
    #[test]
    fn finds_planted_system_calls() {
        let _serial = SELFTEST.lock();
        let me = open(std::process::id()).unwrap();
        let soon = || Instant::now() + Duration::from_secs(60);
        let nt = ntdll().as_ref().expect("ntdll");
        let clean = me.thread_checks(soon()).unwrap().calls;
        eprintln!("lrng-selftest: system calls, clean: {}", clean.meta());
        assert!(nt.stubs.len() > 300, "{} ntdll stubs known", nt.stubs.len());
        assert!(clean.supported && clean.in_syscall >= 1, "{}", clean.meta());
        assert!(clean.hits().is_empty(), "{:?}", clean.hits());

        // ntdll's NtWaitForSingleObject stub, as mapped here (unhooked), and
        // its syscall instruction.
        // SAFETY: reading ntdll's own code in this process.
        let (wait, stub) = unsafe {
            let m = GetModuleHandleW(wide("ntdll.dll").as_ptr());
            let f = GetProcAddress(m, c"NtWaitForSingleObject".as_ptr().cast()).unwrap() as usize;
            (f, *(f as *const [u8; 0x20]))
        };
        let sc = stub
            .windows(2)
            .position(|w| w == [0x0F, 0x05])
            .expect("a syscall in the stub");
        let ntdll_syscall = wait + sc;

        let mut code = vec![0xCCu8; 0x200];
        let mut at = 0x10;
        let mut put = |b: &[u8]| {
            let start = at;
            code[start..start + b.len()].copy_from_slice(b);
            at += b.len() + 8;
            start
        };
        let direct = put(&[0x4C, 0x8B, 0xD1, 0xB8, 0x04, 0, 0, 0, 0x0F, 0x05, 0xC3]);
        let mut indirect = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x04, 0, 0, 0, 0x49, 0xBB];
        indirect.extend_from_slice(&(ntdll_syscall as u64).to_le_bytes());
        indirect.extend_from_slice(&[0x41, 0xFF, 0xE3]);
        put(&indirect);
        put(&[0x4C, 0x8B, 0xD1, 0x41, 0xFF, 0xE3]);
        let mut trampoline = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x04, 0, 0, 0, 0x49, 0xBB];
        trampoline.extend_from_slice(&((wait + 8) as u64).to_le_bytes());
        trampoline.extend_from_slice(&[0x41, 0xFF, 0xE3]);
        put(&trampoline);
        let copy = put(&stub[..sc + 3]);

        // SAFETY: two fresh pages of our own: the code page made RX once
        // written (never run), a RW page for posed stacks; both freed below.
        let (page, data) = unsafe {
            let page =
                VirtualAlloc(null(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize;
            let data =
                VirtualAlloc(null(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) as usize;
            assert!(page != 0 && data != 0);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
            let mut old = 0u32;
            assert_ne!(
                VirtualProtect(page as *const c_void, 0x1000, PAGE_EXECUTE_READ, &mut old),
                0
            );
            *((data + 0x100) as *mut u64) = (page + 0x180) as u64; // returns into injected code
            *((data + 0x200) as *mut u64) = (data + 0x800) as u64; // returns into RW memory
            (page, data)
        };
        let posed: Vec<Posed> = (0..4).map(|_| Posed::new()).collect();
        posed[0].pose(page + direct + 10, data + 0x300);
        posed[1].pose(page + copy + sc + 2, data + 0x300);
        posed[2].pose(ntdll_syscall + 2, data + 0x100);
        posed[3].pose(ntdll_syscall + 2, data + 0x200);
        let (image, f1, m1) = map_ntdll(false);
        let (view, f2, m2) = map_ntdll(true);

        let after = me.thread_checks(soon()).unwrap().calls;

        for p in posed {
            p.release();
        }
        // SAFETY: undoing the mappings and pages above.
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: image as *mut c_void,
            });
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: view as *mut c_void,
            });
            for h in [m1, f1, m2, f2] {
                CloseHandle(h);
            }
            VirtualFree(page as *mut c_void, 0, MEM_RELEASE);
            VirtualFree(data as *mut c_void, 0, MEM_RELEASE);
        }

        let hits = after.hits();
        eprintln!(
            "lrng-selftest: system calls, planted: {} | {:?}",
            after.meta(),
            hits.iter()
                .map(|h| (&h.rule, &h.severity, h.offset))
                .collect::<Vec<_>>()
        );
        let find = |rule: &str, sev: &str| {
            hits.iter()
                .find(|h| h.rule == rule && h.severity == sev)
                .unwrap_or_else(|| panic!("no {rule} [{sev}]: {hits:?}"))
        };
        assert_eq!(
            find("defense.direct_syscall", "critical").offset as usize,
            page + direct + 10
        );
        let c = find("defense.direct_syscall", "notable");
        assert!(
            c.context
                .contains("copy of ntdll's NtWaitForSingleObject stub"),
            "{}",
            c.context
        );
        assert_eq!(
            find("defense.indirect_syscall", "suspect").offset as usize,
            ntdll_syscall + 2
        );
        assert_eq!(
            find("defense.syscall_return_nonexec", "critical").offset as usize,
            ntdll_syscall + 2
        );
        // The planted page by its address: the executable view of ntdll's
        // file is searched too, and is reported as a copy of ntdll below.
        let s = hits
            .iter()
            .find(|h| h.rule == "memory.syscall_stub" && h.offset as usize == page + direct)
            .unwrap_or_else(|| panic!("no memory.syscall_stub at 0x{:x}: {hits:?}", page + direct));
        assert_eq!(s.severity, "suspect");
        assert!(
            s.context.contains("holds 3 system-call stub(s)"),
            "{}",
            s.context
        );
        assert!(
            after.stub_copies >= 1 && after.trampolines >= 1,
            "{}",
            after.meta()
        );
        assert_eq!(
            find("defense.ntdll_second_copy", "suspect").offset as usize,
            image
        );
        assert_eq!(
            find("defense.ntdll_second_copy", "critical").offset as usize,
            view
        );
    }
}
