//! Reading a Windows process's exception hooks (judged in hooks.rs).
//!
//! Hardware breakpoints: every thread of the process is opened with
//! THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION and only its debug
//! registers are read (GetThreadContext with CONTEXT_DEBUG_REGISTERS; the
//! thread isn't suspended, and nothing is set).
//!
//! Vectored handlers: ntdll keeps them on two lists, exception handlers and
//! continue handlers, whose heads sit in ntdll's data section. ntdll is mapped
//! at the same address in every process of one architecture for the life of
//! a boot, so the heads are at the same addresses in the target as here. The
//! sidecar finds them once by registering a no-op handler of each kind in its
//! own process, following that entry to its list's head, noting where in the
//! entry the (pointer-encoded) handler is stored, and removing the handler
//! again. A target's lists are then read with ReadProcessMemory, each entry
//! checked against its neighbours, the whole list read twice so one changing
//! underneath isn't misread, and each handler decoded with DecodeRemotePointer
//! (which reads the target's pointer cookie). Nothing is written to the
//! target. A 32-bit process scanned by the 64-bit sidecar keeps its handlers
//! in its own 32-bit ntdll, which this doesn't read; its debug registers are
//! still checked.
#![cfg_attr(not(windows), allow(dead_code))]

use super::hooks::{self, Handler, HandlerList, Report};
use super::pe;
use super::procmem::{file_name_lower, ProcessMemory};
use super::windows::{protect_name, read_image_file, WinProcess};
use core::ffi::c_void;
use std::collections::BTreeMap;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredContinueHandler, AddVectoredExceptionHandler, CheckRemoteDebuggerPresent,
    DecodePointer, GetThreadContext, ReadProcessMemory, RemoveVectoredContinueHandler,
    RemoveVectoredExceptionHandler, CONTEXT, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, IsWow64Process, OpenThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_LIMITED_INFORMATION,
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_DEBUG: u32 =
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
#[cfg(target_arch = "x86")]
const CONTEXT_DEBUG: u32 =
    windows_sys::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86;

/// Sanity caps: threads read per process, handlers per list.
const MAX_THREADS: usize = 8192;
const MAX_HANDLERS: usize = 64;
const PTR: usize = core::mem::size_of::<usize>();

/// CONTEXT, aligned as GetThreadContext requires on x64.
#[repr(C, align(16))]
pub(super) struct AlignedContext(pub(super) CONTEXT);

pub(super) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Read the exception hooks of the process `p` has open.
pub(super) fn read(p: &WinProcess) -> Report {
    if !cfg!(any(target_arch = "x86_64", target_arch = "x86")) {
        return Report::unsupported("debug registers are read on x86 and x64 only");
    }
    // SAFETY: plain Win32 queries on valid handles.
    let pid = unsafe { GetProcessId(p.h) };
    let me = unsafe { GetCurrentProcess() };
    let (self_wow, target_wow) = (wow64(me), wow64(p.h));
    if cfg!(target_pointer_width = "32") && self_wow == Some(true) && target_wow == Some(false) {
        return Report::unsupported("a 64-bit process can't be read from the 32-bit sidecar");
    }
    let mut rep = Report {
        supported: true,
        ..Default::default()
    };
    let mut present = 0i32;
    // SAFETY: present receives a BOOL.
    if unsafe { CheckRemoteDebuggerPresent(p.h, &mut present) } != 0 {
        rep.debugged = Some(present != 0);
    }
    read_breakpoints(pid, &mut rep);

    if self_wow.is_none() || self_wow != target_wow {
        rep.handlers_skipped = Some(
            "a 32-bit process: its vectored handlers are in its own 32-bit ntdll, which isn't read"
                .into(),
        );
    } else {
        match layout() {
            Err(e) => rep.handlers_skipped = Some(e.clone()),
            Ok(l) => match read_handlers(p, l) {
                Err(e) => rep.handlers_skipped = Some(e),
                Ok(hs) => {
                    rep.handlers_walked = true;
                    for (list, addr) in hs {
                        match locate(p, addr) {
                            Some(m) if m.exec => rep.handlers.push(Handler {
                                list,
                                addr,
                                kind: m.kind.into(),
                                protect: m.protect.into(),
                                module: m
                                    .base
                                    .map(|b| file_name_lower(&p.mapped_file(b)))
                                    .unwrap_or_default(),
                            }),
                            _ => rep.handlers_invalid += 1,
                        }
                    }
                }
            },
        }
    }

    // Name what each breakpoint sits on: the image and its nearest export.
    let mut exports: BTreeMap<usize, (String, pe::Exports)> = BTreeMap::new();
    for b in &mut rep.breakpoints {
        let Some(base) = locate(p, b.addr).and_then(|m| m.base) else {
            continue;
        };
        let (module, ex) = exports.entry(base).or_insert_with(|| {
            let path = p.mapped_file(base);
            let ex = read_image_file(&path)
                .ok()
                .and_then(|file| pe::parse(&file).ok().map(|pe| pe.exports(&file)))
                .unwrap_or_default();
            (file_name_lower(&path), ex)
        });
        b.module = module.clone();
        b.symbol = u32::try_from(b.addr - base)
            .map(|rva| ex.near(rva))
            .unwrap_or_default();
    }
    rep
}

fn wow64(h: HANDLE) -> Option<bool> {
    let mut w = 0i32;
    // SAFETY: w receives a BOOL.
    (unsafe { IsWow64Process(h, &mut w) } != 0).then_some(w != 0)
}

/// Every thread of `pid`, from one system-wide thread snapshot.
fn threads_of(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    // SAFETY: the snapshot handle is closed below; te.dwSize is set as the
    // API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE || snap.is_null() {
            return out;
        }
        let mut te: THREADENTRY32 = core::mem::zeroed();
        te.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
        let mut ok = Thread32First(snap, &mut te);
        while ok != 0 && out.len() < MAX_THREADS {
            if te.th32OwnerProcessID == pid {
                out.push(te.th32ThreadID);
            }
            ok = Thread32Next(snap, &mut te);
        }
        CloseHandle(snap);
    }
    out
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
fn read_breakpoints(_: u32, _: &mut Report) {}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn read_breakpoints(pid: u32, rep: &mut Report) {
    for tid in threads_of(pid) {
        // SAFETY: the thread handle is closed below; the context is aligned
        // and only its debug registers are asked for.
        unsafe {
            let th = OpenThread(
                THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                tid,
            );
            if th.is_null() {
                rep.threads_unreadable += 1;
                continue;
            }
            let mut c: AlignedContext = core::mem::zeroed();
            c.0.ContextFlags = CONTEXT_DEBUG;
            if GetThreadContext(th, &mut c.0) != 0 {
                rep.threads += 1;
                let dr = [
                    c.0.Dr0 as usize,
                    c.0.Dr1 as usize,
                    c.0.Dr2 as usize,
                    c.0.Dr3 as usize,
                ];
                rep.breakpoints
                    .extend(hooks::armed(tid, dr, c.0.Dr7 as usize));
            } else {
                rep.threads_unreadable += 1;
            }
            CloseHandle(th);
        }
    }
}

/// The memory an address points into.
struct Mem {
    kind: &'static str,
    protect: &'static str,
    exec: bool,
    /// The image's allocation base, for image memory.
    base: Option<usize>,
}

fn locate(p: &WinProcess, addr: usize) -> Option<Mem> {
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
    if n == 0 || mbi.State != MEM_COMMIT {
        return None;
    }
    let exec = mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
        && matches!(
            mbi.Protect & 0xff,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        );
    let (kind, base) = match mbi.Type {
        MEM_IMAGE => ("image", Some(mbi.AllocationBase as usize)),
        MEM_MAPPED => ("mapped", None),
        _ => ("private", None),
    };
    Some(Mem {
        kind,
        protect: protect_name(mbi.Protect),
        exec,
        base,
    })
}

fn read_usize(h: HANDLE, addr: usize) -> Option<usize> {
    let mut v = [0u8; PTR];
    let mut got = 0usize;
    // SAFETY: v holds PTR bytes; got receives the count.
    let ok = unsafe {
        ReadProcessMemory(
            h,
            addr as *const c_void,
            v.as_mut_ptr() as *mut c_void,
            PTR,
            &mut got,
        )
    };
    (ok != 0 && got == PTR).then(|| usize::from_ne_bytes(v))
}

/// Where the handler lists are, and where a handler sits in an entry.
#[derive(Clone, Copy, Debug)]
pub(super) struct Layout {
    pub(super) heads: [(HandlerList, usize); 2],
    pub(super) handler_off: usize,
}

/// The no-op handler registered to find the lists. Returns
/// EXCEPTION_CONTINUE_SEARCH: an exception that reaches it in the moment it
/// is registered goes on to the next handler as if it weren't there.
unsafe extern "system" fn probe(_: *mut EXCEPTION_POINTERS) -> i32 {
    0
}

pub(super) fn layout() -> &'static Result<Layout, String> {
    static LAYOUT: OnceLock<Result<Layout, String>> = OnceLock::new();
    LAYOUT.get_or_init(discover)
}

fn discover() -> Result<Layout, String> {
    // SAFETY: Win32 calls on this process; every handler registered here is
    // removed before this function returns.
    unsafe {
        let me = GetCurrentProcess();
        let ntdll = GetModuleHandleW(wide("ntdll.dll").as_ptr());
        let mut mi: MODULEINFO = core::mem::zeroed();
        if ntdll.is_null()
            || K32GetModuleInformation(
                me,
                ntdll,
                &mut mi,
                core::mem::size_of::<MODULEINFO>() as u32,
            ) == 0
        {
            return Err("ntdll's address range is unknown".into());
        }
        let range = (mi.lpBaseOfDll as usize, mi.SizeOfImage as usize);
        let mut heads = [
            (HandlerList::Exception, 0usize),
            (HandlerList::Continue, 0usize),
        ];
        let mut offset = None;
        for (list, head) in heads.iter_mut() {
            let entry = match list {
                HandlerList::Exception => AddVectoredExceptionHandler(0, Some(probe)),
                HandlerList::Continue => AddVectoredContinueHandler(0, Some(probe)),
            };
            if entry.is_null() {
                return Err("couldn't register a probe handler to find the handler lists".into());
            }
            let found = find_head(me, entry as usize, range);
            match list {
                HandlerList::Exception => RemoveVectoredExceptionHandler(entry),
                HandlerList::Continue => RemoveVectoredContinueHandler(entry),
            };
            let (h, off) = found?;
            *head = h;
            match offset {
                Some(o) if o != off => {
                    return Err("the two handler lists store handlers differently".into())
                }
                _ => offset = Some(off),
            }
        }
        Ok(Layout {
            heads,
            handler_off: offset.unwrap_or(0),
        })
    }
}

/// From our own probe's entry: where its encoded handler is, and the head of
/// its list (the first link that leads into ntdll).
fn find_head(me: HANDLE, entry: usize, ntdll: (usize, usize)) -> Result<(usize, usize), String> {
    let want = probe as unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32 as usize;
    let off = (2..=8)
        .map(|i| i * PTR)
        .find(|&o| {
            // SAFETY: DecodePointer only does arithmetic on the value.
            read_usize(me, entry + o)
                .is_some_and(|v| unsafe { DecodePointer(v as *const c_void) } as usize == want)
        })
        .ok_or("the probe handler wasn't found in its list entry")?;
    let mut at = entry;
    for _ in 0..MAX_HANDLERS * 4 {
        at = read_usize(me, at).ok_or("a handler list entry is unreadable")?;
        if at >= ntdll.0 && at - ntdll.0 < ntdll.1 {
            return Ok((at, off));
        }
        if at == entry {
            break;
        }
    }
    Err("the handler list's head wasn't found in ntdll".into())
}

type DecodeRemote = unsafe extern "system" fn(HANDLE, *const c_void, *mut *mut c_void) -> i32;

/// DecodeRemotePointer (Windows 10 and later), found at run time so the
/// sidecar still starts where it is missing.
fn decode_remote() -> Option<DecodeRemote> {
    static F: OnceLock<Option<usize>> = OnceLock::new();
    let f = F.get_or_init(|| {
        ["kernelbase.dll", "kernel32.dll"].iter().find_map(|dll| {
            // SAFETY: plain lookups; the module stays loaded for the process's life.
            unsafe {
                let m = GetModuleHandleW(wide(dll).as_ptr());
                if m.is_null() {
                    return None;
                }
                GetProcAddress(m, c"DecodeRemotePointer".as_ptr().cast()).map(|f| f as usize)
            }
        })
    });
    // SAFETY: the export has this signature.
    f.map(|a| unsafe { core::mem::transmute::<usize, DecodeRemote>(a) })
}

/// One pass over a list: (entry, encoded handler) in order, or why the list
/// can't be trusted.
fn walk(h: HANDLE, head: usize, off: usize) -> Result<Vec<(usize, usize)>, String> {
    let mut out = Vec::new();
    let mut prev = head;
    let mut e = read_usize(h, head).ok_or("the handler list is unreadable")?;
    while e != head {
        if out.len() >= MAX_HANDLERS {
            return Err("a handler list is too long, or changing".into());
        }
        // Every entry links back to the one before it.
        if read_usize(h, e + PTR) != Some(prev) {
            return Err("a handler list is inconsistent".into());
        }
        let enc = read_usize(h, e + off).ok_or("a handler list entry is unreadable")?;
        out.push((e, enc));
        prev = e;
        e = read_usize(h, e).ok_or("a handler list entry is unreadable")?;
    }
    Ok(out)
}

/// Both lists' handlers, decoded. A list is read twice, and read again if the
/// two passes differ, so a list changing underneath isn't misread.
fn read_handlers(p: &WinProcess, l: &Layout) -> Result<Vec<(HandlerList, usize)>, String> {
    let decode =
        decode_remote().ok_or("DecodeRemotePointer is unavailable (Windows 10 or later)")?;
    let mut out = Vec::new();
    for (list, head) in l.heads {
        let mut entries = None;
        for _ in 0..3 {
            let a = walk(p.h, head, l.handler_off);
            if a.is_ok() && a == walk(p.h, head, l.handler_off) {
                entries = a.ok();
                break;
            }
        }
        let entries = entries.ok_or("a handler list kept changing while it was read")?;
        for (_, enc) in entries {
            let mut dec: *mut c_void = core::ptr::null_mut();
            // SAFETY: dec receives the decoded pointer.
            let hr = unsafe { decode(p.h, enc as *const c_void, &mut dec) };
            if hr != 0 {
                return Err(format!(
                    "the process's pointer cookie can't be read (HRESULT 0x{:08X}): its handlers can't be decoded",
                    hr as u32
                ));
            }
            out.push((list, dec as usize));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memscan::windows::open;
    use windows_sys::Win32::System::Diagnostics::Debug::SetThreadContext;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentThreadId, ResumeThread, SuspendThread, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    fn export(module: &str, name: &core::ffi::CStr, load: bool) -> usize {
        // SAFETY: plain lookups of system DLL exports.
        unsafe {
            let w = wide(module);
            let m = if load {
                LoadLibraryW(w.as_ptr())
            } else {
                GetModuleHandleW(w.as_ptr())
            };
            assert!(!m.is_null(), "{module} not loaded");
            GetProcAddress(m, name.as_ptr().cast()).expect("export") as usize
        }
    }

    /// Set (or, with addrs all zero, clear) execute breakpoints on a thread.
    fn set_breakpoints(th: HANDLE, addrs: [usize; 3]) {
        // SAFETY: the thread is our own helper, suspended around the change.
        unsafe {
            assert_ne!(SuspendThread(th), u32::MAX);
            let mut c: AlignedContext = core::mem::zeroed();
            c.0.ContextFlags = CONTEXT_DEBUG;
            assert_ne!(GetThreadContext(th, &mut c.0), 0);
            c.0.Dr0 = addrs[0] as _;
            c.0.Dr1 = addrs[1] as _;
            c.0.Dr2 = addrs[2] as _;
            c.0.Dr7 = if addrs[0] == 0 { 0 } else { 0b01_0101 }; // L0, L1, L2: execute, 1 byte
            assert_ne!(SetThreadContext(th, &c.0), 0);
            ResumeThread(th);
        }
    }

    /// End to end on this process: a clean read finds this test binary's own
    /// handler (Rust's stack-overflow handler) and nothing to report; then a
    /// handler planted in private executable memory, on both lists, and
    /// hardware breakpoints on AmsiScanBuffer, EtwEventWrite and Sleep on a
    /// parked thread must each be found at the right address.
    #[test]
    fn finds_planted_exception_hooks() {
        let me = open(std::process::id()).unwrap();
        let clean = me.exception_hooks().expect("supported on Windows");
        eprintln!("lrng-selftest: exception hooks, clean: {}", clean.meta());
        assert!(clean.supported && clean.handlers_walked, "{}", clean.meta());
        assert!(clean.threads >= 1, "{}", clean.meta());
        let exe = file_name_lower(&std::env::current_exe().unwrap().to_string_lossy());
        assert!(
            clean
                .handlers
                .iter()
                .any(|h| h.list == HandlerList::Exception && h.module == exe),
            "Rust's own handler in {exe} wasn't found: {:?}",
            clean.handlers
        );
        assert!(clean.hits().is_empty(), "{:?}", clean.hits());

        // `xor eax, eax; ret` (x86: `ret 4`): EXCEPTION_CONTINUE_SEARCH, so the
        // handler is harmless if an exception reaches it.
        #[cfg(target_arch = "x86_64")]
        let code: &[u8] = &[0x31, 0xC0, 0xC3];
        #[cfg(target_arch = "x86")]
        let code: &[u8] = &[0x31, 0xC0, 0xC2, 0x04, 0x00];
        // SAFETY: a fresh RWX page holding the stub; registered as a handler on
        // both lists, and every registration undone below before it's freed.
        let (stub, veh, vch) = unsafe {
            let stub = VirtualAlloc(
                core::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            );
            assert!(!stub.is_null());
            core::ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());
            let handler = core::mem::transmute::<
                *mut c_void,
                unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32,
            >(stub);
            let veh = AddVectoredExceptionHandler(0, Some(handler));
            let vch = AddVectoredContinueHandler(0, Some(handler));
            assert!(!veh.is_null() && !vch.is_null());
            (stub as usize, veh, vch)
        };

        let amsi = export("amsi.dll", c"AmsiScanBuffer", true);
        let etw = export("ntdll.dll", c"EtwEventWrite", false);
        let sleep = export("kernel32.dll", c"Sleep", false);
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (tid_tx, tid_rx) = std::sync::mpsc::channel::<u32>();
        let parked = std::thread::spawn(move || {
            // SAFETY: plain query.
            tid_tx.send(unsafe { GetCurrentThreadId() }).unwrap();
            let _ = rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        // SAFETY: our own helper thread; the handle is closed below.
        let th = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT
                    | THREAD_SET_CONTEXT
                    | THREAD_SUSPEND_RESUME
                    | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                tid,
            )
        };
        assert!(!th.is_null());
        set_breakpoints(th, [amsi, etw, sleep]);

        let after = me.exception_hooks().unwrap();

        set_breakpoints(th, [0, 0, 0]);
        tx.send(()).unwrap();
        parked.join().unwrap();
        // SAFETY: undoing the registrations above, then freeing the stub.
        unsafe {
            CloseHandle(th);
            RemoveVectoredExceptionHandler(veh);
            RemoveVectoredContinueHandler(vch);
            VirtualFree(stub as *mut c_void, 0, MEM_RELEASE);
        }

        let hits = after.hits();
        eprintln!(
            "lrng-selftest: exception hooks, planted: {} | {:?}",
            after.meta(),
            hits.iter().map(|h| (&h.rule, h.offset)).collect::<Vec<_>>()
        );
        let ours: Vec<_> = after.breakpoints.iter().filter(|b| b.tid == tid).collect();
        assert_eq!(ours.len(), 3, "{:?}", after.breakpoints);
        let find = |rule: &str| {
            hits.iter()
                .find(|h| h.rule == rule)
                .unwrap_or_else(|| panic!("no {rule}: {hits:?}"))
        };
        let a = find("defense.amsi_hwbp");
        assert_eq!(a.offset as usize, amsi);
        assert!(
            a.context.contains("amsi.dll!AmsiScanBuffer+0x0"),
            "{}",
            a.context
        );
        let e = find("defense.etw_hwbp");
        assert_eq!(e.offset as usize, etw);
        assert!(e.context.contains("EtwEventWrite+0x0"), "{}", e.context);
        assert_eq!(find("memory.hardware_breakpoint").offset as usize, sleep);
        let unbacked: Vec<_> = hits
            .iter()
            .filter(|h| h.rule == "memory.veh_unbacked")
            .collect();
        assert_eq!(unbacked.len(), 2, "{hits:?}");
        assert!(unbacked.iter().all(|h| h.offset as usize == stub));
        assert!(
            unbacked[0].context.contains("exception handler")
                && unbacked[1].context.contains("continue handler")
        );
    }
}
