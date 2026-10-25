//! Windows process memory via VirtualQueryEx / ReadProcessMemory.
//!
//! Opens the target with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (falling
//! back to PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ) and never asks
//! for any write, thread or handle-duplication rights.
//!
//! Compiled on Windows, and on Linux under `--cfg lrng_typecheck_windows` so
//! it can be type-checked without a Windows toolchain (`make check-windows-rs`).
#![cfg_attr(not(windows), allow(dead_code))]

use super::procmem::{OpenError, ProcessMemory, Region};
use core::ffi::c_void;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::ProcessStatus::K32GetMappedFileNameW;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

const PAGE: usize = 4096;
/// Sanity cap on the region walk (a normal process has a few thousand).
const MAX_REGIONS: usize = 1_000_000;

pub struct WinProcess {
    h: HANDLE,
}

impl Drop for WinProcess {
    fn drop(&mut self) {
        // SAFETY: h is a valid process handle owned by this struct.
        unsafe {
            CloseHandle(self.h);
        }
    }
}

pub fn open(pid: u32) -> Result<Box<dyn ProcessMemory>, OpenError> {
    // SAFETY: plain Win32 calls; a null handle signals failure.
    let mut h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if h.is_null() {
        h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
    }
    if h.is_null() {
        let e = unsafe { GetLastError() };
        return Err(match e {
            ERROR_ACCESS_DENIED => OpenError::AccessDenied(format!(
                "pid {pid}: access denied (protected process, or not running elevated)"
            )),
            ERROR_INVALID_PARAMETER => OpenError::NotFound(format!("pid {pid}: no such process")),
            _ => OpenError::Other(format!("pid {pid}: OpenProcess failed (Win32 error {e})")),
        });
    }
    Ok(Box::new(WinProcess { h }))
}

impl ProcessMemory for WinProcess {
    fn regions(&self) -> Result<Vec<Region>, String> {
        let mut out = Vec::new();
        let mut addr: usize = 0;
        let len = core::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        loop {
            // SAFETY: mbi is a plain-data struct VirtualQueryEx fills in.
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
            let n = unsafe { VirtualQueryEx(self.h, addr as *const c_void, &mut mbi, len) };
            if n == 0 {
                break; // past the last region (or the query failed)
            }
            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            if mbi.State == MEM_COMMIT && readable(mbi.Protect) {
                out.push(Region {
                    base,
                    size,
                    protect: protect_name(mbi.Protect).to_string(),
                    kind: kind_name(mbi.Type).to_string(),
                    file: String::new(),
                });
                if out.len() >= MAX_REGIONS {
                    break;
                }
            }
            match base.checked_add(size) {
                Some(next) if next > addr => addr = next,
                _ => break,
            }
        }
        if out.is_empty() {
            let e = unsafe { GetLastError() };
            if e == ERROR_ACCESS_DENIED {
                return Err("VirtualQueryEx: access denied".into());
            }
        }
        Ok(out)
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let mut got: usize = 0;
        // SAFETY: buf is valid for buf.len() bytes; got receives the count.
        let ok = unsafe {
            ReadProcessMemory(
                self.h,
                addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                &mut got,
            )
        };
        if ok != 0 {
            return got.min(buf.len());
        }
        // The bulk read failed (part of the range went away or is
        // unreadable). Salvage the readable prefix a page at a time.
        let mut total = 0;
        while total < buf.len() {
            let here = addr + total;
            let step = (PAGE - here % PAGE).min(buf.len() - total);
            let mut g: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    self.h,
                    here as *const c_void,
                    buf[total..].as_mut_ptr() as *mut c_void,
                    step,
                    &mut g,
                )
            };
            if ok == 0 || g == 0 {
                break;
            }
            total += g.min(step);
        }
        total
    }

    fn image_path(&self) -> String {
        let mut buf = vec![0u16; 32768];
        let mut size = buf.len() as u32;
        // SAFETY: buf holds `size` UTF-16 units.
        let ok = unsafe {
            QueryFullProcessImageNameW(self.h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut size)
        };
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())])
    }

    fn mapped_file(&self, addr: usize) -> String {
        let mut buf = vec![0u16; 1024];
        // SAFETY: buf holds buf.len() UTF-16 units; returns chars written.
        let n = unsafe {
            K32GetMappedFileNameW(
                self.h,
                addr as *const c_void,
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        to_dos_path(&String::from_utf16_lossy(
            &buf[..(n as usize).min(buf.len())],
        ))
    }
}

/// NT device names (\Device\HarddiskVolume3) and the drive letters (C:) they
/// back, read once.
fn dos_devices() -> &'static [(String, String)] {
    static MAP: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut out = Vec::new();
        for letter in b'A'..=b'Z' {
            let drive: Vec<u16> = format!("{}:", letter as char)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut buf = vec![0u16; 1024];
            // SAFETY: drive is NUL-terminated; buf holds buf.len() units.
            let n = unsafe { QueryDosDeviceW(drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if n == 0 {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
            let target = String::from_utf16_lossy(&buf[..end]);
            if !target.is_empty() {
                out.push((target, format!("{}:", letter as char)));
            }
        }
        out
    })
}

/// Rewrite an NT device path from GetMappedFileName as a drive-letter path,
/// so mapped-file names in hits read like the paths everywhere else.
fn to_dos_path(nt: &str) -> String {
    for (dev, drive) in dos_devices() {
        if let Some(rest) = nt.strip_prefix(dev.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
    }
    nt.to_string()
}

fn readable(protect: u32) -> bool {
    if protect & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
        return false;
    }
    matches!(
        protect & 0xff,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

fn protect_name(protect: u32) -> &'static str {
    match protect & 0xff {
        PAGE_READONLY => "R",
        PAGE_READWRITE => "RW",
        PAGE_WRITECOPY => "RWC",
        PAGE_EXECUTE => "X",
        PAGE_EXECUTE_READ => "RX",
        PAGE_EXECUTE_READWRITE => "RWX",
        PAGE_EXECUTE_WRITECOPY => "RWXC",
        _ => "?",
    }
}

fn kind_name(t: u32) -> &'static str {
    match t {
        MEM_IMAGE => "image",
        MEM_MAPPED => "mapped",
        MEM_PRIVATE => "private",
        _ => "unknown",
    }
}
