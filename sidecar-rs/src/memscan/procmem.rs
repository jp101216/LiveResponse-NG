//! Platform-neutral view of another process's memory.

use super::hooks;
use super::integrity::Report;
use super::syscalls;
use super::threads;
use std::time::Instant;

/// One committed, readable memory region.
#[derive(Clone, Debug)]
pub struct Region {
    pub base: usize,
    pub size: usize,
    /// Windows: "R", "RW", "RWC", "RX", "RWX", "RWXC" (C = copy-on-write). Linux: maps perms.
    pub protect: String,
    /// Windows: "image" | "mapped" | "private". Linux: "file" | "anon" |
    /// "heap" | "stack" | other pseudo-path name.
    pub kind: String,
    /// Backing file when the platform reports it cheaply (Linux maps).
    pub file: String,
}

impl Region {
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.base && addr - self.base < self.size
    }
}

/// Why a process couldn't be opened. The variant becomes the response status.
#[derive(Debug)]
pub enum OpenError {
    NotFound(String),
    AccessDenied(String),
    #[cfg_attr(any(windows, target_os = "linux"), allow(dead_code))]
    Unsupported(String),
    Other(String),
}

impl OpenError {
    pub fn status(&self) -> &'static str {
        match self {
            OpenError::NotFound(_) => "not_found",
            OpenError::AccessDenied(_) => "access_denied",
            OpenError::Unsupported(_) => "unsupported",
            OpenError::Other(_) => "error",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            OpenError::NotFound(m)
            | OpenError::AccessDenied(m)
            | OpenError::Unsupported(m)
            | OpenError::Other(m) => m,
        }
    }
}

/// Read-only access to one process's address space.
pub trait ProcessMemory {
    /// Committed, readable regions in ascending address order.
    fn regions(&self) -> Result<Vec<Region>, String>;
    /// Read up to `buf.len()` bytes at `addr`. Returns how many contiguous
    /// bytes from the start of `buf` were filled (0 = unreadable).
    fn read(&self, addr: usize, buf: &mut [u8]) -> usize;
    /// Full path of the process image, or "" if unknown.
    fn image_path(&self) -> String;
    /// Backing file of the region holding `addr` (image/mapped), or "".
    fn mapped_file(&self, _addr: usize) -> String {
        String::new()
    }
    /// Compare the code mapped from image files with those files (see
    /// integrity.rs), stopping at `deadline` or after `max_bytes` compared.
    fn image_integrity(&self, _deadline: Instant, _max_bytes: u64) -> Report {
        Report::unsupported()
    }
    /// The checks made thread by thread, on platforms that have them: hardware
    /// breakpoints and vectored exception handlers (hooks.rs), system calls
    /// (syscalls.rs), and where threads started and what their stacks show
    /// (threads.rs). The stack walks and the search of memory for system-call
    /// stubs stop at `deadline`.
    fn thread_checks(&self, _deadline: Instant) -> Option<ThreadChecks> {
        None
    }
}

/// What the thread-by-thread checks found in one process.
pub struct ThreadChecks {
    pub hooks: hooks::Report,
    pub calls: syscalls::Report,
    pub threads: threads::Report,
}

/// Lower-cased file name of a path using either separator.
pub fn file_name_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(target_os = "linux")]
pub use super::linux::open;
#[cfg(windows)]
pub use super::windows::open;

#[cfg(not(any(windows, target_os = "linux")))]
pub fn open(_pid: u32) -> Result<Box<dyn ProcessMemory>, OpenError> {
    Err(OpenError::Unsupported(
        "process memory scanning is implemented for Windows and Linux".into(),
    ))
}
