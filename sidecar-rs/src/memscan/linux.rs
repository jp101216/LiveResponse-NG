//! Linux process memory via /proc/<pid>/maps and /proc/<pid>/mem.
//!
//! Reading another process's mem file needs ptrace-attach rights (root, or
//! the same user with a permissive kernel.yama.ptrace_scope).

use super::integrity::{Change, DiffAcc, Report, Verdict};
use super::procmem::{OpenError, ProcessMemory, Region};
use std::collections::HashSet;
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::Instant;

/// Image code is compared in chunks of this size.
const CMP_CHUNK: usize = 1 << 20;

pub struct LinuxProcess {
    pid: u32,
    mem: File,
}

pub fn open(pid: u32) -> Result<Box<dyn ProcessMemory>, OpenError> {
    let mem = File::open(format!("/proc/{pid}/mem")).map_err(|e| match e.kind() {
        ErrorKind::NotFound => OpenError::NotFound(format!("pid {pid}: no such process")),
        ErrorKind::PermissionDenied => OpenError::AccessDenied(format!(
            "pid {pid}: permission denied reading /proc/{pid}/mem (run as root)"
        )),
        _ => OpenError::Other(format!("pid {pid}: open /proc/{pid}/mem: {e}")),
    })?;
    Ok(Box::new(LinuxProcess { pid, mem }))
}

impl ProcessMemory for LinuxProcess {
    fn regions(&self) -> Result<Vec<Region>, String> {
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.pid))
            .map_err(|e| format!("read /proc/{}/maps: {e}", self.pid))?;
        Ok(maps.lines().filter_map(parse_maps_line).collect())
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
        let mut done = 0;
        while done < buf.len() {
            match self.mem.read_at(&mut buf[done..], (addr + done) as u64) {
                Ok(0) | Err(_) => break,
                Ok(n) => done += n,
            }
        }
        done
    }

    fn image_path(&self) -> String {
        std::fs::read_link(format!("/proc/{}/exe", self.pid))
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    fn image_integrity(&self, deadline: Instant, max_bytes: u64) -> Report {
        let mut rep = Report {
            supported: true,
            ..Default::default()
        };
        let maps = match std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) {
            Ok(m) => m,
            Err(e) => {
                rep.stopped = Some(format!("read /proc/{}/maps: {e}", self.pid));
                return rep;
            }
        };
        let mut images = HashSet::new();
        let (mut mem_buf, mut file_buf) = (vec![0u8; CMP_CHUNK], vec![0u8; CMP_CHUNK]);
        for m in maps.lines().filter_map(parse_mapping) {
            // Executable mappings of real files; memfd and anonymous code are
            // the region heuristics' business.
            if !m.perms.contains('x') || !m.path.starts_with('/') || m.path.starts_with("/memfd:") {
                continue;
            }
            if Instant::now() >= deadline {
                rep.stopped = Some("time budget exhausted".into());
                break;
            }
            if rep.bytes >= max_bytes {
                rep.stopped = Some("byte cap reached".into());
                break;
            }
            let file = match self.backing_file(&m) {
                Ok(f) => f,
                Err(why) => {
                    rep.skip(why);
                    continue;
                }
            };
            let mut magic = [0u8; 4];
            if read_full_at(&file, &mut magic, 0) != 4 || &magic != b"\x7fELF" {
                rep.skip("not an ELF file");
                continue;
            }
            images.insert(m.inode);

            let mut acc = DiffAcc::new();
            let len = m.end - m.start;
            let mut off = 0;
            while off < len {
                let want = (len - off).min(CMP_CHUNK);
                // Past the end of the file the mapping is zero fill: stop there.
                let nf = read_full_at(&file, &mut file_buf[..want], m.offset + off as u64);
                if nf == 0 {
                    break;
                }
                let nm = self.read(m.start + off, &mut mem_buf[..nf]);
                if nm == 0 {
                    break;
                }
                acc.feed(off, &mem_buf[..nm], &file_buf[..nm], &[]);
                off += nm;
                if nm < want {
                    break;
                }
            }
            let stats = acc.finish();
            rep.compared += 1;
            rep.bytes += stats.compared;
            if stats.verdict() != Verdict::Clean {
                rep.changes.push(Change {
                    path: m.path.trim_end_matches(" (deleted)").to_string(),
                    what: format!("{} mapping at file offset 0x{:x}", m.perms, m.offset),
                    start: m.start,
                    stats,
                    near: Vec::new(),
                });
            }
        }
        rep.images = images.len();
        rep
    }
}

impl LinuxProcess {
    /// The file a mapping was made from. /proc/<pid>/map_files opens the very
    /// inode that was mapped, even if its path has since been replaced or
    /// deleted (it needs CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE). Without
    /// it, the path is opened through the process's root and used only if
    /// it is still the inode the mapping names.
    fn backing_file(&self, m: &Mapping) -> Result<File, &'static str> {
        match File::open(format!(
            "/proc/{}/map_files/{:x}-{:x}",
            self.pid, m.start, m.end
        )) {
            Ok(f) => return Ok(f),
            Err(e) if e.kind() == ErrorKind::NotFound => return Err("mapping went away"),
            Err(_) => {}
        }
        if m.path.ends_with(" (deleted)") {
            return Err("deleted file and no map_files access");
        }
        let f = File::open(format!("/proc/{}/root{}", self.pid, m.path))
            .map_err(|_| "backing file unreadable")?;
        let inode = f.metadata().map_err(|_| "backing file unreadable")?.ino();
        if inode != m.inode {
            return Err("file replaced on disk since it was mapped");
        }
        Ok(f)
    }
}

/// Read until `buf` is full or the file ends; returns the bytes read.
fn read_full_at(f: &File, buf: &mut [u8], at: u64) -> usize {
    let mut done = 0;
    while done < buf.len() {
        match f.read_at(&mut buf[done..], at + done as u64) {
            Ok(0) | Err(_) => break,
            Ok(n) => done += n,
        }
    }
    done
}

/// One /proc/<pid>/maps line, with the fields the integrity check needs.
struct Mapping {
    start: usize,
    end: usize,
    perms: String,
    offset: u64,
    inode: u64,
    path: String,
}

fn parse_mapping(line: &str) -> Option<Mapping> {
    let mut f = line.split_whitespace();
    let (start, end) = f.next()?.split_once('-')?;
    let perms = f.next()?.to_string();
    let offset = u64::from_str_radix(f.next()?, 16).ok()?;
    let _dev = f.next()?;
    let inode = f.next()?.parse().ok()?;
    let path = line
        .splitn(6, char::is_whitespace)
        .nth(5)
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    Some(Mapping {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        perms,
        offset,
        inode,
        path,
    })
}

/// Parse one /proc/<pid>/maps line into a readable region, or None.
/// Format: `start-end perms offset dev inode [path]`.
pub fn parse_maps_line(line: &str) -> Option<Region> {
    let mut f = line.split_whitespace();
    let range = f.next()?;
    let perms = f.next()?;
    let _offset = f.next()?;
    let _dev = f.next()?;
    let _inode = f.next()?;
    // The path is everything after the inode (it may contain spaces).
    let path = line
        .splitn(6, char::is_whitespace)
        .nth(5)
        .map(str::trim)
        .unwrap_or("");

    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    if end <= start || !perms.starts_with('r') {
        return None;
    }
    // Kernel-provided pages that can't be read through /proc/<pid>/mem.
    if matches!(path, "[vvar]" | "[vvar_vclock]" | "[vsyscall]") {
        return None;
    }
    let kind = match path {
        "" => "anon".to_string(),
        "[heap]" => "heap".to_string(),
        p if p.starts_with("[stack") => "stack".to_string(),
        p if p.starts_with('[') => p.trim_matches(['[', ']']).to_string(),
        _ => "file".to_string(),
    };
    Some(Region {
        base: start,
        size: end - start,
        protect: perms.to_string(),
        kind,
        file: if path.starts_with('/') {
            path.to_string()
        } else {
            String::new()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    extern "C" {
        fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            off: i64,
        ) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: i32) -> i32;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
    }
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    const MAP_PRIVATE: i32 = 2;

    #[test]
    fn parses_mappings_with_offset_and_inode() {
        let m = parse_mapping(
            "7f1c2a028000-7f1c2a1bd000 r-xp 00028000 08:01 1234   /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();
        assert_eq!(
            (m.start, m.end, m.offset, m.inode),
            (0x7f1c2a028000, 0x7f1c2a1bd000, 0x28000, 1234)
        );
        assert_eq!(
            (m.perms.as_str(), m.path.as_str()),
            ("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6")
        );
        let m = parse_mapping("1000-2000 r-xp 0 08:01 9 /tmp/a b (deleted)").unwrap();
        assert_eq!(m.path, "/tmp/a b (deleted)");
        assert!(parse_mapping("garbage").is_none());
    }

    /// End to end on this process: an executable file mapping whose private
    /// copy is rewritten is found, at the right offset, and nothing else this
    /// process maps is (a false-positive check on the host's libraries). As
    /// root this reads through map_files; otherwise through the inode-checked
    /// path fallback.
    #[test]
    fn integrity_finds_a_rewritten_file_mapping() {
        const LEN: usize = 3 * 4096;
        let path = std::env::temp_dir().join(format!("lrng-integrity-{}.elf", std::process::id()));
        let mut data: Vec<u8> = (0..LEN).map(|i| (i * 7 + 3) as u8).collect();
        data[..4].copy_from_slice(b"\x7fELF");
        std::fs::write(&path, &data).unwrap();
        let file = File::open(&path).unwrap();
        // SAFETY: a fresh private mapping of our own file; nothing executes it.
        let p = unsafe {
            mmap(
                std::ptr::null_mut(),
                LEN,
                PROT_READ | PROT_EXEC,
                MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if p as isize == -1 {
            let _ = std::fs::remove_file(&path);
            eprintln!(
                "skipped: can't map {} executable here (noexec?)",
                path.display()
            );
            return;
        }
        let me = open(std::process::id()).unwrap();
        let ours = |r: &Report| -> Vec<Change> {
            r.changes
                .iter()
                .filter(|c| c.path == path.to_string_lossy())
                .cloned()
                .collect()
        };
        let deadline = || Instant::now() + Duration::from_secs(60);

        let r = me.image_integrity(deadline(), 1 << 30);
        assert!(r.supported && r.compared > 0 && r.bytes > 0);
        assert!(
            r.changes.is_empty(),
            "this process's own images differ from disk: {:?}",
            r.changes
        );

        // SAFETY: the region is ours; it is made writable, rewritten (a 1 KiB
        // overwrite and a 1-byte patch), and restored to read+exec.
        unsafe {
            assert_eq!(mprotect(p, LEN, PROT_READ | PROT_WRITE), 0);
            for b in std::slice::from_raw_parts_mut((p as *mut u8).add(4096), 1024) {
                *b = !*b; // inverted: every byte differs
            }
            *(p as *mut u8).add(8192 + 100) ^= 0xFF;
            assert_eq!(mprotect(p, LEN, PROT_READ | PROT_EXEC), 0);
        }
        let r = me.image_integrity(deadline(), 1 << 30);
        let c = ours(&r);
        unsafe {
            munmap(p, LEN);
        }
        let _ = std::fs::remove_file(&path);

        assert_eq!(c.len(), 1, "{:?}", r.changes);
        let s = &c[0].stats;
        assert_eq!(s.verdict(), Verdict::Rewritten);
        assert_eq!((s.sites, s.largest, s.largest_at), (2, 1024, 4096));
        assert_eq!(c[0].start, p as usize);
        assert_eq!(
            r.changes.len(),
            1,
            "only the planted change: {:?}",
            r.changes
        );
    }

    #[test]
    fn parses_maps_lines() {
        let r = parse_maps_line(
            "7f1c2a000000-7f1c2a021000 r-xp 00000000 08:01 1234   /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .unwrap();
        assert_eq!((r.base, r.size), (0x7f1c2a000000, 0x21000));
        assert_eq!((r.protect.as_str(), r.kind.as_str()), ("r-xp", "file"));
        assert_eq!(r.file, "/usr/lib/x86_64-linux-gnu/libc.so.6");

        let r = parse_maps_line("55d0c0a00000-55d0c0a21000 rw-p 00000000 00:00 0  [heap]").unwrap();
        assert_eq!(r.kind, "heap");
        let r = parse_maps_line("7ffd1000-7ffd2000 rw-p 00000000 00:00 0").unwrap();
        assert_eq!(r.kind, "anon");
        let r =
            parse_maps_line("1000-2000 r--p 0 08:01 9 /tmp/name with spaces (deleted)").unwrap();
        assert_eq!(r.file, "/tmp/name with spaces (deleted)");

        assert!(
            parse_maps_line("1000-2000 ---p 0 00:00 0").is_none(),
            "unreadable"
        );
        assert!(
            parse_maps_line("1000-2000 r--p 0 00:00 0 [vvar]").is_none(),
            "vvar"
        );
        assert!(parse_maps_line("garbage").is_none());
    }
}
