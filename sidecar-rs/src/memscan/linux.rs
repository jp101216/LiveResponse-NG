//! Linux process memory via /proc/<pid>/maps and /proc/<pid>/mem.
//!
//! Reading another process's mem file needs ptrace-attach rights (root, or
//! the same user with a permissive kernel.yama.ptrace_scope).

use super::procmem::{OpenError, ProcessMemory, Region};
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;

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
