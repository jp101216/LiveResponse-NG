//! A small, bounds-checked PE reader for the image-integrity check: headers,
//! the section table, base relocations, exports (to name patch sites) and the
//! CLR header. Its input is hostile (a file an attacker may control, or a
//! header read out of another process), so every read is checked and nothing
//! panics on malformed data.
//!
//! Compiled everywhere so it is unit-tested on any OS; only windows.rs uses it
//! at run time.
#![cfg_attr(not(windows), allow(dead_code))]

use super::integrity::{Change, DiffAcc, HeaderMismatch, Verdict};

pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const DIR_EXPORT: usize = 0;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;
pub const DIR_CLR: usize = 14;

const MAX_SECTIONS: usize = 96;
const MAX_RELOCS: usize = 4 << 20;
const MAX_EXPORTS: usize = 1 << 16;
/// Sections larger than this aren't compared.
pub const MAX_SECTION: usize = 256 << 20;

// Base-relocation kinds. x86 images use HIGHLOW, x64 and ARM64 use DIR64;
// the rest are masked out of the comparison rather than reproduced.
const REL_ABSOLUTE: u8 = 0;
const REL_HIGHLOW: u8 = 3;
const REL_HIGHADJ: u8 = 4;
const REL_DIR64: u8 = 10;

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(o..o.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub va: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub flags: u32,
}

impl Section {
    pub fn exec(&self) -> bool {
        self.flags & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0
    }

    /// Bytes of the section the file supplies; the rest of its memory is
    /// zero fill.
    pub fn file_len(&self) -> u32 {
        if self.vsize == 0 {
            self.raw_size
        } else {
            self.vsize.min(self.raw_size)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pe {
    pub machine: u16,
    pub timestamp: u32,
    pub magic: u16,
    pub image_base: u64,
    pub entry: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub dirs: Vec<(u32, u32)>,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    pub rva: u32,
    pub kind: u8,
}

/// Parse the DOS, NT and section headers.
pub fn parse(b: &[u8]) -> Result<Pe, &'static str> {
    if b.get(..2) != Some(&b"MZ"[..]) {
        return Err("no MZ signature");
    }
    let lfanew = u32_at(b, 0x3c).ok_or("truncated DOS header")? as usize;
    let fh = lfanew.checked_add(4).ok_or("bad e_lfanew")?;
    if b.get(lfanew..fh) != Some(&b"PE\0\0"[..]) {
        return Err("no PE signature");
    }
    // From here every offset is a small constant past fh, which is inside b.
    let t = "truncated NT headers";
    let machine = u16_at(b, fh).ok_or(t)?;
    let nsec = u16_at(b, fh + 2).ok_or(t)? as usize;
    let timestamp = u32_at(b, fh + 4).ok_or(t)?;
    let opt_size = u16_at(b, fh + 16).ok_or(t)? as usize;
    let oh = fh + 20;
    let magic = u16_at(b, oh).ok_or(t)?;
    let (image_base, ndirs_at) = match magic {
        0x10b => (u64::from(u32_at(b, oh + 28).ok_or(t)?), oh + 92),
        0x20b => (u64_at(b, oh + 24).ok_or(t)?, oh + 108),
        _ => return Err("unknown optional-header magic"),
    };
    let entry = u32_at(b, oh + 16).ok_or(t)?;
    let file_alignment = u32_at(b, oh + 36).ok_or(t)?;
    let size_of_image = u32_at(b, oh + 56).ok_or(t)?;
    let size_of_headers = u32_at(b, oh + 60).ok_or(t)?;
    let checksum = u32_at(b, oh + 64).ok_or(t)?;
    let ndirs = (u32_at(b, ndirs_at).ok_or(t)? as usize).min(16);
    let opt_end = oh + opt_size;
    let mut dirs = Vec::with_capacity(ndirs);
    for i in 0..ndirs {
        let at = ndirs_at + 4 + i * 8;
        if at + 8 > opt_end {
            break;
        }
        dirs.push((u32_at(b, at).ok_or(t)?, u32_at(b, at + 4).ok_or(t)?));
    }
    if nsec > MAX_SECTIONS {
        return Err("implausible section count");
    }
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let s = opt_end + i * 40;
        let h = b.get(s..s + 40).ok_or("truncated section table")?;
        let name_len = h[..8].iter().position(|&c| c == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&h[..name_len]).into_owned(),
            vsize: u32_at(h, 8).ok_or(t)?,
            va: u32_at(h, 12).ok_or(t)?,
            raw_size: u32_at(h, 16).ok_or(t)?,
            raw_ptr: u32_at(h, 20).ok_or(t)?,
            flags: u32_at(h, 36).ok_or(t)?,
        });
    }
    Ok(Pe {
        machine,
        timestamp,
        magic,
        image_base,
        entry,
        file_alignment,
        size_of_image,
        size_of_headers,
        checksum,
        dirs,
        sections,
    })
}

/// Exported names by RVA, for naming the code a patch sits in.
#[derive(Debug, Default)]
pub struct Exports(Vec<(u32, String)>);

impl Exports {
    /// "Name+0xoff" for the nearest export at or below `rva`, or "" when
    /// there is none close enough to be the containing function. Every name
    /// exported at that address is given ("NtTraceEvent/ZwTraceEvent+0x0"):
    /// Nt/Zw stubs and linker-folded functions share one body.
    pub fn near(&self, rva: u32) -> String {
        let Some(j) = self.0.partition_point(|(r, _)| *r <= rva).checked_sub(1) else {
            return String::new();
        };
        let at = self.0[j].0;
        if rva - at >= 0x4000 {
            return String::new();
        }
        let first = self.0[..j].partition_point(|(r, _)| *r < at);
        let names: Vec<&str> = self.0[first..=j]
            .iter()
            .take(3)
            .map(|(_, n)| n.as_str())
            .collect();
        format!("{}+0x{:x}", names.join("/"), rva - at)
    }
}

/// Longest export name kept; longer ones are truncated (as pefile does).
/// Decorated C++ names routinely run past 160 bytes.
const MAX_NAME: usize = 512;

/// The printable-ASCII string at `o`: up to its NUL, or its first `max`
/// bytes when it runs longer.
fn cstr(b: &[u8], o: usize, max: usize) -> Option<String> {
    let s = b.get(o..)?;
    let s = &s[..s.len().min(max)];
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    let s = &s[..n];
    if s.is_empty() || !s.iter().all(u8::is_ascii_graphic) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

/// Add `delta` to the little-endian integer of `N` bytes at `bytes[o..]`.
fn add_le<const N: usize>(bytes: &mut [u8], o: usize, delta: u64) {
    if let Some(dst) = bytes.get_mut(o..o + N) {
        let mut v = [0u8; 8];
        v[..N].copy_from_slice(dst);
        let sum = u64::from_le_bytes(v).wrapping_add(delta);
        dst.copy_from_slice(&sum.to_le_bytes()[..N]);
    }
}

impl Pe {
    /// File offset the loader reads a section from: when FileAlignment is
    /// at least 0x200 it rounds PointerToRawData down to a multiple of 0x200.
    fn raw_start(&self, s: &Section) -> usize {
        let p = s.raw_ptr as usize;
        if self.file_alignment >= 0x200 {
            p & !0x1ff
        } else {
            p
        }
    }

    /// The file offset holding the byte at `rva`, if the file supplies it.
    pub fn rva_to_off(&self, rva: u32) -> Option<usize> {
        self.sections
            .iter()
            .find_map(|s| {
                let d = rva.checked_sub(s.va)?;
                (d < s.raw_size).then(|| self.raw_start(s) + d as usize)
            })
            .or_else(|| (rva < self.size_of_headers).then_some(rva as usize))
    }

    /// Data directory `i`, when present.
    pub fn dir(&self, i: usize) -> Option<(u32, u32)> {
        self.dirs
            .get(i)
            .copied()
            .filter(|&(rva, size)| rva != 0 && size != 0)
    }

    /// The base relocations, sorted by RVA.
    pub fn relocations(&self, file: &[u8]) -> Vec<Reloc> {
        let mut out = Vec::new();
        let Some((rva, size)) = self.dir(DIR_BASERELOC) else {
            return out;
        };
        let Some(start) = self.rva_to_off(rva) else {
            return out;
        };
        let end = start.saturating_add(size as usize).min(file.len());
        let mut p = start;
        while p.saturating_add(8) <= end && out.len() < MAX_RELOCS {
            let (Some(page), Some(block)) = (u32_at(file, p), u32_at(file, p + 4)) else {
                break;
            };
            let block = block as usize;
            if block < 8 {
                break;
            }
            let block_end = p.saturating_add(block).min(end);
            let mut q = p + 8;
            while q + 2 <= block_end {
                let e = u16_at(file, q).unwrap_or(0);
                q += 2;
                let kind = (e >> 12) as u8;
                let at = page.wrapping_add(u32::from(e & 0x0fff));
                match kind {
                    REL_ABSOLUTE => {}
                    REL_HIGHADJ => {
                        // Its parameter occupies the next slot.
                        out.push(Reloc { rva: at, kind });
                        q += 2;
                    }
                    _ => out.push(Reloc { rva: at, kind }),
                }
            }
            p = p.saturating_add(block);
        }
        out.sort_by_key(|r| r.rva);
        out
    }

    /// The bytes the loader maps for section `s`, with the base relocations
    /// for a load `delta` applied, and the [start, end) ranges (relative to
    /// the section) that couldn't be reproduced and so mustn't be compared:
    /// relocation kinds this reader doesn't apply, and fixups that straddle
    /// the section's edge.
    pub fn section_bytes(
        &self,
        file: &[u8],
        s: &Section,
        delta: u64,
        relocs: &[Reloc],
    ) -> (Vec<u8>, Vec<(usize, usize)>) {
        let start = self.raw_start(s);
        let Some(avail) = file.len().checked_sub(start) else {
            return (Vec::new(), Vec::new());
        };
        let len = (s.file_len() as usize).min(MAX_SECTION).min(avail);
        let mut bytes = file[start..start + len].to_vec();
        let mut mask = Vec::new();
        let (va, end) = (u64::from(s.va), u64::from(s.va) + len as u64);
        let first = relocs.partition_point(|r| u64::from(r.rva) + 8 <= va);
        for r in &relocs[first..] {
            let rva = u64::from(r.rva);
            if rva >= end {
                break;
            }
            let width = match r.kind {
                REL_HIGHLOW => 4,
                _ => 8,
            };
            let (a, b) = (rva.max(va), (rva + width).min(end));
            if a >= b {
                continue;
            }
            let inside = rva >= va && rva + width <= end;
            let o = (a - va) as usize;
            match (r.kind, inside) {
                (REL_HIGHLOW, true) => add_le::<4>(&mut bytes, o, delta),
                (REL_DIR64, true) => add_le::<8>(&mut bytes, o, delta),
                _ => mask.push((o, (b - va) as usize)),
            }
        }
        (bytes, mask)
    }

    /// Named exports (forwarders skipped), sorted by RVA.
    pub fn exports(&self, file: &[u8]) -> Exports {
        let mut out = Vec::new();
        let Some((drva, dsize)) = self.dir(DIR_EXPORT) else {
            return Exports(out);
        };
        let Some(d) = self.rva_to_off(drva) else {
            return Exports(out);
        };
        let field = |o: usize| u32_at(file, d + o);
        let (Some(nfuncs), Some(nnames), Some(funcs), Some(names), Some(ords)) =
            (field(20), field(24), field(28), field(32), field(36))
        else {
            return Exports(out);
        };
        let (Some(fo), Some(no), Some(oo)) = (
            self.rva_to_off(funcs),
            self.rva_to_off(names),
            self.rva_to_off(ords),
        ) else {
            return Exports(out);
        };
        for i in 0..(nnames as usize).min(MAX_EXPORTS) {
            let (Some(name_rva), Some(ord)) = (u32_at(file, no + 4 * i), u16_at(file, oo + 2 * i))
            else {
                break;
            };
            if u32::from(ord) >= nfuncs {
                continue;
            }
            let Some(frva) = u32_at(file, fo + 4 * ord as usize) else {
                continue;
            };
            if (drva..drva.saturating_add(dsize)).contains(&frva) {
                continue; // a forwarder string, not code
            }
            if let Some(name) = self
                .rva_to_off(name_rva)
                .and_then(|o| cstr(file, o, MAX_NAME))
            {
                out.push((frva, name));
            }
        }
        out.sort();
        Exports(out)
    }

    /// Whether this is an IL-only .NET image (its only native code is a
    /// loader-managed stub).
    pub fn il_only(&self, file: &[u8]) -> bool {
        self.dir(DIR_CLR)
            .and_then(|(rva, _)| self.rva_to_off(rva))
            .and_then(|o| u32_at(file, o + 16))
            .is_some_and(|flags| flags & 1 != 0)
    }
}

/// Identity fields a loader leaves alone and a replaced image changes.
/// Machine and the entry point are deliberately not compared: Windows
/// re-presents an ARM64X image to x64 code with both rewritten.
pub fn identity_mismatch(mem: &Pe, disk: &Pe) -> Vec<String> {
    let mut f = Vec::new();
    if mem.timestamp != disk.timestamp {
        f.push(format!(
            "TimeDateStamp 0x{:08x} in memory, 0x{:08x} on disk",
            mem.timestamp, disk.timestamp
        ));
    }
    if mem.size_of_image != disk.size_of_image {
        f.push(format!(
            "SizeOfImage 0x{:x} in memory, 0x{:x} on disk",
            mem.size_of_image, disk.size_of_image
        ));
    }
    if mem.sections.len() != disk.sections.len() {
        f.push(format!(
            "{} sections in memory, {} on disk",
            mem.sections.len(),
            disk.sections.len()
        ));
    } else if let Some((m, d)) = mem
        .sections
        .iter()
        .zip(&disk.sections)
        .find(|(m, d)| m.va != d.va || m.vsize != d.vsize)
    {
        f.push(format!(
            "section {} at 0x{:x} (0x{:x} bytes) in memory, 0x{:x} (0x{:x}) on disk",
            d.name, m.va, m.vsize, d.va, d.vsize
        ));
    }
    f
}

/// The section of loader-written function-override thunks.
const FOTHK: &str = "fothk";
const SKIP_FOTHK: &str = "fothk section (thunks the Windows loader writes) not compared";

/// What comparing one mapped PE image with its file found.
#[derive(Debug, Default)]
pub struct ImageCheck {
    pub changes: Vec<Change>,
    pub header: Option<HeaderMismatch>,
    pub compared: usize,
    pub bytes: u64,
    pub skipped: Vec<&'static str>,
}

/// Compare the PE image mapped at `base` with its `file`. `mem_header` holds
/// the first bytes of the mapping; `read` reads process memory at an address
/// into a buffer and returns how many bytes it got.
pub fn check_image(
    path: &str,
    file: &[u8],
    mem_header: &[u8],
    base: usize,
    read: &mut dyn FnMut(usize, &mut [u8]) -> usize,
) -> ImageCheck {
    let mut out = ImageCheck::default();
    let Ok(disk) = parse(file) else {
        out.skipped.push("file is not a valid PE");
        return out;
    };
    let mismatch = |fields: Vec<String>| HeaderMismatch {
        path: path.to_string(),
        base,
        fields,
    };
    let mem = match parse(mem_header) {
        Ok(p) => p,
        Err(e) => {
            out.header = Some(mismatch(vec![format!(
                "no valid PE header in memory ({e})"
            )]));
            return out;
        }
    };
    let fields = identity_mismatch(&mem, &disk);
    if !fields.is_empty() {
        out.header = Some(mismatch(fields));
        return out;
    }

    let delta = (base as u64).wrapping_sub(disk.image_base);
    let relocs = disk.relocations(file);
    let iat = disk.dir(DIR_IAT);
    let il_only = disk.il_only(file);
    let mut exports: Option<Exports> = None;
    for s in disk.sections.iter().filter(|s| s.exec()) {
        // Recent Windows builds give system images a "fothk" section of
        // function-override thunks, and the loader rewrites them when it maps
        // the image, so it never matches the file. Hooking targets live in
        // the code sections proper, which are still compared.
        if s.name == FOTHK {
            out.skipped.push(SKIP_FOTHK);
            continue;
        }
        let (bytes, mut mask) = disk.section_bytes(file, s, delta, &relocs);
        if bytes.is_empty() {
            continue;
        }
        // The loader writes resolved import addresses into the IAT; some
        // images keep it inside a code section.
        if let Some((irva, isize)) = iat {
            let va = u64::from(s.va);
            let a = u64::from(irva).max(va);
            let b = (u64::from(irva) + u64::from(isize)).min(va + bytes.len() as u64);
            if a < b {
                mask.push(((a - va) as usize, (b - va) as usize));
            }
        }
        let mut mem_bytes = vec![0u8; bytes.len()];
        let got = read(base.wrapping_add(s.va as usize), &mut mem_bytes);
        if got == 0 {
            out.skipped.push("code section unreadable in memory");
            continue;
        }
        let mut acc = DiffAcc::new();
        acc.feed(0, &mem_bytes[..got], &bytes[..got], &mask);
        let stats = acc.finish();
        out.compared += 1;
        out.bytes += stats.compared;
        match stats.verdict() {
            Verdict::Clean => {}
            Verdict::Patched if il_only => {
                out.skipped.push("IL-only .NET image: loader stub differs")
            }
            _ => {
                let ex = exports.get_or_insert_with(|| disk.exports(file));
                let near = stats
                    .site_offsets
                    .iter()
                    .take(4)
                    .map(|&o| ex.near(s.va.wrapping_add(o as u32)))
                    .collect();
                out.changes.push(Change {
                    path: path.to_string(),
                    what: format!("section {}", s.name),
                    start: base.wrapping_add(s.va as usize),
                    stats,
                    near,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ DLL: headers, a .text section holding two absolute
    /// pointers (each with a DIR64 relocation) and an exported function, and
    /// .reloc / .edata. Built here to exercise the plumbing; relocation
    /// correctness against a real loader's view is checked by
    /// `matches_pefile_on_real_images` (LRNG_PE_SAMPLES).
    fn tiny_dll() -> Vec<u8> {
        let mut f = vec![0u8; 0x1000];
        f[..2].copy_from_slice(b"MZ");
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let fh = 0x84;
        f[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[fh + 2..fh + 4].copy_from_slice(&3u16.to_le_bytes()); // sections
        f[fh + 4..fh + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        f[fh + 16..fh + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size
        let oh = fh + 20;
        f[oh..oh + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        f[oh + 24..oh + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        f[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        f[oh + 56..oh + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        f[oh + 60..oh + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        f[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
        let dir = |f: &mut Vec<u8>, i: usize, rva: u32, size: u32| {
            let at = oh + 112 + i * 8;
            f[at..at + 4].copy_from_slice(&rva.to_le_bytes());
            f[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
        };
        dir(&mut f, DIR_EXPORT, 0x3000, 0x60);
        dir(&mut f, DIR_BASERELOC, 0x2000, 12);
        let sec = |f: &mut Vec<u8>, i: usize, name: &[u8], va: u32, raw: u32, flags: u32| {
            let s = oh + 0xF0 + i * 40;
            f[s..s + name.len()].copy_from_slice(name);
            f[s + 8..s + 12].copy_from_slice(&0x200u32.to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            f[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&raw.to_le_bytes());
            f[s + 36..s + 40].copy_from_slice(&flags.to_le_bytes());
        };
        sec(
            &mut f,
            0,
            b".text",
            0x1000,
            0x400,
            SCN_CNT_CODE | SCN_MEM_EXECUTE,
        );
        sec(&mut f, 1, b".reloc", 0x2000, 0x600, 0x4200_0040);
        sec(&mut f, 2, b".edata", 0x3000, 0x800, 0x4000_0040);
        // .text: code bytes, and two absolute pointers at +0x10 and +0x40.
        for (i, b) in f[0x400..0x600].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(1);
        }
        f[0x410..0x418].copy_from_slice(&0x1_8000_1100u64.to_le_bytes());
        f[0x440..0x448].copy_from_slice(&0x1_8000_1180u64.to_le_bytes());
        // .reloc: one block for page 0x1000 with two DIR64 entries.
        f[0x600..0x604].copy_from_slice(&0x1000u32.to_le_bytes());
        f[0x604..0x608].copy_from_slice(&12u32.to_le_bytes());
        f[0x608..0x60a].copy_from_slice(&(0xA000u16 | 0x10).to_le_bytes());
        f[0x60a..0x60c].copy_from_slice(&(0xA000u16 | 0x40).to_le_bytes());
        // .edata: one export, "DoWork" at RVA 0x1080.
        let e = 0x800;
        f[e + 20..e + 24].copy_from_slice(&1u32.to_le_bytes()); // functions
        f[e + 24..e + 28].copy_from_slice(&1u32.to_le_bytes()); // names
        f[e + 28..e + 32].copy_from_slice(&0x3030u32.to_le_bytes());
        f[e + 32..e + 36].copy_from_slice(&0x3034u32.to_le_bytes());
        f[e + 36..e + 40].copy_from_slice(&0x3038u32.to_le_bytes());
        f[e + 0x30..e + 0x34].copy_from_slice(&0x1080u32.to_le_bytes());
        f[e + 0x34..e + 0x38].copy_from_slice(&0x3040u32.to_le_bytes());
        f[e + 0x40..e + 0x47].copy_from_slice(b"DoWork\0");
        f
    }

    /// Map `file` at `base` the way the loader would (headers, sections at
    /// their RVAs, relocations applied), for the tests' "process memory".
    fn map(file: &[u8], base: usize) -> Vec<u8> {
        let pe = parse(file).unwrap();
        let mut img = vec![0u8; pe.size_of_image as usize];
        img[..pe.size_of_headers as usize].copy_from_slice(&file[..pe.size_of_headers as usize]);
        let relocs = pe.relocations(file);
        let delta = (base as u64).wrapping_sub(pe.image_base);
        for s in &pe.sections {
            let (b, _) = pe.section_bytes(file, s, delta, &relocs);
            img[s.va as usize..s.va as usize + b.len()].copy_from_slice(&b);
        }
        img
    }

    fn check(file: &[u8], img: &[u8], base: usize) -> ImageCheck {
        let mut read = |addr: usize, buf: &mut [u8]| {
            let src = img.get(addr - base..).unwrap_or(&[]);
            let n = buf.len().min(src.len());
            buf[..n].copy_from_slice(&src[..n]);
            n
        };
        check_image("tiny.dll", file, &img[..0x400], base, &mut read)
    }

    #[test]
    fn parses_and_relocates() {
        let f = tiny_dll();
        let pe = parse(&f).unwrap();
        assert_eq!(
            (pe.machine, pe.magic, pe.image_base),
            (0x8664, 0x20b, 0x1_8000_0000)
        );
        assert_eq!(pe.sections.len(), 3);
        assert!(pe.sections[0].exec() && !pe.sections[1].exec());
        let relocs = pe.relocations(&f);
        assert_eq!(
            relocs,
            vec![
                Reloc {
                    rva: 0x1010,
                    kind: 10
                },
                Reloc {
                    rva: 0x1040,
                    kind: 10
                }
            ]
        );
        let (b, mask) = pe.section_bytes(
            &f,
            &pe.sections[0],
            0x7ff0_0000_0000u64.wrapping_sub(0x1_8000_0000),
            &relocs,
        );
        assert!(mask.is_empty());
        assert_eq!(u64_at(&b, 0x10), Some(0x7ff0_0000_1100));
        assert_eq!(u64_at(&b, 0x40), Some(0x7ff0_0000_1180));
        assert_eq!(pe.exports(&f).near(0x1085), "DoWork+0x5");
        assert_eq!(pe.exports(&f).near(0x1000), "");
    }

    #[test]
    fn clean_mapping_then_patch_then_rewrite() {
        let f = tiny_dll();
        let base = 0x7ff6_1230_0000;
        let mut img = map(&f, base);
        let r = check(&f, &img, base);
        assert!(r.header.is_none() && r.changes.is_empty(), "{r:?}");
        assert_eq!((r.compared, r.bytes), (1, 0x200));

        img[0x1080..0x1085].copy_from_slice(&[0xE9, 0, 0, 0, 0]); // a hook on DoWork
        let r = check(&f, &img, base);
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.changes[0].stats.verdict(), Verdict::Patched);
        assert_eq!(r.changes[0].near[0], "DoWork+0x0");

        img[0x1000..0x1200].fill(0xCC); // the whole section overwritten
        let r = check(&f, &img, base);
        assert_eq!(r.changes[0].stats.verdict(), Verdict::Rewritten);
    }

    #[test]
    fn loader_thunk_section_is_skipped() {
        let mut f = tiny_dll();
        // Rename .text (section header 0 at optional header + 0xF0) to fothk.
        let s0 = 0x84 + 20 + 0xF0;
        f[s0..s0 + 8].copy_from_slice(b"fothk\0\0\0");
        let base = 0x7ff6_1230_0000;
        let mut img = map(&f, base);
        img[0x1000..0x1200].fill(0xCC); // what the loader's rewrite looks like to a diff
        let r = check(&f, &img, base);
        assert!(r.changes.is_empty(), "{r:?}");
        assert_eq!((r.compared, r.skipped.as_slice()), (0, &[SKIP_FOTHK][..]));
    }

    #[test]
    fn a_replaced_header_is_a_mismatch() {
        let f = tiny_dll();
        let base = 0x7ff6_1230_0000;
        let mut img = map(&f, base);
        img[0x84 + 4] ^= 0xFF; // TimeDateStamp
        let r = check(&f, &img, base);
        let h = r.header.expect("mismatch");
        assert!(h.fields[0].starts_with("TimeDateStamp"), "{:?}", h.fields);
        assert!(r.changes.is_empty());

        img[..2].copy_from_slice(b"\0\0"); // header wiped
        let h = check(&f, &img, base).header.expect("mismatch");
        assert!(h.fields[0].contains("no valid PE header"), "{:?}", h.fields);
    }

    #[test]
    fn hostile_input_never_panics() {
        let f = tiny_dll();
        // Every truncation, and many single-byte corruptions, of a valid image.
        for n in 0..f.len() {
            let t = &f[..n];
            if let Ok(pe) = parse(t) {
                let r = pe.relocations(t);
                for s in &pe.sections {
                    let _ = pe.section_bytes(t, s, 0x1234_5678, &r);
                }
                let _ = pe.exports(t);
                let _ = pe.il_only(t);
            }
        }
        let mut x: u32 = 0x9E37_79B9;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let mut g = f.clone();
            let i = (x as usize) % g.len();
            g[i] = (x >> 8) as u8;
            let j = ((x >> 3) as usize) % g.len();
            g[j] = 0xFF;
            if let Ok(pe) = parse(&g) {
                let r = pe.relocations(&g);
                for s in &pe.sections {
                    let _ = pe.section_bytes(&g, s, u64::from(x), &r);
                }
                let _ = pe.exports(&g).near(x);
                let mut read = |_: usize, buf: &mut [u8]| buf.len() / 2;
                let _ = check_image("fuzz", &g, &g, 0x1000_0000, &mut read);
            }
        }
    }

    /// Relocation and mapping checked against pefile's independent loader
    /// emulation on real compiler-built images. Point LRNG_PE_SAMPLES at a
    /// directory of `<image>` + `<image>.mapped-<hexbase>` pairs made by
    /// sidecar-rs/tests/pe_golden.py; skipped when unset.
    #[test]
    fn matches_pefile_on_real_images() {
        let Ok(dir) = std::env::var("LRNG_PE_SAMPLES") else {
            return;
        };
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let Some((stem, hex)) = name.split_once(".mapped-") else {
                continue;
            };
            let base = usize::from_str_radix(hex, 16).unwrap();
            let file = std::fs::read(path.with_file_name(stem)).unwrap();
            let golden = std::fs::read(&path).unwrap();
            let pe = parse(&file).unwrap();
            let relocs = pe.relocations(&file);
            let delta = (base as u64).wrapping_sub(pe.image_base);
            let mut compared = 0usize;
            for s in &pe.sections {
                let (bytes, mask) = pe.section_bytes(&file, s, delta, &relocs);
                let want = &golden[s.va as usize..s.va as usize + bytes.len()];
                for (i, (a, b)) in bytes.iter().zip(want).enumerate() {
                    if !mask.iter().any(|&(x, y)| (x..y).contains(&i)) {
                        assert_eq!(a, b, "{stem}: section {} +0x{i:x}", s.name);
                        compared += 1;
                    }
                }
            }
            let mut read = |addr: usize, buf: &mut [u8]| {
                let src = golden.get(addr - base..).unwrap_or(&[]);
                let n = buf.len().min(src.len());
                buf[..n].copy_from_slice(&src[..n]);
                n
            };
            let header = &golden[..golden.len().min(0x10000)];
            let r = check_image(stem, &file, header, base, &mut read);
            assert!(r.header.is_none() && r.changes.is_empty(), "{stem}: {r:?}");
            assert!(r.compared > 0 && r.bytes > 0, "{stem}: nothing compared");

            // Exports agree with pefile's, and a hook on a real exported
            // function is reported as a patch named after it.
            let ours = pe.exports(&file);
            let mut theirs: Vec<(u32, String)> =
                std::fs::read_to_string(path.with_file_name(format!("{stem}.exports")))
                    .unwrap()
                    .lines()
                    .filter_map(|l| {
                        let (rva, name) = l.split_once(' ')?;
                        Some((u32::from_str_radix(rva, 16).ok()?, name.to_string()))
                    })
                    .collect();
            theirs.sort();
            assert_eq!(ours.0, theirs, "{stem}: exports differ from pefile");
            let target = ours.0.iter().find(|(rva, _)| {
                pe.sections.iter().any(|s| {
                    s.exec()
                        && (s.va..s.va + s.file_len()).contains(rva)
                        && rva + 5 < s.va + s.file_len()
                })
            });
            if let Some((rva, fname)) = target {
                let aliases = ours.0.iter().filter(|(r, _)| r == rva).count();
                let mut hooked = golden.clone();
                hooked[*rva as usize..*rva as usize + 5]
                    .copy_from_slice(&[0xE9, 0x11, 0x22, 0x33, 0x44]);
                let mut read = |addr: usize, buf: &mut [u8]| {
                    let src = hooked.get(addr - base..).unwrap_or(&[]);
                    let n = buf.len().min(src.len());
                    buf[..n].copy_from_slice(&src[..n]);
                    n
                };
                let h = check_image(stem, &file, header, base, &mut read);
                let c = h.changes.first().expect("hook not found");
                assert_eq!(c.stats.verdict(), Verdict::Patched, "{stem}");
                let (names, off) = c.near[0].rsplit_once('+').expect("named");
                assert_eq!(off, "0x0", "{stem}");
                assert!(
                    aliases > 3 || names.split('/').any(|n| n == fname),
                    "{stem}: {:?} for {fname}",
                    c.near
                );
            }
            eprintln!(
                "{stem}: {} relocations, {compared} bytes matched, {} code byte(s) compared clean, {} exports",
                relocs.len(),
                r.bytes,
                ours.0.len()
            );
            checked += 1;
        }
        assert!(checked > 0, "LRNG_PE_SAMPLES={dir} holds no samples");
    }
}
