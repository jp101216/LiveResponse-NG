//! x64 stack unwinding from a module's own unwind data, the way Windows'
//! RtlVirtualUnwind does it, for walking the stacks of another process's
//! threads (windows_threads.rs).
//!
//! Every x64 function that allocates stack or saves registers has a
//! RUNTIME_FUNCTION entry in its image's exception directory (.pdata),
//! pointing at UNWIND_INFO codes that describe its prolog. Undoing them, last
//! operation first, recovers the caller's stack pointer and saved registers;
//! the caller's instruction pointer is then the return address on the stack.
//! The tables are read from the image file on disk, where nothing in the
//! process can have changed them.
//!
//! Only frames stopped at a call are unwound (a thread blocked in a system
//! call and its callers), so an epilog, where RtlVirtualUnwind must simulate
//! the remaining instructions, never needs handling: a return address can
//! only fall at an epilog's first instruction, where undoing the whole prolog
//! is the same thing.
//!
//! Platform-neutral and unit-tested on any OS.
#![cfg_attr(not(any(windows, lrng_typecheck_windows)), allow(dead_code))]

use super::pe;
use std::collections::BTreeMap;

/// IMAGE_DIRECTORY_ENTRY_EXCEPTION.
const DIR_EXCEPTION: usize = 3;
const UNW_FLAG_CHAININFO: u8 = 0x4;
/// RUNTIME_FUNCTION entries read per image, at most.
const MAX_FUNCTIONS: usize = 1 << 20;
/// Chained unwind information followed per frame, at most.
const MAX_CHAIN: usize = 32;

/// The stack pointer's number in unwind codes (and its slot in `Regs::int`).
pub const RSP: usize = 4;

/// The unwind operations (UNWIND_CODE.UnwindOp).
const PUSH_NONVOL: u8 = 0;
const ALLOC_LARGE: u8 = 1;
const ALLOC_SMALL: u8 = 2;
const SET_FPREG: u8 = 3;
const SAVE_NONVOL: u8 = 4;
const SAVE_NONVOL_FAR: u8 = 5;
const EPILOG: u8 = 6; // version 2; SAVE_XMM in version 1
const SPARE_CODE: u8 = 7; // SAVE_XMM_FAR in version 1
const SAVE_XMM128: u8 = 8;
const SAVE_XMM128_FAR: u8 = 9;
const PUSH_MACHFRAME: u8 = 10;

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

/// A thread's registers as an unwind needs them: the instruction pointer and
/// the sixteen integer registers in unwind-code order (RAX, RCX, RDX, RBX,
/// RSP, RBP, RSI, RDI, R8-R15).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub rip: u64,
    pub int: [u64; 16],
}

impl Regs {
    pub fn rsp(&self) -> u64 {
        self.int[RSP]
    }
}

/// One RUNTIME_FUNCTION: a function's code [begin, end) and its unwind
/// information, as RVAs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub begin: u32,
    pub end: u32,
    pub info: u32,
}

/// How a frame came off the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unwound {
    /// Through its return address, as a call returns.
    Return,
    /// Through a machine frame (an interrupt, exception or APC dispatcher):
    /// the next instruction pointer is wherever the thread was interrupted,
    /// and the registers the frame doesn't describe aren't recovered.
    MachineFrame,
}

/// An image's x64 unwind data: its functions and their unwind information.
#[derive(Debug, Default)]
pub struct UnwindTable {
    /// By begin RVA.
    functions: Vec<Function>,
    /// Each UNWIND_INFO by RVA: its header, codes and any chained entry.
    infos: BTreeMap<u32, Vec<u8>>,
}

impl UnwindTable {
    /// The table of an x64 image file, if it has one.
    pub fn from_image(file: &[u8]) -> Option<UnwindTable> {
        let pe = pe::parse(file).ok()?;
        if pe.machine != 0x8664 || pe.magic != 0x20b {
            return None;
        }
        let (rva, size) = pe.dir(DIR_EXCEPTION)?;
        let off = pe.rva_to_off(rva)?;
        let entry = |o: usize| {
            Some(Function {
                begin: u32_at(file, o)?,
                end: u32_at(file, o + 4)?,
                info: u32_at(file, o + 8)?,
            })
        };
        let mut t = UnwindTable::default();
        for i in 0..(size as usize / 12).min(MAX_FUNCTIONS) {
            let Some(mut f) = entry(off + 12 * i) else {
                break;
            };
            if f.info & 1 != 0 {
                // RUNTIME_FUNCTION_INDIRECT: the RVA of the entry that holds
                // the unwind information.
                let Some(g) = pe.rva_to_off(f.info & !1).and_then(entry) else {
                    continue;
                };
                f.info = g.info;
            }
            if f.begin >= f.end || f.info & 1 != 0 {
                continue;
            }
            t.keep_info(&pe, file, f.info, 0);
            t.functions.push(f);
        }
        t.functions.sort_by_key(|f| f.begin);
        Some(t)
    }

    /// Copy the UNWIND_INFO at `rva` (and those it chains to) out of the file.
    fn keep_info(&mut self, pe: &pe::Pe, file: &[u8], rva: u32, depth: usize) {
        if depth > MAX_CHAIN || self.infos.contains_key(&rva) {
            return;
        }
        let Some(o) = pe.rva_to_off(rva) else {
            return;
        };
        let Some(h) = file.get(o..o + 4) else {
            return;
        };
        let codes = 2 * (h[2] as usize + (h[2] as usize & 1));
        let chained = (h[0] >> 3) & UNW_FLAG_CHAININFO != 0;
        let len = 4 + codes + if chained { 12 } else { 0 };
        let Some(b) = file.get(o..o + len) else {
            return;
        };
        let mut b = b.to_vec();
        let next = if chained {
            // The chained entry's unwind information may itself be indirect.
            let mut info = u32_at(&b, 4 + codes + 8).unwrap_or(0);
            if info & 1 != 0 {
                info = pe
                    .rva_to_off(info & !1)
                    .and_then(|o| u32_at(file, o + 8))
                    .unwrap_or(0);
                b[4 + codes + 8..4 + codes + 12].copy_from_slice(&info.to_le_bytes());
            }
            Some(info)
        } else {
            None
        };
        self.infos.insert(rva, b);
        if let Some(info) = next.filter(|&i| i != 0 && i & 1 == 0) {
            self.keep_info(pe, file, info, depth + 1);
        }
    }

    /// The function whose code holds `rva`.
    pub fn function(&self, rva: u32) -> Option<Function> {
        let i = self
            .functions
            .partition_point(|f| f.begin <= rva)
            .checked_sub(1)?;
        let f = self.functions[i];
        (rva < f.end).then_some(f)
    }

    /// Whether `rva` is where a function begins (`Some(true)`), or lies
    /// inside one past its start (`Some(false)`). `None` when no function
    /// covers it (a thunk or a leaf has no entry), so nothing can be said.
    pub fn starts_function(&self, rva: u32) -> Option<bool> {
        self.function(rva).map(|f| f.begin == rva)
    }

    /// Unwind one frame. `pc` is the frame's instruction pointer as an RVA
    /// and `lookup` the RVA its function is found by (for a return address,
    /// the address minus one: a call to a function that never returns can be
    /// a function's last instruction). On success `regs` hold the caller's
    /// registers and instruction pointer. A frame whose function has no
    /// unwind data is an error here: only the innermost frame can be a leaf
    /// (see [`pop_leaf`]).
    pub fn unwind(
        &self,
        pc: u32,
        lookup: u32,
        regs: &mut Regs,
        read: &mut dyn FnMut(u64) -> Option<u64>,
    ) -> Result<Unwound, &'static str> {
        let f = self.function(lookup).ok_or("no unwind data")?;
        let info = self
            .infos
            .get(&f.info)
            .ok_or("unwind information unreadable")?;
        let prolog = pc.wrapping_sub(f.begin);
        // The frame base save-register offsets count from: the stack pointer
        // after the prolog's fixed allocation (the frame register minus its
        // offset, once the prolog has set it).
        let frame_reg = (info[3] & 0x0f) as usize;
        let frame_off = u64::from(info[3] >> 4) * 16;
        let chained = (info[0] >> 3) & UNW_FLAG_CHAININFO != 0;
        let fp_set = frame_reg != 0
            && (prolog >= u32::from(info[1])
                || chained
                || codes(info).any(|(off, op, _)| op == SET_FPREG && prolog >= u32::from(off)));
        let base = if fp_set {
            regs.int[frame_reg].wrapping_sub(frame_off)
        } else {
            regs.rsp()
        };

        let mut info = info;
        let mut primary = true;
        let mut machine = false;
        for _ in 0..MAX_CHAIN {
            let count = info[2] as usize;
            let slot = |k: usize| u16_at(info, 4 + 2 * k).map(u64::from);
            let (fr, fo) = ((info[3] & 0x0f) as usize, u64::from(info[3] >> 4) * 16);
            let mut i = 0;
            while i < count {
                let (off, op, opinfo) = (
                    info[4 + 2 * i],
                    info[5 + 2 * i] & 0x0f,
                    (info[5 + 2 * i] >> 4) as usize,
                );
                let n = slots(op, opinfo).ok_or("unknown unwind code")?;
                if primary && prolog < u32::from(off) {
                    i += n; // not yet executed at this point of the prolog
                    continue;
                }
                let rsp = regs.rsp();
                match op {
                    PUSH_NONVOL => {
                        regs.int[opinfo] = read(rsp).ok_or("stack unreadable")?;
                        regs.int[RSP] = rsp.wrapping_add(8);
                    }
                    ALLOC_LARGE => {
                        let size = if opinfo == 0 {
                            slot(i + 1).ok_or("truncated unwind code")? * 8
                        } else {
                            slot(i + 1).ok_or("truncated unwind code")?
                                | slot(i + 2).ok_or("truncated unwind code")? << 16
                        };
                        regs.int[RSP] = rsp.wrapping_add(size);
                    }
                    ALLOC_SMALL => regs.int[RSP] = rsp.wrapping_add(opinfo as u64 * 8 + 8),
                    SET_FPREG => regs.int[RSP] = regs.int[fr].wrapping_sub(fo),
                    SAVE_NONVOL => {
                        let at = base.wrapping_add(slot(i + 1).ok_or("truncated unwind code")? * 8);
                        regs.int[opinfo] = read(at).ok_or("stack unreadable")?;
                    }
                    SAVE_NONVOL_FAR => {
                        let o = slot(i + 1).ok_or("truncated unwind code")?
                            | slot(i + 2).ok_or("truncated unwind code")? << 16;
                        regs.int[opinfo] = read(base.wrapping_add(o)).ok_or("stack unreadable")?;
                    }
                    EPILOG | SPARE_CODE | SAVE_XMM128 | SAVE_XMM128_FAR => {}
                    PUSH_MACHFRAME => {
                        let at = rsp.wrapping_add(if opinfo != 0 { 8 } else { 0 });
                        regs.rip = read(at).ok_or("stack unreadable")?;
                        regs.int[RSP] = read(at.wrapping_add(24)).ok_or("stack unreadable")?;
                        machine = true;
                    }
                    _ => return Err("unknown unwind code"),
                }
                i += n;
            }
            if (info[0] >> 3) & UNW_FLAG_CHAININFO == 0 {
                break;
            }
            let c = 4 + 2 * (count + (count & 1));
            let next = u32_at(info, c + 8).ok_or("truncated chained entry")?;
            info = self
                .infos
                .get(&next)
                .ok_or("chained unwind information unreadable")?;
            primary = false;
        }
        if machine {
            return Ok(Unwound::MachineFrame);
        }
        let rsp = regs.rsp();
        regs.rip = read(rsp).ok_or("stack unreadable")?;
        regs.int[RSP] = rsp.wrapping_add(8);
        Ok(Unwound::Return)
    }
}

/// Unwind the innermost frame of a function with no unwind data (a leaf: it
/// allocates nothing, so its return address is at the stack pointer).
pub fn pop_leaf(regs: &mut Regs, read: &mut dyn FnMut(u64) -> Option<u64>) -> Option<()> {
    let rsp = regs.rsp();
    regs.rip = read(rsp)?;
    regs.int[RSP] = rsp.wrapping_add(8);
    Some(())
}

/// The unwind codes of an UNWIND_INFO: (prolog offset, operation, info).
fn codes(info: &[u8]) -> impl Iterator<Item = (u8, u8, usize)> + '_ {
    let count = info.get(2).copied().unwrap_or(0) as usize;
    let mut i = 0;
    std::iter::from_fn(move || {
        if i >= count {
            return None;
        }
        let (off, b) = (*info.get(4 + 2 * i)?, *info.get(5 + 2 * i)?);
        let (op, opinfo) = (b & 0x0f, (b >> 4) as usize);
        i += slots(op, opinfo)?;
        Some((off, op, opinfo))
    })
}

/// How many 16-bit slots an unwind code takes.
fn slots(op: u8, opinfo: usize) -> Option<usize> {
    Some(match op {
        PUSH_NONVOL | ALLOC_SMALL | SET_FPREG | PUSH_MACHFRAME => 1,
        ALLOC_LARGE if opinfo == 0 => 2,
        ALLOC_LARGE => 3,
        SAVE_NONVOL | EPILOG | SAVE_XMM128 => 2,
        SAVE_NONVOL_FAR | SPARE_CODE | SAVE_XMM128_FAR => 3,
        _ => return None,
    })
}

/// Whether the bytes just before a return address end with a call: `call
/// rel32`, or `call`/`call far` through a register or memory (FF /2, FF /3)
/// in any addressing form, with legacy prefixes and REX. Every return address
/// a call pushed passes; one forged onto a stack (a gadget made to look like
/// a caller) mostly doesn't.
pub fn follows_call(before: &[u8]) -> bool {
    let n = before.len();
    (2..=n.min(15)).any(|len| call_length(&before[n - len..]) == Some(len))
}

/// The length of the call instruction at the start of `b`, if it is one.
fn call_length(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while matches!(
        b.get(i),
        Some(0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF2 | 0xF3)
    ) {
        i += 1;
        if i > 4 {
            return None;
        }
    }
    if matches!(b.get(i), Some(0x40..=0x4F)) {
        i += 1;
    }
    match *b.get(i)? {
        0xE8 => Some(i + 5),
        0xFF => {
            let modrm = *b.get(i + 1)?;
            if !matches!((modrm >> 3) & 7, 2 | 3) {
                return None;
            }
            let (md, rm) = (modrm >> 6, modrm & 7);
            let mut len = i + 2;
            if md == 3 {
                return Some(len);
            }
            if rm == 4 {
                let sib = *b.get(i + 2)?;
                len += 1;
                if md == 0 && sib & 7 == 5 {
                    len += 4;
                }
            } else if md == 0 && rm == 5 {
                len += 4; // RIP-relative
            }
            Some(len + [0, 1, 4][md as usize])
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A minimal x64 image: one section at RVA 0x1000 (file 0x200, 0x1000
    /// bytes) holding `bytes` at their RVAs, with the exception directory at
    /// `pdata` covering `functions`.
    pub(crate) fn image(functions: &[Function], bytes: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut f = vec![0u8; 0x1200];
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
        let pdata = 0x1E00u32;
        let d = oh + 112 + 8 * DIR_EXCEPTION;
        f[d..d + 4].copy_from_slice(&pdata.to_le_bytes());
        f[d + 4..d + 8].copy_from_slice(&(12 * functions.len() as u32).to_le_bytes());
        let s = oh + 0xF0;
        f[s..s + 5].copy_from_slice(b".text");
        f[s + 8..s + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        f[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        f[s + 16..s + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        f[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        f[s + 36..s + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let at = |rva: u32| (rva - 0x1000 + 0x200) as usize;
        for (k, func) in functions.iter().enumerate() {
            let o = at(pdata) + 12 * k;
            f[o..o + 4].copy_from_slice(&func.begin.to_le_bytes());
            f[o + 4..o + 8].copy_from_slice(&func.end.to_le_bytes());
            f[o + 8..o + 12].copy_from_slice(&func.info.to_le_bytes());
        }
        for (rva, b) in bytes {
            f[at(*rva)..at(*rva) + b.len()].copy_from_slice(b);
        }
        f
    }

    /// An UNWIND_INFO: version 1, `flags`, the prolog size, the frame
    /// register and offset, then the codes (each a (prolog offset, op, info)
    /// or a raw slot) and any chained entry.
    pub(crate) fn info(
        flags: u8,
        prolog: u8,
        frame: (u8, u8),
        codes: &[Code],
        chain: Option<Function>,
    ) -> Vec<u8> {
        let mut slots: Vec<u16> = Vec::new();
        for c in codes {
            match *c {
                Code::Op(off, op, info) => {
                    slots.push(u16::from(off) | u16::from(op | info << 4) << 8)
                }
                Code::Slot(v) => slots.push(v),
            }
        }
        let mut b = vec![
            1 | flags << 3,
            prolog,
            slots.len() as u8,
            frame.0 | frame.1 << 4,
        ];
        for s in &slots {
            b.extend_from_slice(&s.to_le_bytes());
        }
        if slots.len() % 2 == 1 {
            b.extend_from_slice(&[0, 0]);
        }
        if let Some(c) = chain {
            b.extend_from_slice(&c.begin.to_le_bytes());
            b.extend_from_slice(&c.end.to_le_bytes());
            b.extend_from_slice(&c.info.to_le_bytes());
        }
        b
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Code {
        Op(u8, u8, u8),
        Slot(u16),
    }
    use Code::{Op, Slot};

    /// A stack as a map of 8-byte slots.
    fn stack(values: &[(u64, u64)]) -> impl FnMut(u64) -> Option<u64> {
        let m: HashMap<u64, u64> = values.iter().copied().collect();
        move |a| m.get(&a).copied()
    }

    fn regs(rsp: u64) -> Regs {
        let mut r = Regs::default();
        r.int[RSP] = rsp;
        r
    }

    const RBX: usize = 3;
    const RBP: usize = 5;
    const RSI: usize = 6;
    const R15: usize = 15;

    #[test]
    fn unwinds_the_common_prologs() {
        // push rbx; sub rsp, 0x20 (prolog 5 bytes): codes in reverse order.
        let f1 = Function {
            begin: 0x1000,
            end: 0x1040,
            info: 0x1800,
        };
        let i1 = info(
            0,
            5,
            (0, 0),
            &[Op(5, ALLOC_SMALL, 3), Op(1, PUSH_NONVOL, RBX as u8)],
            None,
        );
        // push rbp; sub rsp, 0x100; lea rbp, [rsp+0x20]; mov [rbp-0x20+0x30], rsi
        // (frame register RBP, offset 0x20; SAVE_NONVOL slot 6 = 0x30 from the frame base)
        let f2 = Function {
            begin: 0x1040,
            end: 0x1100,
            info: 0x1820,
        };
        let i2 = info(
            0,
            0x10,
            (RBP as u8, 2),
            &[
                Op(0x10, SAVE_NONVOL, RSI as u8),
                Slot(6),
                Op(0x0c, SET_FPREG, 0),
                Op(0x08, ALLOC_LARGE, 0),
                Slot(0x100 / 8),
                Op(1, PUSH_NONVOL, RBP as u8),
            ],
            None,
        );
        let t = UnwindTable::from_image(&image(&[f1, f2], &[(0x1800, i1), (0x1820, i2)])).unwrap();
        assert_eq!(t.functions.len(), 2);

        // In f1 past its prolog: rsp 0x5000 -> rbx at 0x5020, return at 0x5028.
        let mut r = regs(0x5000);
        let mut read = stack(&[(0x5020, 0xBB), (0x5028, 0x7777)]);
        assert_eq!(
            t.unwind(0x1010, 0x1010, &mut r, &mut read),
            Ok(Unwound::Return)
        );
        assert_eq!((r.rip, r.rsp(), r.int[RBX]), (0x7777, 0x5030, 0xBB));

        // In f1 one byte into its prolog: only the push has happened.
        let mut r = regs(0x5020);
        let mut read = stack(&[(0x5020, 0xBB), (0x5028, 0x7777)]);
        t.unwind(0x1001, 0x1001, &mut r, &mut read).unwrap();
        assert_eq!((r.rip, r.rsp(), r.int[RBX]), (0x7777, 0x5030, 0xBB));

        // In f2: rbp = rsp + 0x20 = 0x6020; frame base 0x6000; rsi at 0x6030;
        // rbp pushed at 0x6100, return at 0x6108.
        let mut r = regs(0x6000);
        r.int[RBP] = 0x6020;
        let mut read = stack(&[(0x6030, 0x51), (0x6100, 0xB0), (0x6108, 0x8888)]);
        t.unwind(0x1080, 0x107f, &mut r, &mut read).unwrap();
        assert_eq!(
            (r.rip, r.rsp(), r.int[RSI], r.int[RBP]),
            (0x8888, 0x6110, 0x51, 0xB0)
        );
        // The same frame found through a stack pointer that moved (alloca):
        // the frame register still leads back.
        let mut r = regs(0x5f00);
        r.int[RBP] = 0x6020;
        t.unwind(0x1080, 0x107f, &mut r, &mut read).unwrap();
        assert_eq!((r.rip, r.rsp()), (0x8888, 0x6110));
    }

    #[test]
    fn unwinds_large_and_far_codes_chains_and_machine_frames() {
        // sub rsp, 0x12340 (ALLOC_LARGE, unscaled 32-bit), mov [rsp+0x10008], r15
        // (SAVE_NONVOL_FAR), and a version-2 epilog code to skip.
        let big = Function {
            begin: 0x1000,
            end: 0x1080,
            info: 0x1800,
        };
        let ibig = info(
            0,
            0x20,
            (0, 0),
            &[
                Op(0x01, EPILOG, 1),
                Slot(0),
                Op(0x20, SAVE_NONVOL_FAR, R15 as u8),
                Slot(0x0008),
                Slot(0x0001),
                Op(0x10, ALLOC_LARGE, 1),
                Slot(0x2340),
                Slot(0x0001),
            ],
            None,
        );
        // A fragment chained to its parent: the fragment pushes nothing; the
        // parent did push rbx; sub rsp, 0x28.
        let parent = Function {
            begin: 0x1100,
            end: 0x1140,
            info: 0x1840,
        };
        let iparent = info(
            0,
            5,
            (0, 0),
            &[Op(5, ALLOC_SMALL, 4), Op(1, PUSH_NONVOL, RBX as u8)],
            None,
        );
        let frag = Function {
            begin: 0x1180,
            end: 0x11a0,
            info: 0x1860,
        };
        let ifrag = info(UNW_FLAG_CHAININFO, 0, (0, 0), &[], Some(parent));
        // An interrupt dispatcher: a machine frame after 0x4d0 bytes of state.
        let disp = Function {
            begin: 0x1200,
            end: 0x1220,
            info: 0x1880,
        };
        let idisp = info(
            0,
            0,
            (0, 0),
            &[
                Op(0, ALLOC_LARGE, 0),
                Slot(0x4d0 / 8),
                Op(0, PUSH_MACHFRAME, 0),
            ],
            None,
        );
        let file = image(
            &[big, parent, frag, disp],
            &[
                (0x1800, ibig),
                (0x1840, iparent),
                (0x1860, ifrag),
                (0x1880, idisp),
            ],
        );
        let t = UnwindTable::from_image(&file).unwrap();

        let mut r = regs(0x10000);
        let mut read = stack(&[(0x10000 + 0x10008, 0xF15), (0x10000 + 0x12340, 0x9999)]);
        t.unwind(0x1040, 0x1040, &mut r, &mut read).unwrap();
        assert_eq!(
            (r.rip, r.rsp(), r.int[R15]),
            (0x9999, 0x10000 + 0x12348, 0xF15)
        );

        // In the fragment: all of the parent's prolog applies.
        let mut r = regs(0x7000);
        let mut read = stack(&[(0x7028, 0xB1), (0x7030, 0xAAAA)]);
        t.unwind(0x1190, 0x118f, &mut r, &mut read).unwrap();
        assert_eq!((r.rip, r.rsp(), r.int[RBX]), (0xAAAA, 0x7038, 0xB1));

        // The machine frame: rip at +0x4d0, rsp at +0x4d0+24.
        let mut r = regs(0x8000);
        let mut read = stack(&[(0x84d0, 0x1234), (0x84e8, 0x9000)]);
        assert_eq!(
            t.unwind(0x1210, 0x1210, &mut r, &mut read),
            Ok(Unwound::MachineFrame)
        );
        assert_eq!((r.rip, r.rsp()), (0x1234, 0x9000));
    }

    #[test]
    fn functions_and_leaves() {
        let f = Function {
            begin: 0x1000,
            end: 0x1040,
            info: 0x1800,
        };
        let g = Function {
            begin: 0x1050,
            end: 0x1060,
            info: 0x1800,
        };
        let i = info(0, 4, (0, 0), &[Op(4, ALLOC_SMALL, 4)], None);
        let t = UnwindTable::from_image(&image(&[g, f], &[(0x1800, i)])).unwrap();
        assert_eq!(t.function(0x1000), Some(f));
        assert_eq!(t.function(0x103f), Some(f));
        assert_eq!(t.function(0x1045), None); // between functions
        assert_eq!(t.function(0x1055), Some(g));
        assert_eq!(t.starts_function(0x1000), Some(true));
        assert_eq!(t.starts_function(0x1021), Some(false));
        assert_eq!(t.starts_function(0x1048), None);
        let mut r = regs(0x4000);
        assert_eq!(
            t.unwind(0x1048, 0x1047, &mut r, &mut stack(&[])),
            Err("no unwind data")
        );
        let mut read = stack(&[(0x4000, 0x55)]);
        pop_leaf(&mut r, &mut read).unwrap();
        assert_eq!((r.rip, r.rsp()), (0x55, 0x4008));
        // Not an x64 image, or no exception directory.
        assert!(UnwindTable::from_image(b"MZ not a pe").is_none());
        let mut no_dir = image(&[], &[]);
        no_dir[0x84 + 20 + 112 + 8 * DIR_EXCEPTION + 4..][..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(UnwindTable::from_image(&no_dir).is_none());
    }

    #[test]
    fn indirect_entries_are_followed() {
        let real = Function {
            begin: 0x1000,
            end: 0x1040,
            info: 0x1800,
        };
        // An entry whose unwind data is the RVA (low bit set) of `real`'s entry.
        let pdata_real = 0x1E00u32;
        let alias = Function {
            begin: 0x1100,
            end: 0x1120,
            info: pdata_real | 1,
        };
        let i = info(0, 4, (0, 0), &[Op(4, ALLOC_SMALL, 1)], None);
        let t = UnwindTable::from_image(&image(&[real, alias], &[(0x1800, i)])).unwrap();
        let mut r = regs(0x2000);
        let mut read = stack(&[(0x2010, 0x42)]);
        t.unwind(0x1110, 0x1110, &mut r, &mut read).unwrap();
        assert_eq!((r.rip, r.rsp()), (0x42, 0x2018));
    }

    #[test]
    fn return_addresses_follow_calls() {
        let ok: &[&[u8]] = &[
            &[0x90, 0xE8, 1, 2, 3, 4],             // call rel32
            &[0xFF, 0x15, 1, 2, 3, 4],             // call [rip+disp32]
            &[0x48, 0xFF, 0x15, 1, 2, 3, 4],       // REX.W call [rip+disp32] (CFG)
            &[0xCC, 0xFF, 0xD0],                   // call rax
            &[0x41, 0xFF, 0xD3],                   // call r11
            &[0xFF, 0x50, 0x08],                   // call [rax+8]
            &[0xFF, 0x14, 0x24],                   // call [rsp]
            &[0x41, 0xFF, 0x94, 0x24, 1, 2, 3, 4], // call [r12+disp32]
            &[0x3E, 0xFF, 0xD0],                   // notrack call rax
        ];
        for b in ok {
            assert!(follows_call(b), "{b:02x?}");
        }
        let not: &[&[u8]] = &[
            &[0xCC, 0xCC, 0xCC, 0xCC],       // padding before a function
            &[0x48, 0x83, 0xC4, 0x28, 0xC3], // add rsp, 0x28; ret
            &[0xFF, 0xE0],                   // jmp rax
            &[0xFF, 0x25, 1, 2, 3, 4],       // jmp [rip+disp32]
            &[],
        ];
        for b in not {
            assert!(!follows_call(b), "{b:02x?}");
        }
    }
}
