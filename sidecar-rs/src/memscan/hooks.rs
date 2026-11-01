//! Exception hooks: hardware breakpoints and vectored exception handlers.
//!
//! A "patchless" hook changes no code, so image integrity (integrity.rs) has
//! nothing to compare. A hardware breakpoint (an address in debug register
//! Dr0-Dr3, armed in Dr7) makes the CPU raise an exception when the thread
//! reaches that address, and a vectored exception handler (VEH) that the same
//! code registered catches it and rewrites the thread's context before the
//! function runs: skip AmsiScanBuffer and report "clean", return early from
//! EtwEventWrite. Both halves can be seen from outside the process: the
//! breakpoint in each thread's debug registers, the handler in ntdll's list of
//! vectored handlers. Injected code also uses a vectored handler on its own,
//! to catch the faults it causes on purpose (sleep obfuscation that strips its
//! memory's permissions between callbacks, guard-page tricks), so a handler
//! that points into memory no image file backs is reported whatever the
//! breakpoints show.
//!
//! This module judges what windows_hooks.rs reads. It is platform-neutral and
//! unit-tested on any OS; hits carry addresses, thread ids and export names,
//! never memory contents.
#![cfg_attr(not(any(windows, lrng_typecheck_windows)), allow(dead_code))]

use super::integrity::{symbol_names, ETW_WRITERS};
use crate::contract::Hit;
use serde_json::json;
use std::collections::BTreeSet;

/// What a debug register watches (its R/W bits in Dr7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Watch {
    Execute,
    Write,
    Io,
    ReadWrite,
}

impl Watch {
    fn name(self) -> &'static str {
        match self {
            Watch::Execute => "execute",
            Watch::Write => "write",
            Watch::Io => "I/O",
            Watch::ReadWrite => "read/write",
        }
    }
}

/// One armed hardware breakpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breakpoint {
    pub tid: u32,
    pub slot: u8,
    pub addr: usize,
    pub watch: Watch,
    pub len: u8,
    /// Lower-case file name of the image holding the address ("" if none).
    pub module: String,
    /// "Export+0xoff" in that image, or "".
    pub symbol: String,
    /// The address is in one of ntdll's system-call stubs.
    pub syscall_stub: bool,
}

/// The breakpoints a thread has armed, from its Dr0-Dr3 and Dr7. A slot is
/// armed when its local or global enable bit is set; an armed slot at address
/// 0 is ignored (nothing runs there).
pub fn armed(tid: u32, dr: [usize; 4], dr7: usize) -> Vec<Breakpoint> {
    let mut out = Vec::new();
    for slot in 0..4u8 {
        let addr = dr[slot as usize];
        if (dr7 >> (2 * slot)) & 3 == 0 || addr == 0 {
            continue;
        }
        let watch = match (dr7 >> (16 + 4 * slot)) & 3 {
            0 => Watch::Execute,
            1 => Watch::Write,
            2 => Watch::Io,
            _ => Watch::ReadWrite,
        };
        let len = match (dr7 >> (18 + 4 * slot)) & 3 {
            0 => 1,
            1 => 2,
            2 => 8,
            _ => 4,
        };
        out.push(Breakpoint {
            tid,
            slot,
            addr,
            watch,
            len,
            module: String::new(),
            symbol: String::new(),
            syscall_stub: false,
        });
    }
    out
}

/// Which list a vectored handler is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerList {
    /// AddVectoredExceptionHandler: called first for every exception.
    Exception,
    /// AddVectoredContinueHandler: called when execution resumes.
    Continue,
}

impl HandlerList {
    fn name(self) -> &'static str {
        match self {
            HandlerList::Exception => "vectored exception handler",
            HandlerList::Continue => "vectored continue handler",
        }
    }
}

/// One registered vectored handler, decoded, and the memory it points into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handler {
    pub list: HandlerList,
    pub addr: usize,
    /// "image", "private" or "mapped".
    pub kind: String,
    /// "RX", "RWX", ...
    pub protect: String,
    /// Lower-case file name of the image, when kind is "image".
    pub module: String,
}

impl Handler {
    fn unbacked(&self) -> bool {
        self.kind != "image"
    }
}

/// Everything read about one process.
#[derive(Debug, Default)]
pub struct Report {
    pub supported: bool,
    /// Why the check didn't run.
    pub why: Option<String>,
    /// Threads whose debug registers were read, and those that couldn't be.
    pub threads: usize,
    pub threads_unreadable: usize,
    pub breakpoints: Vec<Breakpoint>,
    /// Both vectored-handler lists were read.
    pub handlers_walked: bool,
    pub handlers_skipped: Option<String>,
    pub handlers: Vec<Handler>,
    /// Decoded entries that point at nothing executable: a handler that would
    /// crash if called is a stale entry or a misread, not a hook.
    pub handlers_invalid: usize,
    /// A debugger is attached to the process (None: couldn't tell).
    pub debugged: Option<bool>,
}

/// How far into an ETW writer a breakpoint may sit and still be on it (the
/// syscall stubs are 0x20 bytes; a bypass breaks at the entry or the syscall).
const ETW_REACH: usize = 0x200;

fn offset_of(symbol: &str) -> Option<usize> {
    let (_, off) = symbol.rsplit_once("+0x")?;
    usize::from_str_radix(off, 16).ok()
}

fn is_amsi(b: &Breakpoint) -> bool {
    b.module == "amsi.dll" && b.watch == Watch::Execute
}

fn is_etw(b: &Breakpoint) -> bool {
    b.module == "ntdll.dll"
        && b.watch == Watch::Execute
        && offset_of(&b.symbol).is_some_and(|o| o < ETW_REACH)
        && symbol_names(&b.symbol)
            .any(|n| ETW_WRITERS.contains(&n) || n == "NtTraceControl" || n == "ZwTraceControl")
}

/// A breakpoint in a system-call stub (other than ETW's): TamperingSyscalls
/// and LayeredSyscall break there so a handler can rewrite the call.
fn is_syscall(b: &Breakpoint) -> bool {
    b.module == "ntdll.dll" && b.watch == Watch::Execute && b.syscall_stub && !is_etw(b)
}

fn where_(b: &Breakpoint) -> String {
    let at = match (b.module.as_str(), b.symbol.as_str()) {
        ("", _) => format!("0x{:x}", b.addr),
        (m, "") => format!("{m} at 0x{:x}", b.addr),
        (m, s) => format!("{m}!{s}"),
    };
    let size = if b.watch == Watch::Execute {
        String::new()
    } else {
        format!(", {} byte(s)", b.len)
    };
    format!(
        "{at} (thread {}, Dr{}, {}{size})",
        b.tid,
        b.slot,
        b.watch.name()
    )
}

fn list(bps: &[&Breakpoint]) -> String {
    let mut parts: Vec<String> = bps.iter().take(4).map(|b| where_(b)).collect();
    if bps.len() > 4 {
        parts.push(format!("and {} more", bps.len() - 4));
    }
    parts.join("; ")
}

fn hit(
    rule: &str,
    severity: &str,
    technique: &str,
    confidence: i64,
    addr: usize,
    context: String,
) -> Hit {
    Hit {
        rule: rule.to_string(),
        severity: severity.to_string(),
        technique: technique.to_string(),
        offset: addr as i64,
        encoding: String::new(),
        context,
        confidence,
        region: None,
        extracted: None,
    }
}

impl Report {
    pub fn unsupported(why: impl Into<String>) -> Self {
        Report {
            why: Some(why.into()),
            ..Default::default()
        }
    }

    fn unbacked(&self) -> Vec<&Handler> {
        self.handlers.iter().filter(|h| h.unbacked()).collect()
    }

    /// What a breakpoint hit says about the handler half of the hook.
    fn handler_note(&self) -> String {
        let n = self.unbacked().len();
        if n > 0 {
            format!(" This process also has {n} vectored handler(s) in memory no image file backs.")
        } else if self.handlers_walked {
            " No vectored handler points outside the images; the one that acts on this breakpoint lives in a loaded module.".into()
        } else {
            String::new()
        }
    }

    pub fn hits(&self) -> Vec<Hit> {
        let mut out = Vec::new();
        let debugged = self.debugged == Some(true);
        let debugger = if debugged {
            " A debugger is attached to this process, and debuggers set breakpoints like this."
        } else {
            ""
        };
        let (sev, conf) = if debugged {
            ("suspect", 55)
        } else {
            ("critical", 85)
        };
        let amsi: Vec<&Breakpoint> = self.breakpoints.iter().filter(|b| is_amsi(b)).collect();
        let etw: Vec<&Breakpoint> = self.breakpoints.iter().filter(|b| is_etw(b)).collect();
        let syscall: Vec<&Breakpoint> = self.breakpoints.iter().filter(|b| is_syscall(b)).collect();
        let other: Vec<&Breakpoint> = self
            .breakpoints
            .iter()
            .filter(|b| !is_amsi(b) && !is_etw(b) && !is_syscall(b))
            .collect();
        if let Some(first) = amsi.first() {
            out.push(hit(
                "defense.amsi_hwbp",
                sev,
                "T1562.001",
                conf,
                first.addr,
                format!(
                    "hardware breakpoint on amsi.dll code: {}. The CPU stops there before the Antimalware Scan Interface scans anything, and an exception handler can skip the scan without changing a byte of code: the patchless AMSI bypass.{}{debugger}",
                    list(&amsi),
                    self.handler_note()
                ),
            ));
        }
        if let Some(first) = etw.first() {
            out.push(hit(
                "defense.etw_hwbp",
                sev,
                "T1562.006",
                conf,
                first.addr,
                format!(
                    "hardware breakpoint on ntdll's ETW event writer: {}. An exception handler can return before the event is written, blinding event tracing without changing a byte of code: the patchless ETW bypass.{}{debugger}",
                    list(&etw),
                    self.handler_note()
                ),
            ));
        }
        if let Some(first) = syscall.first() {
            out.push(hit(
                "defense.syscall_hwbp",
                sev,
                "T1106",
                if debugged { 50 } else { 80 },
                first.addr,
                format!(
                    "hardware breakpoint on ntdll's system-call stub: {}. An exception handler there can change the call's arguments or number on its way into the kernel, after hooks and logging have seen a harmless one: TamperingSyscalls and LayeredSyscall work this way.{}{debugger}",
                    list(&syscall),
                    self.handler_note()
                ),
            ));
        }
        if let Some(first) = other.first() {
            let exec = other.iter().any(|b| b.watch == Watch::Execute);
            let (sev, conf) = match (debugged, exec) {
                (true, _) => ("info", 20),
                (false, true) => ("notable", 45),
                (false, false) => ("notable", 35),
            };
            out.push(hit(
                "memory.hardware_breakpoint",
                sev,
                "",
                conf,
                first.addr,
                format!(
                    "hardware breakpoint(s) armed in this process: {}. Debuggers set these; malware uses them to hook a function without changing its code.{}",
                    list(&other),
                    if debugged {
                        " A debugger is attached to this process."
                    } else {
                        ""
                    }
                ),
            ));
        }
        for h in self.unbacked() {
            out.push(hit(
                "memory.veh_unbacked",
                "critical",
                "T1055",
                80,
                h.addr,
                format!(
                    "a {} points to 0x{:x}, in {} {} memory that no image file backs: code injected into this process handles its exceptions there, the other half of a patchless hook, or of sleep obfuscation that hides its memory between callbacks",
                    h.list.name(),
                    h.addr,
                    h.protect,
                    h.kind
                ),
            ));
        }
        out
    }

    /// Per-process summary for the response meta.
    pub fn meta(&self) -> serde_json::Value {
        if !self.supported {
            return json!({ "supported": false, "why": self.why });
        }
        let modules: BTreeSet<&str> = self
            .handlers
            .iter()
            .filter(|h| !h.unbacked())
            .map(|h| h.module.as_str())
            .collect();
        json!({
            "supported": true,
            "threads": self.threads,
            "threads_unreadable": self.threads_unreadable,
            "breakpoints": self.breakpoints.len(),
            "handlers_walked": self.handlers_walked,
            "handlers_skipped": self.handlers_skipped,
            "handlers": self.handlers.len(),
            "handlers_unbacked": self.unbacked().len(),
            "handlers_invalid": self.handlers_invalid,
            "handler_modules": modules.into_iter().take(16).collect::<Vec<_>>(),
            "debugged": self.debugged,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bp(module: &str, symbol: &str, addr: usize) -> Breakpoint {
        Breakpoint {
            tid: 77,
            slot: 0,
            addr,
            watch: Watch::Execute,
            len: 1,
            module: module.into(),
            symbol: symbol.into(),
            syscall_stub: false,
        }
    }

    fn handler(kind: &str, protect: &str, module: &str, addr: usize) -> Handler {
        Handler {
            list: HandlerList::Exception,
            addr,
            kind: kind.into(),
            protect: protect.into(),
            module: module.into(),
        }
    }

    fn rules(r: &Report) -> Vec<(String, String)> {
        r.hits().into_iter().map(|h| (h.rule, h.severity)).collect()
    }

    #[test]
    fn decodes_dr7() {
        // Dr0 local execute; Dr1 global write, 4 bytes; Dr2 armed at 0
        // (ignored); Dr3 disarmed but holding an address.
        let dr7 = 0b01 | (0b10 << 2) | (0b01 << 4) | (0b01 << 20) | (0b11 << 22);
        let got = armed(9, [0x1000, 0x2000, 0, 0x4000], dr7);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(
            (got[0].slot, got[0].addr, got[0].watch, got[0].len),
            (0, 0x1000, Watch::Execute, 1)
        );
        assert_eq!(
            (got[1].slot, got[1].addr, got[1].watch, got[1].len),
            (1, 0x2000, Watch::Write, 4)
        );
        // Read/write, 8 bytes, in slot 3.
        let got = armed(9, [0, 0, 0, 0x5000], (1 << 6) | (0b11 << 28) | (0b10 << 30));
        assert_eq!(
            (got[0].slot, got[0].watch, got[0].len),
            (3, Watch::ReadWrite, 8)
        );
        assert!(armed(9, [1, 2, 3, 4], 0).is_empty());
    }

    #[test]
    fn a_clean_process_is_quiet() {
        let r = Report {
            supported: true,
            threads: 12,
            handlers_walked: true,
            handlers: vec![
                handler("image", "RX", "coreclr.dll", 0x7ff0_0000_1000),
                handler("image", "RX", "lrng-sidecar.exe", 0x7ff0_0000_2000),
            ],
            ..Default::default()
        };
        assert!(r.hits().is_empty());
        let m = r.meta();
        assert_eq!(m["handlers"], 2);
        assert_eq!(m["handlers_unbacked"], 0);
        assert_eq!(
            m["handler_modules"],
            json!(["coreclr.dll", "lrng-sidecar.exe"])
        );
    }

    #[test]
    fn the_patchless_bypasses() {
        let r = Report {
            supported: true,
            breakpoints: vec![
                bp("amsi.dll", "AmsiScanBuffer+0x0", 0x10),
                bp("ntdll.dll", "NtTraceEvent/ZwTraceEvent+0x12", 0x20),
                bp("ntdll.dll", "EtwEventWrite+0x0", 0x28),
                bp("kernel32.dll", "Sleep+0x0", 0x30),
            ],
            handlers_walked: true,
            handlers: vec![
                handler("private", "RWX", "", 0x5000),
                handler("image", "RX", "ntdll.dll", 0x6000),
            ],
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [
                ("defense.amsi_hwbp", "critical"),
                ("defense.etw_hwbp", "critical"),
                ("memory.hardware_breakpoint", "notable"),
                ("memory.veh_unbacked", "critical"),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        let hits = r.hits();
        assert_eq!(hits[0].offset, 0x10);
        assert!(hits[0]
            .context
            .contains("amsi.dll!AmsiScanBuffer+0x0 (thread 77, Dr0, execute)"));
        assert!(hits[0]
            .context
            .contains("1 vectored handler(s) in memory no image file backs"));
        assert!(
            hits[1].context.contains("NtTraceEvent/ZwTraceEvent+0x12")
                && hits[1].context.contains("EtwEventWrite+0x0")
        );
        assert_eq!(hits[3].offset, 0x5000);
        assert!(hits[3]
            .context
            .contains("vectored exception handler points to 0x5000, in RWX private memory"));
        assert_eq!(r.meta()["handlers_unbacked"], 1);
    }

    #[test]
    fn a_breakpoint_on_a_system_call_stub() {
        let mut sys = bp(
            "ntdll.dll",
            "NtAllocateVirtualMemory/ZwAllocateVirtualMemory+0x12",
            0x10,
        );
        sys.syscall_stub = true;
        // ETW's stub stays ETW; a non-stub ntdll export stays ordinary.
        let mut etw = bp("ntdll.dll", "NtTraceEvent/ZwTraceEvent+0x0", 0x20);
        etw.syscall_stub = true;
        let r = Report {
            supported: true,
            breakpoints: vec![sys, etw, bp("ntdll.dll", "RtlAllocateHeap+0x0", 0x30)],
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [
                ("defense.etw_hwbp", "critical"),
                ("defense.syscall_hwbp", "critical"),
                ("memory.hardware_breakpoint", "notable"),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        assert!(r.hits()[1]
            .context
            .contains("ntdll.dll!NtAllocateVirtualMemory/ZwAllocateVirtualMemory+0x12"));
    }

    #[test]
    fn what_is_not_a_bypass() {
        // Deep inside an ETW writer, a data breakpoint on amsi.dll, or an
        // export of ntdll that writes no event: ordinary breakpoints.
        let mut write = bp("amsi.dll", "AmsiScanBuffer+0x8", 0x40);
        write.watch = Watch::Write;
        let r = Report {
            supported: true,
            breakpoints: vec![
                bp("ntdll.dll", "EtwEventWrite+0x400", 0x10),
                write,
                bp("ntdll.dll", "NtCreateThreadEx+0x0", 0x20),
                bp("", "", 0x30),
            ],
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [(
                "memory.hardware_breakpoint".to_string(),
                "notable".to_string()
            )]
        );
        let c = &r.hits()[0].context;
        assert!(c.contains("ntdll.dll!EtwEventWrite+0x400"), "{c}");
        assert!(
            c.contains("amsi.dll!AmsiScanBuffer+0x8 (thread 77, Dr0, write, 1 byte(s))"),
            "{c}"
        );
        assert!(c.contains("0x30 (thread 77"), "{c}");
    }

    #[test]
    fn a_debugger_lowers_breakpoints_not_handlers() {
        let r = Report {
            supported: true,
            debugged: Some(true),
            breakpoints: vec![
                bp("amsi.dll", "AmsiScanBuffer+0x0", 0x10),
                bp("x.dll", "F+0x0", 0x20),
            ],
            handlers: vec![handler("private", "RX", "", 0x5000)],
            handlers_walked: true,
            ..Default::default()
        };
        assert_eq!(
            rules(&r),
            [
                ("defense.amsi_hwbp", "suspect"),
                ("memory.hardware_breakpoint", "info"),
                ("memory.veh_unbacked", "critical"),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        assert!(r.hits()[0].context.contains("A debugger is attached"));
    }

    #[test]
    fn unsupported_meta() {
        let r = Report::unsupported("a 64-bit process can't be read from the 32-bit sidecar");
        assert!(r.hits().is_empty());
        assert_eq!(r.meta()["supported"], false);
        assert_eq!(
            r.meta()["why"],
            "a 64-bit process can't be read from the 32-bit sidecar"
        );
    }
}
