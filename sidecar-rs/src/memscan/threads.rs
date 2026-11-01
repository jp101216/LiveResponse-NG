//! Where threads started, and what their stacks show while they wait.
//!
//! - **Start addresses.** Windows records the routine each thread was created
//!   to run. Injected code shows there: a thread started in memory no image
//!   backs (CreateRemoteThread or NtCreateThreadEx into shellcode), one
//!   started at LoadLibrary (the classic DLL injection, still running), or one
//!   started inside a module's function rather than at its start: a start
//!   address chosen to look like system code while the thread's real code is
//!   set elsewhere (Cobalt Strike's process-inject `CreateThread
//!   "ntdll!RtlUserThreadStart+0x42"`, and its kin).
//! - **Stacks.** A thread blocked in a system call is walked frame by frame
//!   with each module's own unwind data (unwind.rs). Code waiting on the call
//!   from memory no image backs (an implant sleeping between callbacks), from
//!   memory that isn't executable now (sleep obfuscation: Ekko, Foliage,
//!   sleep masks), or through a return address that doesn't follow a call (a
//!   frame forged so the stack looks ordinary) is reported. The first return
//!   address is the system-call checks' (syscalls.rs); this goes deeper.
//!
//! Code a runtime registered with ntdll as code (a JIT: .NET, V8, Java) is
//! where managed and script frames live, so it is counted, not judged.
//!
//! Platform-neutral, unit-tested on any OS; windows_threads.rs reads the
//! threads.
#![cfg_attr(not(any(windows, lrng_typecheck_windows)), allow(dead_code))]

use crate::contract::Hit;
use serde_json::json;
use std::collections::BTreeMap;

/// Where a thread started, when that is out of the ordinary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// In memory no image file backs; `exec` when it is still executable.
    Unbacked {
        kind: String,
        protect: String,
        exec: bool,
    },
    /// At LoadLibrary ("kernelbase.dll!LoadLibraryW").
    LoadLibrary { symbol: String },
    /// Inside a module's function past its start ("ntdll.dll!RtlUserThreadStart+0x21").
    MidFunction { symbol: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartFinding {
    pub tid: u32,
    pub addr: usize,
    pub start: Start,
}

/// What is wrong with a frame of a waiting thread's stack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Executable memory no image backs, which no runtime registered as code.
    Unbacked { kind: String, protect: String },
    /// Memory that isn't executable.
    NotExecutable { kind: String, protect: String },
    /// A module's code, but not just after a call instruction.
    NoCall { symbol: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackFinding {
    pub tid: u32,
    /// The frame's return address.
    pub addr: usize,
    /// 1 is the address the system call's stub returns to.
    pub depth: usize,
    pub frame: Frame,
    /// The call the thread waits in, then each frame out to this one, named.
    pub chain: Vec<String>,
}

/// Everything found about one process's threads.
#[derive(Debug, Default)]
pub struct Report {
    pub supported: bool,
    pub why: Option<String>,
    /// Threads whose start address was read, and those it couldn't be read for.
    pub starts_read: usize,
    pub starts_unreadable: usize,
    /// Threads in system calls whose stacks were walked, the frames walked,
    /// and the walks that reached the end of the stack.
    pub walked: usize,
    pub frames: usize,
    pub complete: usize,
    /// Why the other walks stopped, by reason.
    pub stopped: BTreeMap<String, usize>,
    /// Frames in code a runtime registered (JIT), not judged; and how many
    /// code ranges the process registered (None: the list couldn't be read,
    /// and nothing in memory no image backs is judged).
    pub jit_frames: usize,
    pub jit_ranges: Option<usize>,
    /// Findings dropped because the thread had moved when read again.
    pub moved: usize,
    pub starts: Vec<StartFinding>,
    pub stacks: Vec<StackFinding>,
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

fn listed(parts: &[String]) -> String {
    let mut s: Vec<String> = parts.iter().take(4).cloned().collect();
    if parts.len() > 4 {
        s.push(format!("and {} more", parts.len() - 4));
    }
    s.join("; ")
}

/// (rule, severity, technique, confidence, why) for each kind of finding.
type Judged = (&'static str, &'static str, &'static str, i64, &'static str);

impl StartFinding {
    fn judge(&self) -> (Judged, String) {
        let at = format!("thread {} started at 0x{:x}", self.tid, self.addr);
        match &self.start {
            Start::Unbacked { kind, protect, exec: true } => (
                ("memory.thread_start_unbacked", "critical", "T1055", 80,
                 "a thread started in code that was written into the process: CreateRemoteThread or NtCreateThreadEx into shellcode, or a loader starting its payload"),
                format!("{at}, in {protect} {kind} memory no image file backs"),
            ),
            Start::Unbacked { kind, protect, exec: false } => (
                ("memory.thread_start_unbacked", "suspect", "T1055", 65,
                 "the code this thread started in isn't executable any more: hidden while it waits (sleep obfuscation) or freed"),
                format!("{at}, in {protect} {kind} memory, which isn't executable now"),
            ),
            Start::LoadLibrary { symbol } => (
                ("memory.thread_start_loadlibrary", "suspect", "T1055.001", 75,
                 "a thread whose start routine is LoadLibrary is how CreateRemoteThread DLL injection loads a DLL into another process, and this one hasn't finished"),
                format!("{at} ({symbol})"),
            ),
            Start::MidFunction { symbol } => (
                ("memory.thread_start_spoofed", "suspect", "T1036", 70,
                 "a start address inside a function, not at its start, is chosen to look like system code while the thread's real code is set elsewhere (Cobalt Strike's process-inject CreateThread \"module!function+0x..\" option works this way)"),
                format!("{at} ({symbol}), inside that function rather than at its start"),
            ),
        }
    }
}

impl StackFinding {
    fn judge(&self) -> (Judged, String) {
        let (head, rest) = self
            .chain
            .split_first()
            .map_or(("", &[][..]), |(h, r)| (h.as_str(), r));
        let line = format!(
            "thread {} waiting in {head}, called from {}",
            self.tid,
            rest.join(", called from ")
        );
        match &self.frame {
            Frame::Unbacked { protect, .. } => (
                (
                    "memory.stack_unbacked",
                    if protect.contains('W') { "critical" } else { "suspect" },
                    "T1055",
                    if protect.contains('W') { 80 } else { 75 },
                    "code in memory no image backs, which no runtime registered as code, is waiting on this call: an implant sleeping between callbacks (a beacon calling Sleep or WaitForSingleObject from injected memory)",
                ),
                line,
            ),
            Frame::NotExecutable { .. } => (
                ("defense.stack_return_nonexec", "critical", "T1027", 80,
                 "the code waiting on this call isn't executable now: sleep obfuscation (Ekko, Foliage, sleep masks) hides an implant that way while it waits"),
                line,
            ),
            Frame::NoCall { .. } => (
                ("defense.stack_frame_no_call", "suspect", "T1036", 60,
                 "a return address that doesn't follow a call instruction wasn't put on the stack by a call: a frame forged so the stack looks ordinary (call-stack spoofing)"),
                line,
            ),
        }
    }
}

impl Frame {
    /// The frame as it appears at the end of a chain.
    pub fn describe(&self, addr: usize) -> String {
        match self {
            Frame::Unbacked { kind, protect } => {
                format!("0x{addr:x} ({protect} {kind} memory no image file backs)")
            }
            Frame::NotExecutable { kind, protect } => {
                format!("0x{addr:x} ({protect} {kind} memory, which isn't executable)")
            }
            Frame::NoCall { symbol } => {
                format!("{symbol} (0x{addr:x}), which doesn't follow a call")
            }
        }
    }
}

impl Report {
    pub fn unsupported(why: impl Into<String>) -> Self {
        Report {
            why: Some(why.into()),
            ..Default::default()
        }
    }

    pub fn hits(&self) -> Vec<Hit> {
        // One hit per rule and severity, listing its threads, in the order
        // the kinds are judged.
        let mut order: Vec<(Judged, usize, Vec<String>)> = Vec::new();
        let judged = self
            .starts
            .iter()
            .map(|s| (s.judge(), s.addr))
            .chain(self.stacks.iter().map(|s| (s.judge(), s.addr)));
        for ((j, line), addr) in judged {
            match order.iter_mut().find(|(k, _, _)| k.0 == j.0 && k.1 == j.1) {
                Some(g) => g.2.push(line),
                None => order.push((j, addr, vec![line])),
            }
        }
        order
            .into_iter()
            .map(|((rule, sev, technique, conf, why), addr, lines)| {
                hit(
                    rule,
                    sev,
                    technique,
                    conf,
                    addr,
                    format!("{}. {why}", listed(&lines)),
                )
            })
            .collect()
    }

    pub fn meta(&self) -> serde_json::Value {
        if !self.supported {
            return json!({ "supported": false, "why": self.why });
        }
        json!({
            "supported": true,
            "starts_read": self.starts_read,
            "starts_unreadable": self.starts_unreadable,
            "start_findings": self.starts.len(),
            "stacks_walked": self.walked,
            "frames_walked": self.frames,
            "stacks_complete": self.complete,
            "stacks_stopped": self.stopped,
            "jit_frames": self.jit_frames,
            "jit_ranges": self.jit_ranges,
            "threads_moved": self.moved,
            "stack_findings": self.stacks.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx() -> (String, String) {
        ("private".into(), "RX".into())
    }

    #[test]
    fn judges_starts_and_stacks() {
        let (kind, protect) = rx();
        let chain = |last: &str| {
            vec![
                "ntdll.dll!NtWaitForSingleObject".to_string(),
                "kernelbase.dll!WaitForSingleObjectEx+0x9e".to_string(),
                last.to_string(),
            ]
        };
        let r = Report {
            supported: true,
            starts_read: 12,
            jit_ranges: Some(3),
            starts: vec![
                StartFinding {
                    tid: 1,
                    addr: 0x1000,
                    start: Start::Unbacked {
                        kind: kind.clone(),
                        protect: protect.clone(),
                        exec: true,
                    },
                },
                StartFinding {
                    tid: 2,
                    addr: 0x2000,
                    start: Start::Unbacked {
                        kind: kind.clone(),
                        protect: "RW".into(),
                        exec: false,
                    },
                },
                StartFinding {
                    tid: 3,
                    addr: 0x7ff0,
                    start: Start::LoadLibrary {
                        symbol: "kernelbase.dll!LoadLibraryW".into(),
                    },
                },
                StartFinding {
                    tid: 4,
                    addr: 0x7ff1,
                    start: Start::MidFunction {
                        symbol: "ntdll.dll!RtlUserThreadStart+0x21".into(),
                    },
                },
                StartFinding {
                    tid: 5,
                    addr: 0x1100,
                    start: Start::Unbacked {
                        kind: kind.clone(),
                        protect: protect.clone(),
                        exec: true,
                    },
                },
            ],
            stacks: vec![
                StackFinding {
                    tid: 1,
                    addr: 0x1010,
                    depth: 2,
                    frame: Frame::Unbacked {
                        kind: kind.clone(),
                        protect: protect.clone(),
                    },
                    chain: chain("0x1010 (RX private memory no image file backs)"),
                },
                StackFinding {
                    tid: 6,
                    addr: 0x3010,
                    depth: 3,
                    frame: Frame::Unbacked {
                        kind: kind.clone(),
                        protect: "RWX".into(),
                    },
                    chain: chain("0x3010"),
                },
                StackFinding {
                    tid: 2,
                    addr: 0x2010,
                    depth: 2,
                    frame: Frame::NotExecutable {
                        kind,
                        protect: "RW".into(),
                    },
                    chain: chain("0x2010"),
                },
                StackFinding {
                    tid: 7,
                    addr: 0x7ff2,
                    depth: 1,
                    frame: Frame::NoCall {
                        symbol: "kernel32.dll!Sleep".into(),
                    },
                    chain: chain("kernel32.dll!Sleep"),
                },
            ],
            ..Default::default()
        };
        let h = r.hits();
        let got: Vec<(&str, &str, i64)> = h
            .iter()
            .map(|h| (h.rule.as_str(), h.severity.as_str(), h.offset))
            .collect();
        assert_eq!(
            got,
            [
                ("memory.thread_start_unbacked", "critical", 0x1000),
                ("memory.thread_start_unbacked", "suspect", 0x2000),
                ("memory.thread_start_loadlibrary", "suspect", 0x7ff0),
                ("memory.thread_start_spoofed", "suspect", 0x7ff1),
                ("memory.stack_unbacked", "suspect", 0x1010),
                ("memory.stack_unbacked", "critical", 0x3010),
                ("defense.stack_return_nonexec", "critical", 0x2010),
                ("defense.stack_frame_no_call", "suspect", 0x7ff2),
            ]
        );
        // Threads 1 and 5 share one hit.
        assert!(
            h[0].context
                .contains("thread 1 started at 0x1000, in RX private memory")
                && h[0].context.contains("thread 5 started at 0x1100")
        );
        assert!(
            h[2].context.contains("(kernelbase.dll!LoadLibraryW)") && h[2].technique == "T1055.001"
        );
        assert!(h[3]
            .context
            .contains("RtlUserThreadStart+0x21), inside that function"));
        assert_eq!(
            h[4].context.split(". ").next().unwrap(),
            "thread 1 waiting in ntdll.dll!NtWaitForSingleObject, called from kernelbase.dll!WaitForSingleObjectEx+0x9e, called from 0x1010 (RX private memory no image file backs)"
        );
        assert!(h[6].context.contains("sleep obfuscation") && h[6].technique == "T1027");
        let m = r.meta();
        assert_eq!(
            (
                m["start_findings"].as_u64(),
                m["stack_findings"].as_u64(),
                m["jit_ranges"].as_u64()
            ),
            (Some(5), Some(4), Some(3))
        );
        assert!(Report::unsupported("x").hits().is_empty());
        assert_eq!(Report::unsupported("x").meta()["supported"], false);
    }

    #[test]
    fn frames_describe_themselves() {
        let f = Frame::NoCall {
            symbol: "kernel32.dll!Sleep".into(),
        };
        assert_eq!(
            f.describe(0x10),
            "kernel32.dll!Sleep (0x10), which doesn't follow a call"
        );
        let f = Frame::NotExecutable {
            kind: "private".into(),
            protect: "RW".into(),
        };
        assert_eq!(
            f.describe(0x20),
            "0x20 (RW private memory, which isn't executable)"
        );
    }
}
