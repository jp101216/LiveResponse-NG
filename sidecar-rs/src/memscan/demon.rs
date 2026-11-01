//! Havoc Demon configurations in process memory.
//!
//! Havoc's builder packs a Demon's configuration into the payload as plain
//! little-endian fields: integers (u32, the kill date u64) and strings
//! (u32 byte length, then UTF-16LE text ending in NUL), in a fixed order —
//! sleep, jitter, allocation and execution methods, the 64- and 32-bit spawn
//! processes, the sleep-obfuscation and evasion switches, then the listener:
//! for HTTP(S) the kill date, working hours, method, host rotation, the hosts
//! (each with its port), TLS, user agent, headers, URIs and proxy; for SMB the
//! pipe name, kill date and working hours.
//!
//! A running Demon wipes its own copy of the configuration once it has read
//! it, so what this finds is a Demon payload still sitting in memory whole:
//! the shellcode buffer an injector wrote and the loader mapped from, or a
//! payload staged and not yet run. It searches executable memory no image
//! backs, and keeps a candidate only if the whole configuration parses with
//! the values the builder can write.
//!
//! Portable: the reads go through a closure, so tests feed it buffers.

use crate::contract::Hit;
use regex::bytes::Regex;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// How much is read for one configuration.
const READ_SIZE: usize = 16 * 1024;
/// The longest string field accepted (bytes of UTF-16).
const STRING_MAX: usize = 1024;
/// Most hosts, headers or URIs accepted in one list.
const LIST_MAX: u32 = 64;
/// Configurations reported per process.
pub const MAX_CONFIGS: usize = 4;

/// The start: sleep (< 65536 s), jitter (0-100), allocation and execution
/// methods (0-2), then the 64-bit spawn path's length and its first
/// characters ("C:\" or "%windir%…").
static START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?s-u)..\x00\x00[\x00-\x64]\x00\x00\x00[\x00-\x02]\x00\x00\x00[\x00-\x02]\x00\x00\x00[\x04-\xfe][\x00-\x03]\x00\x00(?:[A-Za-z]\x00:\x00\\\x00|%\x00[A-Za-z]\x00)",
    )
    .expect("demon pattern compiles")
});

/// Candidate start addresses in a block read at `base`, skipping matches
/// wholly inside its first `skip` bytes (already searched with the chunk
/// before).
pub fn find(block: &[u8], base: usize, skip: usize, out: &mut Vec<usize>) {
    for m in START.find_iter(block) {
        if m.end() > skip && out.len() < 4 * MAX_CONFIGS {
            out.push(base + m.start());
        }
    }
}

/// A cursor over packed fields.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.b.get(self.pos..self.pos + 4)?.try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    fn u64(&mut self) -> Option<u64> {
        let v = u64::from_le_bytes(self.b.get(self.pos..self.pos + 8)?.try_into().ok()?);
        self.pos += 8;
        Some(v)
    }

    /// An int the builder writes from a small set.
    fn small(&mut self, max: u32) -> Option<u32> {
        self.u32().filter(|&v| v <= max)
    }

    /// A UTF-16LE string field: printable text ending in NUL (empty allowed
    /// when `empty_ok`).
    fn wstring(&mut self, empty_ok: bool) -> Option<String> {
        let len = self.u32()? as usize;
        if len == 0 {
            return empty_ok.then(String::new);
        }
        if !len.is_multiple_of(2) || len > STRING_MAX {
            return None;
        }
        let raw = self.b.get(self.pos..self.pos + len)?;
        self.pos += len;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let (last, text) = units.split_last()?;
        if *last != 0 || text.iter().any(|&u| !(0x20..0x7f).contains(&u)) {
            return None;
        }
        Some(String::from_utf16_lossy(text))
    }
}

/// The listener half of a configuration.
#[derive(Debug, PartialEq)]
pub enum Listener {
    Http {
        secure: bool,
        hosts: Vec<(String, u32)>,
        user_agent: String,
        uris: Vec<String>,
        headers: Vec<String>,
        method: String,
        proxy: Option<String>,
    },
    Smb {
        pipe: String,
    },
}

/// A parsed Demon configuration.
#[derive(Debug)]
pub struct Config {
    pub addr: usize,
    pub sleep: u32,
    pub jitter: u32,
    pub spawn64: String,
    pub spawn32: String,
    pub sleep_technique: u32,
    pub indirect_syscalls: bool,
    pub kill_date: u64,
    pub working_hours: u32,
    pub listener: Listener,
}

/// Parse the configuration at `addr`, reading through `read`; None unless
/// every field holds a value the builder can write.
pub fn parse(addr: usize, read: &dyn Fn(usize, &mut [u8]) -> usize) -> Option<Config> {
    let mut buf = vec![0u8; READ_SIZE];
    let n = read(addr, &mut buf);
    buf.truncate(n);
    let mut c = Cursor { b: &buf, pos: 0 };
    let sleep = c.u32()?;
    let jitter = c.small(100)?;
    c.small(2)?; // allocation method
    c.small(2)?; // execution method
    let spawn64 = c.wstring(false)?;
    let spawn32 = c.wstring(false)?;
    let sleep_technique = c.small(3)?;
    c.small(2)?; // sleep-obfuscation jump gadget
    c.small(1)?; // stack spoofing
    c.small(3)?; // proxy loading
    let indirect_syscalls = c.small(1)? == 1;
    c.small(2)?; // AMSI/ETW patching
    let after_implant = c.pos;

    let http = (|| {
        let kill_date = c.u64()?;
        let working_hours = c.u32()?;
        let method = c.wstring(false)?;
        if method != "POST" && method != "GET" {
            return None;
        }
        c.small(1)?; // host rotation
        let count = c.u32().filter(|&n| (1..=LIST_MAX).contains(&n))?;
        let mut hosts = Vec::new();
        for _ in 0..count {
            let h = c.wstring(false)?;
            let port = c.u32().filter(|&p| (1..=65535).contains(&p))?;
            hosts.push((h, port));
        }
        let secure = c.small(1)? == 1;
        let user_agent = c.wstring(true)?;
        let mut list = || -> Option<Vec<String>> {
            let n = c.u32().filter(|&n| n <= LIST_MAX)?;
            (0..n).map(|_| c.wstring(true)).collect()
        };
        let headers = list()?;
        let uris = list()?;
        let proxy = match c.small(1)? {
            1 => {
                let url = c.wstring(true)?;
                c.wstring(true)?; // user name: not reported
                c.wstring(true)?; // password: not reported
                Some(url)
            }
            _ => None,
        };
        Some((
            kill_date,
            working_hours,
            Listener::Http {
                secure,
                hosts,
                user_agent,
                uris,
                headers,
                method,
                proxy,
            },
        ))
    })();
    let (kill_date, working_hours, listener) = match http {
        Some(h) => h,
        None => {
            c.pos = after_implant;
            let pipe = c.wstring(false)?;
            if !pipe.to_ascii_lowercase().starts_with(r"\\.\pipe\") {
                return None;
            }
            (c.u64()?, c.u32()?, Listener::Smb { pipe })
        }
    };
    Some(Config {
        addr,
        sleep,
        jitter,
        spawn64,
        spawn32,
        sleep_technique,
        indirect_syscalls,
        kill_date,
        working_hours,
        listener,
    })
}

const SLEEP_TECHNIQUES: [&str; 4] = ["WaitForSingleObjectEx", "Ekko", "Zilean", "Foliage"];

impl Config {
    /// The configuration as structured fields (hosts in "c2_hosts").
    pub fn extracted(&self) -> Value {
        let mut m = Map::new();
        m.insert("family".into(), json!("Havoc"));
        m.insert("sleep_s".into(), json!(self.sleep));
        m.insert("jitter_pct".into(), json!(self.jitter));
        m.insert("spawnto_x64".into(), json!(self.spawn64));
        m.insert("spawnto_x86".into(), json!(self.spawn32));
        m.insert(
            "sleep_technique".into(),
            json!(SLEEP_TECHNIQUES[self.sleep_technique as usize]),
        );
        m.insert("indirect_syscalls".into(), json!(self.indirect_syscalls));
        if self.kill_date != 0 {
            m.insert("kill_date_filetime".into(), json!(self.kill_date));
        }
        if self.working_hours != 0 {
            m.insert(
                "working_hours".into(),
                json!(format!("0x{:08x}", self.working_hours)),
            );
        }
        match &self.listener {
            Listener::Http {
                secure,
                hosts,
                user_agent,
                uris,
                headers,
                method,
                proxy,
            } => {
                m.insert(
                    "listener".into(),
                    json!(if *secure { "HTTPS" } else { "HTTP" }),
                );
                m.insert(
                    "c2_hosts".into(),
                    json!(hosts.iter().map(|(h, _)| h).collect::<Vec<_>>()),
                );
                m.insert(
                    "c2_ports".into(),
                    json!(hosts.iter().map(|(_, p)| p).collect::<Vec<_>>()),
                );
                m.insert("method".into(), json!(method));
                if !uris.is_empty() {
                    m.insert("c2_uris".into(), json!(uris));
                }
                if !user_agent.is_empty() {
                    m.insert("user_agent".into(), json!(user_agent));
                }
                if !headers.is_empty() {
                    m.insert("headers".into(), json!(headers));
                }
                if let Some(p) = proxy.as_ref().filter(|p| !p.is_empty()) {
                    m.insert("proxy".into(), json!(p));
                }
            }
            Listener::Smb { pipe } => {
                m.insert("listener".into(), json!("SMB"));
                m.insert("pipe_name".into(), json!(pipe));
            }
        }
        Value::Object(m)
    }

    /// The finding.
    pub fn hit(&self) -> Hit {
        let (technique, to) = match &self.listener {
            Listener::Http {
                secure,
                hosts,
                uris,
                ..
            } => {
                let hs: Vec<String> = hosts.iter().map(|(h, p)| format!("{h}:{p}")).collect();
                let mut to = format!(
                    "{} to {}",
                    if *secure { "HTTPS" } else { "HTTP" },
                    hs.join(", ")
                );
                if !uris.is_empty() {
                    to.push_str(&format!(" ({})", uris.join(", ")));
                }
                ("T1071.001", to)
            }
            Listener::Smb { pipe } => ("T1021.002", format!("SMB over {pipe}")),
        };
        let mut context = format!(
            "Havoc Demon configuration: {to}; sleep {} s with {}% jitter; sleep obfuscation {}; spawn-to {:?}",
            self.sleep, self.jitter, SLEEP_TECHNIQUES[self.sleep_technique as usize], self.spawn64
        );
        if let Listener::Http { user_agent, .. } = &self.listener {
            if !user_agent.is_empty() {
                context.push_str(&format!("; user agent {user_agent:?}"));
            }
        }
        context.truncate(
            context
                .char_indices()
                .nth(600)
                .map(|(i, _)| i)
                .unwrap_or(context.len()),
        );
        Hit {
            rule: "memory.havoc_config".into(),
            severity: "critical".into(),
            technique: technique.into(),
            offset: self.addr as i64,
            encoding: String::new(),
            context,
            confidence: 90,
            region: None,
            extracted: Some(self.extracted()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn int(b: &mut Vec<u8>, v: u32) {
        b.extend_from_slice(&v.to_le_bytes());
    }

    fn wstr(b: &mut Vec<u8>, s: &str) {
        let mut w: Vec<u8> = s
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        if s.is_empty() {
            w.clear();
        }
        int(b, w.len() as u32);
        b.append(&mut w);
    }

    /// A Demon configuration as Havoc's builder packs it: an HTTPS listener
    /// with two hosts, or an SMB one.
    pub(crate) fn packed(smb: bool) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [5, 20, 2, 2] {
            int(&mut b, v);
        }
        wstr(&mut b, r"C:\Windows\System32\notepad.exe");
        wstr(&mut b, r"C:\Windows\SysWOW64\notepad.exe");
        for v in [3, 2, 1, 0, 1, 1] {
            int(&mut b, v);
        }
        if smb {
            wstr(&mut b, r"\\.\pipe\demon_pivot");
            b.extend_from_slice(&0u64.to_le_bytes());
            int(&mut b, 0);
        } else {
            b.extend_from_slice(&0u64.to_le_bytes());
            int(&mut b, 0);
            wstr(&mut b, "POST");
            int(&mut b, 0);
            int(&mut b, 2);
            wstr(&mut b, "havoc.example-c2.com");
            int(&mut b, 443);
            wstr(&mut b, "198.51.100.23");
            int(&mut b, 8443);
            int(&mut b, 1);
            wstr(
                &mut b,
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
            );
            int(&mut b, 1);
            wstr(&mut b, "Content-type: */*");
            int(&mut b, 2);
            wstr(&mut b, "/index.php");
            wstr(&mut b, "/news");
            int(&mut b, 1);
            wstr(&mut b, "http://proxy.corp.local:3128");
            wstr(&mut b, "svc_proxy");
            wstr(&mut b, "P@ssw0rd!");
        }
        b.resize(b.len() + 64, 0x90);
        b
    }

    fn reader(base: usize, mem: &[u8]) -> impl Fn(usize, &mut [u8]) -> usize + '_ {
        move |addr, buf| {
            if addr < base || addr >= base + mem.len() {
                return 0;
            }
            let avail = &mem[addr - base..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n
        }
    }

    #[test]
    fn https_and_smb_configurations() {
        let mut block = vec![0xccu8; 37];
        block.extend(packed(false));
        let mut found = Vec::new();
        find(&block, 0x40000, 0, &mut found);
        assert_eq!(found, [0x40000 + 37]);
        let cfg = parse(found[0], &reader(0x40000, &block)).expect("parses");
        let x = cfg.extracted();
        assert_eq!(x["listener"], "HTTPS");
        assert_eq!(
            x["c2_hosts"],
            json!(["havoc.example-c2.com", "198.51.100.23"])
        );
        assert_eq!(x["c2_ports"], json!([443, 8443]));
        assert_eq!(x["c2_uris"], json!(["/index.php", "/news"]));
        assert_eq!(x["sleep_technique"], "Foliage");
        assert_eq!(x["proxy"], "http://proxy.corp.local:3128");
        let text = x.to_string();
        assert!(
            !text.contains("P@ssw0rd") && !text.contains("svc_proxy"),
            "{text}"
        );
        let h = cfg.hit();
        assert_eq!(h.rule, "memory.havoc_config");
        assert!(
            h.context
                .contains("HTTPS to havoc.example-c2.com:443, 198.51.100.23:8443"),
            "{}",
            h.context
        );

        let smb = packed(true);
        let mut found = Vec::new();
        find(&smb, 0, 0, &mut found);
        let cfg = parse(found[0], &reader(0, &smb)).expect("parses");
        assert_eq!(
            cfg.listener,
            Listener::Smb {
                pipe: r"\\.\pipe\demon_pivot".into()
            }
        );
        assert!(cfg.hit().context.contains(r"SMB over \\.\pipe\demon_pivot"));
    }

    #[test]
    fn broken_configurations_are_rejected() {
        let good = packed(false);
        // Jitter over 100, an unknown sleep technique, a host with port 0.
        for (at, v) in [(4usize, 101u32), (8 + 8 + 4 + 64 + 4 + 64, 9)] {
            let mut b = good.clone();
            b[at..at + 4].copy_from_slice(&v.to_le_bytes());
            assert!(parse(0, &reader(0, &b)).is_none(), "byte {at} = {v}");
        }
        let mut b = good.clone();
        let port = b
            .windows(4)
            .position(|w| w == 443u32.to_le_bytes())
            .unwrap();
        b[port..port + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(0, &reader(0, &b)).is_none());
        // Truncated: the read ends in the middle.
        assert!(parse(0, &reader(0, &good[..100])).is_none());
    }
}
