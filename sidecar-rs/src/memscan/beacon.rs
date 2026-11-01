//! Cobalt Strike beacon configurations in process memory.
//!
//! A beacon carries its configuration (C2 hosts, URIs, sleep, user agent,
//! spawn-to processes, watermark…) in two shapes a memory scan can find:
//!
//! * packed: the settings as written into the payload, a run of
//!   big-endian TLV entries — id (u16), type (u16: 1 short, 2 int, 3 data),
//!   length (u16), value — XOR-encoded with one byte (0x2e in version 4, 0x69
//!   in version 3) or already decoded. It starts with setting 1 (the beacon
//!   type) and setting 2 (the port), both shorts.
//! * in use: the table a running beacon builds from it on the heap, one slot
//!   per setting — {type, value} as two u64 on 64-bit, two u32 on 32-bit —
//!   where a data setting's value points at its buffer. Slot 0 is empty;
//!   slots 1-5 are the beacon type, port, sleep, maximum GET size and jitter.
//!   (This is the structure BeaconEye looks for.)
//!
//! Both are searched for in memory no image file backs; each candidate is then
//! parsed and kept only if it holds together (known beacon type, a readable
//! C2 setting). A sleep mask that encrypts the beacon's memory between
//! check-ins, or a custom loader that never keeps either form, hides it; this
//! finds the many beacons that don't.
//!
//! Portable: the reads go through a closure, so tests feed it buffers.

use crate::contract::Hit;
use regex::bytes::Regex;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

/// How many bytes of a packed configuration are read (the payload reserves
/// 4 KiB for it).
const PACKED_SIZE: usize = 4096;
/// Slots read from an in-use settings table.
const SLOTS: usize = 128;
/// The longest string read through a data setting's pointer.
const STRING_MAX: usize = 512;
/// Configurations reported per process.
pub const MAX_CONFIGS: usize = 8;

/// Where a candidate was found and what shape it has.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Layout {
    /// Packed TLV settings XOR-encoded with this byte (0 when decoded).
    Packed(u8),
    /// The in-use settings table with 8-byte (64-bit) or 4-byte fields.
    Table(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub addr: usize,
    pub layout: Layout,
}

static PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?s-u)",
        // packed, version 4 (XOR 0x2e), version 3 (XOR 0x69), decoded
        r"(?P<v4>\x2e\x2f\x2e\x2f\x2e\x2c..\x2e\x2c\x2e\x2f\x2e\x2c)",
        r"|(?P<v3>\x69\x68\x69\x68\x69\x6b..\x69\x6b\x69\x68\x69\x6b)",
        r"|(?P<plain>\x00\x01\x00\x01\x00\x02..\x00\x02\x00\x01\x00\x02)",
        // in use, 64-bit: the end of slot 0, then slots 1-5
        r"|(?P<t64>\x00{8}\x01\x00{7}[\x00\x01\x02\x04\x08\x10]\x00{7}\x01\x00{7}..\x00{6}",
        r"\x02\x00{7}....\x00{4}\x02\x00{7}....\x00{4}\x01\x00{7}.\x00{7})",
        // in use, 32-bit: slot 0, then slots 1-5
        r"|(?P<t32>\x00{8}\x01\x00{3}[\x00\x01\x02\x04\x08\x10]\x00{3}\x01\x00{3}..\x00{2}",
        r"\x02\x00{3}....\x02\x00{3}....\x01\x00{3}.\x00{3})",
    ))
    .expect("beacon patterns compile")
});

/// Find candidates in a block read at `base`, skipping matches that lie
/// wholly in its first `skip` bytes (the tail carried over from the previous
/// chunk, already searched with it).
pub fn find(block: &[u8], base: usize, skip: usize, out: &mut Vec<Candidate>) {
    for caps in PATTERNS.captures_iter(block) {
        let m = caps.get(0).expect("whole match");
        if m.end() <= skip {
            continue;
        }
        let at = base + m.start();
        let c = if caps.name("v4").is_some() {
            Candidate {
                addr: at,
                layout: Layout::Packed(0x2e),
            }
        } else if caps.name("v3").is_some() {
            Candidate {
                addr: at,
                layout: Layout::Packed(0x69),
            }
        } else if caps.name("plain").is_some() {
            Candidate {
                addr: at,
                layout: Layout::Packed(0),
            }
        } else if caps.name("t64").is_some() {
            Candidate {
                addr: at.saturating_sub(8),
                layout: Layout::Table(8),
            }
        } else {
            Candidate {
                addr: at,
                layout: Layout::Table(4),
            }
        };
        if out.len() < 4 * MAX_CONFIGS {
            out.push(c);
        }
    }
}

/// One setting's value.
#[derive(Clone, Debug, PartialEq)]
pub enum Setting {
    Num(u32),
    Data(Vec<u8>),
}

/// A parsed configuration.
#[derive(Debug)]
pub struct Config {
    pub addr: usize,
    pub layout: Layout,
    pub settings: Vec<(u16, Setting)>,
}

/// Parse a candidate, reading memory through `read` (bytes filled at an
/// address; 0 = unreadable). None when it doesn't hold together.
pub fn parse(c: Candidate, read: &dyn Fn(usize, &mut [u8]) -> usize) -> Option<Config> {
    let settings = match c.layout {
        Layout::Packed(key) => {
            let mut buf = vec![0u8; PACKED_SIZE];
            let n = read(c.addr, &mut buf);
            buf.truncate(n);
            for b in buf.iter_mut() {
                *b ^= key;
            }
            parse_packed(&buf)
        }
        Layout::Table(width) => parse_table(c.addr, width, read),
    };
    let cfg = Config {
        addr: c.addr,
        layout: c.layout,
        settings,
    };
    cfg.valid().then_some(cfg)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Walk packed TLV settings until an id of 0 or anything malformed.
fn parse_packed(b: &[u8]) -> Vec<(u16, Setting)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let (Some(id), Some(kind), Some(len)) = (be16(b, pos), be16(b, pos + 2), be16(b, pos + 4))
    {
        let len = len as usize;
        if id == 0 || !(1..=3).contains(&kind) || out.len() >= SLOTS {
            break;
        }
        let Some(v) = b.get(pos + 6..pos + 6 + len) else {
            break;
        };
        let s = match (kind, len) {
            (1, 2) => Setting::Num(u16::from_be_bytes([v[0], v[1]]) as u32),
            (2, 4) => Setting::Num(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            (3, _) => Setting::Data(v.to_vec()),
            _ => break,
        };
        out.push((id, s));
        pos += 6 + len;
    }
    out
}

/// Read an in-use settings table: `width`-byte type and value per slot.
fn parse_table(
    addr: usize,
    width: usize,
    read: &dyn Fn(usize, &mut [u8]) -> usize,
) -> Vec<(u16, Setting)> {
    let mut raw = vec![0u8; SLOTS * 2 * width];
    let n = read(addr, &mut raw);
    raw.truncate(n - n % (2 * width));
    let word = |b: &[u8]| -> u64 {
        let mut v = [0u8; 8];
        v[..width].copy_from_slice(&b[..width]);
        u64::from_le_bytes(v)
    };
    let mut out = Vec::new();
    for (i, slot) in raw.chunks_exact(2 * width).enumerate().skip(1) {
        let (kind, value) = (word(&slot[..width]), word(&slot[width..]));
        match kind {
            0 => continue,
            1 | 2 if value <= u32::MAX as u64 => out.push((i as u16, Setting::Num(value as u32))),
            3 if value != 0 => {
                let mut buf = vec![0u8; STRING_MAX];
                let got = read(value as usize, &mut buf);
                buf.truncate(got);
                out.push((i as u16, Setting::Data(buf)));
            }
            // A slot type outside 0-3: the table has ended (or never was one).
            _ => break,
        }
    }
    out
}

/// Setting ids, as Cobalt Strike numbers them.
const BEACON_TYPE: u16 = 1;
const PORT: u16 = 2;
const SLEEP: u16 = 3;
const JITTER: u16 = 5;
const C2: u16 = 8;
const USER_AGENT: u16 = 9;
const POST_URI: u16 = 10;
const PIPE: u16 = 15;
const SPAWNTO_X86: u16 = 29;
const SPAWNTO_X64: u16 = 30;
const PROXY: u16 = 32;
const WATERMARK: u16 = 37;
const KILL_DATE: u16 = 40;
const HOST_HEADER: u16 = 54;
const DNS_RESOLVER: u16 = 66;

const BEACON_TYPES: &[(u32, &str)] = &[
    (0, "HTTP"),
    (1, "Hybrid HTTP DNS"),
    (2, "SMB"),
    (4, "TCP"),
    (8, "HTTPS"),
    (16, "Bind TCP"),
];

/// The text of a data setting: up to its first NUL, printable only.
fn text(v: &[u8]) -> Option<String> {
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    let s = &v[..end];
    if s.is_empty() || !s.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return None;
    }
    Some(String::from_utf8_lossy(s).into_owned())
}

impl Config {
    fn get(&self, id: u16) -> Option<&Setting> {
        self.settings.iter().find(|(i, _)| *i == id).map(|(_, s)| s)
    }

    fn num(&self, id: u16) -> Option<u32> {
        match self.get(id)? {
            Setting::Num(n) => Some(*n),
            Setting::Data(_) => None,
        }
    }

    fn string(&self, id: u16) -> Option<String> {
        match self.get(id)? {
            Setting::Data(d) => text(d),
            Setting::Num(_) => None,
        }
    }

    /// A beacon type Cobalt Strike has, a port, a sleep, and either a C2
    /// setting that reads as text or (SMB and TCP beacons, which have none) a
    /// pipe name or enough other settings.
    fn valid(&self) -> bool {
        let Some(kind) = self.num(BEACON_TYPE) else {
            return false;
        };
        if !BEACON_TYPES.iter().any(|(k, _)| *k == kind)
            || self.num(PORT).is_none()
            || self.num(SLEEP).is_none()
        {
            return false;
        }
        if self.num(JITTER).is_some_and(|j| j > 99) {
            return false;
        }
        self.string(C2).is_some() || self.string(PIPE).is_some() || self.settings.len() >= 12
    }

    fn beacon_type(&self) -> &'static str {
        let k = self.num(BEACON_TYPE).unwrap_or(u32::MAX);
        BEACON_TYPES
            .iter()
            .find(|(t, _)| *t == k)
            .map(|(_, n)| *n)
            .unwrap_or("unknown")
    }

    fn layout_name(&self) -> String {
        match self.layout {
            Layout::Packed(0) => "packed settings, decoded".into(),
            Layout::Packed(k) => format!(
                "packed settings, XOR 0x{k:02x} (version {})",
                if k == 0x2e { 4 } else { 3 }
            ),
            Layout::Table(8) => "a running beacon's settings table (64-bit)".into(),
            Layout::Table(_) => "a running beacon's settings table (32-bit)".into(),
        }
    }

    /// The C2 hosts and URIs: "host,/uri,host2,/uri2".
    fn c2(&self) -> (Vec<String>, Vec<String>) {
        let (mut hosts, mut uris) = (Vec::new(), Vec::new());
        if let Some(s) = self.string(C2) {
            for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                if part.starts_with('/') {
                    uris.push(part.to_string());
                } else {
                    hosts.push(part.to_string());
                }
            }
        }
        (hosts, uris)
    }

    /// The configuration as structured fields for the report and the IOC
    /// export (hosts in "c2_hosts").
    pub fn extracted(&self) -> Value {
        let mut m = Map::new();
        m.insert("family".into(), json!("Cobalt Strike"));
        m.insert("layout".into(), json!(self.layout_name()));
        m.insert("beacon_type".into(), json!(self.beacon_type()));
        let (hosts, uris) = self.c2();
        if !hosts.is_empty() {
            m.insert("c2_hosts".into(), json!(hosts));
        }
        if !uris.is_empty() {
            m.insert("c2_uris".into(), json!(uris));
        }
        for (id, key) in [
            (PORT, "port"),
            (SLEEP, "sleep_ms"),
            (JITTER, "jitter_pct"),
            (WATERMARK, "watermark"),
        ] {
            if let Some(n) = self.num(id) {
                m.insert(key.into(), json!(n));
            }
        }
        if let Some(d) = self.num(KILL_DATE).filter(|&d| d != 0) {
            m.insert("kill_date".into(), json!(d.to_string()));
        }
        for (id, key) in [
            (USER_AGENT, "user_agent"),
            (POST_URI, "post_uri"),
            (PIPE, "pipe_name"),
            (SPAWNTO_X86, "spawnto_x86"),
            (SPAWNTO_X64, "spawnto_x64"),
            (PROXY, "proxy"),
            (HOST_HEADER, "host_header"),
            (DNS_RESOLVER, "dns_resolver"),
        ] {
            if let Some(s) = self.string(id) {
                m.insert(key.into(), json!(s));
            }
        }
        m.insert("settings_read".into(), json!(self.settings.len()));
        Value::Object(m)
    }

    /// The finding.
    pub fn hit(&self) -> Hit {
        let (hosts, uris) = self.c2();
        let mut first = format!("{} beacon", self.beacon_type());
        if !hosts.is_empty() {
            first.push_str(&format!(" to {}", hosts.join(", ")));
            if !uris.is_empty() {
                first.push_str(&format!(" ({})", uris.join(", ")));
            }
        }
        let mut what = vec![first];
        if let Some(p) = self.num(PORT).filter(|&p| p != 0) {
            what.push(format!("port {p}"));
        }
        if let Some(s) = self.num(SLEEP) {
            let jitter = self
                .num(JITTER)
                .map(|j| format!(" with {j}% jitter"))
                .unwrap_or_default();
            what.push(format!("sleep {s} ms{jitter}"));
        }
        if let Some(w) = self.num(WATERMARK) {
            what.push(format!("watermark {w}"));
        }
        for (id, label) in [
            (PIPE, "pipe"),
            (SPAWNTO_X64, "spawn-to"),
            (USER_AGENT, "user agent"),
        ] {
            if let Some(s) = self.string(id) {
                what.push(format!("{label} {s:?}"));
            }
        }
        let mut context = format!(
            "Cobalt Strike beacon configuration ({}): {}",
            self.layout_name(),
            what.join("; ")
        );
        context.truncate(
            context
                .char_indices()
                .nth(600)
                .map(|(i, _)| i)
                .unwrap_or(context.len()),
        );
        let technique = match self.num(BEACON_TYPE) {
            Some(2) => "T1021.002",
            Some(4) | Some(16) => "T1095",
            Some(1) => "T1071.004",
            _ => "T1071.001",
        };
        Hit {
            rule: "memory.cobalt_strike_config".into(),
            severity: "critical".into(),
            technique: technique.into(),
            offset: self.addr as i64,
            encoding: String::new(),
            context,
            confidence: 95,
            region: None,
            extracted: Some(self.extracted()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A packed configuration as a payload carries it (before XOR).
    pub(crate) fn packed() -> Vec<u8> {
        let mut b = Vec::new();
        let mut put = |id: u16, kind: u16, v: &[u8]| {
            b.extend_from_slice(&id.to_be_bytes());
            b.extend_from_slice(&kind.to_be_bytes());
            b.extend_from_slice(&(v.len() as u16).to_be_bytes());
            b.extend_from_slice(v);
        };
        let string = |s: &str, size: usize| {
            let mut v = s.as_bytes().to_vec();
            v.resize(size, 0);
            v
        };
        put(1, 1, &8u16.to_be_bytes()); // HTTPS
        put(2, 1, &443u16.to_be_bytes());
        put(3, 2, &45000u32.to_be_bytes());
        put(4, 2, &1048576u32.to_be_bytes());
        put(5, 1, &37u16.to_be_bytes());
        put(6, 1, &255u16.to_be_bytes());
        put(7, 3, &[0x30; 256]);
        put(
            8,
            3,
            &string(
                "cdn.example-c2.net,/jquery-3.3.1.min.js,203.0.113.80,/api/v2",
                256,
            ),
        );
        put(
            9,
            3,
            &string("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0", 256),
        );
        put(10, 3, &string("/submit.php", 64));
        put(30, 3, &string("%windir%\\sysnative\\dllhost.exe", 64));
        put(37, 2, &305419896u32.to_be_bytes());
        put(40, 2, &20271231u32.to_be_bytes());
        b.extend_from_slice(&[0u8; 6]);
        b.resize(PACKED_SIZE, 0);
        b
    }

    pub(crate) fn reader(mem: &[(usize, Vec<u8>)]) -> impl Fn(usize, &mut [u8]) -> usize + '_ {
        move |addr, buf| {
            for (base, bytes) in mem {
                if addr >= *base && addr < base + bytes.len() {
                    let avail = &bytes[addr - base..];
                    let n = avail.len().min(buf.len());
                    buf[..n].copy_from_slice(&avail[..n]);
                    return n;
                }
            }
            0
        }
    }

    #[test]
    fn packed_configurations_in_every_encoding() {
        for key in [0x2eu8, 0x69, 0] {
            let mut block = vec![0x41u8; 100];
            block.extend(packed().iter().map(|b| b ^ key));
            let mut found = Vec::new();
            find(&block, 0x10000, 0, &mut found);
            assert_eq!(found.len(), 1, "key {key:#x}: {found:?}");
            assert_eq!(found[0].addr, 0x10000 + 100);
            assert_eq!(found[0].layout, Layout::Packed(key));
            let mem = [(0x10000usize, block.clone())];
            let cfg = parse(found[0], &reader(&mem)).expect("parses");
            let x = cfg.extracted();
            assert_eq!(x["beacon_type"], "HTTPS");
            assert_eq!(x["c2_hosts"], json!(["cdn.example-c2.net", "203.0.113.80"]));
            assert_eq!(x["c2_uris"], json!(["/jquery-3.3.1.min.js", "/api/v2"]));
            assert_eq!(x["watermark"], 305419896);
            assert_eq!(x["sleep_ms"], 45000);
            assert_eq!(x["jitter_pct"], 37);
            assert_eq!(x["kill_date"], "20271231");
            assert_eq!(x["spawnto_x64"], "%windir%\\sysnative\\dllhost.exe");
            let h = cfg.hit();
            assert_eq!(h.rule, "memory.cobalt_strike_config");
            assert!(
                h.context
                    .contains("HTTPS beacon to cdn.example-c2.net, 203.0.113.80"),
                "{}",
                h.context
            );
            assert!(h.context.contains("watermark 305419896"), "{}", h.context);
        }
    }

    #[test]
    fn a_match_in_the_carried_tail_is_not_found_twice() {
        let block: Vec<u8> = packed().iter().map(|b| b ^ 0x2e).collect();
        let mut found = Vec::new();
        find(&block, 0, 14, &mut found); // wholly in the tail: found with the previous chunk
        assert!(found.is_empty());
        find(&block, 0, 13, &mut found); // runs past the tail: new
        assert_eq!(found.len(), 1);
    }

    /// A running beacon's settings table, with its strings elsewhere.
    pub(crate) fn table(width: usize, strings_at: usize) -> (Vec<u8>, Vec<u8>) {
        let mut t = vec![0u8; SLOTS * 2 * width];
        let mut strings = Vec::new();
        let mut set = |slot: usize, kind: u64, value: u64| {
            let at = slot * 2 * width;
            t[at..at + width].copy_from_slice(&kind.to_le_bytes()[..width]);
            t[at + width..at + 2 * width].copy_from_slice(&value.to_le_bytes()[..width]);
        };
        set(1, 1, 0); // HTTP
        set(2, 1, 80);
        set(3, 2, 60000);
        set(4, 2, 1048576);
        set(5, 1, 0);
        set(6, 1, 255);
        let c2 = b"update.example-c2.org,/ga.js\0";
        set(8, 3, strings_at as u64);
        strings.extend_from_slice(c2);
        set(9, 3, (strings_at + strings.len()) as u64);
        strings.extend_from_slice(b"Mozilla/5.0 (compatible; MSIE 9.0)\0");
        set(37, 2, 1359593325);
        (t, strings)
    }

    #[test]
    fn running_tables_in_both_widths() {
        for width in [8usize, 4] {
            let (t, strings) = table(width, 0x7000_0000);
            let mut block = vec![0x55u8; 64];
            block.extend_from_slice(&t);
            let mut found = Vec::new();
            find(&block, 0x20000, 0, &mut found);
            assert_eq!(found.len(), 1, "width {width}: {found:?}");
            assert_eq!(found[0].layout, Layout::Table(width));
            assert_eq!(found[0].addr, 0x20000 + 64, "slot 0 starts the table");
            let mem = [
                (0x20000usize, block.clone()),
                (0x7000_0000usize, strings.clone()),
            ];
            let cfg = parse(found[0], &reader(&mem)).expect("parses");
            let x = cfg.extracted();
            assert_eq!(x["beacon_type"], "HTTP");
            assert_eq!(x["c2_hosts"], json!(["update.example-c2.org"]));
            assert_eq!(x["user_agent"], "Mozilla/5.0 (compatible; MSIE 9.0)");
            assert_eq!(x["watermark"], 1359593325);
        }
    }

    #[test]
    fn look_alikes_are_rejected() {
        // The packed start with nothing sensible after it.
        let mut b = vec![
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02,
            0x01, 0xbb,
        ];
        b.extend_from_slice(&[0xff; 64]);
        let mut found = Vec::new();
        find(&b, 0, 0, &mut found);
        assert_eq!(found.len(), 1);
        assert!(parse(found[0], &reader(&[(0, b.clone())])).is_none());
        // A table whose C2 pointer leads nowhere and has too few settings.
        let (t, _) = table(8, 0x7000_0000);
        let mut found = Vec::new();
        find(&t, 0x1000, 0, &mut found);
        assert!(parse(found[0], &reader(&[(0x1000, t.clone())])).is_none());
        // A beacon type Cobalt Strike doesn't have.
        let mut p = packed();
        p[7] = 3;
        assert!(parse(
            Candidate {
                addr: 0,
                layout: Layout::Packed(0)
            },
            &reader(&[(0, p)])
        )
        .is_none());
    }
}
