//! Wire contract with the Go host. One JSON Request line in on stdin; one JSON
//! Response line out on stdout per result (scan_memory with several PIDs
//! streams one line per PID). These types mirror internal/sidecar/contract.go.

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
pub struct Request {
    pub op: String,
    /// Single target for scan_memory.
    #[serde(default)]
    pub pid: i64,
    /// Several targets for scan_memory: rules compile once, one response
    /// line is written per PID as each finishes.
    #[serde(default)]
    pub pids: Vec<i64>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub data: String,
    /// YARA rules: a .yar/.yara file, or a directory searched recursively.
    #[serde(default)]
    pub rules_path: String,
    /// Run the module-B prompt scan on each memory region (default true).
    #[serde(default)]
    pub prompts: Option<bool>,
    /// Per-process time budget in milliseconds (default 60000).
    #[serde(default)]
    pub budget_ms: Option<u64>,
    /// Per-process cap on bytes read (default 4 GiB).
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Scan processes excluded by default (lsass.exe).
    #[serde(default)]
    pub include_sensitive: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Response {
    pub op: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<Hit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl Response {
    pub fn err(op: &str, msg: impl Into<String>) -> Self {
        Response {
            op: op.to_string(),
            ok: false,
            error: msg.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub rule: String,
    pub severity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub technique: String,
    /// File offset, or virtual address for scan_memory.
    pub offset: i64,
    /// "ascii" (also covers UTF-8), "utf-16le", or "" for YARA hits.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub encoding: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub context: String,
    pub confidence: i64,
    /// For scan_memory: the memory region holding the first match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<HitRegion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HitRegion {
    pub base: u64,
    pub size: u64,
    /// Windows: "RX", "RW", "RWX", "R", "WC", "RWC"... Linux: maps perms.
    pub protect: String,
    /// Windows: "image" | "mapped" | "private". Linux: "file" | "anon" |
    /// "heap" | "stack" | other pseudo-path.
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file: String,
}
