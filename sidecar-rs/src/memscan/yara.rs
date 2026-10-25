//! YARA-X rule loading and block scanning of process memory.
//!
//! Memory is fed to a `yara_x::blocks::Scanner` one region (or chunk) at a
//! time with its virtual address as the block base — the same model as
//! `yara rules.yar <pid>`: conditions are evaluated over the whole process and
//! match offsets are virtual addresses. Limits of that model (inherited from
//! classic YARA process scanning): modules such as `pe` and `hash`, `uint32()`
//! style reads and `filesize` are undefined, so rules relying on them won't
//! match. Files importing modules are listed in the response so that's visible.

use std::path::{Path, PathBuf};
use std::time::Duration;
use yara_x::{blocks, Compiler, MetaValue, Rules, ScanError, SourceCode};

const MAX_RULE_FILES: usize = 20_000;
const MAX_DEPTH: usize = 16;
/// Bounds memory and time on rules with very common patterns.
const MAX_MATCHES_PER_PATTERN: usize = 1_000;

pub struct LoadedRules {
    pub rules: Rules,
    pub path: String,
    pub files: usize,
    pub count: usize,
    /// "file: first line of error" for files that didn't compile.
    pub failed: Vec<String>,
    /// Files with `import "..."` (module-based conditions can't match here).
    pub module_imports: Vec<String>,
}

/// Load a .yar/.yara file, or every such file under a directory. Each file
/// gets its own namespace so rule names from different sets can't collide.
/// Files that fail to compile are reported, not silently dropped; it's an
/// error only if nothing compiled at all.
pub fn load(path: &str) -> Result<LoadedRules, String> {
    let root = Path::new(path);
    let md = std::fs::metadata(root).map_err(|e| format!("rules {path}: {e}"))?;
    let mut files = Vec::new();
    if md.is_dir() {
        collect(root, 0, &mut files)?;
        files.sort();
    } else {
        files.push(root.to_path_buf());
    }
    if files.is_empty() {
        return Err(format!("rules {path}: no .yar or .yara files found"));
    }

    // Sources are read up front so they outlive the compiler that borrows them.
    let mut failed = Vec::new();
    let mut sources = Vec::with_capacity(files.len());
    for f in &files {
        match std::fs::read_to_string(f) {
            Ok(s) => sources.push((f.clone(), s)),
            Err(e) => failed.push(format!("{}: {e}", f.display())),
        }
    }

    let mut module_imports = Vec::new();
    let mut compiler = Compiler::new();
    for (f, src) in &sources {
        if src.contains("import \"") {
            module_imports.push(f.display().to_string());
        }
        compiler.new_namespace(&namespace(root, f, md.is_dir()));
        let code = SourceCode::from(src.as_str()).with_origin(f.display().to_string());
        if let Err(e) = compiler.add_source(code) {
            failed.push(format!("{}: {}", f.display(), first_line(&e.to_string())));
        }
    }
    let rules = compiler.build();
    let count = rules.iter().len();
    if count == 0 {
        return Err(format!(
            "rules {path}: no rules compiled ({} file(s) failed){}",
            failed.len(),
            failed
                .first()
                .map(|f| format!("; first error: {f}"))
                .unwrap_or_default()
        ));
    }
    Ok(LoadedRules {
        rules,
        path: path.to_string(),
        files: files.len(),
        count,
        failed,
        module_imports,
    })
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| format!("rules {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let p = entry.path();
        if ft.is_dir() {
            collect(&p, depth + 1, out)?; // symlinked dirs are not followed
        } else if ft.is_file() && is_rule_file(&p) {
            out.push(p);
            if out.len() > MAX_RULE_FILES {
                return Err(format!("rules: more than {MAX_RULE_FILES} rule files"));
            }
        }
    }
    Ok(())
}

fn is_rule_file(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
}

/// Namespace from the file's path relative to the rules root.
fn namespace(root: &Path, file: &Path, root_is_dir: bool) -> String {
    let rel = if root_is_dir {
        file.strip_prefix(root).unwrap_or(file)
    } else {
        Path::new(file.file_name().unwrap_or_default())
    };
    let s: String = rel
        .with_extension("")
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if s.is_empty() {
        "default".into()
    } else {
        s
    }
}

fn first_line(s: &str) -> String {
    let line = s
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    line.chars().take(300).collect()
}

/// One matching rule, with everything the response needs and no raw bytes.
#[derive(Debug, Default)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    /// Lowest address of any pattern match (None for condition-only rules).
    pub first_addr: Option<usize>,
    pub total_matches: usize,
    /// (pattern identifier, match count)
    pub patterns: Vec<(String, usize)>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub technique: Option<String>,
    pub score: Option<i64>,
    pub description: Option<String>,
}

pub enum Stop {
    Timeout,
    Error(String),
}

/// A block scan over one process.
pub struct Session<'r> {
    scanner: blocks::Scanner<'r>,
}

impl<'r> Session<'r> {
    pub fn new(loaded: &'r LoadedRules) -> Self {
        let mut scanner = blocks::Scanner::new(&loaded.rules);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
        Session { scanner }
    }

    /// Scan one block at virtual address `base`, within the remaining budget.
    pub fn feed(&mut self, base: usize, data: &[u8], remaining: Duration) -> Result<(), Stop> {
        if remaining.is_zero() {
            return Err(Stop::Timeout);
        }
        self.scanner.set_timeout(remaining);
        match self.scanner.scan(base, data) {
            Ok(_) => Ok(()),
            Err(ScanError::Timeout) => Err(Stop::Timeout),
            Err(e) => Err(Stop::Error(e.to_string())),
        }
    }

    /// Evaluate conditions over everything fed so far.
    pub fn finish(mut self) -> Result<Vec<YaraMatch>, String> {
        let results = self.scanner.finish().map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for rule in results.matching_rules() {
            let mut m = YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                ..Default::default()
            };
            for p in rule.patterns() {
                let mut n = 0usize;
                for hit in p.matches() {
                    n += 1;
                    let a = hit.range().start;
                    m.first_addr = Some(m.first_addr.map_or(a, |f| f.min(a)));
                }
                if n > 0 {
                    m.patterns.push((p.identifier().to_string(), n));
                    m.total_matches += n;
                }
            }
            m.tags = rule.tags().map(|t| t.identifier().to_string()).collect();
            for (key, value) in rule.metadata() {
                let k = key.to_ascii_lowercase();
                match (k.as_str(), value) {
                    ("severity" | "threat_level", MetaValue::String(s)) => {
                        m.severity = Some(s.to_string())
                    }
                    ("score" | "confidence", MetaValue::Integer(i)) => m.score = Some(i),
                    (
                        "mitre_attack" | "mitre_att" | "attack" | "attack_id" | "technique",
                        MetaValue::String(s),
                    ) => m.technique = Some(s.to_string()),
                    ("description", MetaValue::String(s)) => m.description = Some(s.to_string()),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_rules(dir: &Path, name: &str, src: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), src).unwrap();
    }

    #[test]
    fn loads_directory_with_namespaces_and_reports_failures() {
        let dir = std::env::temp_dir().join(format!("lrng-rules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Same rule name in two files: namespaces keep them apart.
        write_rules(
            &dir,
            "a.yar",
            r#"rule dup { strings: $a = "alpha" condition: $a }"#,
        );
        write_rules(
            &dir.join("sub"),
            "b.YARA",
            r#"rule dup { strings: $b = "beta" condition: $b }"#,
        );
        write_rules(&dir, "broken.yar", "rule nope { condition: ");
        write_rules(&dir, "notes.txt", "not a rule file");
        write_rules(
            &dir,
            "pe.yar",
            r#"import "pe" rule usespe { condition: pe.is_pe }"#,
        );

        let l = load(dir.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(l.files, 4, "txt must be ignored");
        assert_eq!(l.count, 3);
        assert_eq!(l.failed.len(), 1);
        assert!(l.failed[0].contains("broken.yar"), "{:?}", l.failed);
        assert_eq!(l.module_imports.len(), 1);
    }

    #[test]
    fn nothing_compiled_is_an_error() {
        let dir = std::env::temp_dir().join(format!("lrng-rules-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_rules(&dir, "x.yar", "rule nope {");
        let e = load(dir.to_str().unwrap()).err().unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(e.contains("no rules compiled"), "{e}");
    }

    #[test]
    fn block_scan_reports_virtual_addresses_and_metadata() {
        let dir = std::env::temp_dir().join(format!("lrng-rules-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_rules(
            &dir,
            "m.yar",
            r#"rule two_blocks : demo {
                 meta: severity = "critical" score = 90 mitre_attack = "T1055" description = "test"
                 strings: $a = "needle-one" $b = "needle-two"
                 condition: all of them }"#,
        );
        let l = load(dir.join("m.yar").to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let mut s = Session::new(&l);
        // Two separate "regions" far apart; the rule needs both.
        s.feed(
            0x7ff6_0000_1000,
            b"....needle-one....",
            Duration::from_secs(5),
        )
        .ok()
        .unwrap();
        s.feed(0x0000_0200_0000, b"needle-two", Duration::from_secs(5))
            .ok()
            .unwrap();
        let ms = s.finish().unwrap();
        assert_eq!(ms.len(), 1);
        let m = &ms[0];
        assert_eq!(m.rule, "two_blocks");
        assert_eq!(m.first_addr, Some(0x0000_0200_0000));
        assert_eq!(m.total_matches, 2);
        assert_eq!(m.severity.as_deref(), Some("critical"));
        assert_eq!((m.score, m.technique.as_deref()), (Some(90), Some("T1055")));
        assert_eq!(m.tags, vec!["demo".to_string()]);
    }
}
