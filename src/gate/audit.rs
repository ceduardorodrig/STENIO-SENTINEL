//! The append-only record of what the gate judged: one hash-chained JSON line per command or
//! edit, one file per host and day (so a synchronised folder never merges two writers), with
//! secrets removed before anything is written.

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const TEXT_LIMIT: usize = 4000;
const TAIL: u64 = 64 * 1024;

fn patterns() -> &'static [(Regex, &'static str)] {
    static LIST: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    LIST.get_or_init(|| {
        [
            (
                r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)",
                "[redacted key]",
            ),
            (
                r"\b(?:gh[pousr]_|github_pat_|sk-|xox[abprs]-|hf_|glpat-|npm_|tskey-)[A-Za-z0-9_-]{8,}",
                "[redacted]",
            ),
            (r"\bAGE-SECRET-KEY-1[A-Za-z0-9]+", "[redacted]"),
            (r"\bAKIA[0-9A-Z]{16}\b", "[redacted]"),
            (
                r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
                "[redacted]",
            ),
            (
                r"(?i)\b((?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]{8,}",
                "${1}[redacted]",
            ),
            (r"(://[^/\s:@'\x22]+:)[^@\s/'\x22]+@", "${1}[redacted]@"),
            (
                r"(?i)((?:token|secret|passwd|password|passphrase|api[_-]?key|private[_-]?key|credential|_key|authorization)[A-Za-z0-9_]*[\x22']?\s*[=:]\s*)(\x22[^\x22$]*\x22|'[^'$]*'|[^\s\x22'$;&|]+)",
                "${1}[redacted]",
            ),
            (
                r"(?i)(--?(?:password|passwd|token|secret|api-key|passphrase)[ =])(\x22[^\x22]*\x22|'[^']*'|[^\s$]+)",
                "${1}[redacted]",
            ),
            (r"\b(sshpass\s+-p\s*)\S+", "${1}[redacted]"),
            (
                r"\b((?:mysql|mariadb|mysqldump)\b[^|;&\n]*?\s-p)[^\s-]\S*",
                "${1}[redacted]",
            ),
        ]
        .into_iter()
        .filter_map(|(p, to)| Regex::new(p).ok().map(|r| (r, to)))
        .collect()
    })
}

/// A long run of mixed characters with no path separator is treated as a key.
fn opaque(text: &str) -> String {
    static RUN: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(run) = RUN.get_or_init(|| Regex::new(r"[A-Za-z0-9+=_-]{32,}").ok()) else {
        return text.to_string();
    };
    run.replace_all(text, |c: &regex::Captures<'_>| {
        let word = &c[0];
        let mixed = word.chars().any(|c| c.is_ascii_uppercase())
            && word.chars().any(|c| c.is_ascii_lowercase())
            && word.chars().any(|c| c.is_ascii_digit());
        if mixed {
            "[redacted]".to_string()
        } else {
            word.to_string()
        }
    })
    .into_owned()
}

pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for (re, to) in patterns() {
        out = re.replace_all(&out, *to).into_owned();
    }
    let out = opaque(&out);
    match out.char_indices().nth(TEXT_LIMIT) {
        Some((at, _)) => format!("{}… [{} bytes]", &out[..at], out.len()),
        None => out,
    }
}

pub fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

fn digest(entry: &Map<String, Value>) -> String {
    let mut bare = entry.clone();
    bare.remove("hash");
    Sha256::digest(Value::Object(bare).to_string().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn last_hash(file: &mut File) -> std::io::Result<String> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    Ok(String::from_utf8_lossy(&tail)
        .lines()
        .rev()
        .find_map(|l| {
            serde_json::from_str::<Value>(l)
                .ok()
                .and_then(|v| v["hash"].as_str().map(str::to_string))
        })
        .unwrap_or_default())
}

/// Appends one entry to today's file of this host under `dir`.
pub fn append(dir: &Path, mut entry: Map<String, Value>) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let now = chrono::Utc::now();
    let host = host_name();
    let path = dir.join(format!("{host}-{}.jsonl", now.format("%Y%m%d")));
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)?;
    // SAFETY: the descriptor belongs to `file`, which outlives the lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    entry.insert("at".into(), json!(now.to_rfc3339()));
    entry.insert("host".into(), json!(host));
    entry.insert("prev".into(), json!(last_hash(&mut file)?));
    let hash = digest(&entry);
    entry.insert("hash".into(), json!(hash));
    let line = format!("{}\n", Value::Object(entry));
    file.write_all(line.as_bytes())?;
    Ok(path)
}

#[derive(Debug, Default)]
pub struct Report {
    pub files: usize,
    pub entries: usize,
    pub verdicts: BTreeMap<String, usize>,
    pub rules: BTreeMap<String, usize>,
    /// Entries that were not simply allowed.
    pub notable: Vec<Value>,
    /// `file:line` of an entry whose hash or chain does not hold.
    pub broken: Vec<String>,
}

/// Reads every file under `dir` and keeps the entries at or after `since` (RFC 3339).
pub fn report(dir: &Path, since: &str) -> std::io::Result<Report> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();
    let mut out = Report::default();
    for path in files {
        out.files += 1;
        let text = std::fs::read_to_string(&path)?;
        let mut previous = String::new();
        for (index, line) in text.lines().enumerate() {
            let Ok(Value::Object(entry)) = serde_json::from_str::<Value>(line) else {
                out.broken
                    .push(format!("{}:{} unreadable", path.display(), index + 1));
                continue;
            };
            let said = |k: &str| entry.get(k).and_then(Value::as_str).unwrap_or_default();
            if said("hash") != digest(&entry) || said("prev") != previous {
                out.broken
                    .push(format!("{}:{} chain", path.display(), index + 1));
            }
            previous = said("hash").to_string();
            if said("at") < since {
                continue;
            }
            out.entries += 1;
            *out.verdicts.entry(said("verdict").to_string()).or_default() += 1;
            for rule in entry
                .get("rules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(rule) = rule.as_str() {
                    *out.rules.entry(rule.to_string()).or_default() += 1;
                }
            }
            if said("verdict") != "allow" {
                out.notable.push(Value::Object(entry));
            }
        }
    }
    Ok(out)
}
