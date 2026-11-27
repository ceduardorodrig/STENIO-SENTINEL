//! Loads dotenv-style secret stores into memory. SECURITY: values stay inside the process; no type
//! here implements `Display`/`Debug` and no error message carries file content.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};

pub struct Store {
    /// Key name to raw value (ciphertext when `encrypted`). `sops_*` metadata is excluded.
    pub entries: BTreeMap<String, String>,
    pub encrypted: bool,
    /// `sops_lastmodified` of an encrypted file (RFC 3339, lexically comparable).
    pub last_modified: Option<String>,
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// `KEY=value` lines, with an optional `export ` / `declare -x ` prefix.
pub fn assignment(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    let t = t
        .strip_prefix("export ")
        .or_else(|| t.strip_prefix("declare -x "))
        .unwrap_or(t);
    let (k, v) = t.split_once('=')?;
    let k = k.trim_end();
    let valid = k.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then(|| (k, unquote(v)))
}

pub fn parse(content: &str) -> Store {
    let mut store = Store {
        entries: BTreeMap::new(),
        encrypted: false,
        last_modified: None,
    };
    for (k, v) in content.lines().filter_map(assignment) {
        if k == "sops_lastmodified" {
            store.last_modified = Some(v.to_string());
        }
        if k.starts_with("sops_") {
            store.encrypted = true;
        } else {
            store.entries.insert(k.to_string(), v.to_string());
        }
    }
    store.encrypted |= store
        .entries
        .values()
        .any(|v| v.starts_with("ENC[AES256_GCM"));
    store
}

/// Reads `path`; with `decrypt`, a sops file is decrypted by `sops -d` into memory only.
pub fn load(path: &Path, decrypt: bool) -> Result<Store, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e.kind()))?;
    let store = parse(&content);
    if !(decrypt && store.encrypted) {
        return Ok(store);
    }
    let out = Command::new("sops")
        .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run sops: {}", e.kind()))?;
    if !out.status.success() {
        return Err(format!(
            "sops could not decrypt {} ({})",
            path.display(),
            out.status
        ));
    }
    let mut plain = parse(&String::from_utf8_lossy(&out.stdout));
    plain.encrypted = false;
    plain.last_modified = store.last_modified;
    Ok(plain)
}

/// `label=path` command-line values.
pub fn labelled(spec: &str) -> Result<(String, std::path::PathBuf), String> {
    spec.split_once('=')
        .filter(|(l, p)| !l.is_empty() && !p.is_empty())
        .map(|(l, p)| (l.to_string(), p.into()))
        .ok_or_else(|| format!("expected LABEL=PATH, got `{spec}`"))
}
