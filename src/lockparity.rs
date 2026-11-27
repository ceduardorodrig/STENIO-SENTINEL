//! `LOCK-VERSION-PARITY` (GB-070): the version a crate declares in `Cargo.toml` is the version
//! `Cargo.lock` pins for it.
//!
//! WHY IT EXISTS: in the 4.19.1 -> 4.20.0 release the lockfile stayed behind,
//! `cargo build --release --locked` exited 101 and left the previous binary in `target/`.
//! `cargo metadata --locked --no-deps` exits 0 on the same drift, so its exit code proves nothing.
//! The check is offline: it reads the two TOML files. A lockfile package without `source` is a
//! local one; every `Cargo.toml` of the tree is compared with the nearest `Cargo.lock` above it.

use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "LOCK-VERSION-PARITY";

fn str_at<'a>(v: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

/// `(name, declared version)` of a manifest; `version.workspace = true` resolves in `workspace`.
fn declared(manifest: &str, workspace: Option<&str>) -> Option<(String, String)> {
    let doc: toml::Value = toml::from_str(manifest).ok()?;
    let name = str_at(&doc, &["package", "name"])?.to_string();
    let inherited = doc
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(|v| v.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true);
    let version = if inherited {
        let root: toml::Value = toml::from_str(workspace?).ok()?;
        str_at(&root, &["workspace", "package", "version"])?.to_string()
    } else {
        str_at(&doc, &["package", "version"])?.to_string()
    };
    Some((name, version))
}

/// The versions a lockfile pins for the local (source-less) package `name`.
fn pinned(lock: &str, name: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Value>(lock) else {
        return Vec::new();
    };
    doc.get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get("source").is_none() && str_at(p, &["name"]) == Some(name))
        .filter_map(|p| str_at(p, &["version"]).map(str::to_string))
        .collect()
}

/// The drift message of one manifest against its lockfile, `None` when they agree or when the
/// lockfile does not know the crate (a manifest outside that workspace).
pub fn drift(manifest: &str, workspace: Option<&str>, lock: &str) -> Option<String> {
    let (name, version) = declared(manifest, workspace)?;
    let found = pinned(lock, &name);
    (!found.is_empty() && !found.contains(&version)).then(|| {
        format!(
            "Cargo.toml declares {name} {version} but Cargo.lock pins {}: `cargo build --locked` refuses this tree",
            found.join(", ")
        )
    })
}

/// Every manifest under `root` (a directory or one file) against the nearest lockfile.
pub fn audit(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();
    for path in crate::shell::walk(root) {
        if path.file_name().is_none_or(|n| n != "Cargo.toml") {
            continue;
        }
        let Ok(manifest) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(lock_dir) = path
            .ancestors()
            .skip(1)
            .find(|d| d.join("Cargo.lock").is_file())
        else {
            continue;
        };
        let Ok(lock) = fs::read_to_string(lock_dir.join("Cargo.lock")) else {
            continue;
        };
        let workspace = fs::read_to_string(lock_dir.join("Cargo.toml")).ok();
        if let Some(message) = drift(&manifest, workspace.as_deref(), &lock) {
            let line = manifest
                .lines()
                .position(|l| l.trim_start().starts_with("version"))
                .map_or(1, |i| i + 1);
            out.push(Violation {
                rule_id: RULE_ID.to_string(),
                rule_name: "Cargo.lock Behind Cargo.toml".to_string(),
                severity: Severity::Error,
                file_path: path.to_string_lossy().to_string(),
                line_number: line,
                snippet: String::new(),
                message,
                suggestion: Some(
                    "Run `cargo update --workspace` (or any cargo command without --locked) and commit Cargo.lock."
                        .to_string(),
                ),
            });
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let manifest = |v: &str| format!("[package]\nname = \"p\"\nversion = \"{v}\"\n");
    let lock = "[[package]]\nname = \"p\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"p\"\nversion = \"9.0.0\"\nsource = \"registry+x\"\n";
    let inherited = "[package]\nname = \"p\"\nversion.workspace = true\n";
    let root = "[workspace.package]\nversion = \"0.2.0\"\n";
    let tree = |v: &str| {
        let files = vec![
            ("Cargo.toml".to_string(), manifest(v)),
            ("Cargo.lock".to_string(), lock.to_string()),
        ];
        let root = crate::frappe::write_fixture("lockparity", &files)?;
        let n = audit(&root).len();
        let _ = fs::remove_dir_all(&root);
        Some(n)
    };
    vec![
        (
            "lock parity: bumped manifest, stale lock".to_string(),
            drift(&manifest("0.2.0"), None, lock).is_some() && tree("0.2.0") == Some(1),
        ),
        (
            "lock parity: in sync is silent".to_string(),
            drift(&manifest("0.1.0"), None, lock).is_none() && tree("0.1.0") == Some(0),
        ),
        (
            "lock parity: inherited workspace version, unknown crate".to_string(),
            drift(inherited, Some(root), lock).is_some()
                && drift(&manifest("0.2.0").replace("\"p\"", "\"q\""), None, lock).is_none(),
        ),
    ]
}
