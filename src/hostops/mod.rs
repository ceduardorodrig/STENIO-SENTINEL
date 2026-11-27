//! `stenio hostops`: operations, monitoring, systemd and host rules.
//!
//! Two kinds of check live here, one file per queue item:
//! - static lints over a tree (vault plus config mirror), run by `--scope homelab`, by
//!   `stenio --only <RULE_ID> --path <dir>` and by `stenio hostops lint --path <dir>`;
//! - read-only host probes, run by `stenio hostops <check> --host <name|local>`.
//!
//! Every probe sends fixed read-only commands; nothing here changes a host.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

mod alert_independence; // GB-213
mod autopilot_last; // GB-175
mod backup_verify; // GB-051
mod boots; // GB-155
mod false_alive; // GB-231
mod fundamental_probe; // GB-232
mod kuma; // GB-014 GB-015
mod lua_load_api; // GB-234
mod onfailure; // GB-016
mod ports_vs_ss; // GB-013
mod proxy_env; // GB-200
mod session_orphan; // GB-235
mod socket_order; // GB-171


/// One file of a linted tree.
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

type Lint = fn(&[SourceFile]) -> Vec<Violation>;

/// Static lints: rule id and function.
const LINTS: &[(&str, Lint)] = &[
    (alert_independence::RULE_ID, alert_independence::lint), // GB-213
    (backup_verify::RULE_ID, backup_verify::lint),           // GB-051
    (fundamental_probe::RULE_ID, fundamental_probe::lint),   // GB-232
    (lua_load_api::RULE_ID, lua_load_api::lint),             // GB-234
    (proxy_env::RULE_ID, proxy_env::lint),                   // GB-200
    (session_orphan::RULE_ID, session_orphan::lint),         // GB-235
    (socket_order::RULE_ID, socket_order::lint),             // GB-171
];

pub static EXPLANATIONS: &[RuleExplanation] = &[
    alert_independence::EXPLAIN, // GB-213
    autopilot_last::EXPLAIN,     // GB-175
    backup_verify::EXPLAIN,      // GB-051
    boots::EXPLAIN,              // GB-155
    false_alive::EXPLAIN,        // GB-231
    fundamental_probe::EXPLAIN,  // GB-232
    kuma::EXPLAIN_LOOPBACK,      // GB-014
    kuma::EXPLAIN_NOTIFY,        // GB-015
    lua_load_api::EXPLAIN,       // GB-234
    onfailure::EXPLAIN,          // GB-016
    ports_vs_ss::EXPLAIN,        // GB-013
    proxy_env::EXPLAIN,          // GB-200
    session_orphan::EXPLAIN,     // GB-235
    socket_order::EXPLAIN,       // GB-171
];

const USAGE: &str = "usage: stenio hostops <check> [options]\n  lint --path DIR [--only RULE_ID]";

pub fn run_cli(argv: &[String]) -> i32 {
    let Some(name) = argv.first() else {
        eprintln!("{USAGE}");
        return 2;
    };
    let rest = &argv[1..];
    match name.as_str() {
        "lint" => lint_cli(rest),
        "autopilot-last" => autopilot_last::run_cli(rest), // GB-175
        "boots" => boots::run_cli(rest),                   // GB-155
        "false-alive" => false_alive::run_cli(rest),       // GB-231
        "kuma" => kuma::run_cli(rest),                     // GB-014 GB-015
        "onfailure" => onfailure::run_cli(rest),           // GB-016
        "ports" => ports_vs_ss::run_cli(rest),             // GB-013
        _ => {
            eprintln!("unknown check '{name}'\n{USAGE}");
            2
        }
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let mut all = Vec::new();
    all.extend(alert_independence::self_test_cases()); // GB-213
    all.extend(autopilot_last::self_test_cases()); // GB-175
    all.extend(backup_verify::self_test_cases()); // GB-051
    all.extend(boots::self_test_cases()); // GB-155
    all.extend(false_alive::self_test_cases()); // GB-231
    all.extend(fundamental_probe::self_test_cases()); // GB-232
    all.extend(kuma::self_test_cases()); // GB-014 GB-015
    all.extend(lua_load_api::self_test_cases()); // GB-234
    all.extend(onfailure::self_test_cases()); // GB-016
    all.extend(ports_vs_ss::self_test_cases()); // GB-013
    all.extend(proxy_env::self_test_cases()); // GB-200
    all.extend(session_orphan::self_test_cases()); // GB-235
    all.extend(socket_order::self_test_cases()); // GB-171
    all
}

/// True when `rule` is one of the static lints of this module.
pub fn is_lint_rule(rule: &str) -> bool {
    LINTS.iter().any(|(id, _)| id.eq_ignore_ascii_case(rule))
}

fn violation(
    rule_id: &str,
    severity: Severity,
    file: &str,
    line: usize,
    snippet: &str,
    message: String,
    suggestion: &str,
) -> Violation {
    Violation {
        rule_id: rule_id.to_string(),
        rule_name: rule_id.to_string(),
        severity,
        file_path: file.to_string(),
        line_number: line.max(1),
        snippet: snippet.trim().chars().take(160).collect(),
        message,
        suggestion: Some(suggestion.to_string()),
    }
}

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".stversions",
    ".smart-env",
    ".agents-work",
    "cold-storage",
    "node_modules",
    "target",
];
const LINT_EXTENSIONS: &[&str] = &[
    "service", "socket", "timer", "conf", "lua", "sh", "md", "yml", "yaml", "desktop", "",
];

/// Reads the lintable files under `root` (backups and rollback copies are skipped).
pub fn collect(root: &Path) -> Vec<SourceFile> {
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .standard_filters(false)
        .filter_entry(|e| {
            !(e.file_type().is_some_and(|t| t.is_dir())
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| SKIP_DIRS.contains(&n)))
        })
        .build();
    let mut out = Vec::new();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy();
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if name.contains(".bak") || name.contains(".prev") || !LINT_EXTENSIONS.contains(&ext) {
            continue;
        }
        if entry.metadata().map_or(true, |m| m.len() > 512 * 1024) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if ext.is_empty() && !content.starts_with("#!") {
            continue;
        }
        out.push(SourceFile {
            path: path.to_string_lossy().into_owned(),
            content,
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Runs the static lints (all of them, or the `only` one) over `files`.
pub fn lint_files(files: &[SourceFile], only: Option<&str>) -> Vec<Violation> {
    LINTS
        .iter()
        .filter(|(id, _)| only.is_none_or(|o| o.eq_ignore_ascii_case(id)))
        .flat_map(|(_, f)| f(files))
        .collect()
}

const MIRROR: &str = "/mnt/BACKUP/configs-homelab";

/// Mirror subtrees that hold units, scripts, session and monitoring configs. Walking the whole
/// mirror reads service data and took 70 s.
const MIRROR_SUBDIRS: &[&str] = &[
    "bin",
    "golden/etc/systemd",
    "hypr",
    "data/monitoring",
    "homelab/mnemocine-ops/provisioning",
];

fn mirror_dirs(mirror: &Path) -> Vec<PathBuf> {
    let Ok(hosts) = std::fs::read_dir(mirror) else {
        return Vec::new();
    };
    hosts
        .flatten()
        .flat_map(|h| MIRROR_SUBDIRS.iter().map(move |s| h.path().join(s)))
        .filter(|d| d.is_dir())
        .collect()
}

/// Entry point of the main scan. In the aggregate homelab scope every finding is a warning (the
/// live tree still carries known open items); an explicit `--only <RULE_ID>` keeps the
/// severity the rule declares.
pub fn audit(root: &Path, only: Option<&str>) -> (Vec<String>, Vec<Violation>) {
    let mut files = collect(root);
    if root.join("mnemocine").is_dir() {
        for dir in mirror_dirs(Path::new(MIRROR)) {
            files.extend(collect(&dir));
        }
    }
    let mut found = lint_files(&files, only);
    if only.is_none() {
        for v in &mut found {
            v.severity = Severity::Warning;
        }
    }
    let message = format!(
        "hostops: {} static lint(s) over {} file(s), {} finding(s)",
        LINTS.len(),
        files.len(),
        found.len()
    );
    (vec![message], found)
}

fn lint_cli(args: &[String]) -> i32 {
    let root = PathBuf::from(opt(args, "--path").unwrap_or_else(|| ".".to_string()));
    let only = opt(args, "--only");
    if let Some(o) = &only
        && !is_lint_rule(o)
    {
        eprintln!("unknown static rule '{o}'");
        return 2;
    }
    let files = collect(&root);
    if files.is_empty() {
        eprintln!("nothing to lint under {}", root.display());
        return 2;
    }
    let found = lint_files(&files, only.as_deref());
    for v in &found {
        println!(
            "{} {} {}:{} {}",
            if v.severity == Severity::Error {
                "FAIL"
            } else {
                "WARN"
            },
            v.rule_id,
            v.file_path,
            v.line_number,
            v.message
        );
    }
    println!("{} file(s) linted, {} finding(s)", files.len(), found.len());
    i32::from(!found.is_empty())
}

/// Value of `--name value` or `--name=value`.
fn opt(args: &[String], name: &str) -> Option<String> {
    opts(args, name).into_iter().next()
}

/// All values of a repeatable `--name` option.
fn opts(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            out.extend(it.next().cloned());
        } else if let Some(v) = a.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            out.push(v.to_string());
        }
    }
    out
}

/// A host name safe to pass to ssh (`local` runs on this machine).
fn host_arg(args: &[String]) -> Option<String> {
    opt(args, "--host").filter(|h| !h.starts_with('-') && crate::verify_release::safe(h, ""))
}

/// Runs a fixed read-only shell command on `host` (`local` or an ssh name).
fn host_run(host: &str, command: &str) -> Result<String, String> {
    let this = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    if host == "local" || host.eq_ignore_ascii_case(this.trim()) {
        let mut c = Command::new("sh");
        c.args(["-c", command]);
        let out = crate::verify_release::spawn_with_timeout(c, std::time::Duration::from_secs(60))?;
        return if out.code == 0 {
            Ok(out.stdout)
        } else {
            Err(format!("command exited {}", out.code))
        };
    }
    match crate::remote::run_ssh(host, command, 20) {
        crate::remote::RemoteOutcome::Success(s) => Ok(s),
        other => Err(format!("{other:?}")),
    }
}

/// Prints the verdict of a probe: exit 0 without findings, 1 with findings.
fn verdict(rule: &str, subject: &str, checked: usize, findings: &[String]) -> i32 {
    for f in findings {
        println!("FAIL {rule} {f}");
    }
    if findings.is_empty() {
        println!("PASS {rule} {subject}: {checked} item(s) checked");
    } else {
        println!(
            "{} finding(s), {checked} item(s) checked on {subject}",
            findings.len()
        );
    }
    i32::from(!findings.is_empty())
}

fn unreadable(rule: &str, why: impl std::fmt::Display) -> i32 {
    eprintln!("UNREADABLE {rule}: {why}");
    2
}

/// `key=value` entries of a systemd unit as (section, key, value, line).
fn unit_entries(content: &str) -> Vec<(String, String, String, usize)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let l = raw.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            out.push((
                section.clone(),
                k.trim().to_string(),
                v.trim().to_string(),
                i + 1,
            ));
        }
    }
    out
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// One-file tree for the synthetic cases.
fn fixture(files: &[(&str, &str)]) -> Vec<SourceFile> {
    files
        .iter()
        .map(|(p, c)| SourceFile {
            path: (*p).to_string(),
            content: (*c).to_string(),
        })
        .collect()
}

fn case(name: &str, ok: bool) -> (String, bool) {
    (name.to_string(), ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_cases_pass() {
        crate::testkit::assert_cases(self_test_cases());
    }

    #[test]
    fn every_rule_is_explained() {
        for (id, _) in LINTS {
            assert!(
                EXPLANATIONS.iter().any(|e| e.id == *id),
                "no --explain entry for {id}"
            );
        }
    }
}
