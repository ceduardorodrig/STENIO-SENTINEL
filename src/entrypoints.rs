//! `AGENT-ENTRYPOINT-RULES` (GB-033): every agent harness must point at the shared rules.
//!
//! The vault file `governance/agent-entrypoints.toml` lists each harness entry file (absolute
//! or `~/` paths) and the strings it must contain (the path of `agent-global-rules.md`, the
//! name of the shared reminder script). A required file that is missing or lacks a reference is
//! an ERROR; an optional one is a WARN. `host_only` names the host that owns the file: on any
//! other host a missing file is an INFO line, not a finding.

use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "AGENT-ENTRYPOINT-RULES";
const CONFIG_REL: &str = "governance/agent-entrypoints.toml";

#[derive(Debug, serde::Deserialize)]
struct Config {
    #[serde(default)]
    entry: Vec<Entry>,
}

#[derive(Debug, serde::Deserialize)]
struct Entry {
    harness: String,
    file: String,
    #[serde(default)]
    must_reference: Vec<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    host_only: Option<String>,
}

/// Outcome of one entry: a PASS/INFO message or a finding.
#[derive(Debug, PartialEq)]
enum Verdict {
    Pass,
    Info(String),
    Finding(Severity, String),
}

pub struct EntrypointReport {
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

fn expand(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => Path::new(&home).join(rest),
        _ => PathBuf::from(path),
    }
}

fn current_host() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

fn evaluate(entry: &Entry, content: Option<&str>, host: &str) -> Verdict {
    let Some(text) = content else {
        let foreign = entry
            .host_only
            .as_deref()
            .is_some_and(|h| !h.eq_ignore_ascii_case(host));
        if foreign {
            return Verdict::Info(format!("{} not on this host, skipped", entry.file));
        }
        let severity = if entry.required {
            Severity::Error
        } else {
            Severity::Warning
        };
        return Verdict::Finding(
            severity,
            format!("{} entry file {} is missing", entry.harness, entry.file),
        );
    };
    let absent: Vec<&str> = entry
        .must_reference
        .iter()
        .map(String::as_str)
        .filter(|needle| !text.contains(needle))
        .collect();
    if absent.is_empty() {
        return Verdict::Pass;
    }
    let severity = if entry.required {
        Severity::Error
    } else {
        Severity::Warning
    };
    Verdict::Finding(
        severity,
        format!(
            "{} entry file {} does not reference: {}",
            entry.harness,
            entry.file,
            absent.join(", ")
        ),
    )
}

/// Finds `governance/agent-entrypoints.toml` at `start` or in one of its ancestors.
fn find_config(start: &Path) -> Option<PathBuf> {
    let base = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    base.ancestors()
        .map(|a| a.join(CONFIG_REL))
        .find(|p| p.is_file())
}

pub fn audit(start: &Path) -> EntrypointReport {
    let mut report = EntrypointReport {
        messages: Vec::new(),
        violations: Vec::new(),
    };
    let Some(cfg_path) = find_config(start) else {
        return report;
    };
    let cfg: Config = match fs::read_to_string(&cfg_path).map(|t| toml::from_str(&t)) {
        Ok(Ok(c)) => c,
        _ => {
            report.violations.push(finding(
                &cfg_path.to_string_lossy(),
                "config",
                Severity::Error,
                "agent-entrypoints.toml cannot be parsed".to_string(),
            ));
            return report;
        }
    };
    let host = current_host();
    for entry in &cfg.entry {
        let path = expand(&entry.file);
        let content = fs::read_to_string(&path).ok();
        match evaluate(entry, content.as_deref(), &host) {
            Verdict::Pass => report
                .messages
                .push(format!("PASS {RULE_ID} {}: {}", entry.harness, entry.file)),
            Verdict::Info(m) => report
                .messages
                .push(format!("INFO {RULE_ID} {}: {m}", entry.harness)),
            Verdict::Finding(sev, m) => {
                report
                    .violations
                    .push(finding(&entry.file, &entry.harness, sev, m))
            }
        }
    }
    report
}

fn finding(file: &str, harness: &str, severity: Severity, message: String) -> Violation {
    Violation {
        rule_id: RULE_ID.to_string(),
        rule_name: "Agent Entry Point Must Reference Shared Rules".to_string(),
        severity,
        file_path: file.to_string(),
        line_number: 1,
        snippet: harness.to_string(),
        message,
        suggestion: Some(
            "Add the missing reference to the entry file (surgical edit), or fix governance/agent-entrypoints.toml.".to_string(),
        ),
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let entry = |required: bool, host: Option<&str>| Entry {
        harness: "h".into(),
        file: "/x/CLAUDE.md".into(),
        must_reference: vec!["agent-global-rules.md".into()],
        required,
        host_only: host.map(str::to_string),
    };
    let good = "see governance/agent-global-rules.md";
    vec![
        (
            "entrypoint passes with reference".to_string(),
            evaluate(&entry(true, None), Some(good), "a") == Verdict::Pass,
        ),
        (
            "entrypoint fails without reference".to_string(),
            matches!(
                evaluate(&entry(true, None), Some("nothing"), "a"),
                Verdict::Finding(Severity::Error, _)
            ) && matches!(
                evaluate(&entry(false, None), Some("nothing"), "a"),
                Verdict::Finding(Severity::Warning, _)
            ),
        ),
        (
            "entrypoint missing file and host_only".to_string(),
            matches!(
                evaluate(&entry(true, None), None, "a"),
                Verdict::Finding(Severity::Error, _)
            ) && matches!(
                evaluate(&entry(true, Some("b")), None, "a"),
                Verdict::Info(_)
            ) && matches!(
                evaluate(&entry(true, Some("a")), None, "a"),
                Verdict::Finding(Severity::Error, _)
            ),
        ),
    ]
}
