//! Release, rehearsal, test and patch rules of the `frappe` scope, one module per rule.
//!
//! A child module of `frappe`, so it reads the same parsed tree (`Ctx`) without widening any
//! visibility. Adding a rule is one `mod` line and one `ITEMS` line; every item carries its
//! `--explain` text and its own mutation proof, run by `--self-test` and `cargo test`.

use super::{Ctx, build_ctx, rel, write_fixture};
use crate::config::FrappeConfig;
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;
use std::path::{Path, PathBuf};

mod access_log; // FRAPPE-ACCESS-LOG-SYNC-ASSERT
mod dead_except; // FRAPPE-DEAD-EXCEPT
mod masked_literal; // TEST-NO-MASKED-LITERAL
mod privacy_lists; // FRAPPE-PRIVACY-LIST-NAMES-EXIST
mod sidebar_lists; // FRAPPE-SIDEBAR-ALLOWLIST-PARITY
mod test_cleanup; // FRAPPE-TEST-CLEANUP-DEFERRED
mod test_verdict; // FRAPPE-TEST-VERDICT

pub(crate) struct Item {
    pub severity: Severity,
    rule: fn(&Ctx) -> Vec<Violation>,
    self_test: fn() -> bool,
    pub explain: RuleExplanation,
}

pub(crate) static ITEMS: &[&Item] = &[
    &access_log::ITEM,
    &dead_except::ITEM,
    &masked_literal::ITEM,
    &privacy_lists::ITEM,
    &sidebar_lists::ITEM,
    &test_cleanup::ITEM,
    &test_verdict::ITEM,
];

/// `(id, name, severity)` of every rule here, in the shape of `frappe::RULES`.
pub(crate) fn rules() -> impl Iterator<Item = (&'static str, &'static str, Severity)> {
    ITEMS
        .iter()
        .map(|i| (i.explain.id, i.explain.name, i.severity))
}

pub(crate) fn explanations() -> impl Iterator<Item = &'static RuleExplanation> {
    ITEMS.iter().map(|i| {
        let item: &'static Item = i;
        &item.explain
    })
}

pub(super) fn audit(c: &Ctx) -> Vec<Violation> {
    ITEMS.iter().flat_map(|i| (i.rule)(c)).collect()
}

pub(super) fn self_test_cases() -> Vec<(String, bool)> {
    ITEMS
        .iter()
        .map(|i| (i.explain.id.to_string(), (i.self_test)()))
        .collect()
}

fn hit(item: &Item, path: &str, line: usize, snippet: &str, message: String) -> Violation {
    Violation {
        rule_id: item.explain.id.to_string(),
        rule_name: item.explain.name.to_string(),
        severity: item.severity,
        file_path: path.to_string(),
        line_number: line.max(1),
        snippet: snippet.trim().chars().take(120).collect(),
        message,
        suggestion: Some(item.explain.remediation.to_string()),
    }
}

/// `(relative path, text)` of the Python modules directly or deeper under `<app>/tests`.
fn test_modules(c: &Ctx) -> Vec<(String, PathBuf, String)> {
    python_under(c, &c.pkg.join("tests"))
}

fn python_under(c: &Ctx, dir: &Path) -> Vec<(String, PathBuf, String)> {
    let mut out: Vec<(String, PathBuf, String)> = c
        .files
        .iter()
        .filter(|p| p.starts_with(dir) && p.extension().is_some_and(|e| e == "py"))
        .map(|p| (rel(&c.root, p), p.clone(), super::read(p)))
        .collect();
    out.sort();
    out
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Line ranges (0-based, end exclusive) of every `def` block, outermost and nested.
fn functions(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if !l.trim_start().starts_with("def ") {
            continue;
        }
        let own = indent(l);
        let end = (i + 1..lines.len())
            .find(|&j| {
                let t = lines[j].trim_start();
                !t.is_empty()
                    && !t.starts_with('#')
                    && !t.starts_with(')')
                    && indent(lines[j]) <= own
            })
            .unwrap_or(lines.len());
        out.push((i, end));
    }
    out
}

/// The innermost function around line `at`, or the whole module.
fn scope_of(lines: &[&str], at: usize) -> (usize, usize) {
    functions(lines)
        .into_iter()
        .filter(|(s, e)| *s <= at && at < *e)
        .max_by_key(|(s, _)| *s)
        .unwrap_or((0, lines.len()))
}

/// Major version of the Frappe base image pinned by the app's Dockerfile, when it declares one.
fn frappe_major(c: &Ctx) -> Option<u64> {
    let text = super::read(&c.root.join("Dockerfile"));
    crate::frappe_drift::pinned_major(&text)
}

/// Mutation-proof runner: writes `files` under `repo/` beside a minimal app, runs ONE rule and
/// returns its findings. None when the fixture cannot be built.
fn probe(item: &Item, cfg: &FrappeConfig, files: &[(&str, &str)]) -> Option<Vec<Violation>> {
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut all: Vec<(String, String)> = vec![
        (
            "repo/app/__init__.py".into(),
            "__version__ = \"0.1.0\"\n".into(),
        ),
        ("repo/app/hooks.py".into(), "app_name = \"app\"\n".into()),
    ];
    for (p, t) in files {
        let path = format!("repo/{p}");
        all.retain(|(q, _)| *q != path);
        all.push((path, t.to_string()));
    }
    let base = write_fixture(&format!("ext-{n}"), &all)?;
    let cfg = FrappeConfig {
        app: Some("app".into()),
        ..cfg.clone()
    };
    let got = build_ctx(&base.join("repo"), &cfg)
        .ok()
        .map(|c| (item.rule)(&c));
    let _ = std::fs::remove_dir_all(&base);
    got
}

/// Number of findings of one rule over a fixture.
fn count(item: &Item, files: &[(&str, &str)]) -> Option<usize> {
    probe(item, &FrappeConfig::default(), files).map(|v| v.len())
}

/// A DocType JSON fixture; `extra` is spliced into the object.
fn doctype(name: &str, extra: &str) -> String {
    format!(
        "{{\"doctype\":\"DocType\",\"name\":\"{name}\",\"fields\":[],\"permissions\":[]{extra}}}"
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_rule_proves_itself_on_a_mutated_tree() {
        let failed: Vec<String> = super::self_test_cases()
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(id, _)| id)
            .collect();
        assert!(failed.is_empty(), "mutation proof failed: {failed:?}");
    }
}
