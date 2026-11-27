//! Frappe permission and security rules of `--scope frappe`, one file per rule under
//! `frappe_perm/`. This core reads the tree once (DocType JSONs, hooks.py registrations,
//! permission data files) and holds the shared helpers; `frappe.rs` only calls [`audit`].
//!
//! Every rule ships its own fixtures: at least one tree where it must stay silent and one where
//! it must fire (the mutation proof), executed by `--self-test` and `cargo test`.

mod docperm_row;
mod permlevel_list_view;
mod permlevel_row;
mod permlevel_write;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

/// One rule: metadata, check, fixtures and the `--explain` entry.
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    run: fn(&Tree) -> Vec<Violation>,
    cases: fn() -> Vec<Case>,
    pub explain: RuleExplanation,
}

/// One synthetic tree and the number of findings the rule must report on it.
struct Case {
    label: &'static str,
    files: Vec<(String, String)>,
    /// DocType names that the app's `RULES` gate validates.
    validated: &'static [&'static str],
    expect: usize,
}

pub static RULES: &[&Rule] = &[&docperm_row::RULE, &permlevel_row::RULE];

/// Roles that carry no identity of their own (house policy, same list as `FRAPPE-PERMISSION-SCOPE`).
const BROAD_ROLES: &[&str] = crate::frappe::BROAD_ROLES;

struct Doc {
    name: String,
    rel: String,
    path: PathBuf,
    text: String,
    json: Value,
}

impl Doc {
    fn is_child(&self) -> bool {
        flag(&self.json, "istable")
    }

    fn fields(&self) -> &[Value] {
        list(&self.json, "fields")
    }

    fn perms(&self) -> &[Value] {
        list(&self.json, "permissions")
    }

    /// 1-based line that declares the field, or 1.
    fn field_line(&self, fieldname: &str) -> usize {
        let quoted = format!("\"{fieldname}\"");
        self.text
            .lines()
            .position(|l| l.contains("\"fieldname\"") && l.contains(&quoted))
            .map_or(1, |i| i + 1)
    }

    /// 1-based line naming the role of the `index`-th permission row.
    fn perm_line(&self, index: usize) -> usize {
        let perms = self.perms();
        let Some(role) = perms.get(index).map(|p| str_of(p, "role")) else {
            return 1;
        };
        let nth = perms
            .iter()
            .take(index)
            .filter(|p| str_of(p, "role") == role)
            .count();
        let quoted = format!("\"{role}\"");
        self.text
            .lines()
            .enumerate()
            .filter(|(_, l)| l.contains("\"role\"") && l.contains(&quoted))
            .nth(nth)
            .map_or(1, |(i, _)| i + 1)
    }
}

struct Tree {
    root: PathBuf,
    pkg: PathBuf,
    files: Vec<PathBuf>,
    docs: Vec<Doc>,
    validated: BTreeSet<String>,
}

impl Tree {
    fn rel(&self, p: &Path) -> String {
        p.strip_prefix(&self.root)
            .unwrap_or(p)
            .to_string_lossy()
            .to_string()
    }
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn int_of(v: &Value, key: &str) -> i64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::Bool(b)) => i64::from(*b),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn flag(v: &Value, key: &str) -> bool {
    int_of(v, key) != 0
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn viol(rule: &Rule, path: &str, line: usize, snip: &str, msg: String, hint: &str) -> Violation {
    Violation {
        rule_id: rule.id.to_string(),
        rule_name: rule.name.to_string(),
        severity: rule.severity,
        file_path: path.to_string(),
        line_number: line.max(1),
        snippet: snip.chars().take(120).collect(),
        message: msg,
        suggestion: Some(hint.to_string()),
    }
}

fn tree(root: &Path, pkg: &Path, files: &[PathBuf], validated: BTreeSet<String>) -> Tree {
    let docs = files
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| {
            let dir = p.parent();
            dir.and_then(Path::file_name) == p.file_stem()
                && dir.and_then(Path::parent).and_then(Path::file_name)
                    == Some(std::ffi::OsStr::new("doctype"))
        })
        .filter_map(|p| {
            let text = read(p);
            let json: Value = serde_json::from_str(&text).ok()?;
            (str_of(&json, "doctype") == "DocType").then(|| Doc {
                name: str_of(&json, "name").to_string(),
                rel: p
                    .strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .to_string(),
                path: p.clone(),
                text,
                json,
            })
        })
        .collect();
    Tree {
        root: root.to_path_buf(),
        pkg: pkg.to_path_buf(),
        files: files.to_vec(),
        docs,
        validated,
    }
}

/// Runs every permission rule over an app tree already walked by `frappe.rs`.
pub fn audit(
    root: &Path,
    pkg: &Path,
    files: &[PathBuf],
    validated: BTreeSet<String>,
) -> Vec<Violation> {
    let t = tree(root, pkg, files, validated);
    RULES.iter().flat_map(|r| (r.run)(&t)).collect()
}

pub fn explanations() -> impl Iterator<Item = &'static RuleExplanation> {
    RULES.iter().map(|r| &r.explain)
}

fn run_case(rule: &Rule, tag: &str, case: &Case) -> Option<usize> {
    let root = crate::frappe::write_fixture(tag, &case.files)?;
    let pkg = root.join("demoapp");
    let files: Vec<PathBuf> = case.files.iter().map(|(p, _)| root.join(p)).collect();
    let validated = case.validated.iter().map(|s| s.to_string()).collect();
    let found = (rule.run)(&tree(&root, &pkg, &files, validated))
        .iter()
        .filter(|v| v.rule_id == rule.id)
        .count();
    let _ = fs::remove_dir_all(root);
    Some(found)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (r, rule) in RULES.iter().enumerate() {
        let cases = (rule.cases)();
        // a rule never seen both silent and red proves nothing
        let proof = cases.iter().any(|c| c.expect == 0) && cases.iter().any(|c| c.expect > 0);
        out.push((
            format!("{}: has silent and firing fixtures", rule.id),
            proof,
        ));
        for (n, case) in cases.iter().enumerate() {
            let tag = format!("perm-{r}-{n}");
            out.push((
                format!("{}: {}", rule.id, case.label),
                run_case(rule, &tag, case) == Some(case.expect),
            ));
        }
    }
    out
}

/// A field that holds a value (layout fields carry no permission of their own).
fn data_field(f: &Value) -> bool {
    !matches!(
        str_of(f, "fieldtype"),
        "Section Break" | "Column Break" | "Tab Break" | "Fold" | "Heading" | "HTML" | "Button"
    )
}

/// Fixture helper: a DocType JSON at its canonical path (`demoapp/m/doctype/<slug>/<slug>.json`).
fn doctype_file(name: &str, extra: &str, fields: &str, perms: &str) -> (String, String) {
    let slug = name.to_lowercase().replace(' ', "_");
    (
        format!("demoapp/m/doctype/{slug}/{slug}.json"),
        format!(
            "{{\"doctype\":\"DocType\",\"name\":\"{name}\",{extra}\"fields\":[{fields}],\"permissions\":[{perms}]}}"
        ),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_test_cases_all_pass() {
        // fixtures share temp tags with `--self-test`; one thread runs them all
        for (name, ok) in super::self_test_cases() {
            assert!(ok, "{name}");
        }
    }
}
