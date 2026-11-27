//! Helpers shared by the rules of `frappe_desk`.

use super::super::*;
use crate::explain::RuleExplanation;

/// A finding of the rule `e` at its documented severity.
pub(super) fn finding(
    e: &RuleExplanation,
    path: &str,
    line: usize,
    snip: &str,
    msg: String,
) -> Violation {
    Violation {
        rule_id: e.id.to_string(),
        rule_name: e.name.to_string(),
        severity: super::severity(e),
        file_path: path.to_string(),
        line_number: line.max(1),
        snippet: snip.chars().take(120).collect(),
        message: msg,
        suggestion: Some(e.remediation.to_string()),
    }
}

/// Files of the app package with one of the extensions, tests excluded.
pub(super) fn sources<'a>(c: &'a Ctx, exts: &'a [&str]) -> impl Iterator<Item = &'a PathBuf> {
    c.files.iter().filter(move |p| {
        p.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
            && !rel(&c.pkg, p).split('/').any(|d| d == "tests")
    })
}

/// One document shipped as JSON: a file holding one object or an array of objects.
pub(super) struct Record {
    pub path: String,
    pub text: String,
    pub value: Value,
    pub doctype: String,
}

impl Record {
    pub fn name(&self) -> String {
        str_of(&self.value, "name")
    }

    /// Line of the first occurrence of `needle` after the record's own name.
    pub fn line(&self, needle: &str) -> usize {
        let quoted = format!("\"{}\"", self.name());
        let from = self.text.find(&quoted).unwrap_or(0);
        let at = self.text[from..]
            .find(needle)
            .map(|i| i + from)
            .or_else(|| self.text.find(needle))
            .unwrap_or(from);
        self.text[..at].matches('\n').count() + 1
    }
}

/// Every shipped record whose `doctype` is one of `doctypes`.
pub(super) fn records(c: &Ctx, doctypes: &[&str]) -> Vec<Record> {
    let mut out = Vec::new();
    for p in sources(c, &["json"]) {
        let text = read(p);
        let items = match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(a)) => a,
            Ok(v @ Value::Object(_)) => vec![v],
            _ => continue,
        };
        for value in items {
            let doctype = str_of(&value, "doctype");
            if doctypes.contains(&doctype.as_str()) {
                out.push(Record {
                    path: rel(&c.root, p),
                    text: text.clone(),
                    value,
                    doctype,
                });
            }
        }
    }
    out
}

/// A column every Frappe table has, so naming it is never a typo.
pub(super) fn standard_column(name: &str) -> bool {
    [
        "name",
        "owner",
        "creation",
        "modified",
        "modified_by",
        "docstatus",
        "idx",
        "_assign",
        "_liked_by",
        "_comments",
        "_user_tags",
        "_seen",
        "parent",
        "parenttype",
        "parentfield",
    ]
    .contains(&name)
}

/// True when the app DocType `d` has the column `field`.
pub(super) fn has_column(d: &DocType, field: &str) -> bool {
    standard_column(field) || d.fields.iter().any(|f| f.fieldname == field)
}

/// Line number of byte offset `at`.
pub(super) fn line_at(text: &str, at: usize) -> usize {
    text.get(..at)
        .map(|s| s.matches('\n').count() + 1)
        .unwrap_or(1)
}

/// Mutation-proof harness: writes a throwaway app (`app/hooks.py` included unless given), runs
/// one rule over it and returns `(file, line, message)` of every finding.
pub(super) fn probe(
    run: fn(&Ctx) -> Vec<Violation>,
    files: &[(&str, &str)],
) -> Option<Vec<(String, usize, String)>> {
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut all: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect();
    if !files.iter().any(|(p, _)| *p == "app/hooks.py") {
        all.push(("app/hooks.py".into(), "app_name = \"app\"\n".into()));
    }
    let root = write_fixture(&format!("desk-{n}"), &all)?;
    let cfg = FrappeConfig {
        app: Some("app".into()),
        ..FrappeConfig::default()
    };
    let got = build_ctx(&root, &cfg).ok().map(|c| {
        run(&c)
            .into_iter()
            .map(|v| (v.file_path, v.line_number, v.message))
            .collect()
    });
    let _ = fs::remove_dir_all(&root);
    got
}

/// The probe ran and found nothing.
pub(super) fn silent(run: fn(&Ctx) -> Vec<Violation>, files: &[(&str, &str)]) -> bool {
    probe(run, files).is_some_and(|v| v.is_empty())
}

/// The probe found exactly `n` things and one message holds every needle.
pub(super) fn fires(
    run: fn(&Ctx) -> Vec<Violation>,
    files: &[(&str, &str)],
    n: usize,
    needles: &[&str],
) -> bool {
    probe(run, files).is_some_and(|v| {
        v.len() == n
            && v.iter()
                .any(|(_, _, m)| needles.iter().all(|s| m.contains(s)))
    })
}
