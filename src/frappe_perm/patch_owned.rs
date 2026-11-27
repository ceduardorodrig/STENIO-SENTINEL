//! `FRAPPE-PATCH-SERVER-OWNED-WRITE` (GB-217): a data patch that saves a document to fill a field
//! the app's own prepare step rewrites from the stored row.

use super::{Case, Rule, Tree, doctype_file, flag, read, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;
use regex::Regex;
use std::collections::BTreeSet;

pub static RULE: Rule = Rule {
    id: "FRAPPE-PATCH-SERVER-OWNED-WRITE",
    name: "Patch Saves A Server-Owned Field",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PATCH-SERVER-OWNED-WRITE",
        name: "Patch Saves A Server-Owned Field",
        severity: "ERROR",
        tag: "frappe",
        summary: "A file under patches/ assigns a read_only field of a DocType it names and calls .save(), while app code copies that field back from get_doc_before_save() (`doc.f = before.f`).",
        rationale: "GB-217 (decision approved_on backfill, 2026-11-06): the prepare step writes the stored value back over the patch's assignment, so the save is a no-op or is refused by the following check.",
        bad_example: "doc.approved_on = DATE\ndoc.save()",
        good_example: "frappe.db.set_value(\"Decision\", name, {\"approved_on\": DATE, \"modified\": stamp}, update_modified=False)",
        remediation: "Write the server-owned field with frappe.db.set_value and an explicit modified.",
    },
};

/// Python source with docstrings blanked (line numbers kept) and comments removed.
fn code(text: &str) -> String {
    let blanked = match Regex::new(r#"(?s)""".*?"""|'''.*?'''"#) {
        Ok(re) => re
            .replace_all(text, |c: &regex::Captures| {
                "\n".repeat(c[0].matches('\n').count())
            })
            .into_owned(),
        Err(_) => text.to_string(),
    };
    blanked
        .lines()
        .map(crate::frappe::strip_comment)
        .collect::<Vec<_>>()
        .join("\n")
}

fn run(t: &Tree) -> Vec<Violation> {
    let Ok(restore) =
        Regex::new(r#"(?m)^\s*\w+\.(\w+)\s*=[^=\n].*?\bbefore\w*(?:\.get\(\s*["']|\.)(\w+)"#)
    else {
        return Vec::new();
    };
    let python = |dir: bool| {
        t.files.iter().filter(move |p| {
            let rel = t.rel(p);
            p.extension().is_some_and(|e| e == "py")
                && !rel.split('/').any(|s| s == "tests")
                && rel.split('/').any(|s| s == "patches") == dir
        })
    };
    let owned: BTreeSet<String> = python(false)
        .flat_map(|p| {
            restore
                .captures_iter(&code(&read(p)))
                .filter(|c| c[1] == c[2])
                .map(|c| c[1].to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut out = Vec::new();
    for p in python(true) {
        let text = code(&read(p));
        if !text.contains(".save(") {
            continue;
        }
        for d in &t.docs {
            if !text.contains(&format!("\"{}\"", d.name))
                && !text.contains(&format!("'{}'", d.name))
            {
                continue;
            }
            for f in d.fields().iter().filter(|f| flag(f, "read_only")) {
                let field = str_of(f, "fieldname");
                if !owned.contains(field) {
                    continue;
                }
                let field_re = regex::escape(field);
                let Ok(write) = Regex::new(&format!(
                    r#"(?:\b\w+\.{field_re}\s*=[^=]|\.set\(\s*["']{field_re}["'])"#
                )) else {
                    continue;
                };
                for (n, line) in text.lines().enumerate() {
                    if write.is_match(line) {
                        out.push(viol(
                            &RULE,
                            &t.rel(p),
                            n + 1,
                            line.trim(),
                            format!("Patch assigns `{}.{field}` and saves the document, but the app rewrites that read-only field from the stored row: the write is lost or refused.", d.name),
                            "Use frappe.db.set_value with an explicit modified and update_modified=False.",
                        ));
                    }
                }
            }
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, patch: &str, expect| {
        Case {
        label,
        files: vec![
            doctype_file(
                "Decision",
                "",
                r#"{"fieldname":"approved_on","fieldtype":"Date","read_only":1},{"fieldname":"title","fieldtype":"Data"}"#,
                "",
            ),
            (
                "demoapp/structure.py".into(),
                "def prepare(doc):\n    before = doc.get_doc_before_save()\n    doc.approved_on = before.approved_on if before else None\n".into(),
            ),
            ("demoapp/patches/p.py".into(), patch.into()),
        ],
        validated: &[],
        expect,
    }
    };
    vec![
        case(
            "db.set_value with explicit modified is accepted",
            "\"\"\"Never `doc.approved_on = x` plus doc.save().\"\"\"\ndef execute():\n    frappe.db.set_value(\"Decision\", n, {\"approved_on\": D, \"modified\": s}, update_modified=False)\n",
            0,
        ),
        case(
            "saving an ordinary field is accepted",
            "def execute():\n    doc = frappe.get_doc(\"Decision\", n)\n    doc.title = \"x\"\n    doc.save()\n",
            0,
        ),
        case(
            "assigning the server-owned field and saving fires",
            "def execute():\n    doc = frappe.get_doc(\"Decision\", n)\n    doc.approved_on = D\n    doc.save()\n",
            1,
        ),
    ]
}
