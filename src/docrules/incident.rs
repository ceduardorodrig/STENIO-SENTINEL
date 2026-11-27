//! `DOC-INCIDENT-REGISTER` (GB-050): every incident names its symptom, root cause, mechanism
//! and verification, the mechanism is something a machine runs, and the register indexes it.

use std::fs;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-INCIDENT-REGISTER",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-INCIDENT-REGISTER",
        name: "Incident Without Mechanism or Index Row",
        severity: "ERROR",
        tag: "doc",
        summary: "Every file in governance/incidents/ (README excepted) must carry, per `### ` entry, Symptom, Root cause, Mechanism and Verification, name a mechanism a machine runs, and be listed in the register README.",
        rationale: "GB-050, 2026-11-04: lessons were scattered over a skill, a queue row and handoff prose, and nothing verified that an incident ended in a mechanism. An entry whose mechanism is attention is a wish (governance/incidents/README.md).",
        bad_example: "### A1 - tag burned\n- **Symptom:** FAIL\n- **Root cause:** no step\n- **Mechanism:** be more careful next time\n- **Verification:** none",
        good_example: "- **Mechanism:** `FRAPPE-DOCTYPE-HEADER-KEYS` in `src/frappe.rs`",
        remediation: "Add the missing field, name the rule id, test, hook, gate or GB- item that prevents the repeat, and add the file to the README table.",
    },
};

const FIELDS: &[(&str, &[&str])] = &[
    ("Symptom", &["symptom", "sintoma"]),
    ("Root cause", &["root cause", "causa raiz"]),
    ("Mechanism", &["mechanism", "mecanismo"]),
    (
        "Verification",
        &["verification", "verificação", "verificacao"],
    ),
];

/// The field a line opens, for `- **Label ...:** text` and `## Label` forms.
fn field_of(line: &str) -> Option<usize> {
    let t = line.trim_start_matches(['-', '*', ' ']);
    let heading = line.trim_start().starts_with('#');
    let bold = line.trim_start_matches(['-', ' ']).starts_with("**");
    if !heading && !bold {
        return None;
    }
    let label = t.trim_start_matches(['#', ' ', '*']).to_lowercase();
    FIELDS
        .iter()
        .position(|(_, names)| names.iter().any(|n| label.starts_with(n)))
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Ok(mechanism_re) = Regex::new(
        r"\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+\b|`[^`]*(?:\.(?:rs|py|sh|toml|yml|yaml|json)|stenio |--)[^`]*`|\b[\w./-]+\.(?:rs|py|sh|yml|yaml)\b|(?i:\b(?:tests?|hook|gate|teste|preflight|pre-release|release-engine)\b)",
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let in_register = path
            .parent()
            .is_some_and(|d| d.ends_with("governance/incidents"));
        if !in_register || path.file_name().is_some_and(|n| n == "README.md") {
            continue;
        }
        let file = ctx.display(&path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let readme = path.with_file_name("README.md");
        if !fs::read_to_string(&readme).is_ok_and(|r| r.contains(&format!("({name})"))) {
            out.push(finding(
                &RULE.explain,
                Severity::Error,
                file.clone(),
                1,
                name,
                format!("incident '{name}' is not listed in governance/incidents/README.md"),
            ));
        }

        // Entries are `### ` blocks; a file without any is one entry.
        let lines = prose_lines(&content);
        let has_entries = lines.iter().any(|(_, l)| l.starts_with("### "));
        let mut entries: Vec<(usize, &str, Vec<&str>)> = Vec::new();
        if !has_entries {
            entries.push((0, name, Vec::new()));
        }
        let mut open = !has_entries;
        for (idx, line) in &lines {
            if has_entries && line.starts_with("### ") {
                entries.push((*idx, line, Vec::new()));
                open = true;
                continue;
            }
            if has_entries && (line.starts_with("## ") || line.starts_with("# ")) {
                open = false;
            }
            if open && let Some(last) = entries.last_mut() {
                last.2.push(line);
            }
        }

        for (idx, title, body) in entries {
            let mut text: Vec<Option<String>> = vec![None; FIELDS.len()];
            let mut current = None;
            for line in body {
                if let Some(f) = field_of(line) {
                    current = Some(f);
                    let rest = line.split_once(":**").map(|(_, r)| r).unwrap_or("");
                    text[f] = Some(rest.to_string());
                    continue;
                }
                if line.trim_start().starts_with("- **") {
                    current = None;
                }
                if let Some(Some(t)) = current.map(|f: usize| text[f].as_mut()) {
                    t.push(' ');
                    t.push_str(line);
                }
            }
            let missing: Vec<&str> = FIELDS
                .iter()
                .zip(&text)
                .filter(|(_, t)| t.is_none())
                .map(|((label, _), _)| *label)
                .collect();
            if !missing.is_empty() {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    file.clone(),
                    idx + 1,
                    title,
                    format!(
                        "incident entry lacks the section(s): {}",
                        missing.join(", ")
                    ),
                ));
            }
            if let Some(m) = &text[2]
                && !mechanism_re.is_match(m)
            {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    file.clone(),
                    idx + 1,
                    title,
                    "the mechanism names no rule id, test, hook, gate or GB- item".to_string(),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const README: &str = "# Register\n| [one](one.md) |\n";
    const GOOD: &str = "# Day\n## App\n### A1 - broke\n- **Symptom:** FAIL\n- **Root cause (process):** no step\n- **Mechanism:** `FRAPPE-X-Y` in\n  `src/a.rs`\n- **Verification:** run it\n## What changed\ntext\n";
    let r = "governance/incidents/README.md";
    let f = "governance/incidents/one.md";
    let no_mechanism = GOOD.replace("- **Mechanism:** `FRAPPE-X-Y` in\n  `src/a.rs`\n", "");
    let wish = GOOD.replace("`FRAPPE-X-Y` in\n  `src/a.rs`", "be more careful next time");
    vec![
        red_green(
            &RULE,
            "missing-section",
            &[(r, README), (f, GOOD)],
            &[(r, README), (f, &no_mechanism)],
            1,
        ),
        red_green(
            &RULE,
            "descriptive-only",
            &[(r, README), (f, GOOD)],
            &[(r, README), (f, &wish)],
            1,
        ),
        red_green(
            &RULE,
            "unindexed",
            &[(r, README), (f, GOOD)],
            &[(r, "# Register\n"), (f, GOOD)],
            1,
        ),
    ]
}
