//! FRAPPE-PRIVACY-LIST-NAMES-EXIST (GB-210).

use super::*;
use regex::Regex;

/// Frappe's own DocTypes an app list may legitimately name.
pub(super) const CORE_DOCTYPES: &[&str] = &[
    "Access Log",
    "Activity Log",
    "Address",
    "Comment",
    "Communication",
    "Contact",
    "DocType",
    "Email Queue",
    "Error Log",
    "Event",
    "File",
    "Note",
    "Notification Log",
    "Role",
    "ToDo",
    "User",
    "Version",
    "View Log",
    "Workspace",
];

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-PRIVACY-LIST-NAMES-EXIST",
        name: "Privacy Block List Names A Ghost Or Is Narrower Than Another",
        severity: "ERROR",
        tag: "frappe",
        summary: "Module-level DocType collections named `*PERSONAL*`, `*PRIVACY*` or `EXCLUDED` (two or more entries that are app DocTypes) must name only existing DocTypes; and every such list must be covered by the app's block list (`*PERSONAL_NAMES` / `*PERSONAL_SOURCES` outside tests).",
        rationale: "GB-210: PERSONAL_SOURCES missed seven personal DocTypes that another list already blocked, and the handoff asked for `Employee Feedback`, which does not exist. A ghost name in a block list reads as protection and blocks nothing.",
        bad_example: "PERSONAL_SOURCES = frozenset({\"Member Private\", \"Employee Feedback\"})",
        good_example: "PERSONAL_SOURCES = frozenset({\"Member Private\", \"Candidate\"})  # both exist on disk",
        remediation: "Fix or remove the ghost name; add to the block list every DocType another privacy list blocks.",
    },
};

/// `(byte offset, entry)` of the first literal collection in `text`: dict keys, or every string of a
/// list, set or tuple.
pub(super) fn literal_names(text: &str) -> Vec<(usize, String)> {
    let Some(open) = text.find(['{', '[', '(']) else {
        return Vec::new();
    };
    let mut depth = 0usize;
    let mut found: Vec<(usize, String, usize)> = Vec::new();
    let mut chars = text.char_indices().skip_while(|(i, _)| *i < open);
    while let Some((i, ch)) = chars.next() {
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            '#' => {
                for (_, c) in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '"' | '\'' => {
                let mut s = String::new();
                let mut end = i;
                while let Some((j, c)) = chars.next() {
                    if c == '\\' {
                        chars.next();
                    } else if c == ch {
                        end = j;
                        break;
                    } else {
                        s.push(c);
                    }
                }
                found.push((i, s, end));
            }
            _ => {}
        }
    }
    // A set and a dict share the brace: it is a dict when its first string is a key.
    let key = |end: usize| text[end + 1..].trim_start().starts_with(':');
    let dict = found.first().is_some_and(|(_, _, end)| key(*end));
    found
        .into_iter()
        .filter(|(_, _, end)| !dict || key(*end))
        .map(|(i, s, _)| (i, s))
        .collect()
}

struct List {
    path: String,
    line: usize,
    name: String,
    entries: Vec<String>,
    block: bool,
}

fn rule(c: &Ctx) -> Vec<Violation> {
    let Ok(head) = Regex::new(
        r"(?m)^(_?[A-Z_]*(?:PERSONAL|PRIVACY)[A-Z_]*|EXCLUDED)\s*=\s*(?:(?:frozenset|set|tuple|dict)\()?\s*[\{\[\(]",
    ) else {
        return Vec::new();
    };
    let known: Vec<&str> = c.doctypes.iter().map(|d| d.name.as_str()).collect();
    let mut lists = Vec::new();
    for (path, file, text) in python_under(c, &c.pkg) {
        for m in head.captures_iter(&text) {
            let (Some(all), Some(name)) = (m.get(0), m.get(1)) else {
                continue;
            };
            let from = name.end();
            let entries: Vec<String> = literal_names(&text[from..])
                .into_iter()
                .map(|(_, s)| s)
                .collect();
            if entries
                .iter()
                .filter(|e| known.contains(&e.as_str()))
                .count()
                < 2
            {
                continue;
            }
            let n = name.as_str();
            lists.push(List {
                path: path.clone(),
                line: text[..all.start()].matches('\n').count() + 1,
                name: n.to_string(),
                entries,
                block: (n.ends_with("PERSONAL_NAMES") || n.ends_with("PERSONAL_SOURCES"))
                    && !file.starts_with(c.pkg.join("tests")),
            });
        }
    }
    let blocked: Vec<&String> = lists
        .iter()
        .filter(|l| l.block)
        .flat_map(|l| &l.entries)
        .collect();
    let mut out = Vec::new();
    for l in &lists {
        for e in &l.entries {
            if !known.contains(&e.as_str()) && !CORE_DOCTYPES.contains(&e.as_str()) {
                out.push(hit(
                    &ITEM,
                    &l.path,
                    l.line,
                    e,
                    format!(
                        "`{}` names `{e}`, which is not a DocType of the app: it blocks nothing.",
                        l.name
                    ),
                ));
            }
        }
        if l.block || blocked.is_empty() {
            continue;
        }
        let missing: Vec<&str> = l
            .entries
            .iter()
            .filter(|e| known.contains(&e.as_str()) && !blocked.contains(e))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            out.push(hit(
                &ITEM,
                &l.path,
                l.line,
                &l.name,
                format!(
                    "the privacy block list is narrower than `{}`: it does not cover {}.",
                    l.name,
                    missing.join(", ")
                ),
            ));
        }
    }
    out
}

fn self_test() -> bool {
    let a = doctype("Member Private", "");
    let b = doctype("Candidate", "");
    let d = doctype("Ranking", "");
    let run = |block: &str, other: &str| {
        count(
            &ITEM,
            &[
                ("app/m/doctype/member_private/member_private.json", &a),
                ("app/m/doctype/candidate/candidate.json", &b),
                ("app/m/doctype/ranking/ranking.json", &d),
                ("app/core.py", block),
                ("app/tests/read.py", other),
            ],
        )
    };
    let good = "_PERSONAL_NAMES = (\n\t# (note)\n\t\"Member Private\",\n\t\"Candidate\",\n)\nPERSONAL_SOURCES = frozenset(_PERSONAL_NAMES)\n";
    let ghost = "PERSONAL_SOURCES = frozenset({\"Member Private\", \"Candidate\", \"Employee Feedback\"})\n";
    let narrow = "EXCLUDED = {\n\t\"Candidate\": \"data (child of X)\",\n\t\"Ranking\": \"performance\",\n}\n";
    run(good, "x = 1\n") == Some(0)
        && run(ghost, "x = 1\n") == Some(1)
        && run(good, narrow) == Some(1)
        && run(
            good,
            "EXCLUDED = {\"Candidate\": \"a\", \"Member Private\": \"b\"}\n",
        ) == Some(0)
}
