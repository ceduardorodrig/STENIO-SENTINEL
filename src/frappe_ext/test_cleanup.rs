//! FRAPPE-TEST-CLEANUP-DEFERRED (GB-043).

use super::*;
use regex::Regex;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-TEST-CLEANUP-DEFERRED",
        name: "Deterministic Name Inserted With Deferred Cleanup",
        severity: "ERROR",
        tag: "frappe",
        summary: "A test inserts a DocType whose name is deterministic (`autoname` `field:` or `format:` without a series) with no protection at the insert: no enclosing `try`/`finally` that deletes, no earlier `exists`/delete of that DocType in the same function, and no run-unique identity in the module (`fixture.mail(`, `fixture.TAG`, `generate_hash`, `uuid`). Inserts expected to be refused (`_fails(`, `assertRaises`) are ignored.",
        rationale: "GB-043: tags rc80 and rc81 died on the same line. The w3 test inserted Member Compensation (`MCOMP-member-date`) and cleaned up only at the end of the run; the aborted run left the row and the next one hit DuplicateEntryError before reaching the case under test.",
        bad_example: "def _salary():\n\tfrappe.get_doc({\"doctype\": \"Member Compensation\", \"member\": \"a\"}).insert()\n# deleted by run() at the end",
        good_example: "try:\n\tfrappe.get_doc({\"doctype\": \"Member Compensation\", \"member\": \"a\"}).insert()\nfinally:\n\tfrappe.delete_doc(\"Member Compensation\", name, force=True)",
        remediation: "Guard the insert (delete or `frappe.db.exists` first), wrap it in `try`/`finally` that deletes the row, or derive the key from a run-unique tag.",
    },
};

/// DocTypes whose record name is a function of the inserted values.
fn deterministic(c: &Ctx) -> Vec<String> {
    c.doctypes
        .iter()
        .filter(|d| {
            let auto = serde_json::from_str::<serde_json::Value>(&d.text)
                .ok()
                .and_then(|v| {
                    v.get("autoname")
                        .and_then(|a| a.as_str())
                        .map(str::to_string)
                })
                .unwrap_or_default();
            auto.starts_with("field:") || (auto.starts_with("format:") && !auto.contains('#'))
        })
        .map(|d| d.name.clone())
        .collect()
}

fn deletes(line: &str) -> bool {
    ["delete_doc", "db.delete(", "cleanup", "purge"]
        .iter()
        .any(|w| line.contains(w))
}

/// True when line `at` sits in the body of a `try` whose `finally` block deletes.
fn finally_covers(lines: &[&str], at: usize) -> bool {
    let mut level = indent(lines[at]);
    for t in (0..at).rev() {
        let line = lines[t];
        if line.trim().is_empty() || indent(line) >= level {
            continue;
        }
        level = indent(line);
        if line.trim() != "try:" {
            continue;
        }
        let closing = (at + 1..lines.len()).find(|&j| {
            let s = lines[j].trim();
            !s.is_empty()
                && indent(lines[j]) <= level
                && !s.starts_with("except")
                && !s.starts_with("else")
                && !s.starts_with(')')
        });
        let Some(f) = closing.filter(|&j| lines[j].trim() == "finally:") else {
            continue;
        };
        if lines[f + 1..]
            .iter()
            .take_while(|l| l.trim().is_empty() || indent(l) > level)
            .any(|l| deletes(l))
        {
            return true;
        }
    }
    false
}

fn rule(c: &Ctx) -> Vec<Violation> {
    let names = deterministic(c);
    let Ok(insert) = Regex::new(r#"(?:["']doctype["']\s*:\s*|new_doc\(\s*)["']([^"']+)["']"#)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, _, text) in test_modules(c) {
        if ["fixture.mail(", "fixture.TAG", "generate_hash", "uuid"]
            .iter()
            .any(|u| text.contains(u))
        {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with('#')
                || line.contains("_fails(")
                || line.contains("assertRaises")
            {
                continue;
            }
            for m in insert.captures_iter(line) {
                let name = &m[1];
                if !names.iter().any(|n| n == name)
                    || !lines.iter().skip(i).take(8).any(|l| l.contains(".insert("))
                {
                    continue;
                }
                let (s, _) = scope_of(&lines, i);
                let guarded = lines[s..i].iter().any(|l| {
                    l.contains(name)
                        && ["db.exists(", "delete_doc(", "db.delete("]
                            .iter()
                            .any(|w| l.contains(w))
                });
                if !guarded && !finally_covers(&lines, i) {
                    out.push(hit(
                        &ITEM,
                        &path,
                        i + 1,
                        line,
                        format!("`{name}` has a deterministic name and nothing protects this insert: an aborted run leaves the row and the next run fails with DuplicateEntryError."),
                    ));
                }
            }
        }
    }
    out
}

fn self_test() -> bool {
    let json = doctype("Pay", ",\"autoname\":\"format:PAY-{member}-{date}\"");
    let series = doctype("Pay", ",\"autoname\":\"format:PAY-{member}-{###}\"");
    let run = |dt: &str, body: &str| {
        count(
            &ITEM,
            &[
                ("app/m/doctype/pay/pay.json", dt),
                ("app/tests/w3.py", body),
            ],
        )
    };
    const BAD: &str = "def pay():\n\tfrappe.get_doc({\"doctype\": \"Pay\", \"member\": \"a\"}).insert()\n\n\ndef run():\n\ttry:\n\t\tpay()\n\tfinally:\n\t\t_cleanup()\n";
    const TRIED: &str = "def pay():\n\ttry:\n\t\tfrappe.get_doc({\"doctype\": \"Pay\", \"member\": \"a\"}).insert()\n\tfinally:\n\t\tfrappe.delete_doc(\"Pay\", \"x\")\n";
    const GUARDED: &str = "def pay():\n\tif frappe.db.exists(\"Pay\", \"x\"):\n\t\treturn\n\tfrappe.get_doc({\"doctype\": \"Pay\", \"member\": \"a\"}).insert()\n";
    const UNIQUE: &str = "def pay():\n\tfrappe.get_doc({\"doctype\": \"Pay\", \"member\": fixture.mail(\"a\")}).insert()\n";
    run(&json, BAD) == Some(1)
        && run(&json, TRIED) == Some(0)
        && run(&json, GUARDED) == Some(0)
        && run(&json, UNIQUE) == Some(0)
        && run(&series, BAD) == Some(0)
}
