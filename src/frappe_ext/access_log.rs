//! FRAPPE-ACCESS-LOG-SYNC-ASSERT (GB-065).

use super::*;
use regex::Regex;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-ACCESS-LOG-SYNC-ASSERT",
        name: "Deferred Log Read Without Test Mode",
        severity: "ERROR",
        tag: "frappe",
        summary: "A test function reads `Access Log` (count, exists, get_all, get_list, get_value) and neither sets `frappe.in_test = True` (or calls `toggle_test_mode(True)`) nor flushes the deferred queue. Applies to Frappe 16 or later (Dockerfile `BASE_IMAGE`; every version when unpinned).",
        rationale: "GB-065: Frappe 16 `make_access_log` calls `Document.deferred_insert()` when `frappe.in_test` is false, so the row sits in Redis and the count right after the call is 0; rehearsal rc90 read that as an unlogged read. Source: https://github.com/frappe/frappe/blob/version-16/frappe/core/doctype/access_log/access_log.py (read 2026-11-26).",
        bad_example: "reviewer_identity(review)\nassert frappe.db.count(\"Access Log\", {\"reference_document\": review}) == 1",
        good_example: "was = frappe.in_test\nfrappe.in_test = True\ntry:\n\treviewer_identity(review)\nfinally:\n\tfrappe.in_test = was\nassert frappe.db.count(\"Access Log\", {\"reference_document\": review}) == 1",
        remediation: "Set `frappe.in_test = True` around the call that logs (restore it in `finally`), or flush the deferred inserts before reading.",
    },
};

fn rule(c: &Ctx) -> Vec<Violation> {
    if frappe_major(c).is_some_and(|m| m < 16) {
        return Vec::new();
    }
    let (Ok(read_re), Ok(sync_re)) = (
        Regex::new(
            r#"frappe\.(?:db\.)?(?:count|exists|get_all|get_list|get_value)\(\s*["']Access Log["']"#,
        ),
        Regex::new(
            r"in_test\b[^=\n]*=[^=\n].*\bTrue\b|toggle_test_mode\(\s*True|flush_deferred|deferred_insert\.save_to_db",
        ),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, _, text) in test_modules(c) {
        let lines: Vec<&str> = text.lines().collect();
        let mut reported = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with('#') || !read_re.is_match(line) {
                continue;
            }
            let (s, e) = scope_of(&lines, i);
            let synced = lines[s..e]
                .iter()
                .any(|l| !l.trim_start().starts_with('#') && sync_re.is_match(l));
            if !synced && !reported.contains(&s) {
                reported.push(s);
                out.push(hit(
                    &ITEM,
                    &path,
                    i + 1,
                    line,
                    "this reads `Access Log` in a function that never turns test mode on: outside test mode Frappe 16 queues the row and the read sees nothing.".into(),
                ));
            }
        }
    }
    out
}

fn self_test() -> bool {
    const BAD: &str = "def run():\n\tread()\n\tassert frappe.db.count(\"Access Log\", {}) == 1\n";
    const GOOD: &str = "def run():\n\tbefore = frappe.db.count(\"Access Log\", {})\n\tfrappe.in_test = frappe.flags.in_test = True\n\ttry:\n\t\tread()\n\tfinally:\n\t\tfrappe.in_test = False\n\tassert frappe.db.count(\"Access Log\", {}) == before + 1\n";
    // test mode switched in another function does not cover this one
    const ELSEWHERE: &str = "def other():\n\tfrappe.in_test = True\n\n\ndef run():\n\tassert frappe.db.count(\"Access Log\", {}) == 1\n";
    const DELETE: &str = "def run():\n\tfrappe.db.delete(\"Access Log\", {})\n";
    let run = |b: &str| count(&ITEM, &[("app/tests/w2.py", b)]);
    run(BAD) == Some(1)
        && run(ELSEWHERE) == Some(1)
        && run(GOOD) == Some(0)
        && run(DELETE) == Some(0)
}
