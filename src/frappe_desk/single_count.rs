//! FRAPPE-SINGLE-NO-COUNT (GB-107).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-SINGLE-NO-COUNT",
    name: "Row Count Asked Of A Single DocType",
    severity: "ERROR",
    tag: "frappe",
    summary: "A Single DocType of the app is asked for rows: a Number Card or a Group By / Count chart over it, a Workspace shortcut declaring `stats_filter` or `format` for it, or a literal `db.count(\"X\")` / `get_count(\"X\")` in the app code.",
    rationale: "GB-107 (2026-11-05): a Single has no table of its own, so `frappe.client.get_count` on one raises ProgrammingError, an HTTP 500. The shortcut widget skips the count for `boot.single_types` (frappe v16.55.1 shortcut_widget.js), so a count badge declared there is dead configuration, and cards, charts and code have no such guard.",
    bad_example: "{\"type\": \"DocType\", \"link_to\": \"Handbook\", \"format\": \"{} Open\"}",
    good_example: "{\"type\": \"DocType\", \"link_to\": \"Handbook\"}",
    remediation: "Drop the count (badge, card, chart or call), or read the Single with get_single_value.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let singles: BTreeSet<&str> = c
        .doctypes
        .iter()
        .filter(|d| d.is_single)
        .map(|d| d.name.as_str())
        .collect();
    let mut out = Vec::new();
    if singles.is_empty() {
        return out;
    }
    for r in records(c, &["Number Card", "Dashboard Chart", "Workspace"]) {
        let mut targets: Vec<(&str, String)> = Vec::new();
        if r.doctype == "Workspace" {
            for s in r
                .value
                .get("shortcuts")
                .and_then(|s| s.as_array())
                .into_iter()
                .flatten()
            {
                let counts =
                    !str_of(s, "stats_filter").is_empty() || !str_of(s, "format").is_empty();
                if str_of(s, "type") == "DocType" && counts {
                    targets.push(("shortcut with a count badge", str_of(s, "link_to")));
                }
            }
        } else if str_of(&r.value, "chart_type") != "Report" && str_of(&r.value, "type") != "Report"
        {
            targets.push(("record counting rows", str_of(&r.value, "document_type")));
        }
        for (what, dt) in targets {
            if singles.contains(dt.as_str()) {
                out.push(finding(
                    &EXPLAIN,
                    &r.path,
                    r.line(&format!("\"{dt}\"")),
                    &dt,
                    format!(
                        "{} `{}` has a {what} over the Single `{dt}`.",
                        r.doctype,
                        r.name()
                    ),
                ));
            }
        }
    }
    let Ok(call) = Regex::new(
        r#"(?:db\.count|db\.estimate_count|get_count)\(\s*(?:\{\s*doctype\s*:\s*)?["']([^"'\n]+)["']"#,
    ) else {
        return out;
    };
    for p in sources(c, &["py", "js", "html"]) {
        let text = read(p);
        for m in call.captures_iter(&text) {
            let dt = &m[1];
            if singles.contains(dt) {
                out.push(finding(
                    &EXPLAIN,
                    &rel(&c.root, p),
                    line_at(&text, m.get(0).map(|x| x.start()).unwrap_or(0)),
                    dt,
                    format!("Code counts rows of the Single `{dt}`, which has no table: HTTP 500."),
                ));
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let single = (
        "app/m/doctype/book/book.json",
        r#"{"doctype":"DocType","name":"Book","issingle":1,"fields":[]}"#,
    );
    let ws = |extra: &str| {
        format!(
            "[{{\"doctype\":\"Workspace\",\"name\":\"W\",\"shortcuts\":[{{\"type\":\"DocType\",\"link_to\":\"Book\"{extra}}}]}}]"
        )
    };
    let (plain, badge) = (ws(""), ws(",\"format\":\"{} Open\""));
    let card = r#"[{"doctype":"Number Card","name":"N","document_type":"Book"}]"#;
    let wpath = "app/desk/workspace.json";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[single, (wpath, &plain)])
            && fires(run, &[single, (wpath, &badge)], 1, &["count badge", "Book"])
            && fires(
                run,
                &[single, ("app/desk/number_card.json", card)],
                1,
                &["Number Card", "Book"],
            )
            && fires(
                run,
                &[
                    single,
                    (
                        "app/api.py",
                        "def n():\n\treturn frappe.db.count(\"Book\")\n",
                    ),
                ],
                1,
                &["Book", "HTTP 500"],
            )
            && silent(
                run,
                &[
                    single,
                    (
                        "app/api.py",
                        "def n():\n\treturn frappe.db.count(\"Task\")\n",
                    ),
                ],
            ),
    )]
}
