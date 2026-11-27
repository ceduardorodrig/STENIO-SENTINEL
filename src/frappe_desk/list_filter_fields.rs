//! FRAPPE-DESK-LAYOUT-FIELDS (GB-102).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-DESK-LAYOUT-FIELDS",
    name: "List Layout Naming A Field That Does Not Exist",
    severity: "ERROR",
    tag: "frappe",
    summary: "A shipped List Filter must declare `reference_doctype` and `for_user` (empty = global), and every `filters` row and `columns[].fieldname` must be a column of that DocType. A DocType the app does not ship is not resolved.",
    rationale: "GB-102 (rc101): `ListFilter.before_save` silently drops rows naming a field that is not in the reference DocType (frappe/desk/doctype/list_filter/list_filter.py), so a typo ships a layout with fewer columns and no error.",
    bad_example: "{\"reference_doctype\": \"Task\", \"for_user\": \"\", \"columns\": \"[{\\\"fieldname\\\": \\\"titel\\\"}]\"}",
    good_example: "{\"reference_doctype\": \"Task\", \"for_user\": \"\", \"columns\": \"[{\\\"fieldname\\\": \\\"title\\\"}]\"}",
    remediation: "Fix the fieldname, or declare reference_doctype / for_user.",
};

/// A value Frappe stores as a JSON string and an export may also inline.
fn decoded(v: &Value, key: &str) -> Vec<Value> {
    match v.get(key) {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or_default(),
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for r in records(c, &["List Filter"]) {
        let mut report = |needle: &str, msg: String| {
            out.push(finding(
                &EXPLAIN,
                &r.path,
                r.line(needle),
                needle,
                format!("List Filter `{}` {msg}", r.name()),
            ));
        };
        let target = str_of(&r.value, "reference_doctype");
        if target.is_empty() {
            report("\"doctype\"", "declares no `reference_doctype`.".into());
        }
        if r.value.get("for_user").is_none() {
            report(
                "\"doctype\"",
                "declares no `for_user` (an empty string means global).".into(),
            );
        }
        let Some(d) = app_doctype(c, &target) else {
            continue;
        };
        // A filter row is [doctype, field, operator, value] or [field, operator, value].
        for row in decoded(&r.value, "filters") {
            let Some(a) = row.as_array() else { continue };
            let (dt, field) = if a.len() >= 4 {
                (a[0].as_str().unwrap_or(""), a[1].as_str().unwrap_or(""))
            } else {
                ("", a.first().and_then(|x| x.as_str()).unwrap_or(""))
            };
            if (dt.is_empty() || dt == target) && !has_column(d, field) {
                report(
                    "\"filters\"",
                    format!("filters on `{field}`, which is not a field of {target}."),
                );
            }
        }
        for col in decoded(&r.value, "columns") {
            let field = str_of(&col, "fieldname");
            if !field.is_empty() && !has_column(d, &field) {
                report(
                    "\"columns\"",
                    format!("shows column `{field}`, which is not a field of {target}."),
                );
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let dt = (
        "app/m/doctype/task/task.json",
        r#"{"doctype":"DocType","name":"Task","fields":[{"fieldname":"title","fieldtype":"Data"}]}"#,
    );
    let lf = |body: &str| format!("[{{\"doctype\":\"List Filter\",\"name\":\"T\"{body}}}]");
    let head = ",\"reference_doctype\":\"Task\",\"for_user\":\"\"";
    let good = lf(&format!(
        "{head},\"filters\":\"[[\\\"Task\\\",\\\"title\\\",\\\"=\\\",1]]\",\"columns\":\"[{{\\\"fieldname\\\":\\\"title\\\"}},{{\\\"fieldname\\\":\\\"name\\\"}}]\""
    ));
    let filter = lf(&format!(
        "{head},\"filters\":\"[[\\\"Task\\\",\\\"squadd\\\",\\\"=\\\",1]]\""
    ));
    let column = lf(&format!(
        "{head},\"columns\":\"[{{\\\"fieldname\\\":\\\"titel\\\"}}]\""
    ));
    let bare = lf(",\"for_user\":\"\"");
    let path = "app/desk/list_filter.json";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[dt, (path, &good)])
            && fires(run, &[dt, (path, &filter)], 1, &["squadd", "Task"])
            && fires(run, &[dt, (path, &column)], 1, &["titel", "Task"])
            && fires(run, &[dt, (path, &bare)], 1, &["reference_doctype"]),
    )]
}
