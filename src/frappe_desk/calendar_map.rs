//! FRAPPE-CALENDAR-FIELD-MAP (GB-091).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-CALENDAR-FIELD-MAP",
    name: "Calendar Field Map That Names Nothing",
    severity: "ERROR",
    tag: "frappe",
    summary: "In a `*_calendar.js` of the app, `frappe.views.calendar[\"<DocType>\"].field_map` uses a key Frappe does not read and that is no field, misses `start` or `end`, maps a key to a field the DocType does not have, or maps `start`/`end` to a field that is not Date/Datetime. With `get_events_method` the values are the method's business and are not resolved.",
    rationale: "GB-091: the keys are free text. Frappe reads id, start, end, title, allDay, progress, color, is_milestone, depends_on, convertToUserTz (v16.55.1 calendar.js, gantt_view.js); a missing end silently collapses the bar to one day and a typo only opens a msgprint for the user.",
    bad_example: "field_map: { start_at: \"start_date\", end: \"end_date\" }",
    good_example: "field_map: { start: \"start_date\", end: \"end_date\", id: \"name\", title: \"subject\" }",
    remediation: "Use Frappe's keys and fieldnames of the DocType; start and end must be Date or Datetime.",
};

const KEYS: &[&str] = &[
    "id",
    "start",
    "end",
    "title",
    "allDay",
    "progress",
    "color",
    "is_milestone",
    "depends_on",
    "convertToUserTz",
    "status",
    "description",
    "doctype",
];

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let (Ok(head), Ok(map), Ok(entry)) = (
        Regex::new(r#"frappe\.views\.calendar(?:\[\s*["']([^"']+)["']\s*\]|\.(\w+))\s*=\s*\{"#),
        Regex::new(r"\bfield_map\s*:\s*\{"),
        Regex::new(r#"^\s*["']?(\w+)["']?\s*:\s*(?:["']([^"']*)["']\s*$)?"#),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in sources(c, &["js"]) {
        if !p.to_string_lossy().ends_with("_calendar.js") {
            continue;
        }
        let text = blank_js_comments(&read(p));
        for m in head.captures_iter(&text) {
            let dt = m
                .get(1)
                .or_else(|| m.get(2))
                .map(|x| x.as_str())
                .unwrap_or("");
            let Some(d) = app_doctype(c, dt) else {
                continue;
            };
            let Some(open) = m.get(0).map(|x| x.end() - 1) else {
                continue;
            };
            let Some((_, end)) = balanced_at(&text, open, b'{', b'}') else {
                continue;
            };
            let block = &text[open..end];
            let Some(fm) = map.find(block) else { continue };
            let at = open + fm.end() - 1;
            let Some((_, map_end)) = balanced_at(&text, at, b'{', b'}') else {
                continue;
            };
            let remote = block.contains("get_events_method");
            let mut seen = BTreeSet::new();
            let mut report = |needle: &str, msg: String| {
                let off = text[at..map_end].find(needle).unwrap_or(0);
                out.push(finding(
                    &EXPLAIN,
                    &rel(&c.root, p),
                    line_at(&text, at + off),
                    needle,
                    format!("Calendar of DocType `{dt}`: {msg}"),
                ));
            };
            for part in split_top(&text[at + 1..map_end.saturating_sub(1)]) {
                let Some(e) = entry.captures(part) else {
                    continue;
                };
                let key = e[1].to_string();
                seen.insert(key.clone());
                if !KEYS.contains(&key.as_str()) && !has_column(d, &key) {
                    report(
                        &key,
                        format!("field_map key `{key}` is neither a calendar key nor a field."),
                    );
                    continue;
                }
                let Some(value) = e.get(2).map(|v| v.as_str()) else {
                    continue; // a function or a boolean
                };
                if remote || key == "convertToUserTz" || value.is_empty() {
                    continue;
                }
                let field = d.fields.iter().find(|f| f.fieldname == value);
                if !has_column(d, value) {
                    report(
                        &key,
                        format!("field_map key `{key}` names `{value}`, which is not a field."),
                    );
                } else if matches!(key.as_str(), "start" | "end")
                    && field.is_some_and(|f| !matches!(f.fieldtype.as_str(), "Date" | "Datetime"))
                {
                    report(
                        &key,
                        format!(
                            "field_map key `{key}` names `{value}`, which is not a Date/Datetime."
                        ),
                    );
                }
            }
            for key in ["start", "end"] {
                if !seen.contains(key) {
                    report("", format!("field_map has no `{key}` key."));
                }
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let dt = (
        "app/m/doctype/sprint/sprint.json",
        r#"{"doctype":"DocType","name":"Sprint","fields":[{"fieldname":"start_date","fieldtype":"Date"},{"fieldname":"end_date","fieldtype":"Date"},{"fieldname":"goal","fieldtype":"Data"}]}"#,
    );
    let js = |map: &str| {
        format!("frappe.views.calendar[\"Sprint\"] = {{\n\tfield_map: {{ {map} }},\n}};\n")
    };
    let good =
        js("start: \"start_date\", end: \"end_date\", id: \"name\", progress: (d) => f(d, 1)");
    let typo = js("start_at: \"start_date\", end: \"end_date\"");
    let ghost = js("start: \"start_date\", end: \"ends_on\"");
    let kind = js("start: \"goal\", end: \"end_date\"");
    let path = "app/public/js/sprint_calendar.js";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[dt, (path, &good)])
            && fires(run, &[dt, (path, &typo)], 2, &["start_at", "Sprint"])
            && fires(run, &[dt, (path, &ghost)], 1, &["ends_on", "not a field"])
            && fires(run, &[dt, (path, &kind)], 1, &["goal", "Date/Datetime"]),
    )]
}
