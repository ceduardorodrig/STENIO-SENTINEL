//! DASHBOARD-REPORT-RESOLVES (GB-103).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "DASHBOARD-REPORT-RESOLVES",
    name: "Report Chart That Resolves To Nothing",
    severity: "ERROR",
    tag: "frappe",
    summary: "A Dashboard Chart with `chart_type: Report` names a report the app does not ship, or (with `use_report_chart` off) an `x_field` / `y_axis[].y_field` that the report declares no column for. Columns are read from the report JSON and from `fieldname` literals of its .py/.js; a report with none readable is not judged on columns.",
    rationale: "GB-103: a typo in x_field or a renamed report blanks the panel with no error at migrate; only a hand-written test of one app looked.",
    bad_example: "{\"chart_type\": \"Report\", \"report_name\": \"Deal Funel\", \"x_field\": \"stage\"}",
    good_example: "{\"chart_type\": \"Report\", \"report_name\": \"Deal Funnel\", \"x_field\": \"stage\"}",
    remediation: "Name a report the app ships and columns that report returns.",
};

/// The fieldnames the report `r` can return.
fn columns(c: &Ctx, r: &Record) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for col in r
        .value
        .get("columns")
        .and_then(|x| x.as_array())
        .into_iter()
        .flatten()
    {
        out.extend(Some(str_of(col, "fieldname")).filter(|s| !s.is_empty()));
    }
    let Ok(re) = Regex::new(r#"["']?\bfieldname["']?\s*[:=]\s*["']([A-Za-z_]\w*)["']"#) else {
        return out;
    };
    let json = c.root.join(&r.path);
    for ext in ["py", "js"] {
        let text = read(&json.with_extension(ext));
        out.extend(re.captures_iter(&text).map(|m| m[1].to_string()));
    }
    out
}

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let reports = records(c, &["Report"]);
    let mut out = Vec::new();
    for chart in records(c, &["Dashboard Chart"]) {
        if str_of(&chart.value, "chart_type") != "Report" {
            continue;
        }
        let wanted = str_of(&chart.value, "report_name");
        let mut report = |needle: &str, msg: String| {
            out.push(finding(
                &EXPLAIN,
                &chart.path,
                chart.line(needle),
                needle,
                format!("Dashboard Chart `{}` {msg}", chart.name()),
            ));
        };
        let Some(r) = reports.iter().find(|r| r.name() == wanted) else {
            report(
                "\"report_name\"",
                format!("names report `{wanted}`, which the app does not ship."),
            );
            continue;
        };
        if flag(&chart.value, "use_report_chart") {
            continue;
        }
        let cols = columns(c, r);
        if cols.is_empty() {
            continue;
        }
        let x = Some(("x_field", str_of(&chart.value, "x_field")));
        let ys = chart
            .value
            .get("y_axis")
            .and_then(|y| y.as_array())
            .into_iter()
            .flatten()
            .map(|y| ("y_field", str_of(y, "y_field")));
        for (key, field) in x.into_iter().chain(ys) {
            if !field.is_empty() && !cols.contains(&field) {
                report(
                    &format!("\"{field}\""),
                    format!(
                        "sets {key} `{field}`, which report `{wanted}` declares no column for."
                    ),
                );
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let rep = (
        "app/m/report/funnel/funnel.json",
        r#"{"doctype":"Report","name":"Funnel","columns":[]}"#,
    );
    let py = (
        "app/m/report/funnel/funnel.py",
        "def execute(filters=None):\n\treturn [{\"fieldname\": \"stage\"}, {\"fieldname\": \"value\"}], []\n",
    );
    let chart = |name: &str, x: &str, y: &str| {
        format!(
            "[{{\"doctype\":\"Dashboard Chart\",\"name\":\"C\",\"chart_type\":\"Report\",\"report_name\":\"{name}\",\"x_field\":\"{x}\",\"y_axis\":[{{\"y_field\":\"{y}\"}}]}}]"
        )
    };
    let path = "app/desk/dashboard_chart.json";
    let good = chart("Funnel", "stage", "value");
    let missing = chart("Funel", "stage", "value");
    let bad_x = chart("Funnel", "stagee", "value");
    let bad_y = chart("Funnel", "stage", "total");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[rep, py, (path, &good)])
            && fires(
                run,
                &[rep, py, (path, &missing)],
                1,
                &["Funel", "does not ship"],
            )
            && fires(run, &[rep, py, (path, &bad_x)], 1, &["x_field", "stagee"])
            && fires(run, &[rep, py, (path, &bad_y)], 1, &["y_field", "total"]),
    )]
}
