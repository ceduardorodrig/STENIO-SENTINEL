//! FRAPPE-DESK-FIELD-REAL (GB-092).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-DESK-FIELD-REAL",
    name: "Desk Record Key That Frappe Does Not Have",
    severity: "ERROR",
    tag: "frappe",
    summary: "A shipped Dashboard Chart, Dashboard, Number Card, Workspace, Kanban Board or List Filter record (or one of its child rows) carries a key that is not a field of that DocType in Frappe v16. Silent for an app whose Dockerfile pins an older major.",
    rationale: "GB-092 (2026-11-05): nine charts carried `is_custom` for releases. `Document.update` sets the attribute and only real fields reach the table, so a renamed or invented key ships as a no-op. The field lists are vendored from frappe v16.55.1 `frappe/desk/doctype/*/*.json`.",
    bad_example: "{\"doctype\": \"Dashboard Chart\", \"group_by_field\": \"status\"}",
    good_example: "{\"doctype\": \"Dashboard Chart\", \"group_by_based_on\": \"status\"}",
    remediation: "Use the fieldname the DocType declares, or drop the key.",
};

/// Keys every exported document may carry.
const COMMON: &str = "doctype name owner creation modified modified_by docstatus idx parent parenttype parentfield _assign _comments _liked_by _user_tags";

/// `(DocType, fields, child tables as field=ChildDocType)`.
const SCHEMA: &[(&str, &str, &str)] = &[
    (
        "Dashboard Chart",
        "chart_name chart_type source document_type based_on value_based_on timespan time_interval timeseries filters_json type color last_synced_on group_by_based_on group_by_type aggregate_function_based_on number_of_groups from_date to_date x_field report_name y_axis custom_options is_public heatmap_year is_standard module dynamic_filters_json use_report_chart parent_document_type roles currency show_values_over_chart empty_state_message",
        "y_axis=Dashboard Chart Field;roles=Has Role",
    ),
    (
        "Dashboard",
        "dashboard_name is_default charts chart_options cards is_standard module",
        "charts=Dashboard Chart Link;cards=Number Card Link",
    ),
    (
        "Number Card",
        "document_type function aggregate_function_based_on filters_json label color is_public show_percentage_stats stats_time_interval is_standard module dynamic_filters_json type report_name report_field method filters_config report_function parent_document_type currency background_color show_full_number",
        "",
    ),
    (
        "Workspace",
        "label charts shortcuts restrict_to_domain module for_user hide_custom icon links public title parent_page content sequence_id roles quick_lists is_hidden number_cards custom_blocks indicator_color type link_type link_to external_link standard module_onboarding app",
        "charts=Workspace Chart;shortcuts=Workspace Shortcut;links=Workspace Link;roles=Has Role;quick_lists=Workspace Quick List;number_cards=Workspace Number Card;custom_blocks=Workspace Custom Block",
    ),
    (
        "Kanban Board",
        "kanban_board_name reference_doctype field_name columns card_fields preview_fields group_by_fields filters is_standard module private fields show_labels use_kanban_v2 title_field show_assigned_to show_tags_on_card image_field footer_date_field",
        "columns=Kanban Board Column;card_fields=Kanban Board Field;preview_fields=Kanban Board Field;group_by_fields=Kanban Board Group Field",
    ),
    (
        "List Filter",
        "filter_name reference_doctype for_user route_signature filters columns sort_field sort_order is_standard module layout_order",
        "",
    ),
    ("Dashboard Chart Field", "y_field color", ""),
    ("Has Role", "role", ""),
    ("Dashboard Chart Link", "chart width", ""),
    ("Number Card Link", "card", ""),
    (
        "Workspace Shortcut",
        // `is_query_report` is set on the widget by the editor (widget_dialog.js) and read by
        // shortcut_widget.js; exports carry it, so it is not a typo.
        "type link_to doc_view label icon restrict_to_domain stats_filter color format url kanban_board report_ref_doctype is_query_report",
        "",
    ),
    (
        "Workspace Link",
        "type label icon hidden link_type link_to dependencies only_for onboard is_query_report link_count description report_ref_doctype",
        "",
    ),
    ("Workspace Chart", "chart_name label", ""),
    ("Workspace Number Card", "number_card_name label", ""),
    (
        "Workspace Quick List",
        "document_type label quick_list_filter",
        "",
    ),
    ("Workspace Custom Block", "custom_block_name label", ""),
    (
        "Kanban Board Column",
        "column_name status indicator order",
        "",
    ),
    ("Kanban Board Field", "fieldname icon label", ""),
    ("Kanban Board Group Field", "fieldname label", ""),
];

/// Major version of the Frappe/ERPNext base image the app pins, if the Dockerfile says.
fn pinned_major(c: &Ctx) -> Option<u32> {
    let re = Regex::new(r"(?:frappe|erpnext)[\w/.-]*:(?:v|version-)(\d+)").ok()?;
    re.captures(&read(&c.root.join("Dockerfile")))?[1]
        .parse()
        .ok()
}

fn check(r: &Record, doctype: &str, v: &Value, out: &mut impl Extend<Violation>) {
    let Some((_, fields, tables)) = SCHEMA.iter().find(|s| s.0 == doctype) else {
        return;
    };
    let Some(map) = v.as_object() else {
        return;
    };
    for (key, value) in map {
        let known =
            fields.split(' ').chain(COMMON.split(' ')).any(|f| f == key) || key.starts_with("__");
        if !known {
            out.extend(std::iter::once(finding(
                &EXPLAIN,
                &r.path,
                r.line(&format!("\"{key}\"")),
                key,
                format!(
                    "{} `{}` sets `{key}`, which is not a field of {doctype}: the value is dropped on import.",
                    r.doctype,
                    r.name()
                ),
            )));
        }
        let child = tables
            .split(';')
            .filter_map(|t| t.split_once('='))
            .find(|(f, _)| f == key);
        if let Some((_, child)) = child {
            for row in value.as_array().into_iter().flatten() {
                check(r, child, row, out);
            }
        }
    }
}

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    if pinned_major(c).is_some_and(|m| m < 16) {
        return Vec::new();
    }
    let top = [
        "Dashboard Chart",
        "Dashboard",
        "Number Card",
        "Workspace",
        "Kanban Board",
        "List Filter",
    ];
    let mut out = Vec::new();
    for r in records(c, &top) {
        check(&r, &r.doctype, &r.value, &mut out);
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let good = r#"[{"doctype":"Dashboard Chart","name":"A","group_by_based_on":"status","y_axis":[{"y_field":"value"}]}]"#;
    let renamed = r#"[{"doctype":"Dashboard Chart","name":"A","group_by_field":"status"}]"#;
    let child = r#"[{"doctype":"Dashboard Chart","name":"A","y_axis":[{"y_fieldname":"value"}]}]"#;
    let path = "app/desk/dashboard_chart.json";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, good)])
            && fires(
                run,
                &[(path, renamed)],
                1,
                &["group_by_field", "Dashboard Chart"],
            )
            && fires(
                run,
                &[(path, child)],
                1,
                &["y_fieldname", "Dashboard Chart Field"],
            )
            && silent(
                run,
                &[
                    (path, renamed),
                    ("Dockerfile", "ARG BASE_IMAGE=frappe/erpnext:v15.1.0\n"),
                ],
            ),
    )]
}
