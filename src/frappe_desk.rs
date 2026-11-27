//! Desk, UI and i18n rules of scope `frappe`, one file per rule in `src/frappe_desk/`.
//!
//! The module is a child of `frappe` so a rule reads the same parsed context as the core rules.
//! A rule is one `Item`: its `--explain` entry (id, name and severity live there, once), the
//! check, and its mutation proof for `--self-test`.

use super::*;
use crate::explain::RuleExplanation;

#[path = "frappe_desk/calendar_map.rs"]
mod calendar_map;
#[path = "frappe_desk/desk_field_real.rs"]
mod desk_field_real;
#[path = "frappe_desk/fieldname_shadow.rs"]
mod fieldname_shadow;
#[path = "frappe_desk/list_filter_fields.rs"]
mod list_filter_fields;
#[path = "frappe_desk/po_resolves.rs"]
mod po_resolves;
#[path = "frappe_desk/report_chart.rs"]
mod report_chart;
#[path = "frappe_desk/reqd_messages.rs"]
mod reqd_messages;
#[path = "frappe_desk/single_count.rs"]
mod single_count;
#[path = "frappe_desk/support.rs"]
mod support;
#[path = "frappe_desk/table_section.rs"]
mod table_section;

pub(super) struct Item {
    explain: &'static RuleExplanation,
    run: fn(&Ctx) -> Vec<Violation>,
    cases: fn() -> Vec<(String, bool)>,
}

const ITEMS: &[Item] = &[
    Item {
        explain: &po_resolves::EXPLAIN,
        run: po_resolves::run,
        cases: po_resolves::cases,
    },
    Item {
        explain: &reqd_messages::EXPLAIN,
        run: reqd_messages::run,
        cases: reqd_messages::cases,
    },
    Item {
        explain: &fieldname_shadow::EXPLAIN,
        run: fieldname_shadow::run,
        cases: fieldname_shadow::cases,
    },
    Item {
        explain: &table_section::EXPLAIN,
        run: table_section::run,
        cases: table_section::cases,
    },
    Item {
        explain: &desk_field_real::EXPLAIN,
        run: desk_field_real::run,
        cases: desk_field_real::cases,
    },
    Item {
        explain: &list_filter_fields::EXPLAIN,
        run: list_filter_fields::run,
        cases: list_filter_fields::cases,
    },
    Item {
        explain: &report_chart::EXPLAIN,
        run: report_chart::run,
        cases: report_chart::cases,
    },
    Item {
        explain: &single_count::EXPLAIN,
        run: single_count::run,
        cases: single_count::cases,
    },
    Item {
        explain: &calendar_map::EXPLAIN,
        run: calendar_map::run,
        cases: calendar_map::cases,
    },
];

fn severity(e: &RuleExplanation) -> Severity {
    if e.severity == "ERROR" {
        Severity::Error
    } else {
        Severity::Warning
    }
}

/// `(id, name, severity)` of every rule here, appended to the core table for `--list`.
pub(super) fn rule_table() -> impl Iterator<Item = (&'static str, &'static str, Severity)> {
    ITEMS
        .iter()
        .map(|i| (i.explain.id, i.explain.name, severity(i.explain)))
}

pub(crate) fn explanations() -> impl Iterator<Item = &'static RuleExplanation> {
    ITEMS.iter().map(|i| i.explain)
}

pub(super) fn audit(c: &Ctx) -> Vec<Violation> {
    ITEMS.iter().flat_map(|i| (i.run)(c)).collect()
}

pub(super) fn self_test_cases() -> Vec<(String, bool)> {
    ITEMS.iter().flat_map(|i| (i.cases)()).collect()
}
