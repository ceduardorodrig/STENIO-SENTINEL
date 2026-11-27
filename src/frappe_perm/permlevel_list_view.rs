//! `FRAPPE-PERMLEVEL-IN-LIST-VIEW` (GB-203): a restricted field published as a list column or
//! standard filter.

use super::{Case, Rule, Tree, doctype_file, flag, int_of, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: Rule = Rule {
    id: "FRAPPE-PERMLEVEL-IN-LIST-VIEW",
    name: "Restricted Field In List View Or Standard Filter",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PERMLEVEL-IN-LIST-VIEW",
        name: "Restricted Field In List View Or Standard Filter",
        severity: "ERROR",
        tag: "frappe",
        summary: "A field with permlevel > 0 declares in_list_view=1 or in_standard_filter=1.",
        rationale: "GB-203: Member.email kept in_list_view=1 while raised to permlevel 1. The desk keeps a column whose value get_permitted_fields drops for every role without that level.",
        bad_example: "{\"fieldname\": \"email\", \"permlevel\": 1, \"in_list_view\": 1}",
        good_example: "{\"fieldname\": \"email\", \"permlevel\": 1, \"in_list_view\": 0}",
        remediation: "Set both flags to 0 (and remove a Property Setter that restores them).",
    },
};

fn run(t: &Tree) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in &t.docs {
        for f in d.fields() {
            if int_of(f, "permlevel") == 0 {
                continue;
            }
            for flag_name in ["in_list_view", "in_standard_filter"] {
                if flag(f, flag_name) {
                    let name = str_of(f, "fieldname");
                    out.push(viol(
                        &RULE,
                        &d.rel,
                        d.field_line(name),
                        &format!("{name} {flag_name}"),
                        format!("`{}.{name}` has permlevel {} and {flag_name}=1: roles without that level get an empty column or filter.", d.name, int_of(f, "permlevel")),
                        "Set the flag to 0.",
                    ));
                }
            }
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, field: &str, expect| Case {
        label,
        files: vec![doctype_file("Member", "", field, "")],
        validated: &[],
        expect,
    };
    vec![
        case(
            "a hidden restricted field and a public column are accepted",
            r#"{"fieldname":"email","permlevel":1,"in_list_view":0},{"fieldname":"name1","in_list_view":1}"#,
            0,
        ),
        case(
            "a restricted list column fires",
            r#"{"fieldname":"email","permlevel":1,"in_list_view":1}"#,
            1,
        ),
        case(
            "a restricted standard filter fires",
            r#"{"fieldname":"email","permlevel":1,"in_standard_filter":1}"#,
            1,
        ),
    ]
}
