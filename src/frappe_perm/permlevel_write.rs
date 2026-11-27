//! `FRAPPE-PERMLEVEL-WRITE-PARITY` (GB-186): an editable field above level 0 that no role can
//! write is silently reset on save.

use super::{Case, Rule, Tree, data_field, doctype_file, flag, int_of, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: Rule = Rule {
    id: "FRAPPE-PERMLEVEL-WRITE-PARITY",
    name: "Field Level Nobody Can Write",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PERMLEVEL-WRITE-PARITY",
        name: "Field Level Nobody Can Write",
        severity: "ERROR",
        tag: "frappe",
        summary: "A non-read-only field at permlevel n>0 of a non-child DocType that is writable at level 0, while no permission row of level n has write=1.",
        rationale: "GB-186 (2026-11-06): with Member.email at permlevel 1 and read-only level-1 rows, Frappe's validate_higher_perm_levels resets the field to the stored value on save, so a correction is silently discarded.",
        bad_example: "{\"role\": \"System Manager\", \"permlevel\": 1, \"read\": 1}  // email can never be corrected",
        good_example: "{\"role\": \"System Manager\", \"permlevel\": 1, \"read\": 1, \"write\": 1}",
        remediation: "Give one approved role write=1 at that level, or mark the field read_only if only the server fills it.",
    },
};

fn run(t: &Tree) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in t.docs.iter().filter(|d| !d.is_child()) {
        let writes = |level: i64| {
            d.perms()
                .iter()
                .any(|p| int_of(p, "permlevel") == level && flag(p, "write"))
        };
        if !writes(0) {
            continue; // nobody edits this DocType at all
        }
        for f in d.fields().iter().filter(|f| data_field(f)) {
            let level = int_of(f, "permlevel");
            if level == 0 || flag(f, "read_only") || flag(f, "is_virtual") || writes(level) {
                continue;
            }
            let name = str_of(f, "fieldname");
            out.push(viol(
                &RULE,
                &d.rel,
                d.field_line(name),
                &format!("{name} permlevel {level}"),
                format!("`{}.{name}` is at permlevel {level} and no role has write=1 there: the field is silently read-only, a save restores the stored value.", d.name),
                "Add write=1 to an approved level row, or mark the field read_only.",
            ));
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, ro: u8, level_row: &str, expect| Case {
        label,
        files: vec![doctype_file(
            "Member",
            "",
            &format!(
                r#"{{"fieldname":"email","fieldtype":"Data","permlevel":1,"read_only":{ro}}}"#
            ),
            &format!(r#"{{"role":"A","read":1,"write":1}},{level_row}"#),
        )],
        validated: &[],
        expect,
    };
    let reader = r#"{"role":"A","permlevel":1,"read":1}"#;
    vec![
        case(
            "a writable level row is accepted",
            0,
            r#"{"role":"A","permlevel":1,"read":1,"write":1}"#,
            0,
        ),
        case("a read_only field is accepted", 1, reader, 0),
        case("a level with read-only rows fires", 0, reader, 1),
    ]
}
