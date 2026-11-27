//! `FRAPPE-DOCPERM-ROW` (GB-059): the row checks of Frappe's `validate_permissions`
//! (frappe/core/doctype/doctype/doctype.py, version-16), decided from the JSON alone.

use super::{Case, Rule, Tree, doctype_file, flag, int_of, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: Rule = Rule {
    id: "FRAPPE-DOCPERM-ROW",
    name: "Permission Row Frappe Would Refuse",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-DOCPERM-ROW",
        name: "Permission Row Frappe Would Refuse",
        severity: "ERROR",
        tag: "frappe",
        summary: "A DocType permission row that Frappe's validate_permissions rejects: two rows with the same role, permlevel and if_owner; a row with none of select/read/write/submit/cancel/create; a permlevel above 0 for a role with no level-0 row (All and Desk User excepted); cancel without submit; submit, cancel or amend without write; import without create; submit/amend on a DocType that is not submittable; import on one that does not allow it.",
        rationale: "GB-059 (rc85): the checks run only when someone saves the DocType in a developer site, so a hand-edited JSON ships and fails later, or silently keeps two contradicting rows. Source: frappe/core/doctype/doctype/doctype.py validate_permissions, branch version-16. Translation coverage of the same item is FRAPPE-I18N-SOURCE-LITERALS.",
        bad_example: "\"permissions\": [{\"role\": \"A\", \"read\": 1}, {\"role\": \"A\", \"read\": 1, \"write\": 1}]",
        good_example: "\"permissions\": [{\"role\": \"A\", \"read\": 1, \"write\": 1}]",
        remediation: "Merge the duplicate rows, or give the row the basic permission and the level-0 row it depends on.",
    },
};

fn run(t: &Tree) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in &t.docs {
        let perms = d.perms();
        let key = |p: &serde_json::Value| {
            (
                str_of(p, "role").to_string(),
                int_of(p, "permlevel"),
                flag(p, "if_owner"),
            )
        };
        for (i, p) in perms.iter().enumerate() {
            let (role, level, if_owner) = key(p);
            let on = |f: &str| flag(p, f);
            let mut why: Vec<&str> = Vec::new();
            if perms.iter().take(i).any(|q| key(q) == key(p)) {
                why.push("a second row with the same role, permlevel and if_owner");
            }
            if !["select", "read", "write", "submit", "cancel", "create"]
                .iter()
                .any(|f| on(f))
            {
                why.push("no basic permission set (select, read, write, submit, cancel, create)");
            }
            if level > 0
                && role != "All"
                && role != "Desk User"
                && !perms
                    .iter()
                    .any(|q| str_of(q, "role") == role && int_of(q, "permlevel") == 0)
            {
                why.push("a level above 0 without a level-0 row for the role");
            }
            if on("cancel") && !on("submit") {
                why.push("cancel without submit");
            }
            if (on("submit") || on("cancel") || on("amend")) && !on("write") {
                why.push("submit, cancel or amend without write");
            }
            if on("import") && !on("create") {
                why.push("import without create");
            }
            if (on("submit") || on("amend")) && !flag(&d.json, "is_submittable") {
                why.push("submit or amend on a DocType that is not submittable");
            }
            if on("import") && !flag(&d.json, "allow_import") {
                why.push("import on a DocType without allow_import");
            }
            for w in why {
                out.push(viol(
                    &RULE,
                    &d.rel,
                    d.perm_line(i),
                    &format!("{role} level {level} if_owner {}", i32::from(if_owner)),
                    format!(
                        "DocType `{}`, role `{role}` at level {level}: {w}. Frappe's validate_permissions refuses it.",
                        d.name
                    ),
                    "Fix the permission row in the DocType JSON.",
                ));
            }
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let tree = |extra: &str, perms: &str| vec![doctype_file("Thing", extra, "", perms)];
    let case = |label, files, expect| Case {
        label,
        files,
        validated: &[],
        expect,
    };
    vec![
        case(
            "level rows and an if_owner twin are accepted",
            tree(
                "",
                r#"{"role":"A","read":1},{"role":"A","read":1,"write":1,"if_owner":1},{"role":"A","permlevel":1,"read":1},{"role":"All","permlevel":1,"read":1}"#,
            ),
            0,
        ),
        case(
            "submit on a submittable DocType is accepted",
            tree(
                "\"is_submittable\":1,",
                r#"{"role":"A","read":1,"write":1,"submit":1,"cancel":1}"#,
            ),
            0,
        ),
        case(
            "a duplicated (role, permlevel, if_owner) fires",
            tree("", r#"{"role":"A","read":1},{"role":"A","write":1}"#),
            1,
        ),
        case(
            "a row without basic permission fires",
            tree("", r#"{"role":"A","report":1}"#),
            1,
        ),
        case(
            "a level-1 row without level 0 fires",
            tree("", r#"{"role":"A","permlevel":1,"read":1}"#),
            1,
        ),
        case(
            "cancel without submit and write fires twice",
            tree("", r#"{"role":"A","read":1,"cancel":1}"#),
            2,
        ),
        case(
            "import without create or allow_import fires twice",
            tree("", r#"{"role":"A","read":1,"import":1}"#),
            2,
        ),
    ]
}
