//! `FRAPPE-PERMLEVEL-ROW-PARITY` (GB-146): a level used by a field needs a readable permission
//! row, and a row above level 0 must read; a declared deny map keeps roles off a level.

use super::{Case, Rule, Tree, data_field, doctype_file, flag, int_of, read, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

/// `DocType | level | Role  # reason`, read from the app package or from `--path`.
const DENY_FILE: &str = "permlevel-deny.txt";

pub static RULE: Rule = Rule {
    id: "FRAPPE-PERMLEVEL-ROW-PARITY",
    name: "Field Permlevel Without A Matching Permission Row",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PERMLEVEL-ROW-PARITY",
        name: "Field Permlevel Without A Matching Permission Row",
        severity: "ERROR",
        tag: "frappe",
        summary: "On a non-child DocType: a field at permlevel n>0 with no permission row at level n with read=1 (nobody but Administrator sees it); a permission row above level 0 without read=1; or a row at a level for a role that permlevel-deny.txt (`DocType | level | Role  # reason`) keeps off it.",
        rationale: "GB-146 (2026-11-06): the Asset purchase value, supplier and fiscal note moved to permlevel 1. A level with no row is a silent lockout and a row for the wrong role a silent leak; both were checked by hand.",
        bad_example: "{\"fieldname\": \"price\", \"permlevel\": 1}  /  permissions: [{\"role\": \"Finance\", \"read\": 1}]",
        good_example: "permissions: [{\"role\": \"Finance\", \"read\": 1}, {\"role\": \"Finance\", \"permlevel\": 1, \"read\": 1}]",
        remediation: "Add the level row with read=1 for the approved role, or remove the row of a denied role.",
    },
};

/// (DocType, level, role) entries and the file lines that are not in that shape or lack a reason.
fn deny_map(t: &Tree) -> (Vec<(String, i64, String)>, Vec<(String, usize, String)>) {
    let (mut entries, mut bad) = (Vec::new(), Vec::new());
    let mut paths = vec![t.pkg.join(DENY_FILE), t.root.join(DENY_FILE)];
    paths.dedup();
    for p in paths {
        for (n, raw) in read(&p).lines().enumerate() {
            let (body, reason) = raw.split_once('#').unwrap_or((raw, ""));
            if body.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = body.split('|').map(str::trim).collect();
            match (parts.as_slice(), parts.get(1).and_then(|l| l.parse().ok())) {
                ([dt, _, role], Some(level)) if !reason.trim().is_empty() => {
                    entries.push((dt.to_string(), level, role.to_string()))
                }
                _ => bad.push((t.rel(&p), n + 1, raw.trim().to_string())),
            }
        }
    }
    (entries, bad)
}

fn run(t: &Tree) -> Vec<Violation> {
    let (deny, bad) = deny_map(t);
    let mut out: Vec<Violation> = bad
        .into_iter()
        .map(|(file, line, text)| {
            viol(
                &RULE,
                &file,
                line,
                &text,
                format!(
                    "`{text}` is not `DocType | level | Role  # reason`: the deny entry is ignored."
                ),
                "Write the three columns and the reason after `#`.",
            )
        })
        .collect();
    for d in t.docs.iter().filter(|d| !d.is_child()) {
        for f in d.fields().iter().filter(|f| data_field(f)) {
            let level = int_of(f, "permlevel");
            let readable = d
                .perms()
                .iter()
                .any(|p| int_of(p, "permlevel") == level && flag(p, "read"));
            if level > 0 && !readable {
                let name = str_of(f, "fieldname");
                out.push(viol(
                    &RULE,
                    &d.rel,
                    d.field_line(name),
                    &format!("{name} permlevel {level}"),
                    format!("`{}.{name}` is at permlevel {level} and no permission row of that level reads it: every role but Administrator is locked out.", d.name),
                    "Add a permission row at that level with read=1 for the approved roles.",
                ));
            }
        }
        for (i, p) in d.perms().iter().enumerate() {
            let (role, level) = (str_of(p, "role"), int_of(p, "permlevel"));
            if level == 0 {
                continue;
            }
            let denied = deny
                .iter()
                .any(|(dt, l, r)| *dt == d.name && *l == level && r == role);
            let why = if denied {
                format!("is listed in {DENY_FILE} as denied")
            } else if !flag(p, "read") {
                "has no read=1".to_string()
            } else {
                continue;
            };
            out.push(viol(
                &RULE,
                &d.rel,
                d.perm_line(i),
                &format!("{role} permlevel {level}"),
                format!(
                    "DocType `{}`: the level-{level} row of role `{role}` {why}.",
                    d.name
                ),
                "Remove the row, or fix its read flag.",
            ));
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let field = r#"{"fieldname":"price","fieldtype":"Currency","permlevel":1}"#;
    let tree = |perms: &str| vec![doctype_file("Thing", "", field, perms)];
    let ok = r#"{"role":"A","read":1},{"role":"A","permlevel":1,"read":1}"#;
    let denied = |line: &str| {
        let mut files = tree(ok);
        files.push(("demoapp/permlevel-deny.txt".into(), line.into()));
        files
    };
    let case = |label, files, expect| Case {
        label,
        files,
        validated: &[],
        expect,
    };
    vec![
        case("a level with a reading row is accepted", tree(ok), 0),
        case(
            "a deny entry for another role is accepted",
            denied("Thing | 1 | Member  # no price\n"),
            0,
        ),
        case(
            "a level without any row fires",
            tree(r#"{"role":"A","read":1}"#),
            1,
        ),
        case(
            "a level row without read fires for field and row",
            tree(r#"{"role":"A","read":1},{"role":"A","permlevel":1,"write":1}"#),
            2,
        ),
        case(
            "a row for a denied role fires",
            denied("Thing | 1 | A  # no price\n"),
            1,
        ),
        case(
            "a deny entry without a reason fires",
            denied("Thing | 1 | Member\n"),
            1,
        ),
    ]
}
