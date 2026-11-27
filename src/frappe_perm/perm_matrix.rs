//! `FRAPPE-PERM-MATRIX-GUARD` (GB-053): a destructive or writing grant to a broad role needs a
//! server-side guard that the tree can show.

use super::{BROAD_ROLES, Case, Rule, Tree, doctype_file, flag, hook_block, read, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;
use regex::Regex;

pub static RULE: Rule = Rule {
    id: "FRAPPE-PERM-MATRIX-GUARD",
    name: "Broad Role Write Or Delete Without A Server Guard",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PERM-MATRIX-GUARD",
        name: "Broad Role Write Or Delete Without A Server Guard",
        severity: "ERROR",
        tag: "frappe",
        summary: "On a non-child DocType, a broad role (member, freelancer, Desk User, All, Guest) holds delete without if_owner while the DocType has no has_permission entry and no on_trash guard; or holds write/create without if_owner while it has no has_permission entry and no entry in the app's RULES validation gate.",
        rationale: "GB-053 (audit 04): Task granted Miracena Member delete and Consent Record granted write with no hook, and the permission matrix test measured only read and write. A grant is the whole table unless code narrows it.",
        bad_example: "{\"role\": \"Miracena Member\", \"delete\": 1}  // no has_permission, no on_trash",
        good_example: "has_permission = {\"Task\": \"app.access.task_has_permission\"}",
        remediation: "Remove the grant, set if_owner, or register has_permission (delete: on_trash; write/create: RULES) for the DocType.",
    },
};

/// Whether the DocType refuses a delete somewhere: `doc_events[DocType].on_trash` in hooks.py or
/// an `on_trash`/`before_delete`-style method of its controller. The `"*"` wildcard does not count.
fn deletes_guarded(d: &super::Doc, events: &str) -> bool {
    let controller = read(&d.path.with_extension("py"));
    if controller.contains("def on_trash") {
        return true;
    }
    let Ok(head) = Regex::new(&format!(r#"["']{}["']\s*:\s*\{{"#, regex::escape(&d.name))) else {
        return false;
    };
    head.find(events).is_some_and(|m| {
        crate::frappe::balanced_at(events, m.end() - 1, b'{', b'}')
            .and_then(|(s, e)| events.get(s..e))
            .is_some_and(|b| b.contains("on_trash"))
    })
}

fn run(t: &Tree) -> Vec<Violation> {
    let has_permission = hook_block(t, "has_permission");
    let events = hook_block(t, "doc_events");
    let mut out = Vec::new();
    for d in t.docs.iter().filter(|d| !d.is_child()) {
        if has_permission.contains(&format!("\"{}\"", d.name))
            || has_permission.contains(&format!("'{}'", d.name))
        {
            continue;
        }
        for (i, p) in d.perms().iter().enumerate() {
            let role = str_of(p, "role");
            if flag(p, "if_owner") || !BROAD_ROLES.iter().any(|r| r.eq_ignore_ascii_case(role)) {
                continue;
            }
            let mut ops = Vec::new();
            if flag(p, "delete") && !deletes_guarded(d, &events) {
                ops.push("delete");
            }
            if !t.validated.contains(&d.name) {
                ops.extend(["write", "create"].into_iter().filter(|o| flag(p, o)));
            }
            if ops.is_empty() {
                continue;
            }
            let ops = ops.join(", ");
            out.push(viol(
                &RULE,
                &d.rel,
                d.perm_line(i),
                &format!("{role}: {ops}"),
                format!("DocType `{}` grants `{role}` {ops} on every record and no server guard covers it (has_permission, if_owner; delete: on_trash; write/create: RULES).", d.name),
                "Remove the grant, set if_owner, or register the guard.",
            ));
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, ops: &str, hooks: &str, validated: &'static [&'static str], expect| Case {
        label,
        files: vec![
            doctype_file(
                "Task",
                "",
                "",
                &format!(
                    r#"{{"role":"Miracena Member","read":1,{ops}}},{{"role":"Boss","delete":1}}"#
                ),
            ),
            ("demoapp/hooks.py".into(), hooks.into()),
        ],
        validated,
        expect,
    };
    let del = r#""delete":1"#;
    vec![
        case(
            "has_permission guards both",
            r#""delete":1,"write":1"#,
            "has_permission = {\"Task\": \"demoapp.a.f\"}\n",
            &[],
            0,
        ),
        case(
            "on_trash guards the delete",
            del,
            "doc_events = {\n\t\"Task\": {\"on_trash\": \"demoapp.a.f\"},\n}\n",
            &[],
            0,
        ),
        case("RULES guards a write", r#""write":1"#, "", &["Task"], 0),
        case(
            "if_owner narrows the row",
            r#""delete":1,"if_owner":1"#,
            "",
            &[],
            0,
        ),
        case("an unguarded delete fires", del, "", &["Task"], 1),
        case(
            "a wildcard or commented hook is no guard",
            del,
            "doc_events = {\n\t\"*\": {\"on_trash\": \"demoapp.a.f\"},\n}\n# has_permission = {\"Task\": \"x\"}\n",
            &[],
            1,
        ),
        case("an unvalidated write fires", r#""write":1"#, "", &[], 1),
    ]
}
