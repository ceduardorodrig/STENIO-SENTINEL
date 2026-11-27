//! `FRAPPE-WHITELIST-GUEST` (GB-021) and the one-level helper follow of
//! `FRAPPE-WHITELIST-PERMISSION`.

use super::{Case, Rule, Tree, read, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;
use regex::Regex;

pub static RULE: Rule = Rule {
    id: "FRAPPE-WHITELIST-GUEST",
    name: "Endpoint Open To Guests",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-WHITELIST-GUEST",
        name: "Endpoint Open To Guests",
        severity: "ERROR",
        tag: "frappe",
        summary: "A @frappe.whitelist() decorator with allow_guest=True in production code: the function answers a caller with no session.",
        rationale: "GB-021 (rc76 review policy): an unauthenticated endpoint is public exposure and must be a reviewed decision, never a default. The same item makes FRAPPE-WHITELIST-PERMISSION follow one level of same-module helpers.",
        bad_example: "@frappe.whitelist(allow_guest=True)\ndef lookup(name): ...",
        good_example: "@frappe.whitelist(methods=[\"POST\"])\ndef lookup(name):\n    frappe.only_for(\"Member\")",
        remediation: "Remove allow_guest and check the caller; a truly public form needs an owner decision and a change to this rule.",
    },
};

/// The indented block of the module-level function `name`, if the module defines it.
fn module_function(text: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let at = lines.iter().position(|l| {
        l.strip_prefix("def ")
            .or_else(|| l.strip_prefix("async def "))
            .and_then(|r| r.strip_prefix(name))
            .is_some_and(|r| r.starts_with('('))
    })?;
    let mut end = at + 1;
    while end < lines.len()
        && (lines[end].trim().is_empty() || lines[end].starts_with([' ', '\t', ')']))
    {
        end += 1;
    }
    Some(lines[at..end].join("\n"))
}

/// True when `body` calls a function of the same module (one level, comments ignored) whose own
/// body carries a permission marker.
pub fn guarded_by_helper(module: &str, body: &str, markers: &[&str]) -> bool {
    let Ok(call) = Regex::new(r"(?:^|[^.\w])([A-Za-z_]\w*)\(") else {
        return false;
    };
    let code = |t: &str| {
        t.lines()
            .map(crate::frappe::strip_comment)
            .collect::<Vec<_>>()
            .join("\n")
    };
    // the first line is the endpoint's own `def`
    let inner = body.split_once('\n').map_or("", |(_, rest)| rest);
    call.captures_iter(&code(inner)).any(|c| {
        module_function(module, &c[1]).is_some_and(|helper| {
            let helper = code(&helper);
            markers.iter().any(|m| helper.contains(m))
        })
    })
}

fn run(t: &Tree) -> Vec<Violation> {
    let Ok(guest) = Regex::new(
        r"(?m)^[ \t]*@(?:frappe\.)?whitelist\([^()]*?(?:\[[^\]]*\][^()]*?)?\ballow_guest\s*=\s*True",
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in t.files.iter().filter(|p| {
        p.extension().is_some_and(|e| e == "py")
            && !t.rel(p).split('/').any(|s| s == "tests" || s == "patches")
    }) {
        let text = read(p);
        for m in guest.find_iter(&text) {
            let line = text[..m.start()].matches('\n').count() + 1;
            out.push(viol(
                &RULE,
                &t.rel(p),
                line,
                "allow_guest=True",
                "Whitelisted endpoint declares allow_guest=True: anyone on the network can call it without signing in.".into(),
                "Remove allow_guest and check the caller inside the function.",
            ));
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, path: &str, text: &str, expect| Case {
        label,
        files: vec![(path.to_string(), text.to_string())],
        validated: &[],
        expect,
    };
    vec![
        case(
            "a session endpoint and a commented guest decorator are accepted",
            "demoapp/api.py",
            "# @frappe.whitelist(allow_guest=True)\n@frappe.whitelist(allow_guest=False)\ndef f():\n    pass\n",
            0,
        ),
        case(
            "a test stub is not judged",
            "demoapp/tests/t.py",
            "@frappe.whitelist(allow_guest=True)\ndef f():\n    pass\n",
            0,
        ),
        case(
            "a multi-line guest decorator fires",
            "demoapp/api.py",
            "@frappe.whitelist(\n    methods=[\"POST\"],\n    allow_guest=True,\n)\ndef f():\n    pass\n",
            1,
        ),
    ]
}

/// Fixtures of the helper follow used by `FRAPPE-WHITELIST-PERMISSION`.
pub fn helper_cases() -> Vec<(String, bool)> {
    let markers = ["only_for", "require_"];
    let module = "def _gate():\n    frappe.only_for(\"A\")\n\ndef _plain():\n    pass\n\ndef _deep():\n    _gate()\n";
    let hit =
        |call: &str| guarded_by_helper(module, &format!("def api():\n    {call}\n"), &markers);
    [
        (
            "a same-module helper that calls only_for guards",
            hit("_gate()"),
        ),
        ("a helper without a check does not guard", !hit("_plain()")),
        ("a second level is not followed", !hit("_deep()")),
        (
            "a method call of the same name does not guard",
            !hit("doc._gate()"),
        ),
        ("a commented call does not guard", !hit("pass  # _gate()")),
    ]
    .into_iter()
    .map(|(n, ok)| (format!("FRAPPE-WHITELIST-PERMISSION: {n}"), ok))
    .collect()
}
