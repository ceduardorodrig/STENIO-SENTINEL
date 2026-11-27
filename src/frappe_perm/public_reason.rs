//! `FRAPPE-PUBLIC-ALLOWLIST-REASON` (GB-147): every public declaration records why.

use super::{Case, PUBLIC_FILE, Rule, Tree, declarations, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: Rule = Rule {
    id: "FRAPPE-PUBLIC-ALLOWLIST-REASON",
    name: "Public Permission Declaration Without A Reason",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PUBLIC-ALLOWLIST-REASON",
        name: "Public Permission Declaration Without A Reason",
        severity: "ERROR",
        tag: "frappe",
        summary: "A line of permissions-public.txt (app root or --path) without a `# reason`.",
        rationale: "GB-147: a bare line silences FRAPPE-PERMISSION-SCOPE with no recorded decision; FRAPPE-SIDEBAR-COVERAGE already refuses reasonless allowlist entries.",
        bad_example: "Asset Category",
        good_example: "Asset Category  # closed catalogue, no person and no price",
        remediation: "Write the reason after `#` on the same line.",
    },
};

fn run(t: &Tree) -> Vec<Violation> {
    declarations(t, PUBLIC_FILE)
        .into_iter()
        .filter(|d| d.reason.is_empty())
        .map(|d| {
            viol(
                &RULE,
                &d.file,
                d.line,
                &d.entry,
                format!("`{}` is declared public without a reason: the declaration silences the permission scope rules with no recorded decision.", d.entry),
                "Add `# reason` to the line.",
            )
        })
        .collect()
}

fn cases() -> Vec<Case> {
    let case = |label, text: &str, expect| Case {
        label,
        files: vec![("demoapp/permissions-public.txt".into(), text.into())],
        validated: &[],
        expect,
    };
    vec![
        case(
            "comments, blanks and reasoned lines are accepted",
            "# header\n\nTag  # colour catalogue\n",
            0,
        ),
        case("a bare name and an empty reason fire", "Tag\nSquad #\n", 2),
    ]
}
