//! `DOC-RULE-COUNT-DERIVED` (GB-198): the `## N.` headings of the global rules are contiguous
//! from 0 and every live document that types a rule range or count agrees with them.

use std::fs;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

const RULES_DOC: &str = "governance/agent-global-rules.md";

pub static RULE: DocRule = DocRule {
    id: "DOC-RULE-COUNT-DERIVED",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-RULE-COUNT-DERIVED",
        name: "Global Rule Numbering or Typed Rule Count Drift",
        severity: "ERROR",
        tag: "doc",
        summary: "The `## N.` headings of governance/agent-global-rules.md must be contiguous from 0, and a document that states a rule range (`rules 0-14`) or count (`15 global rules`) must match them.",
        rationale: "GB-198: adding rules 13 and 14 meant sweeping the vault by hand for stale counts, and nothing would turn red when a rule was removed or renumbered. A declared count is derived, never typed (rule 12.3).",
        bad_example: "## 13. Three degrees\n## 15. The maturity ladder\n\nSee global rules 0-12.",
        good_example: "## 13. Three degrees\n## 14. The maturity ladder\n\nSee global rules 0-14.",
        remediation: "Renumber the headings without holes, or drop the typed count and link the rules document.",
    },
};

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Some(vault) = ctx.vault.as_deref() else {
        return;
    };
    let rules_path = vault.join(RULES_DOC);
    let Ok(rules) = fs::read_to_string(&rules_path) else {
        return;
    };
    let (Ok(heading), Ok(range), Ok(count)) = (
        Regex::new(r"^## (\d+)\. "),
        Regex::new(
            r"(?i)\b(?:global rules|rules|regras globais|regras|leis globais)\s+§?0\s*(?:-|–|to|a)\s*§?(\d+)\b",
        ),
        Regex::new(r"(?i)\b(\d+)\s+(?:global rules|regras globais|leis globais)\b"),
    ) else {
        return;
    };
    let numbers: Vec<(usize, usize, &str)> = prose_lines(&rules)
        .into_iter()
        .filter_map(|(i, l)| {
            let n = heading.captures(l)?.get(1)?.as_str().parse().ok()?;
            Some((i, n, l))
        })
        .collect();
    if numbers.is_empty() {
        return;
    }
    // The numbering is judged when the rules document is part of the scan.
    if rules_path.starts_with(&ctx.target) {
        for (position, (idx, n, line)) in numbers.iter().enumerate() {
            if *n != position {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&rules_path),
                    idx + 1,
                    line,
                    format!(
                        "rule numbering has a hole: expected '## {position}.', found '## {n}.'"
                    ),
                ));
                break;
            }
        }
    }
    let total = numbers.len();
    let last = numbers.iter().map(|(_, n, _)| *n).max().unwrap_or(0);
    for (path, content) in ctx.docs() {
        for (idx, line) in prose_lines(&content) {
            let mut wrong = None;
            for c in range.captures_iter(line) {
                if c[1].parse::<usize>().is_ok_and(|n| n != last) {
                    wrong = Some(format!(
                        "states the rule range '{}' but the rules end at {last}",
                        &c[0]
                    ));
                }
            }
            for c in count.captures_iter(line) {
                if c[1].parse::<usize>().is_ok_and(|n| n != total) {
                    wrong = Some(format!(
                        "states '{}' but {RULES_DOC} has {total} rules (0-{last})",
                        &c[0]
                    ));
                }
            }
            if let Some(message) = wrong {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&path),
                    idx + 1,
                    line,
                    message,
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const GOOD: &str = "## 0. a\n## 1. b\n## 2. c\n";
    let doc = ("note.md", "Follow global rules 0-2 (3 global rules).\n");
    vec![
        red_green(
            &RULE,
            "hole",
            &[(RULES_DOC, GOOD), doc],
            &[(RULES_DOC, "## 0. a\n## 2. c\n"), ("note.md", "x\n")],
            1,
        ),
        red_green(
            &RULE,
            "stale-range",
            &[(RULES_DOC, GOOD), doc],
            &[(RULES_DOC, GOOD), ("note.md", "Follow global rules 0-1.\n")],
            1,
        ),
    ]
}
