//! `DOC-LIVE-CLAIM` (GB-017): "rcNN is live" ages the moment the next release ships, so it is
//! only acceptable inside a dated line or section.

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-LIVE-CLAIM",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-LIVE-CLAIM",
        name: "Undated Present-Tense Release Claim",
        severity: "WARN",
        tag: "doc",
        summary: "A sentence saying a release candidate or version is live or in production, with no ISO date on the line, in the paragraph or in an enclosing heading.",
        rationale: "GB-017 (phase 2 of GB-009): undated release claims rot silently and the next agent builds on them (rule 7: a fact about the environment carries its date and source).",
        bad_example: "rc73 is live and the sidebar shows all links.",
        good_example: "2026-11-04: rc73 is live (verified with `stenio verify-release`).",
        remediation: "Date the sentence or its section, or replace it with the command that answers the question today.",
    },
};

const CLAIM: &str = r"(?ix)
    (?: \brc\d{2,4}\b | \bv?\d+\.\d+\.\d+(?:-rc\d+)?\b ) [`*)]{0,3} \s+
        (?: is\s+(?:now\s+|currently\s+)?(?:live\b|in\s+production\b|deployed\b)
          | está\s+(?:no\s+ar\b|em\s+produção\b) )
  | \b (?: production\s+(?:is\s+(?:now\s+|currently\s+)?(?:on|at|running)\s+ | runs\s+ | is\s+)
         | (?:a\s+)?produção\s+(?:está\s+(?:na|no|em)\s+ | roda\s+ | é\s+) )
        [`*]{0,3} (?: rc\d{2,4} | v?\d+\.\d+\.\d+ ) \b";

/// Dated when an ISO or `DD/MM/YYYY` date sits on the line, earlier in its paragraph or list
/// item, or in an enclosing heading.
pub fn dated(lines: &[(usize, &str)], at: usize, date: &Regex) -> bool {
    for (_, line) in lines[..=at].iter().rev() {
        if date.is_match(line) {
            return true;
        }
        let t = line.trim_start();
        if t.is_empty() || t.starts_with('#') || t.starts_with("- ") || t.starts_with('|') {
            break;
        }
    }
    let mut level = usize::MAX;
    for (_, line) in lines[..=at].iter().rev() {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if hashes > 0 && hashes < level && line[hashes..].starts_with(' ') {
            if date.is_match(line) {
                return true;
            }
            level = hashes;
        }
    }
    false
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(claim), Ok(date)) = (
        Regex::new(CLAIM),
        Regex::new(r"\d{4}-\d{2}-\d{2}|\b\d{2}/\d{2}/\d{4}\b"),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // A file named after its day is a dated log as a whole.
        if date.is_match(name) || name.eq_ignore_ascii_case("CHANGELOG.md") {
            continue;
        }
        let lines = prose_lines(&content);
        for (at, (idx, line)) in lines.iter().enumerate() {
            if claim.is_match(line) && !dated(&lines, at, &date) {
                out.push(finding(
                    &RULE.explain,
                    Severity::Warning,
                    ctx.display(&path),
                    idx + 1,
                    line,
                    "present-tense release claim with no date saying when it was true".to_string(),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const GOOD: &str =
        "## Log\n- 2026-11-04: rc73 is live.\n## State (2026-11-04)\nProduction is rc127.\n";
    vec![
        red_green(
            &RULE,
            "prose",
            &[("d.md", GOOD)],
            &[("d.md", "## State\nrc73 is live: all links show.\n")],
            1,
        ),
        red_green(
            &RULE,
            "portuguese",
            &[("d.md", GOOD)],
            &[("d.md", "A produção está na rc127.\n")],
            1,
        ),
    ]
}
