//! `DOC-RESEARCH-CITE-CURRENT` (GB-260): an external compatibility claim in a research note
//! carries its URL and the date it was read, and that date is recent.

use chrono::NaiveDate;
use regex::Regex;

use super::{Ctx, DocRule, finding, frontmatter, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

const MAX_AGE_DAYS: i64 = 180;

pub static RULE: DocRule = DocRule {
    id: "DOC-RESEARCH-CITE-CURRENT",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-RESEARCH-CITE-CURRENT",
        name: "Research Claim Without a Current Source",
        severity: "WARN",
        tag: "doc",
        summary: "In research notes (file name containing research/pesquisa, or frontmatter tag research/pesquisa), a line claiming support or compatibility of a numbered version needs a URL and an ISO date in its paragraph or list item (or the date in an enclosing heading), and the date must be at most 180 days old.",
        rationale: "GB-260: one page said no patched firmware existed as of January 2025 while another source said nearly every firmware was patched; undated external claims age without anyone noticing.",
        bad_example: "Rooting works on webOS 6.",
        good_example: "Rooting works on webOS 6 (https://example.org/rooting, read 2026-11-01).",
        remediation: "Add the URL and the access date, or re-check the claim and update both.",
    },
};

fn research(name: &str, content: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("research")
        || lower.contains("pesquisa")
        || frontmatter(content)
            .and_then(|f| f.get("tags").and_then(|t| t.as_sequence().cloned()))
            .is_some_and(|tags| {
                tags.iter()
                    .filter_map(|t| t.as_str())
                    .any(|t| matches!(t, "research" | "pesquisa"))
            })
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(claim), Ok(date), Ok(url)) = (
        Regex::new(
            r"(?i)\b(?:works?|supported|supports|compatible|patched|vulnerable|requires|funciona|suportad\w|suporta|compatível|corrigid\w|exige)\b[^.|]{0,60}?\b[A-Za-z][\w+-]*[ -]v?\d+(?:\.\d+)*\b",
        ),
        Regex::new(r"\d{4}-\d{2}-\d{2}"),
        Regex::new(r"https?://"),
    ) else {
        return;
    };
    let today = chrono::Local::now().date_naive();
    for (path, content) in ctx.docs() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !research(name, &content) {
            continue;
        }
        let lines = prose_lines(&content);
        for (at, (idx, line)) in lines.iter().enumerate() {
            if line.starts_with('#') || !claim.is_match(line) {
                continue;
            }
            // The paragraph or list item around the line.
            let boundary = |l: &str| l.trim().is_empty() || l.starts_with('#');
            let item = |l: &str| l.trim_start().starts_with("- ") || l.starts_with('|');
            let mut from = at;
            while from > 0 && !item(lines[from].1) && !boundary(lines[from - 1].1) {
                from -= 1;
            }
            let mut to = at + 1;
            while to < lines.len() && !boundary(lines[to].1) && !item(lines[to].1) {
                to += 1;
            }
            let mut block: Vec<&str> = lines[from..to].iter().map(|(_, l)| *l).collect();
            let sourced = block.iter().any(|l| url.is_match(l));
            // The nearest heading may date the whole section.
            if let Some((_, h)) = lines[..at].iter().rev().find(|(_, l)| l.starts_with('#')) {
                block.push(h);
            }
            let newest = block
                .iter()
                .flat_map(|l| date.find_iter(l))
                .filter_map(|m| NaiveDate::parse_from_str(m.as_str(), "%Y-%m-%d").ok())
                .max();
            let message = match newest {
                _ if !sourced => "compatibility claim with no URL".to_string(),
                None => "compatibility claim with no access date".to_string(),
                Some(d) if (today - d).num_days() > MAX_AGE_DAYS => format!(
                    "compatibility claim last read on {d}, more than {MAX_AGE_DAYS} days ago"
                ),
                Some(_) => continue,
            };
            out.push(finding(
                &RULE.explain,
                Severity::Warning,
                ctx.display(&path),
                idx + 1,
                line,
                message,
            ));
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let good = format!("Rooting works on webOS 6\n(https://example.org/r, read {today}).\n");
    let bare = "Rooting works on webOS 6.\n";
    let old = good.replace(&today, "2020-01-01");
    let n = "tv-research.md";
    vec![
        red_green(&RULE, "unsourced", &[(n, &good)], &[(n, bare)], 1),
        red_green(&RULE, "stale", &[(n, &good)], &[(n, &old)], 1),
    ]
}
