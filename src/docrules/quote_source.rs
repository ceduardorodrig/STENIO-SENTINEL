//! `DOC-QUOTE-SOURCE-RESOLVES` (GB-228): a quoted phrase attributed to `file:line` is on that
//! line, and a bare `<Source> line N` names one file only.

use std::collections::HashMap;

use regex::Regex;

use super::sources::Sources;
use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-QUOTE-SOURCE-RESOLVES",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-QUOTE-SOURCE-RESOLVES",
        name: "Quoted Source Does Not Say That",
        severity: "WARN",
        tag: "doc",
        summary: "Warns when `\"a quoted phrase\" (file:line)` (three words or more) is not on the cited lines, and when `<Source> line N` names two or more documents of the vault.",
        rationale: "GB-228: `Handbook line 66` could mean two files and each phrase had to be searched by hand to learn which source was meant.",
        bad_example: "\"reversible decisions\" (`handbook.md:3`)   # line 3 says something else",
        good_example: "\"reversible decisions\" (`handbook.md:65`)",
        remediation: "Fix the line number or the quote, and qualify an ambiguous source with its path.",
    },
};

/// Case, markup and spacing do not change what a line says.
fn normalize(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .filter(|c| !"*_`>|—–\"“”«»".contains(*c))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(quoted), Ok(bare)) = (
        Regex::new(
            r#"["“«]([^"“”«»]{8,240})["”»]\s*\(\s*`?([\w./-]*[\w-]\.[A-Za-z]{1,5}):(\d+)(?:-(\d+))?`?"#,
        ),
        Regex::new(r"\b([A-Z][a-z]{3,}) line (\d+)\b"),
    ) else {
        return;
    };
    let mut sources = Sources::new(ctx);
    let mut stems: Option<HashMap<String, usize>> = None;
    for (path, content) in ctx.docs() {
        let file = ctx.display(&path);
        let bases = Sources::declared_bases(&content);
        for (idx, line) in prose_lines(&content) {
            for c in quoted.captures_iter(line) {
                // A single quoted word is a term being named, not a quotation of the source.
                if c[1].split_whitespace().count() < 3 {
                    continue;
                }
                let (Ok(first), last) = (c[3].parse::<usize>(), c.get(4)) else {
                    continue;
                };
                let last = last.and_then(|m| m.as_str().parse().ok()).unwrap_or(first);
                let hits = sources.resolve(&path, &bases, &c[2]);
                if hits.is_empty() || first == 0 {
                    continue;
                }
                // An ellipsis splits the quote; every fragment must be there. The line after
                // the range is included because a quoted sentence may wrap.
                let quote = c[1].replace("...", "…");
                let found = hits.iter().any(|hit| {
                    let text: Vec<String> = Sources::lines(hit)
                        .into_iter()
                        .skip(first - 1)
                        .take(last.saturating_sub(first) + 2)
                        .collect();
                    let hay = normalize(&text.join(" "));
                    quote
                        .split('…')
                        .map(normalize)
                        .all(|part| hay.contains(part.trim_end_matches(['.', ','])))
                });
                if !found {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Warning,
                        file.clone(),
                        idx + 1,
                        &c[0],
                        format!(
                            "line {first} of '{}' does not contain the quoted text",
                            &c[2]
                        ),
                    ));
                }
            }
            for c in bare.captures_iter(line) {
                let stems = stems.get_or_insert_with(|| {
                    let mut map = HashMap::new();
                    let whole = ctx.vault.as_deref().map(|v| Ctx::new(v, None));
                    for p in whole.as_ref().unwrap_or(ctx).files(&["md"]) {
                        if let Some(s) = p.file_stem().and_then(|s| s.to_str()) {
                            *map.entry(s.to_lowercase()).or_insert(0) += 1;
                        }
                    }
                    map
                });
                let n = stems.get(&c[1].to_lowercase()).copied().unwrap_or(0);
                if n >= 2 {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Warning,
                        file.clone(),
                        idx + 1,
                        &c[0],
                        format!(
                            "'{}' names {n} documents in the vault; cite the path",
                            &c[1]
                        ),
                    ));
                }
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let src = (
        "handbook.md",
        "# H\nWho executes decides reversible matters.\n",
    );
    const GOOD: &str = "It says \"who executes decides\" (`handbook.md:2`).\n";
    let wrong = GOOD
        .replace(":2", ":1")
        .replace("who executes", "who approves");
    let twins = [
        ("a/handbook.md", "x\n"),
        ("b/handbook.md", "y\n"),
        ("d.md", "Handbook line 6 says so.\n"),
    ];
    vec![
        red_green(
            &RULE,
            "wrong-quote",
            &[src, ("d.md", GOOD)],
            &[src, ("d.md", &wrong)],
            1,
        ),
        red_green(&RULE, "ambiguous-name", &[twins[0], twins[2]], &twins, 1),
    ]
}
