//! `DOC-RACI-CITATION` (GB-048): in a matrix or specification document every `file:line`
//! citation resolves to a file with that many lines, and every RACI row has exactly one A.

use regex::Regex;

use super::contract_parity::{cells, tables};
use super::sources::Sources;
use super::{Ctx, DocRule, finding, frontmatter, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-RACI-CITATION",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-RACI-CITATION",
        name: "Matrix Citation or RACI Accountability Broken",
        severity: "ERROR",
        tag: "doc",
        summary: "In documents marked as matrix or specification (file name containing raci/matriz/matrix/spec, or frontmatter tag raci/spec/matrix): each `file:line` citation must name an existing file with that many lines, and each RACI table row must carry exactly one A.",
        rationale: "GB-048, 2026-11-04: 12 decisions, 57 file:line references and the single-A rule of a RACI draft were verified with an ad hoc script because nothing in the engine validated them.",
        bad_example: "| D1 | A | A/R | I |   <!-- two accountable -->\nSource: `gone.py:900`",
        good_example: "| D1 | A/R | C | I |\nSource: `structure.py:127-130`",
        remediation: "Point the citation at the current file and line, and leave one accountable role per decision.",
    },
};

/// A cell without emphasis and notes: `**A (2 assin.)/R**` is `A/R`.
fn value(cell: &str) -> String {
    let mut depth = 0usize;
    let kept: String = cell
        .chars()
        .filter(|&c| {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    return false;
                }
                _ => {}
            }
            depth == 0 && c != '*'
        })
        .collect();
    kept.split('/').map(str::trim).collect::<Vec<_>>().join("/")
}

fn marked(name: &str, content: &str) -> bool {
    let lower = name.to_lowercase();
    if lower
        .split(['-', '_', '.'])
        .any(|w| matches!(w, "raci" | "matriz" | "matrix" | "spec"))
    {
        return true;
    }
    frontmatter(content)
        .and_then(|f| f.get("tags").and_then(|t| t.as_sequence().cloned()))
        .is_some_and(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str())
                .any(|t| matches!(t, "raci" | "spec" | "matrix"))
        })
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(citation), Ok(role)) = (
        Regex::new(r"`([\w./-]*[\w-]\.[A-Za-z]{1,5}):(\d+)(?:-(\d+))?`"),
        // A RACI cell once bold and parenthesised notes are removed: letters joined by `/`.
        Regex::new(r"^([RACI](?:\s*/\s*[RACI])*|—|–|-)?$"),
    ) else {
        return;
    };
    let mut sources = Sources::new(ctx);
    for (path, content) in ctx.docs() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !marked(name, &content) {
            continue;
        }
        let file = ctx.display(&path);
        let bases = Sources::declared_bases(&content);
        for (idx, line) in prose_lines(&content) {
            for c in citation.captures_iter(line) {
                let cited = &c[1];
                let last = c.get(3).or_else(|| c.get(2));
                let Some(wanted) = last.and_then(|m| m.as_str().parse::<usize>().ok()) else {
                    continue;
                };
                let hits = sources.resolve(&path, &bases, cited);
                let longest = hits.iter().map(|h| Sources::lines(h).len()).max();
                let message = match longest {
                    None => format!("cites '{cited}', which resolves to no file"),
                    Some(n) if n < wanted => {
                        format!("cites line {wanted} of '{cited}', which has {n} lines")
                    }
                    Some(_) => continue,
                };
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    file.clone(),
                    idx + 1,
                    &c[0],
                    message,
                ));
            }
        }
        for table in tables(&content) {
            let body: Vec<(usize, &str, Vec<String>)> = table
                .rows
                .iter()
                .skip(1)
                .map(|(i, r)| (*i, *r, cells(r)))
                .collect();
            // The role columns are those whose every cell is a RACI value.
            let columns: Vec<usize> = (1..table.header.len())
                .filter(|&col| {
                    !body.is_empty()
                        && body
                            .iter()
                            .all(|(_, _, c)| c.get(col).is_some_and(|v| role.is_match(&value(v))))
                })
                .collect();
            let accountable = |v: &str| {
                role.captures(&value(v))
                    .and_then(|c| c.get(1))
                    .is_some_and(|m| m.as_str().contains('A'))
            };
            let any_a = body.iter().any(|(_, _, c)| {
                columns
                    .iter()
                    .any(|&col| c.get(col).is_some_and(|v| accountable(v)))
            });
            if columns.len() < 3 || !any_a {
                continue;
            }
            for (idx, row, c) in &body {
                let n = columns
                    .iter()
                    .filter(|&&col| c.get(col).is_some_and(|v| accountable(v)))
                    .count();
                if n != 1 {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Error,
                        file.clone(),
                        idx + 1,
                        row,
                        format!("RACI row has {n} accountable (A) cells, it needs exactly one"),
                    ));
                }
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const DOC: &str = "x-raci.md";
    let src = ("src.py", "a\nb\nc\n");
    const GOOD: &str = "| # | X | Y | Z |\n|---|---|---|---|\n| D1 | **A (2 assin.)/R** | C | — |\nSee `src.py:2-3`.\n";
    let two = GOOD.replace("| C |", "| A |");
    let gone = GOOD.replace("src.py:2-3", "gone.py:2");
    let long = GOOD.replace("src.py:2-3", "src.py:9");
    vec![
        red_green(
            &RULE,
            "two-accountable",
            &[src, (DOC, GOOD)],
            &[src, (DOC, &two)],
            1,
        ),
        red_green(
            &RULE,
            "missing-file",
            &[src, (DOC, GOOD)],
            &[src, (DOC, &gone)],
            1,
        ),
        red_green(
            &RULE,
            "line-past-end",
            &[src, (DOC, GOOD)],
            &[src, (DOC, &long)],
            1,
        ),
    ]
}
