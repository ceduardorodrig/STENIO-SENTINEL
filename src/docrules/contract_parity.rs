//! `DOC-DELIVERABLE-CONTRACT-PARITY` (GB-128): a deliverable matches the shape it declares
//! (frontmatter `contract-lines`, `contract-columns`) and its Markdown tables are aligned.

use regex::Regex;

use super::{Ctx, DocRule, finding, frontmatter, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-DELIVERABLE-CONTRACT-PARITY",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-DELIVERABLE-CONTRACT-PARITY",
        name: "Deliverable Contract or Table Shape Drift",
        severity: "ERROR (declared contract) / WARN (table shape)",
        tag: "doc",
        summary: "Frontmatter `contract-lines: 120-180` and `contract-columns: [A, B]` are enforced (ERROR); every Markdown table row must have as many cells as its header (WARN).",
        rationale: "GB-128: four delegated deliverables declared a line range and tables with fixed columns; every check was done by hand and one table with a misaligned row was found by a private script. GFM silently drops extra cells and splits on any unescaped pipe, code spans included.",
        bad_example: "| a | b | c | d |\n|---|---|---|---|\n| 1 | 2 | 3 | 4 | 5 |",
        good_example: "| a | b |\n|---|---|\n| `x \\| y` | 2 |",
        remediation: "Escape literal pipes as `\\|`, align the row with the header, or bring the file inside the declared contract.",
    },
};

/// Cells of a table row under GFM: only an unescaped pipe separates.
pub fn cells(row: &str) -> Vec<String> {
    let t = row.trim();
    let t = t.strip_prefix('|').unwrap_or(t);
    let mut out = vec![String::new()];
    let mut escaped = false;
    for ch in t.chars() {
        if ch == '|' && !escaped {
            out.push(String::new());
        } else if let Some(last) = out.last_mut() {
            last.push(ch);
        }
        escaped = ch == '\\' && !escaped;
    }
    if out.len() > 1 && out.last().is_some_and(|c| c.trim().is_empty()) && t.ends_with('|') {
        out.pop();
    }
    out.into_iter().map(|c| c.trim().to_string()).collect()
}

/// A table: the header line index, its cells and the body rows.
pub struct Table<'a> {
    pub line: usize,
    pub header: Vec<String>,
    pub rows: Vec<(usize, &'a str)>,
}

pub fn tables(content: &str) -> Vec<Table<'_>> {
    let lines = prose_lines(content);
    let delimiter = |l: &str| {
        let t = l.trim();
        t.contains('-') && t.contains('|') && t.chars().all(|c| "|-: ".contains(c))
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < lines.len() {
        let (idx, header) = lines[i];
        let (next, delim) = lines[i + 1];
        if !header.trim_start().starts_with('|') || next != idx + 1 || !delimiter(delim) {
            i += 1;
            continue;
        }
        let mut table = Table {
            line: idx,
            header: cells(header),
            rows: vec![(next, delim)],
        };
        let mut j = i + 2;
        while j < lines.len()
            && lines[j].0 == lines[j - 1].0 + 1
            && lines[j].1.trim_start().starts_with('|')
        {
            table.rows.push(lines[j]);
            j += 1;
        }
        out.push(table);
        i = j;
    }
    out
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Ok(range) = Regex::new(r"^\s*(\d+)\s*-\s*(\d+)\s*$") else {
        return;
    };
    for (path, content) in ctx.docs() {
        let file = ctx.display(&path);
        let found = tables(&content);
        for table in &found {
            for (idx, row) in &table.rows {
                let n = cells(row).len();
                if n != table.header.len() {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Warning,
                        file.clone(),
                        idx + 1,
                        row,
                        format!(
                            "table row has {n} cell(s), the header at line {} has {}",
                            table.line + 1,
                            table.header.len()
                        ),
                    ));
                }
            }
        }
        let Some(meta) = frontmatter(&content) else {
            continue;
        };
        let mut broken = Vec::new();
        if let Some(declared) = meta.get("contract-lines").and_then(|v| v.as_str()) {
            let total = content.lines().count();
            match range
                .captures(declared)
                .and_then(|c| Some((c[1].parse::<usize>().ok()?, c[2].parse::<usize>().ok()?)))
            {
                Some((lo, hi)) if total < lo || total > hi => broken.push(format!(
                    "the file has {total} lines, the contract asks for {lo}-{hi}"
                )),
                Some(_) => {}
                None => broken.push(format!("contract-lines '{declared}' is not 'MIN-MAX'")),
            }
        }
        if let Some(columns) = meta.get("contract-columns").and_then(|v| v.as_sequence()) {
            let wanted: Vec<&str> = columns.iter().filter_map(|c| c.as_str()).collect();
            let present = found.iter().any(|t| {
                wanted
                    .iter()
                    .all(|w| t.header.iter().any(|h| h.eq_ignore_ascii_case(w)))
            });
            if !present {
                broken.push(format!(
                    "no table carries the required column(s): {}",
                    wanted.join(", ")
                ));
            }
        }
        for message in broken {
            out.push(finding(
                &RULE.explain,
                Severity::Error,
                file.clone(),
                1,
                "contract",
                message,
            ));
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const GOOD: &str = "---\ncontract-lines: 5-12\ncontract-columns: [a, b]\n---\n| a | b |\n|---|---|\n| `x \\| y` | 2 |\n";
    let wide = GOOD.replace("| 2 |", "| 2 | 3 |");
    let short = GOOD.replace("5-12", "120-180");
    let column = GOOD.replace("[a, b]", "[a, z]");
    vec![
        red_green(&RULE, "row-shape", &[("d.md", GOOD)], &[("d.md", &wide)], 1),
        red_green(
            &RULE,
            "line-range",
            &[("d.md", GOOD)],
            &[("d.md", &short)],
            1,
        ),
        red_green(&RULE, "column", &[("d.md", GOOD)], &[("d.md", &column)], 1),
    ]
}
