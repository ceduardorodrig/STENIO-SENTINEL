//! `DOC-OFFSET-SANITY` (GB-257): published partition offsets and sizes fit the flash they
//! describe and do not overlap.

use std::fs;

use regex::Regex;

use super::{Ctx, DocRule, finding, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-OFFSET-SANITY",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-OFFSET-SANITY",
        name: "Partition Ranges Overlap or Exceed the Flash",
        severity: "ERROR",
        tag: "doc",
        summary: "A .md, .py or .sh file declaring `stenio: flash-size=<bytes>` is checked: each `0xOFFSET/0xSIZE` pair in it must end inside the flash and no two ranges may overlap. Files without the declaration are not judged.",
        rationale: "GB-257: a published unpack map summed to 19,331,160 bytes for a 16,777,216-byte flash, with the third range starting inside the second; it was found by hand before being reused.",
        bad_example: "# stenio: flash-size=16777216\n0x0/0x14FAC1 0x14FAC1/0x800200 0x800200/0x91FB97",
        good_example: "# stenio: flash-size=16777216\n0x0/0x150000 0x150000/0x800000",
        remediation: "Recompute the map from the dump (offset of each part = previous offset + size) before reusing it.",
    },
};

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(declared), Ok(pair)) = (
        Regex::new(r"stenio:\s*flash-size=(0x[0-9A-Fa-f]+|\d+)"),
        Regex::new(r"\b0x([0-9A-Fa-f]+)\s*/\s*0x([0-9A-Fa-f]+)\b"),
    ) else {
        return;
    };
    for path in ctx.files(&["md", "py", "sh"]) {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Some(size) = declared
            .captures(&content)
            .and_then(|c| match c[1].strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => c[1].parse().ok(),
            })
        else {
            continue;
        };
        let mut ranges: Vec<(u64, u64, usize, String)> = content
            .lines()
            .enumerate()
            .flat_map(|(i, l)| pair.captures_iter(l).map(move |c| (i, c)))
            .filter_map(|(i, c)| {
                let start = u64::from_str_radix(&c[1], 16).ok()?;
                let len = u64::from_str_radix(&c[2], 16).ok()?;
                Some((start, start.saturating_add(len), i + 1, c[0].to_string()))
            })
            .collect();
        ranges.sort();
        ranges.dedup_by_key(|r| (r.0, r.1));
        let mut covered = 0;
        for (start, end, line, text) in ranges {
            let message = if end > size {
                Some(format!("range ends at {end}, past the {size}-byte flash"))
            } else if start < covered {
                Some(format!(
                    "range starts at {start}, inside the previous range ending at {covered}"
                ))
            } else {
                None
            };
            covered = covered.max(end);
            if let Some(message) = message {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&path),
                    line,
                    &text,
                    message,
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const GOOD: &str = "# stenio: flash-size=0x1000\nparts = '0x0/0x800 0x800/0x800'\n";
    let overlap = GOOD.replace("0x800/0x800'", "0x700/0x100'");
    let over = GOOD.replace("0x800/0x800'", "0x800/0x801'");
    vec![
        red_green(
            &RULE,
            "overlap",
            &[("u.py", GOOD)],
            &[("u.py", &overlap)],
            1,
        ),
        red_green(&RULE, "past-end", &[("u.py", GOOD)], &[("u.py", &over)], 1),
    ]
}
