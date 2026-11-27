//! `DOC-ASSERTED-COUNT-DRIFT` (GB-158): a document that types the size of a list declared in a
//! script must agree with the script.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use super::{Ctx, DocRule, finding, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-ASSERTED-COUNT-DRIFT",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-ASSERTED-COUNT-DRIFT",
        name: "Typed Count Differs From the Declared List",
        severity: "WARN",
        tag: "doc",
        summary: "`<!-- stenio:count list=scripts/x.sh#NAME -->` makes the number just before the next occurrence of a count in the following text equal the size of the bash array NAME. The `N \\`miracena.tests.*.run\\` modules` sentence is checked against scripts/rehearse.sh#TESTS without a marker.",
        rationale: "GB-158: a README said the rehearsal runs 18 modules while the script declared 20; nothing forced the document to follow (rule 12.3: a declared count is derived).",
        bad_example: "<!-- stenio:count list=scripts/rehearse.sh#TESTS -->\nruns the 18 modules   # TESTS has 20",
        good_example: "runs the modules listed in `TESTS` (scripts/rehearse.sh)",
        remediation: "Update the number, or drop it and point at the list.",
    },
};

/// Entries of the bash array `name=( ... )`, comments ignored.
fn array_len(script: &str, name: &str) -> Option<usize> {
    let open = Regex::new(&format!(
        r"(?m)^\s*(?:declare\s+-a\s+)?{}=\(",
        regex::escape(name)
    ))
    .ok()?;
    let rest = &script[open.find(script)?.end()..];
    let mut count = 0;
    for line in rest.lines() {
        let code = line.split('#').next().unwrap_or("");
        let (items, closed) = match code.split_once(')') {
            Some((items, _)) => (items, true),
            None => (code, false),
        };
        count += items.split_whitespace().count();
        if closed {
            return Some(count);
        }
    }
    None
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(marker), Ok(number), Ok(rehearsal)) = (
        Regex::new(r"<!--\s*stenio:count\s+list=([^\s#]+)#(\w+)\s*-->"),
        Regex::new(r"\b(\d+)\b"),
        Regex::new(r"\b(\d+)\s+`miracena\.tests\.\*\.run`\s+modules\b"),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let dir = path.parent().unwrap_or(ctx.root()).to_path_buf();
        // (offset of the number, the number as typed, the script, the array)
        let mut claims: Vec<(usize, usize, PathBuf, String)> = Vec::new();
        for m in marker.captures_iter(&content) {
            let Some(end) = m.get(0).map(|w| w.end()) else {
                continue;
            };
            if let Some(found) = number.find(&content[end..])
                && let Ok(n) = found.as_str().parse()
            {
                let script = resolve(ctx, &dir, &m[1]);
                claims.push((end + found.start(), n, script, m[2].to_string()));
            }
        }
        for m in rehearsal.captures_iter(&content) {
            let script = dir.join("scripts/rehearse.sh");
            if let Some(found) = m.get(1)
                && script.is_file()
                && !claims.iter().any(|c| c.0 == found.start())
                && let Ok(n) = found.as_str().parse()
            {
                claims.push((found.start(), n, script, "TESTS".to_string()));
            }
        }
        for (offset, typed, script, name) in claims {
            let line = content[..offset].matches('\n').count();
            let measured = fs::read_to_string(&script)
                .ok()
                .and_then(|s| array_len(&s, &name));
            let message = match measured {
                Some(n) if n == typed => continue,
                Some(n) => format!(
                    "asserts {typed}, but {name} in {} has {n} entries",
                    ctx.display(&script)
                ),
                None => format!(
                    "asserts {typed}, but no array {name} can be read from {}",
                    ctx.display(&script)
                ),
            };
            out.push(finding(
                &RULE.explain,
                Severity::Warning,
                ctx.display(&path),
                line + 1,
                content.lines().nth(line).unwrap_or(""),
                message,
            ));
        }
    }
}

/// A list path is relative to the citing document or to the scanned root.
fn resolve(ctx: &Ctx, dir: &Path, listed: &str) -> PathBuf {
    let near = dir.join(listed);
    if near.is_file() {
        near
    } else {
        ctx.root().join(listed)
    }
}

fn self_test() -> Vec<(String, bool)> {
    let script = ("c/scripts/rehearse.sh", "TESTS=(a b\n  c) # three\n");
    let sentence = "runs the 3\n`miracena.tests.*.run` modules\n";
    let wrong = sentence.replace('3', "2");
    let marked = "<!-- stenio:count list=scripts/rehearse.sh#TESTS -->\nruns 3 suites\n";
    let stale = marked.replace("runs 3", "runs 4");
    vec![
        red_green(
            &RULE,
            "rehearsal-sentence",
            &[script, ("c/README.md", sentence)],
            &[script, ("c/README.md", &wrong)],
            1,
        ),
        red_green(
            &RULE,
            "marker",
            &[script, ("c/README.md", marked)],
            &[script, ("c/README.md", &stale)],
            1,
        ),
    ]
}
