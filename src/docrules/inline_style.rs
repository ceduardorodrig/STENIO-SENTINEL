//! `DOC-NO-INLINE-STYLE` (GB-129): published HTML of a tagged application carries no styling;
//! the page stylesheet owns the look.

use std::fs;

use regex::Regex;

use super::{Ctx, DocRule, finding, probe_with};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-NO-INLINE-STYLE",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-NO-INLINE-STYLE",
        name: "Inline Style in Published Documentation HTML",
        severity: "ERROR",
        tag: "doc",
        summary: "Under `--tag <t>`, where <t> is a custom-rule tag of the repository steniocheck.toml, any `.html` below a docs/ directory must contain neither `style=` nor `<style`.",
        rationale: "GB-129: `pandoc -t html5` without --columns emitted 28 `<col style=\"width: N%\">` into a published manual; a colour or width baked into the data breaks the other theme, and no gate noticed.",
        bad_example: "<col style=\"width: 20%\" />",
        good_example: "<col />  <!-- pandoc --columns=1000 -->",
        remediation: "Regenerate with `--columns=1000` (or strip the attributes) and move the styling into the page stylesheet.",
    },
};

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Some(tag) = ctx.tag.as_deref() else {
        return;
    };
    if !super::custom_tags(ctx.root())
        .iter()
        .any(|t| t.eq_ignore_ascii_case(tag))
    {
        return;
    }
    let Ok(style) = Regex::new(r"(?i)<style\b|<[a-z][^<>]*\sstyle\s*=") else {
        return;
    };
    for path in ctx.files(&["html", "htm"]) {
        let rel = path.strip_prefix(ctx.root()).unwrap_or(&path);
        if !rel
            .parent()
            .is_some_and(|d| d.components().any(|c| c.as_os_str() == "docs"))
        {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            if let Some(m) = style.find(line) {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&path),
                    idx + 1,
                    m.as_str(),
                    "published documentation HTML carries inline styling".to_string(),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let cfg = (
        "steniocheck.toml",
        "[[custom_rules]]\nid = \"APP-X\"\ntag = \"app\"\nname = \"x\"\ndescription = \"x\"\npattern = \"zzz\"\nextensions = [\"css\"]\n",
    );
    let good = (
        "app/docs/manual.html",
        "<table><col /><p>style=\"x\" in text</p></table>\n",
    );
    let bad = (
        "app/docs/manual.html",
        "<table><col style=\"width: 2%\" />\n<style>p{}</style>\n",
    );
    let silent = probe_with(&RULE, "good", &[cfg, good], Some("app")).is_some_and(|v| v.is_empty());
    let fires = probe_with(&RULE, "bad", &[cfg, bad], Some("app")).is_some_and(|v| v.len() == 2);
    let untagged = probe_with(&RULE, "untagged", &[cfg, bad], None).is_some_and(|v| v.is_empty());
    vec![
        (format!("{} tagged", RULE.id), silent && fires),
        (format!("{} untagged-silent", RULE.id), untagged),
    ]
}
