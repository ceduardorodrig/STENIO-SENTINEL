//! `DOC-PUBLISH-OPEN-WEAKNESS` (GB-333): a folder mirrored to a public repository must not say
//! where an open security weakness is. A line that names a credential variable and describes a
//! missing protection is such a map; the detail belongs in the private governance note.

use std::fs;

use regex::Regex;

use super::{Ctx, DocRule, finding, probe, red_green};
use crate::backlog::queue_index::published_dirs;
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-PUBLISH-OPEN-WEAKNESS",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-PUBLISH-OPEN-WEAKNESS",
        name: "Open Weakness In A Published Folder",
        severity: "ERROR",
        tag: "doc",
        summary: "In a queue directory declared `published` (backlog-queues.toml), a Markdown line that names a credential variable (`..._TOKEN`, `..._PASSWORD`, `..._SECRET`, `..._KEY`) and describes a missing or broken protection fails. Table rows already `resolved` or `discarded` are history.",
        rationale: "GB-333: backlog rows and service notes described unfixed weaknesses beside secret variable names in the folder published to a public repository; only a human reading them stopped the daily publication.",
        bad_example: "| HB-200 | the endpoint has no authentication, EXAMPLE_API_TOKEN is unused | ... | open |",
        good_example: "| HB-200 | access hardening, detail in the private governance note | ... | open |",
        remediation: "Move the detail to a private note under governance/ and leave a neutral row that points to it. The gate blocks a publication only when it runs with --strict.",
    },
};

const CREDENTIAL: &str = r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|SECRET_KEY|CREDENTIALS?)(?:_B64)?\b";

const WEAKNESS: &str = r"(?ix)
    \b(?:no|without|missing|lacks?|lacking|sem)\s+(?:[a-z-]+\s+){0,2}?
        (?:authentication|authorization|auth\b|access\s+control|signature\s+(?:check|verification)|
           tls\s+verification|rate[\s-]limit(?:ing)?|autentica)
  | \bunauthenticated\s+(?:access|endpoint|api|route|port|request|service|page|webhook)
  | \b(?:is|are|left|remains?|stays?)\s+(?:still\s+)?(?:unauthenticated|unprotected)\b
  | \bunfixed\b | \bvulnerable\b | \bworld[\s-]readable\b
  | \b(?:secret|token|password|key)\s+(?:is\s+|was\s+)?(?:hardcoded|exposed|leaked)\b
";

/// A table row whose state cell says the item is closed.
fn closed(line: &str) -> bool {
    line.starts_with('|')
        && line
            .split('|')
            .any(|c| matches!(c.trim(), "resolved" | "discarded"))
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let mut published = published_dirs(&ctx.target);
    if let Some(vault) = &ctx.vault {
        published.extend(published_dirs(vault));
    }
    if published.is_empty() {
        return;
    }
    let (Ok(credential), Ok(weakness)) = (Regex::new(CREDENTIAL), Regex::new(WEAKNESS)) else {
        return;
    };
    // `ctx.files`, not `ctx.docs`: the backlogs are published too.
    for path in ctx.files(&["md"]) {
        if !published.iter().any(|dir| path.starts_with(dir)) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        for (idx, line) in content.lines().enumerate() {
            if !closed(line) && credential.is_match(line) && weakness.is_match(line) {
                // The finding must not repeat the weakness: gate output reaches logs and alerts.
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&path),
                    idx + 1,
                    "",
                    "an open weakness is described next to a credential name in a published folder"
                        .to_string(),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let queue = ("mnemocine/backlog.md", "| ID |\n|---|\n");
    let planted =
        "| HB-200 | the endpoint has no authentication and EXAMPLE_API_TOKEN is unused | open |\n";
    let neutral = (
        "mnemocine/note.md",
        "Store EXAMPLE_API_TOKEN in the secret store.\nThe page has no authentication yet.\n| HB-1 | was unauthenticated, EXAMPLE_API_TOKEN | resolved |\n",
    );
    let private = (
        "governance/security-findings.md",
        "No authentication: EXAMPLE_API_TOKEN\n",
    );
    let row = ("mnemocine/backlog.md", planted);
    let prose = (
        "mnemocine/service.md",
        "The API is unauthenticated; ADMIN_PASSWORD_B64 sits beside it.\n",
    );
    let outside = probe(
        &RULE,
        "unpublished",
        &[queue, ("other/note.md", planted), private],
    );
    vec![
        red_green(&RULE, "planted-row", &[queue, neutral, private], &[row], 1),
        red_green(&RULE, "prose", &[queue, neutral], &[queue, prose], 1),
        (
            format!("{} unpublished-silent", RULE.id),
            outside.is_some_and(|v| v.is_empty()),
        ),
    ]
}
