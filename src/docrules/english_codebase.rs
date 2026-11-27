//! `DOC-ENGLISH-ONLY-CODEBASE` (GB-072): the Markdown of a repository that declares language
//! tier A is written in English.

use std::fs;
use std::path::Path;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-ENGLISH-ONLY-CODEBASE",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-ENGLISH-ONLY-CODEBASE",
        name: "Portuguese Prose in a Tier A Repository",
        severity: "WARN",
        tag: "doc",
        summary: "Under a directory whose AGENTS.md or steniocheck.toml declares `Language tier: A`, Markdown headings and prose (outside code, quotes and link targets) must be English. Translation files (locale/, *pt-br*, *.pt.md) are exempt.",
        rationale: "GB-072: Portuguese text in the documentation of public repositories escaped every check, because DOC-LANGUAGE-EN judges only the Hub (governance/language-policy.md, tier A).",
        bad_example: "## Como instalar o serviço para o usuário",
        good_example: "## Installing the service",
        remediation: "Translate the document, or move the Portuguese version to a file named as a translation.",
    },
};

fn declares_tier_a(dir: &Path, re: &Regex) -> bool {
    ["AGENTS.md", "steniocheck.toml"]
        .iter()
        .any(|f| fs::read_to_string(dir.join(f)).is_ok_and(|t| re.is_match(&t)))
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(tier), Ok(noise)) = (
        Regex::new(r"(?im)^[#>*\s]*\**language tier\**\s*:\**\s*\**A\b"),
        // Code spans, link targets and quoted terms are citations, not prose.
        Regex::new(
            r#"`[^`]*`|\]\([^)]*\)|<[^>]*>|https?://\S+|"[^"]*"|“[^”]*”|\([^()]*\bpt-BR\b[^()]*\)"#,
        ),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let rel = ctx.display(&path).to_lowercase();
        let translation = ["locale/", "i18n/", "pt-br", "pt_br", "ptbr", ".pt.md"]
            .iter()
            .any(|m| rel.contains(m));
        let tier_a = path
            .ancestors()
            .skip(1)
            .take_while(|d| d.starts_with(ctx.root()))
            .any(|d| declares_tier_a(d, &tier));
        if translation || !tier_a {
            continue;
        }
        let hits: Vec<(usize, &str)> = prose_lines(&content)
            .into_iter()
            .filter(|(_, l)| !l.trim_start().starts_with('>'))
            .filter(|(_, l)| crate::comments::is_portuguese_comment(&noise.replace_all(l, " ")))
            .collect();
        if let Some((idx, line)) = hits.first() {
            out.push(finding(
                &RULE.explain,
                Severity::Warning,
                ctx.display(&path),
                idx + 1,
                line,
                format!(
                    "{} line(s) of Portuguese prose in a tier A repository",
                    hits.len()
                ),
            ));
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let agents = ("AGENTS.md", "**Language Tier:** A (Public OSS)\n");
    let good = (
        "README.md",
        "## Installing the service\nThe label is `Configuração`.\n",
    );
    let bad = (
        "README.md",
        "## Como instalar o serviço\nEste documento não é opcional para o usuário.\n",
    );
    let untiered = [("README.md", bad.1)];
    let silent = super::probe(&RULE, "untiered", &untiered).is_some_and(|v| v.is_empty());
    vec![
        red_green(&RULE, "tier-a", &[agents, good], &[agents, bad], 1),
        (format!("{} untiered-silent", RULE.id), silent),
    ]
}
