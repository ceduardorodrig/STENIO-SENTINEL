//! `DOC-PDF-COVERS-SOURCE` (GB-141): the published HTML and PDF beside a Markdown document
//! carry every one of its `## ` headings.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-PDF-COVERS-SOURCE",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-PDF-COVERS-SOURCE",
        name: "Published Artifact Is Stale",
        severity: "ERROR",
        tag: "doc",
        summary: "When `<name>.html` or `<name>.pdf` (beside the document or in `pdf/`) is published from `<name>.md`, every `## ` heading must appear in it. PDF text is read with `pdftotext`; without it the PDF is not judged.",
        rationale: "GB-141: two manuals were updated while the .html and .pdf beside them kept the previous day, and only a human opening them would notice.",
        bad_example: "manual.md has `## 8. Refusals`; manual.pdf ends at section 7",
        good_example: "regenerate the artifact after editing the Markdown",
        remediation: "Regenerate the stale artifact from the Markdown.",
    },
};

/// Letters and digits only: line breaks, hyphenation, quotes and markup differ per format.
fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn text_of(artifact: &Path) -> Option<String> {
    if artifact.extension().is_some_and(|e| e == "pdf") {
        let run = Command::new("pdftotext")
            .args(["-q", "-enc", "UTF-8"])
            .arg(artifact)
            .arg("-")
            .output()
            .ok()?;
        return Some(String::from_utf8_lossy(&run.stdout).into_owned()).filter(|t| !t.is_empty());
    }
    let html = fs::read_to_string(artifact).ok()?;
    let tags = Regex::new(r"<[^>]*>").ok()?;
    Some(
        tags.replace_all(&html, " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&nbsp;", " "),
    )
}

fn published(source: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(stem)) = (source.parent(), source.file_stem()) else {
        return Vec::new();
    };
    let stem = stem.to_string_lossy();
    [dir.to_path_buf(), dir.join("pdf")]
        .iter()
        .flat_map(|d| ["html", "pdf"].map(|e| d.join(format!("{stem}.{e}"))))
        .filter(|p| p.is_file())
        .collect()
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Ok(markup) = Regex::new(r"\]\([^)]*\)|\{[#.][^}]*\}|<[^>]*>") else {
        return;
    };
    for (path, content) in ctx.docs() {
        for artifact in published(&path) {
            let Some(text) = text_of(&artifact).map(|t| squash(&t)) else {
                continue;
            };
            let missing: Vec<(usize, &str)> = prose_lines(&content)
                .into_iter()
                .filter(|(_, l)| l.starts_with("## "))
                .filter(|(_, l)| !text.contains(&squash(&markup.replace_all(l, ""))))
                .collect();
            if let Some((idx, heading)) = missing.first() {
                out.push(finding(
                    &RULE.explain,
                    Severity::Error,
                    ctx.display(&path),
                    idx + 1,
                    heading,
                    format!(
                        "{} is stale: {} heading(s) missing, first '{}'",
                        ctx.display(&artifact),
                        missing.len(),
                        heading.trim_start_matches('#').trim()
                    ),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    let source = ("g.md", "# T\n## 1. Panels & rules\n## 2. New part\n");
    let good = (
        "g.html",
        "<h2 id=\"p\">1. Panels &amp;\nrules</h2><h2>2. New <em>part</em></h2>\n",
    );
    let stale = ("g.html", "<h2>1. Panels &amp; rules</h2>\n");
    vec![red_green(
        &RULE,
        "stale-html",
        &[source, good],
        &[source, stale],
        1,
    )]
}
