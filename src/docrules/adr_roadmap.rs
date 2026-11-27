//! `DOC-ADR-NO-REJECTED-ROADMAP` (GB-180): an ADR does not decide, or schedule, what it also
//! rejects.

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-ADR-NO-REJECTED-ROADMAP",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-ADR-NO-REJECTED-ROADMAP",
        name: "ADR Plans What It Rejects",
        severity: "WARN",
        tag: "doc",
        summary: "A component named (in backticks) in the bold title of a rejected alternative must not appear affirmatively in the Decision section or in a phase/step section of the same ADR; a `Phase N` section (N >= 2) the Decision never mentions is flagged too.",
        rationale: "GB-180, 2026-11-06: ADR-0006 described a second phase with six implementation duties for a path the owner had already discarded; it was coherent, dated and passed every document rule.",
        bad_example: "## Decision\nRun a `lease-daemon` on the GPU.\n## Rejected alternatives\n- **Local route through `lease-daemon`.** Discarded.",
        good_example: "## Decision\nOne remote backend; no local route.\n## Rejected alternatives\n- **Local route through `lease-daemon`.** Discarded.",
        remediation: "Remove the rejected path from the decision and its phases, or move it back out of the rejected list with the decision that authorizes it.",
    },
};

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Decision,
    Rejected,
    Phase(u32),
    Other,
}

/// Runs of consecutive non-blank lines of the Decision and phase sections.
fn paragraphs<'a>(body: &[(Section, usize, &'a str)]) -> Vec<Vec<(usize, &'a str)>> {
    let mut out: Vec<Vec<(usize, &str)>> = vec![Vec::new()];
    for (section, idx, line) in body {
        let planned = matches!(section, Section::Decision | Section::Phase(_));
        let starts_item = line.starts_with('#') || line.trim_start().starts_with("- ");
        if !planned || line.trim().is_empty() || starts_item {
            out.push(Vec::new());
        }
        if planned
            && !line.trim().is_empty()
            && let Some(last) = out.last_mut()
        {
            last.push((*idx, line));
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

fn line_at<'a>(paragraph: &[(usize, &'a str)], offset: usize) -> (usize, &'a str) {
    let mut end = 0;
    for (idx, line) in paragraph {
        end += line.len() + 1;
        if offset < end {
            return (*idx, line);
        }
    }
    paragraph.last().copied().unwrap_or((0, ""))
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(adr_name), Ok(decision), Ok(rejected), Ok(phase), Ok(term), Ok(negation), Ok(bold)) = (
        Regex::new(r"(?i)^adr[-_]?\d+.*\.md$"),
        Regex::new(r"(?i)^(?:\d+[.)]?\s*)?(?:decision|decisão|decisao)\b"),
        Regex::new(r"(?i)(?:rejected|discarded|rejeitad|descartad)|alternativ"),
        Regex::new(r"(?i)\b(?:phase|fase)\s+([2-9])\b"),
        Regex::new(r"`([\w.:/-]{3,60})`"),
        Regex::new(
            r"(?i)\b(?:não|nao|nunca|nenhum\w*|sem|proibid\w*|fora|descartad\w*|rejeitad\w*|not|no|never|without|forbidden|banned|discarded|rejected|instead of|em vez)\b",
        ),
        Regex::new(r"^\s*(?:[-*]|\d+\.)\s+\*\*(.+?)\*\*"),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let in_adr_dir = path.parent().is_some_and(|d| d.ends_with("adr"));
        if !(adr_name.is_match(name) || in_adr_dir && name != "README.md") {
            continue;
        }
        let mut section = Section::Other;
        let mut level = 0;
        let mut body: Vec<(Section, usize, &str)> = Vec::new();
        for (idx, line) in prose_lines(&content) {
            let hashes = line.chars().take_while(|c| *c == '#').count();
            if hashes > 0 && line[hashes..].starts_with(' ') {
                let title = line[hashes..].trim();
                let found = if decision.is_match(title) {
                    Some(Section::Decision)
                } else if rejected.is_match(title) {
                    Some(Section::Rejected)
                } else {
                    phase
                        .captures(title)
                        .and_then(|c| c[1].parse().ok())
                        .map(Section::Phase)
                };
                // A subsection stays inside its parent section.
                match found {
                    Some(s) => (section, level) = (s, hashes),
                    None if hashes <= level => (section, level) = (Section::Other, hashes),
                    None => {}
                }
                if let Some(Section::Phase(_)) = found {
                    body.push((section, idx, line));
                }
                continue;
            }
            body.push((section, idx, line));
        }

        let mut rejects: Vec<(String, usize)> = Vec::new();
        for (s, idx, line) in &body {
            if *s == Section::Rejected
                && let Some(title) = bold.captures(line)
            {
                // `x como padrão` rejects a role, not the component: both sentences about it
                // are then judged by the negation filter below.
                rejects.extend(
                    term.captures_iter(&title[1])
                        .map(|c| (c[1].to_string(), *idx)),
                );
            }
        }
        let decided = body
            .iter()
            .filter(|(s, _, _)| *s == Section::Decision)
            .map(|(_, _, l)| *l)
            .collect::<Vec<_>>()
            .join(" ");
        let file = ctx.display(&path);
        // A negation governs its whole sentence, which may wrap over several lines.
        for paragraph in paragraphs(&body) {
            let text: String = paragraph.iter().map(|(_, l)| format!("{l} ")).collect();
            let mut offset = 0;
            for sentence in text.split_inclusive(". ") {
                if !negation.is_match(sentence) {
                    for (what, at) in &rejects {
                        let Some(found) = sentence.find(&format!("`{what}`")) else {
                            continue;
                        };
                        let (idx, line) = line_at(&paragraph, offset + found);
                        out.push(finding(
                            &RULE.explain,
                            Severity::Warning,
                            file.clone(),
                            idx + 1,
                            line,
                            format!("`{what}` is planned here and rejected at line {}", at + 1),
                        ));
                    }
                }
                offset += sentence.len();
            }
        }
        for (s, idx, line) in &body {
            if let Section::Phase(n) = s
                && line.starts_with('#')
                && !decided.is_empty()
                && !phase.captures_iter(&decided).any(|c| c[1] == n.to_string())
            {
                out.push(finding(
                    &RULE.explain,
                    Severity::Warning,
                    file.clone(),
                    idx + 1,
                    line,
                    format!("phase {n} has a section, but the Decision never authorizes it"),
                ));
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const ADR: &str = "adr-0001-x.md";
    const GOOD: &str = "# A\n## Decision\nOne remote backend. There is no `lease-daemon` route.\n## Rejected alternatives\n- **Local `lease-daemon` route.** Discarded.\n";
    let planned = GOOD.replace(
        "There is no `lease-daemon` route",
        "Jobs lease from `lease-daemon`",
    );
    let phased = format!("{GOOD}## Phase 2\nLater.\n");
    vec![
        red_green(&RULE, "planned", &[(ADR, GOOD)], &[(ADR, &planned)], 1),
        red_green(&RULE, "phase", &[(ADR, GOOD)], &[(ADR, &phased)], 1),
    ]
}
