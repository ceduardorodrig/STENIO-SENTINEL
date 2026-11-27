//! `DOC-PANEL-LABEL-EXISTS` (GB-113, GB-114): a panel a client document sends the reader to
//! exists in the application.

use std::collections::HashSet;

use regex::Regex;

use super::panel_app::{catalogue, labels};
use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-PANEL-LABEL-EXISTS",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-PANEL-LABEL-EXISTS",
        name: "Documented Panel Does Not Exist",
        severity: "ERROR",
        tag: "doc",
        summary: "In clients/miracena/**/*.md, each name of a `**Onde isso vive:**` line, and in conteudo-handbook/ each `1. **Name** (Original)` item, must be a sidebar, workspace or dashboard label, its pt-BR translation, or a msgid of locale/pt_BR.po.",
        rationale: "GB-113/GB-114: the onboarding guide named panels (Avaliacoes 360, Links Uteis, Oportunidades Comerciais) that no menu, workspace or catalogue declares; each was checked by hand against the JSON and the .po.",
        bad_example: "**Onde isso vive:** Squads, Propostas e Editais.",
        good_example: "**Onde isso vive:** Squads, Propostas.",
        remediation: "Use the label shown on screen (miracena/desk, miracena/sidebar, locale/pt_BR.po).",
    },
};

/// The names of a `Onde isso vive:` line: `menu X →` prefixes and the lead-in before a dash
/// are not names.
fn listed(rest: &str) -> Vec<&str> {
    let rest = rest.rsplit(['→', '—']).next().unwrap_or(rest);
    let mut out = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (i, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' | ';' if depth == 0 => {
                out.push(&rest[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&rest[start..]);
    out.into_iter()
        .map(|n| n.trim().trim_end_matches('.').trim_matches('*').trim())
        .filter(|n| !n.is_empty())
        .collect()
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Some(app) = ctx.panel_app.as_deref() else {
        return;
    };
    let (Ok(lives), Ok(item)) = (
        Regex::new(r"^\*\*Onde isso vive:?\*\*:?\s*(.+)$"),
        Regex::new(r"^\d+\.\s+\*\*([^*]+)\*\*\s+\(([^)]+)\)"),
    ) else {
        return;
    };
    let mut known: Option<HashSet<String>> = None;
    for (path, content) in ctx.docs() {
        let text = path.to_string_lossy().to_string();
        if !text.contains("clients/miracena/") {
            continue;
        }
        for (idx, line) in prose_lines(&content) {
            let mut names: Vec<&str> = Vec::new();
            if let Some(c) = lives.captures(line) {
                names = c.get(1).map(|m| listed(m.as_str())).unwrap_or_default();
            } else if text.contains("conteudo-handbook/")
                && let Some(c) = item.captures(line)
            {
                names = c.get(1).map(|m| m.as_str().trim()).into_iter().collect();
            }
            if names.is_empty() {
                continue;
            }
            let known = known.get_or_insert_with(|| {
                let po = catalogue(app);
                let mut set: HashSet<String> = po.keys().map(|k| k.to_lowercase()).collect();
                for label in labels(app) {
                    set.extend(po.get(&label).map(|t| t.to_lowercase()));
                    set.insert(label.to_lowercase());
                }
                set
            });
            if known.is_empty() {
                return;
            }
            for name in names {
                // `Membros (o seu registro)` names `Membros`; `Tarefas (Kanban)` is a label.
                let bare = name.split(" (").next().unwrap_or(name);
                if !known.contains(&name.to_lowercase()) && !known.contains(&bare.to_lowercase()) {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Error,
                        ctx.display(&path),
                        idx + 1,
                        line,
                        format!("panel '{name}' is no label of the application"),
                    ));
                }
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const DOC: &str = "clients/miracena/marca-e-conteudo/conteudo-handbook/guia.md";
    let ws = (
        "app/desk/workspace.json",
        "[{\"shortcuts\":[{\"label\":\"Daily Syncs\"},{\"label\":\"Tasks (Kanban)\"}]}]",
    );
    let po = (
        "app/locale/pt_BR.po",
        "msgid \"Daily Syncs\"\nmsgstr \"Sincronias\"\n",
    );
    let good = (
        DOC,
        "**Onde isso vive:** menu X → Sincronias (as suas), Tasks (Kanban).\n1. **Sincronias** (Daily Syncs)\n",
    );
    let bad = (
        DOC,
        "**Onde isso vive:** Sincronias, Links Úteis.\n1. **Mural de Debates** (Debates)\n",
    );
    vec![red_green(
        &RULE,
        "unknown-panel",
        &[ws, po, good],
        &[ws, po, bad],
        2,
    )]
}
