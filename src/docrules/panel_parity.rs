//! `DOC-PANEL-PARITY` (GB-115): the menu and permission tables of the platform manuals say what
//! the application declares.

use std::collections::BTreeSet;

use super::contract_parity::{cells, tables};
use super::panel_app::{menu, permissions};
use super::{Ctx, DocRule, finding, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-PANEL-PARITY",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-PANEL-PARITY",
        name: "Manual Menu or Permission Table Drift",
        severity: "WARN",
        tag: "doc",
        summary: "In clients/miracena/plataforma/*.md: the `Secao do menu | Itens` table lists exactly the sidebar links, and the `Registro | Membro | Freelancer | Cliente | Auditor` table (L read, E write, C create, D delete) matches the level-0 permissions of each DocType JSON. Cards, dashboards and refusal messages are not judged.",
        rationale: "GB-115: 13 permission rows were compared with the DocType JSON by hand; nothing compares the manual with the application, so it ages silently.",
        bad_example: "| Task | L | — |   # task.json grants Member read, write and create",
        good_example: "| Task | L E C | L E |",
        remediation: "Correct the table from the application (or the DocType permissions, if the manual states the decision).",
    },
};

const ROLES: &[(&str, &str)] = &[
    ("Membro", "Miracena Member"),
    ("Freelancer", "Miracena Freelancer"),
    ("Cliente", "Miracena Client"),
    ("Auditor", "Miracena Auditor"),
];

/// The grants a cell states: notes in parentheses removed, `L E C D` read as flags.
fn granted(cell: &str) -> Option<[bool; 4]> {
    let mut depth = 0usize;
    let bare: String = cell
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
            depth == 0
        })
        .collect();
    let mut flags = [false; 4];
    for word in bare.split_whitespace() {
        match word {
            "L" => flags[0] = true,
            "E" => flags[1] = true,
            "C" => flags[2] = true,
            "D" => flags[3] = true,
            "—" | "-" | "·" => {}
            // Prose: the cell cannot be judged.
            _ => return None,
        }
    }
    Some(flags)
}

fn spell(flags: [bool; 4]) -> String {
    let letters: Vec<&str> = ["L", "E", "C", "D"]
        .iter()
        .zip(flags)
        .filter_map(|(l, on)| on.then_some(*l))
        .collect();
    if letters.is_empty() {
        "—".to_string()
    } else {
        letters.join(" ")
    }
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Some(app) = ctx.panel_app.as_deref() else {
        return;
    };
    for (path, content) in ctx.docs() {
        if !path
            .to_string_lossy()
            .contains("clients/miracena/plataforma/")
        {
            continue;
        }
        let file = ctx.display(&path);
        let mut push = |line: usize, snippet: &str, message: String| {
            out.push(finding(
                &RULE.explain,
                Severity::Warning,
                file.clone(),
                line + 1,
                snippet,
                message,
            ));
        };
        for table in tables(&content) {
            let head: Vec<&str> = table.header.iter().map(String::as_str).collect();
            if head.first() == Some(&"Seção do menu") {
                let listed: BTreeSet<String> = table
                    .rows
                    .iter()
                    .skip(1)
                    .filter_map(|(_, r)| cells(r).get(1).cloned())
                    .flat_map(|c| {
                        c.split(',')
                            .map(|s| s.trim().to_string())
                            .collect::<Vec<_>>()
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                let real: BTreeSet<String> = menu(app).into_iter().collect();
                if real.is_empty() {
                    continue;
                }
                for (idx, row) in table.rows.iter().skip(1) {
                    let items = cells(row).get(1).cloned().unwrap_or_default();
                    for item in items.split(',').map(str::trim) {
                        if !item.is_empty() && !real.contains(item) {
                            push(
                                *idx,
                                row,
                                format!("menu item '{item}' is not a link of the sidebar JSON"),
                            );
                        }
                    }
                }
                for missing in real.difference(&listed) {
                    push(
                        table.line,
                        missing,
                        format!("sidebar link '{missing}' is missing from the menu table"),
                    );
                }
                continue;
            }
            let columns: Vec<(usize, &str)> = head
                .iter()
                .enumerate()
                .filter_map(|(i, h)| ROLES.iter().find(|(l, _)| l == h).map(|(_, r)| (i, *r)))
                .collect();
            if head.first() != Some(&"Registro") || columns.is_empty() {
                continue;
            }
            let doctypes = permissions(app);
            for (idx, row) in table.rows.iter().skip(1) {
                let row_cells = cells(row);
                let record = row_cells.first().map(String::as_str).unwrap_or("");
                for name in record.split(" / ") {
                    let Some((source, roles)) = doctypes.get(name) else {
                        continue;
                    };
                    for (col, role) in &columns {
                        let Some(said) = row_cells.get(*col).and_then(|c| granted(c)) else {
                            continue;
                        };
                        let real = roles.get(*role).copied().unwrap_or_default();
                        if said != real {
                            push(
                                *idx,
                                row,
                                format!(
                                    "{name} / {role}: the table says '{}', {} grants '{}'",
                                    spell(said),
                                    source.strip_prefix(app).unwrap_or(source).display(),
                                    spell(real)
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const DOC: &str = "clients/miracena/plataforma/manual.md";
    let task = (
        "app/m/doctype/task/task.json",
        "{\"doctype\":\"DocType\",\"name\":\"Task\",\"permissions\":[{\"role\":\"Miracena Member\",\"read\":1,\"write\":1}]}",
    );
    let side = (
        "app/sidebar/m/m.json",
        "{\"items\":[{\"type\":\"Link\",\"label\":\"Tasks\"}]}",
    );
    const GOOD: &str = "| Seção do menu | Itens |\n|---|---|\n| Op | Tasks |\n\n| Registro | Membro | Auditor |\n|---|---|---|\n| Task | L E (só o próprio) | — |\n";
    let role = GOOD.replace("L E (só o próprio)", "L");
    let label = GOOD.replace("| Op | Tasks |", "| Op | Tarefas |");
    vec![
        red_green(
            &RULE,
            "permission",
            &[task, side, (DOC, GOOD)],
            &[task, side, (DOC, &role)],
            1,
        ),
        // The renamed item is wrong and the real link is now missing.
        red_green(
            &RULE,
            "menu",
            &[task, side, (DOC, GOOD)],
            &[task, side, (DOC, &label)],
            2,
        ),
    ]
}
