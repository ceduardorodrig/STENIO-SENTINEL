//! `DOC-HOMELAB-ROUTE-DRIFT` (GB-179): every `METHOD /path` row of a service document's
//! endpoint table resolves in the router of the service it documents.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-HOMELAB-ROUTE-DRIFT",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-HOMELAB-ROUTE-DRIFT",
        name: "Documented Route Absent From the Router",
        severity: "ERROR",
        tag: "doc",
        summary: "Table rows `| \\`GET\\` | \\`/path\\` |` of mnemocine/services/<name>.md are compared with the axum `.route(..)` calls of the router. The router is <repos>/mnemocine-ops/provisioning/<name>/src/api.rs, or the file named by `<!-- stenio:router path=... -->`; documents with no router source are not judged. Source is compared, not the running binary.",
        rationale: "GB-179, 2026-11-06: a service document and the deployed gateway disagreed about a route and nothing compared them, so it surfaced as a failed integration.",
        bad_example: "| `GET` | `/v1/jobs` |   # router: .route(\"/v1/jobs\", post(submit))",
        good_example: "| `POST` | `/v1/jobs` |",
        remediation: "Fix the table from the router, or serve the route; add the router marker if the source lives elsewhere.",
    },
};

/// `path -> methods` of every `.route("path", get(..).post(..))` in an axum router source.
fn routes(source: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let (Ok(start), Ok(method)) = (
        Regex::new(r#"\.route\(\s*"([^"]+)"\s*,"#),
        Regex::new(r"(?:^|[^\w])(get|post|put|delete|patch|head|any)\s*\("),
    ) else {
        return out;
    };
    for found in start.captures_iter(source) {
        let Some(whole) = found.get(0) else {
            continue;
        };
        // The handler expression ends where the parenthesis of `.route(` closes.
        let mut depth = 1usize;
        let rest = &source[whole.end()..];
        let end = rest
            .char_indices()
            .find(|(_, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map_or(rest.len(), |(i, _)| i);
        out.entry(shape(&found[1])).or_default().extend(
            method
                .captures_iter(&rest[..end])
                .map(|c| c[1].to_uppercase()),
        );
    }
    out
}

/// Path parameters compare by position, whatever their name or syntax (`{id}`, `:id`).
fn shape(path: &str) -> String {
    path.split('?')
        .next()
        .unwrap_or(path)
        .split('/')
        .map(|s| {
            if s.starts_with(['{', ':', '<']) {
                "{}"
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let (Ok(row), Ok(marker)) = (
        Regex::new(r"^\|\s*`?(GET|POST|PUT|DELETE|PATCH|HEAD)`?\s*\|\s*`(/[^`\s]*)`"),
        Regex::new(r"<!--\s*stenio:router\s+path=(\S+)\s*-->"),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        if !path
            .parent()
            .is_some_and(|d| d.ends_with("mnemocine/services"))
        {
            continue;
        }
        let name = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
        let declared = marker.captures(&content).map(|c| {
            let p = PathBuf::from(&c[1]);
            if p.is_absolute() {
                p
            } else {
                path.parent().map_or(p.clone(), |d| d.join(&p))
            }
        });
        let conventional = ctx
            .repos
            .as_ref()
            .map(|r| r.join(format!("mnemocine-ops/provisioning/{name}/src/api.rs")));
        let Some(source) = declared
            .or(conventional)
            .and_then(|p| fs::read_to_string(p).ok())
        else {
            continue;
        };
        let served = routes(&source);
        if served.is_empty() {
            continue;
        }
        for (idx, line) in prose_lines(&content) {
            let Some(c) = row.captures(line) else {
                continue;
            };
            let methods = served.get(&shape(&c[2]));
            if methods.is_some_and(|m| m.iter().any(|m| m == &c[1] || m == "ANY")) {
                continue;
            }
            let why = methods.map_or_else(
                || "the router has no such path".to_string(),
                |m| format!("the router serves it only for {}", m.join(", ")),
            );
            out.push(finding(
                &RULE.explain,
                Severity::Error,
                ctx.display(&path),
                idx + 1,
                line,
                format!("documented route {} {}: {why}", &c[1], &c[2]),
            ));
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const DOC: &str = "mnemocine/services/svc.md";
    let router = (
        "repos/mnemocine-ops/provisioning/svc/src/api.rs",
        "Router::new()\n  .route(\"/v1/jobs\", post(submit))\n  .route(\n    \"/v1/jobs/{job}\",\n    get(state).delete(drop_it),\n  )\n",
    );
    let good = (
        DOC,
        "| `POST` | `/v1/jobs` |\n| `GET` | `/v1/jobs/{id}` |\n| `DELETE` | `/v1/jobs/{id}` |\n",
    );
    let bad = (DOC, "| `GET` | `/v1/jobs` |\n| `GET` | `/n` |\n");
    vec![red_green(
        &RULE,
        "drift",
        &[router, good],
        &[router, bad],
        2,
    )]
}
