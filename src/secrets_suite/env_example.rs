//! `COMPOSE-ENV-EXAMPLE-PARITY` (GB-195): every variable a compose file interpolates is declared
//! in the `.env.example` beside it. Error when the interpolation has no default (a blank value at
//! `up -d`), Warning when it has one. Inert for a compose file with no sibling example.

use super::{tree, violation};
use crate::engine::Violation;
use crate::rule::Severity;
use std::collections::BTreeSet;
use std::path::PathBuf;

pub const RULE_ID: &str = "COMPOSE-ENV-EXAMPLE-PARITY";
/// Set by compose or the shell, never by the operator.
const PROVIDED: &[&str] = &[
    "COMPOSE_PROJECT_NAME",
    "HOME",
    "PWD",
    "USER",
    "UID",
    "GID",
    "HOSTNAME",
];

pub fn audit(files: &[PathBuf]) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut composes: Vec<&PathBuf> = files.iter().filter(|p| tree::is_compose(p)).collect();
    composes.sort();
    let mut reported = BTreeSet::new();
    for compose in composes {
        let example = compose.with_file_name(".env.example");
        let (Ok(declared), Ok(content)) = (
            std::fs::read_to_string(&example),
            std::fs::read_to_string(compose),
        ) else {
            continue;
        };
        let declared = tree::declared_in_example(&declared);
        let mut uses = tree::interpolations(&content);
        // A use without a default decides the severity of its variable.
        uses.sort_by_key(|u| (u.has_default, u.line));
        for u in uses {
            if declared.contains(&u.name)
                || PROVIDED.contains(&u.name.as_str())
                || !reported.insert((example.clone(), u.name.clone()))
            {
                continue;
            }
            let severity = if u.has_default {
                Severity::Warning
            } else {
                Severity::Error
            };
            out.push(violation(
                RULE_ID,
                "Compose Variable Missing From The Env Example",
                severity,
                &example,
                1,
                format!(
                    "{} is interpolated at {}:{} but not declared here.",
                    u.name,
                    tree::name_of(compose),
                    u.line
                ),
                "Add a `NAME=` line (empty or commented) to .env.example and to the host .env.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let compose = "services:\n  a:\n    image: x:${TAG}\n    environment:\n      K: ${APP_KEY:-}\n      D: $$NOT_ONE\n# ${COMMENTED}\n";
    let run = |tag: &str, example: Option<&str>| {
        let mut files = vec![("s/compose.yml", compose)];
        if let Some(e) = example {
            files.push(("s/.env.example", e));
        }
        let d = super::fixture(tag, &files);
        let v = audit(&tree::files(&d));
        let _ = std::fs::remove_dir_all(&d);
        v
    };
    let red = run("x1", Some("TAG=1\n"));
    let hard = run("x2", Some("# APP_KEY=\n"));
    vec![
        (
            "env example: full parity is clean".to_string(),
            run("x0", Some("TAG=1\n# APP_KEY=\n")).is_empty(),
        ),
        (
            "env example: mutation, removed line names variable and compose line".to_string(),
            red.len() == 1
                && red[0].file_path.ends_with(".env.example")
                && red[0]
                    .message
                    .starts_with("APP_KEY is interpolated at compose.yml:5")
                && red[0].severity == Severity::Warning,
        ),
        (
            "env example: variable without default is an error".to_string(),
            hard.len() == 1 && hard[0].severity == Severity::Error,
        ),
        (
            "env example: inert without an example file".to_string(),
            run("x3", None).is_empty(),
        ),
    ]
}
