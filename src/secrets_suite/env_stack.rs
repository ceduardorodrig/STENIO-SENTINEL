//! `STACK-ENV-REQUIRED-HAS-CONSUMER` (GB-190): a `${VAR:?...}` handed to a container under its own
//! name blocks `docker stack deploy` when unset, so some code must read it. Variables interpolated
//! into another key, command or URL are consumed by compose itself and are not judged, nor are the
//! settings third-party images read. Warning during rollout (the Hub had ten hits on 2026-11-26).
//! `steniocheck.toml`: `[stack_env] external = ["NAME"]`.

use super::{tree, violation};
use crate::engine::Violation;
use crate::rule::Severity;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const RULE_ID: &str = "STACK-ENV-REQUIRED-HAS-CONSUMER";

/// Read by third-party images, not by repository code.
const IMAGE_PREFIXES: &[&str] = &[
    "POSTGRES_",
    "PG",
    "MYSQL_",
    "MARIADB_",
    "MONGO_",
    "REDIS_",
    "VALKEY_",
    "GF_",
    "MINIO_",
    "TS_",
    "TZ",
    "BORG_",
    "RABBITMQ_",
    "KEYCLOAK_",
];
const CODE_EXTENSIONS: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "py", "sh", "bash", "toml", "conf",
];

fn external(root: &Path) -> Vec<String> {
    std::fs::read_to_string(root.join("steniocheck.toml"))
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| {
            let list = t.get("stack_env")?.get("external")?.as_array()?;
            Some(
                list.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .unwrap_or_default()
}

fn mentions(content: &str, name: &str) -> bool {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    content.match_indices(name).any(|(i, _)| {
        !word(content[..i].chars().next_back()) && !word(content[i + name.len()..].chars().next())
    })
}

/// True when the line passes `${NAME:?...}` to the environment key `NAME` and nothing else.
fn passes_under_own_name(line: &str, name: &str) -> bool {
    let t = tree::code_part(line).trim().trim_start_matches("- ");
    let Some((key, value)) = t.split_once(['=', ':']) else {
        return false;
    };
    let value = value.trim().trim_matches(['"', '\'']);
    key.trim().trim_matches(['"', '\'']) == name
        && value.starts_with(&format!("${{{name}"))
        && value.ends_with('}')
}

pub fn audit(root: &Path, files: &[PathBuf]) -> Vec<Violation> {
    let ignored = external(root);
    let mut wanted: BTreeMap<String, (&PathBuf, usize)> = BTreeMap::new();
    for p in files.iter().filter(|p| tree::is_stack(p)) {
        let Ok(content) = std::fs::read_to_string(p) else {
            continue;
        };
        let lines: Vec<&str> = content.lines().collect();
        for i in tree::interpolations(&content) {
            let own = lines
                .get(i.line - 1)
                .is_some_and(|l| passes_under_own_name(l, &i.name));
            if i.required
                && own
                && !IMAGE_PREFIXES.iter().any(|x| i.name.starts_with(x))
                && !ignored.contains(&i.name)
            {
                wanted.entry(i.name).or_insert((p, i.line));
            }
        }
    }
    for p in files {
        if wanted.is_empty() {
            break;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !CODE_EXTENSIONS.contains(&ext) || tree::name_of(p) == "steniocheck.toml" {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(p) {
            wanted.retain(|name, _| !mentions(&content, name));
        }
    }
    wanted
        .into_iter()
        .map(|(name, (path, line))| {
            violation(
                RULE_ID,
                "Mandatory Stack Variable Without A Consumer",
                Severity::Warning,
                path,
                line,
                format!("{name} is mandatory (`:?`) but no code in the repository reads it."),
                "Use `${VAR:-}`, remove it, or list it in [stack_env] external when an image reads it.",
            )
        })
        .collect()
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let stack = |op: &str| {
        format!(
            "services:\n  a:\n    environment:\n      HF_TOKEN: ${{HF_TOKEN{op}}}\n      URL: pg://u:${{DB_PW:?x}}@db\n      POSTGRES_PASSWORD: ${{POSTGRES_PASSWORD:?x}}\n"
        )
    };
    let run = |tag: &str, op: &str, code: &str| {
        let s = stack(op);
        let d = super::fixture(
            tag,
            &[
                ("provisioning/stacks/core.yml", s.as_str()),
                ("app/server/src/main.rs", code),
            ],
        );
        let v = audit(&d, &tree::files(&d));
        let _ = std::fs::remove_dir_all(&d);
        v
    };
    let red = run("s1", ":?HF_TOKEN", "let t = var(\"HF_TOKEN_FILE\");\n");
    vec![
        (
            "stack env: mutation, dead mandatory variable fails".to_string(),
            red.len() == 1 && red[0].line_number == 4 && red[0].severity == Severity::Warning,
        ),
        (
            "stack env: optional form passes".to_string(),
            run("s2", ":-", "\n").is_empty(),
        ),
        (
            "stack env: a consumer passes".to_string(),
            run("s3", ":?x", "let t = var(\"HF_TOKEN\");\n").is_empty(),
        ),
    ]
}
