//! `ENV-VAR-WIRED` (GB-187): an environment variable the code reads must be provided by the stack
//! (a compose or stack file, a Dockerfile, a unit) or declared in an env example; otherwise the
//! deploy degrades silently. Compose files come from the scanned repository, or from its sibling
//! `<name>-infra` repository (then only `<NAME>_*` variables are judged). Inert without compose files.
//! `steniocheck.toml`: `[env_wiring] ignore = ["NAME"]`.

use super::{tree, violation};
use crate::engine::Violation;
use crate::rule::Severity;
use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const RULE_ID: &str = "ENV-VAR-WIRED";

/// Provided by the operating system, the runtime or the toolchain.
const AMBIENT: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "PWD",
    "SHELL",
    "TERM",
    "TMPDIR",
    "HOSTNAME",
    "HOST",
    "PORT",
    "CI",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "OUT_DIR",
    "EDITOR",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "NO_COLOR",
    "INVOCATION_ID",
    "NOTIFY_SOCKET",
    "LISTEN_FDS",
];
const AMBIENT_PREFIXES: &[&str] = &["CARGO_", "XDG_", "GITHUB_", "HYPRLAND_", "SYSTEMD_"];

fn is_test_path(rel: &str) -> bool {
    rel.split('/').any(|part| {
        matches!(part, "tests" | "test" | "benches" | "examples" | "fixtures")
            || part.starts_with("test_")
            || part.ends_with("_test.py")
            || part.ends_with("_test.rs")
            || part.ends_with("tests.rs")
    })
}

/// Names the compose-side files provide: YAML keys, `- NAME=` items and interpolations.
fn provided(files: &[PathBuf]) -> (usize, BTreeSet<String>) {
    let mut names = BTreeSet::new();
    let mut composes = 0usize;
    let key = Regex::new(r#"^\s*(?:-\s*)?["']?([A-Z][A-Z0-9_]*)["']?\s*(?:[:=]|$)"#).ok();
    let docker = Regex::new(r"^\s*(?:ENV|ARG|Environment=)\s*\x22?([A-Z][A-Z0-9_]*)").ok();
    for p in files {
        let n = tree::name_of(p);
        let compose = tree::is_compose(p) || tree::is_stack(p);
        let example = n.contains("env") && (n.ends_with(".example") || n.ends_with(".sample"));
        let unit = n.starts_with("Dockerfile") || n.ends_with(".service");
        if !(compose || example || unit) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(p) else {
            continue;
        };
        if compose {
            composes += 1;
            names.extend(tree::interpolations(&content).into_iter().map(|i| i.name));
        }
        if example {
            names.extend(tree::declared_in_example(&content));
        }
        let re = if unit { &docker } else { &key };
        if let Some(re) = re
            && !example
        {
            names.extend(
                content
                    .lines()
                    .filter_map(|l| re.captures(tree::code_part(l)))
                    .map(|c| c[1].to_string()),
            );
        }
    }
    (composes, names)
}

fn config_ignores(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(root.join("steniocheck.toml"))
        .ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .and_then(|t| {
            let list = t.get("env_wiring")?.get("ignore")?.as_array()?;
            Some(
                list.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .unwrap_or_default()
}

pub fn audit(root: &Path, files: &[PathBuf]) -> Vec<Violation> {
    let (mut composes, mut names) = provided(files);
    let mut prefix = None;
    if composes == 0 {
        let Ok(real) = root.canonicalize() else {
            return Vec::new();
        };
        let base = tree::name_of(&real).to_string();
        let sibling = real.with_file_name(format!("{base}-infra"));
        if !sibling.is_dir() {
            return Vec::new();
        }
        let (c, n) = provided(&tree::files(&sibling));
        composes = c;
        names.extend(n);
        prefix = Some(format!("{}_", base.to_ascii_uppercase().replace('-', "_")));
    }
    if composes == 0 {
        return Vec::new();
    }
    let Ok(read) = Regex::new(
        r#"(?:os\.environ\.get\(|os\.environ\[|os\.getenv\(|\benv::var(?:_os)?\()\s*["']([A-Z][A-Z0-9_]*)["'](\s*\]\s*=[^=])?"#,
    ) else {
        return Vec::new();
    };
    let ignored = config_ignores(root);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut sorted: Vec<&PathBuf> = files.iter().collect();
    sorted.sort();
    for p in sorted {
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        let rel = p.strip_prefix(root).unwrap_or(p).to_string_lossy();
        if !matches!(ext, "py" | "rs") || is_test_path(&rel) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(p) else {
            continue;
        };
        for (i, line) in content.lines().enumerate() {
            let t = line.trim_start();
            if ext == "rs" && t.starts_with("#[cfg(test)]") {
                break;
            }
            if t.starts_with('#') || t.starts_with("//") {
                continue;
            }
            for c in read.captures_iter(line) {
                let name = c[1].to_string();
                if c.get(2).is_some()
                    || AMBIENT.contains(&name.as_str())
                    || AMBIENT_PREFIXES.iter().any(|a| name.starts_with(a))
                    || prefix
                        .as_ref()
                        .is_some_and(|p| !name.starts_with(p.as_str()))
                    || names.contains(&name)
                    || ignored.contains(&name)
                    || !seen.insert(name.clone())
                {
                    continue;
                }
                out.push(violation(
                    RULE_ID,
                    "Environment Variable Read But Never Wired",
                    Severity::Warning,
                    p,
                    i + 1,
                    format!("{name} is read here but no compose/stack file passes it and no env example declares it."),
                    "Pass it in the service environment, declare it in .env.example, or list it in [env_wiring] ignore.",
                ));
            }
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let code = "import os\nK = os.environ.get(\"APP_LLM_KEY\")\nos.environ[\"APP_SET\"] = 1\n";
    let compose = "services:\n  a:\n    environment:\n      APP_OTHER: ${APP_OTHER}\n";
    let wired = "services:\n  a:\n    environment:\n      APP_LLM_KEY: ${APP_LLM_KEY:-}\n";
    let run = |tag: &str, files: &[(&str, &str)], sub: &str| {
        let d = super::fixture(tag, files);
        let root = d.join(sub);
        let v = audit(&root, &tree::files(&root));
        let _ = std::fs::remove_dir_all(&d);
        v
    };
    let red = run("w1", &[("m.py", code), ("compose.yml", compose)], "");
    let sibling = run(
        "w5",
        &[
            (
                "app/m.py",
                "import os\nos.getenv(\"APP_LLM_KEY\")\nos.getenv(\"OTHER_X\")\n",
            ),
            ("app-infra/compose.yml", compose),
        ],
        "app",
    );
    vec![
        (
            "env wired: mutation, unwired read is reported at file:line".to_string(),
            red.len() == 1 && red[0].line_number == 2 && red[0].message.contains("APP_LLM_KEY"),
        ),
        (
            "env wired: compose passes it".to_string(),
            run("w2", &[("m.py", code), ("compose.yml", wired)], "").is_empty(),
        ),
        (
            "env wired: env example declares it".to_string(),
            run(
                "w3",
                &[
                    ("m.py", code),
                    ("compose.yml", compose),
                    (".env.example", "# APP_LLM_KEY=\n"),
                ],
                "",
            )
            .is_empty(),
        ),
        (
            "env wired: inert without compose".to_string(),
            run("w4", &[("m.py", code)], "").is_empty(),
        ),
        (
            "env wired: sibling infra repo judged on the project prefix only".to_string(),
            sibling.len() == 1 && sibling[0].message.starts_with("APP_LLM_KEY"),
        ),
    ]
}
