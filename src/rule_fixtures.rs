//! One tree that must be reported and one that must not, for every rule of the registry. The
//! list under test is the registry itself: a rule without a case, or whose pattern stops
//! matching, turns `cargo test` red.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::SteniocheckConfig;
use crate::pipeline::{self, Request};
use crate::rule::get_rules_from_config;

#[derive(Clone, Copy, PartialEq)]
enum How {
    /// A full scan under the scope.
    Scan(&'static str),
    /// The delivery gate.
    Gate,
    /// `--diff staged` over a Git tree.
    Staged,
}

struct Case {
    id: &'static str,
    how: How,
    path: &'static str,
    bad: String,
    good: String,
    /// `steniocheck.toml` of both trees, for a rule that judges only what is declared.
    config: &'static str,
}

fn case(id: &'static str, path: &'static str, bad: &str, good: &str) -> Case {
    Case {
        id,
        how: How::Scan("project"),
        path,
        bad: format!("{bad}\n"),
        good: format!("{good}\n"),
        config: "",
    }
}

fn special(how: How, id: &'static str, path: &'static str, bad: &str, good: &str) -> Case {
    Case {
        how,
        ..case(id, path, bad, good)
    }
}

/// Sources are assembled from pieces so that this file holds no line a rule would report.
fn cases() -> Vec<Case> {
    const SERVER: &str = "app/server/src/api.rs";
    let duplicated: String = (0..9)
        .map(|n| format!("    let value_{n} = compute_total(input, {n}) + offset_{n};\n"))
        .collect();
    let block = format!("pub fn first(input: u8) {{\n{duplicated}}}\n");
    vec![
        case("ARCH-NO-PYTHON", "a.py", "x = 1", ""),
        case("SEC-BAN-TORCH", "a.py", "import torch", "import os"),
        case(
            "SEC-BAN-CTRANSLATE2",
            "a.py",
            "from ctranslate2 import x",
            "import os",
        ),
        case(
            "ARCH-BANNED-MODULES",
            "app/a.py",
            "import worker_vision",
            "import os",
        ),
        case("SEC-SUDO", "a.sh", concat!("su", "do rm x"), "rm x"),
        case(
            "SEC-SECRETS",
            "a.rs",
            concat!("let k = \"AK", "IAABCDEFGHIJKLMNOP12\";"),
            "let k = env_key();",
        ),
        case(
            "SEC-SQL",
            "a.py",
            "q = f\"SELECT * FROM t WHERE id = {x}\"",
            "q = \"SELECT * FROM t WHERE id = %s\"",
        ),
        case("SEC-EXCEPT", "a.py", "except:", "except ValueError:"),
        case(
            "FRONT-ZUSTAND",
            "a.ts",
            "const s = useAppStore((state) => {",
            "const s = useAppStore(useShallow(pick))",
        ),
        case(
            "FRONT-LOGS",
            "a.ts",
            concat!("console.", "log(1)"),
            "logger.info(1)",
        ),
        case(
            "INFRA-WS-BUFFERING",
            "a.conf",
            "proxy_pass http://up; # ws",
            "proxy_pass http://up;",
        ),
        case(
            "ARCH-RUST-TOOLS",
            "a.sh",
            concat!("gr", "ep -r x ."),
            "rg x",
        ),
        case(
            "RUST-ASYNC-SLEEP",
            "a.rs",
            concat!("async fn f() { std::thread::", "sleep(d); }"),
            "async fn f() { tokio::time::sleep(d).await; }",
        ),
        case(
            "RUST-STRUCTURED-LOGGING",
            SERVER,
            concat!("print", "ln!(\"x\");"),
            "tracing::info!(\"x\");",
        ),
        case(
            "ARCH-RUST-CMD-LEGACY",
            "a.rs",
            concat!("Command::new(\"cu", "rl\")"),
            "Command::new(\"xh\")",
        ),
        case("RUST-NO-UNWRAP", "a.rs", concat!("x.", "unwrap();"), "x?;"),
        case(
            "RUST-CANONICAL-REMOTE",
            "a.rs",
            concat!("Command::new(\"s", "sh\")"),
            "crate::remote::run_ssh(host)",
        ),
        case(
            "AGENT-NO-LAZY-STUB",
            "a.rs",
            concat!("to", "do!()"),
            "Ok(())",
        ),
        case(
            "AGENT-NO-SUPPRESSION-DIRECTIVES",
            "a.ts",
            concat!("// @ts-", "ignore"),
            "// typed",
        ),
        case(
            "AGENT-NO-TAMPERING-VERIFIER",
            "a.sh",
            concat!("git commit -m x --no-", "verify"),
            "git commit -m x",
        ),
        case(
            "CONF-NO-WEAKEN-STRICT",
            "tsconfig.json",
            concat!("{\"strict\": ", "false}"),
            "{\"strict\": true}",
        ),
        case(
            "TEST-NO-SILENT-SKIP",
            "a.ts",
            concat!("it.", "skip('x')"),
            "it('x')",
        ),
        case(
            "CODE-NO-EMPTY-CATCH",
            "a.ts",
            concat!("try { f() } catch (e) ", "{}"),
            "try { f() } catch (e) { report(e) }",
        ),
        case(
            "CODE-NO-PORTUGUESE-COMMENTS",
            "a.rs",
            concat!("// essa fun", "ção não faz nada quando o usuário já saiu"),
            "// this function does nothing once the user has left",
        ),
        case(
            "BACKEND-BLOCKING-IO",
            SERVER,
            concat!("std::fs::", "read(p)"),
            "tokio::fs::read(p)",
        ),
        case(
            "BACKEND-NO-PANIC",
            SERVER,
            concat!("pan", "ic!(\"x\");"),
            "return Err(e);",
        ),
        case(
            "BACKEND-NO-HARDCODED-TEXT",
            SERVER,
            concat!("return Err(\"usuário não encon", "trado\");"),
            "return Err(\"USER_NOT_FOUND\");",
        ),
        special(
            How::Gate,
            "ARCH-DRY-DUPLICATION",
            "a.rs",
            &format!("{block}{}", block.replace("first", "second")),
            &block,
        ),
        special(
            How::Staged,
            "ARCH-SCOPE-ISOLATION",
            "governance/stenio/src/x.rs",
            "fn x() {}",
            "",
        ),
        case(
            "PERF-GPU-ZERO-REPAINT",
            "a.css",
            ".a { transition: box-shadow 1s; }",
            ".a { transition: opacity 1s; }",
        ),
        case(
            "PERF-NO-LAYOUT-THRASH",
            "a.tsx",
            "el.getBoundingClientRect()",
            "cachedRect.current",
        ),
        case("PERF-GPU-CONTAINMENT", "a.tsx", "<MagicCard />", "<Card />"),
        case(
            "PERF-GPU-WILL-CHANGE",
            "a.css",
            ".a { will-change: transform; }",
            ".a:hover { color: red; }",
        ),
        case(
            "FRONT-MODULAR-HOOKS",
            "pages/a.tsx",
            "fetch(url)",
            "useData()",
        ),
        case(
            "FRONT-FEEDBACK-ON-ERROR",
            "a.tsx",
            concat!("console.", "error(e)"),
            "toast.error(e)",
        ),
        case(
            "FRONT-NO-HARDCODED-HOST",
            "web/src/a.ts",
            concat!("const u = \"http://local", "host:3000/api\";"),
            "const u = \"/api\";",
        ),
        special(
            How::Scan("hub"),
            "DB-IDEMPOTENT-MIGRATION",
            "migrations/v1.0_a.sql",
            "CREATE TABLE a (id int);",
            "CREATE TABLE IF NOT EXISTS a (id int);",
        ),
        case(
            "RUST-NO-UNBOUNDED-CHANNEL",
            "a.rs",
            concat!("mpsc::unbounded_", "channel()"),
            "mpsc::channel(8)",
        ),
        case(
            "RUST-ASYNC-BLOCKING-CMD",
            SERVER,
            concat!("std::process::", "Command::new(\"xh\")"),
            "tokio::process::Command::new(\"xh\")",
        ),
        case(
            "RUST-NO-SYNC-MUTEX-AWAIT",
            SERVER,
            concat!("use std::sync::", "Mutex;"),
            "use tokio::sync::Mutex;",
        ),
        case(
            "RUST-IDIOMATIC-ARC-CLONE",
            "a.rs",
            "let x = shared_state.clone();",
            "let x = Arc::clone(&state);",
        ),
        case(
            "RUST-IDIOMATIC-SLICES",
            "a.rs",
            "fn f(a: &String) {}",
            "fn f(a: &str) {}",
        ),
        case(
            "RUST-SPAWN-ERROR-HANDLING",
            SERVER,
            "tokio::spawn(async move {",
            "let h = tokio::spawn(run());",
        ),
        special(
            How::Scan("hub"),
            "GOV-NAMING-KEBAB-CASE",
            "docs/Bad_Name/a.md",
            "text",
            "",
        ),
        Case {
            config: "[topology]\nbackend_nodes = [\"node-a\"]\n",
            ..case(
                "INFRA-TOPOLOGY-COMPLIANCE",
                "deploy.sh",
                "export DEPLOY_HOST=\"admin@old-node\"",
                "export DEPLOY_HOST=\"admin@node-a.example.net:22\"\nDEPLOY_TARGET=$1",
            )
        },
    ]
}

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The tree of one case: its file (none for an empty text), its configuration and, for a staged
/// case, a Git index.
fn plant(root: &Path, case: &Case, content: &str) -> Result<(), String> {
    let text = |e: std::io::Error| e.to_string();
    let _ = fs::remove_dir_all(root);
    // An empty text stands for the tree without the file.
    fs::create_dir_all(root).map_err(text)?;
    if !content.trim().is_empty() {
        let file = root.join(case.path);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir).map_err(text)?;
        }
        fs::write(file, content).map_err(text)?;
    }
    if !case.config.is_empty() {
        fs::write(root.join("steniocheck.toml"), case.config).map_err(text)?;
    }
    if case.how == How::Staged {
        // Scope isolation fires when the engine and an application change together.
        fs::write(root.join("app.rs"), "fn app() {}\n").map_err(text)?;
        for args in [&["init", "-q"][..], &["add", "-A"][..]] {
            let status = Command::new("git")
                .current_dir(root)
                .args(args)
                .status()
                .map_err(text)?;
            if !status.success() {
                return Err(format!("git {args:?} failed"));
            }
        }
    }
    Ok(())
}

fn reported(case: &Case, content: &str, label: &str) -> Result<bool, String> {
    let text = |e: std::io::Error| e.to_string();
    let root = Tree(std::env::temp_dir().join(format!(
        "stenio-rule-{}-{}-{label}",
        std::process::id(),
        case.id
    )));
    plant(&root.0, case, content)?;
    let request = Request {
        path: root.0.clone(),
        path_explicit: true,
        scope: match case.how {
            How::Scan(scope) => Some(scope.to_string()),
            _ => Some("project".to_string()),
        },
        gate: case.how == How::Gate,
        diff: (case.how == How::Staged).then(|| "staged".to_string()),
        ..Request::default()
    };
    let outcome = pipeline::run(&request)?;
    Ok(outcome
        .report
        .violations
        .iter()
        .any(|v| v.rule_id == case.id))
}

#[test]
fn every_rule_of_the_registry_fires_on_its_fixture_and_only_there() -> Result<(), String> {
    let rules = get_rules_from_config(&SteniocheckConfig::default());
    let cases = cases();
    let uncovered: Vec<&str> = rules
        .iter()
        .map(|r| r.id.as_str())
        .filter(|id| !cases.iter().any(|c| c.id == *id))
        .collect();
    assert!(
        uncovered.is_empty(),
        "rules without fixtures: {uncovered:?}"
    );
    let mut wrong = Vec::new();
    for case in &cases {
        if !rules.iter().any(|r| r.id == case.id) {
            wrong.push(format!("{}: fixture of a rule that is gone", case.id));
        }
        if !reported(case, &case.bad, "bad")? {
            wrong.push(format!("{}: silent on its positive fixture", case.id));
        }
        if reported(case, &case.good, "good")? {
            wrong.push(format!("{}: fires on its negative fixture", case.id));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    Ok(())
}

/// GB-375: the scan and the delivery gate are one pipeline. Under the default scope they report
/// the same errors on every fixture; under a narrow scope the gate only adds (it also judges
/// governance, documentation and the queues, deliberately).
#[test]
fn the_gate_reports_what_the_scan_reports_on_every_fixture() -> Result<(), String> {
    // Duplication and engine integrity are judged by the gate alone.
    const GATE_ONLY: [&str; 2] = ["ARCH-DRY-DUPLICATION", "GUARDIAN-TAMPER"];
    let mut wrong = Vec::new();
    for case in cases() {
        if case.how == How::Staged {
            continue;
        }
        let root = Tree(std::env::temp_dir().join(format!(
            "stenio-parity-{}-{}",
            std::process::id(),
            case.id
        )));
        plant(&root.0, &case, &case.bad)?;
        let own = match case.how {
            How::Scan(scope) => scope,
            _ => "project",
        };
        for scope in [None, Some(own)] {
            let errors = |gate: bool| -> Result<BTreeSet<(String, String, usize)>, String> {
                let outcome = pipeline::run(&Request {
                    path: root.0.clone(),
                    path_explicit: true,
                    scope: scope.map(str::to_string),
                    gate,
                    ..Request::default()
                })?;
                Ok(outcome
                    .report
                    .violations
                    .into_iter()
                    .filter(|v| v.severity == crate::rule::Severity::Error)
                    .filter(|v| !GATE_ONLY.contains(&v.rule_id.as_str()))
                    .map(|v| (v.rule_id, v.file_path, v.line_number))
                    .collect())
            };
            let (scan, gate) = (errors(false)?, errors(true)?);
            let same = if scope.is_none() {
                scan == gate
            } else {
                scan.is_subset(&gate)
            };
            if !same {
                wrong.push(format!(
                    "{} scope={scope:?}: scan only {:?}, gate only {:?}",
                    case.id,
                    scan.difference(&gate).collect::<Vec<_>>(),
                    gate.difference(&scan).collect::<Vec<_>>()
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    Ok(())
}
