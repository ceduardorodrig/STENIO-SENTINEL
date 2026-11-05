//! End-to-end cycle of `stenio opportunity add`: `--help` must advertise the subcommand, and the
//! command must insert exactly one row (or none, under `--dry-run`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BACKLOG: &str = "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
|---|---|---|---|---|---|---|\n\
| **GB-001** | plain item | [`area.md`](area.md) | 🟡 | open | a | — |\n";

const ARCHIVE: &str = "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n\
|---|---|---|---|---|---|---|\n\
| **GB-002** | old | [`area.md`](area.md) | 🔵 | resolved | 2026-11-01 | — |\n";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stenio")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", bin()))
}

struct Vault(PathBuf);

impl Drop for Vault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn vault(label: &str) -> Vault {
    let root = std::env::temp_dir().join(format!("stenio-cli-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let gov = root.join("governance");
    let ok = fs::create_dir_all(&gov).is_ok()
        && fs::write(gov.join("backlog.md"), BACKLOG).is_ok()
        && fs::write(gov.join("backlog-archive.md"), ARCHIVE).is_ok()
        && fs::write(
            gov.join("area.md"),
            "---\ntags: [gov]\npending: [GB-001]\n---\n# Area\n",
        )
        .is_ok();
    assert!(ok, "cannot seed the fixture vault");
    Vault(root)
}

fn add_args(root: &Path, title: &str, dry_run: bool) -> Vec<String> {
    let mut args = vec![
        "opportunity".to_string(),
        "add".to_string(),
        "--path".to_string(),
        root.display().to_string(),
        "--title".to_string(),
        title.to_string(),
        "--evidence".to_string(),
        "seen".to_string(),
        "--desired".to_string(),
        "do it".to_string(),
        "--acceptance".to_string(),
        "fixture".to_string(),
        "--origin".to_string(),
        "test, harness".to_string(),
        "--ref".to_string(),
        "governance/area.md".to_string(),
    ];
    if dry_run {
        args.push("--dry-run".to_string());
    }
    args
}

#[test]
fn help_advertises_the_opportunity_add_subcommand() {
    let out = run(&["--help"]);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stenio --help failed");
    assert!(
        help.contains("opportunity add"),
        "subcommand missing from --help:\n{help}"
    );

    let out = run(&["opportunity", "add", "--help"]);
    let sub = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "opportunity add --help must exit 0");
    for flag in [
        "--title",
        "--evidence",
        "--desired",
        "--acceptance",
        "--origin",
        "--dry-run",
    ] {
        assert!(sub.contains(flag), "{flag} missing from subcommand help");
    }
}

#[test]
fn cli_dry_run_writes_nothing_and_a_real_run_adds_one_row() {
    let v = vault("cycle");
    let before = fs::read(v.0.join("governance/backlog.md")).unwrap_or_default();

    let dry = run(&add_args(&v.0, "CLI-RULE", true)
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>());
    let stdout = String::from_utf8_lossy(&dry.stdout);
    assert!(
        dry.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(
        stdout.contains("GB-003") && stdout.contains("**Stenio: CLI-RULE.**"),
        "{stdout}"
    );
    assert_eq!(
        fs::read(v.0.join("governance/backlog.md")).unwrap_or_default(),
        before,
        "dry run must not write the backlog"
    );

    let real = run(&add_args(&v.0, "CLI-RULE", false)
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>());
    let stdout = String::from_utf8_lossy(&real.stdout);
    assert!(
        real.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&real.stderr)
    );
    assert!(
        stdout.contains("GB-003"),
        "the created id must be printed: {stdout}"
    );
    let after = fs::read_to_string(v.0.join("governance/backlog.md")).unwrap_or_default();
    assert_eq!(after.lines().count(), BACKLOG.lines().count() + 1);
    assert!(after.contains("| **GB-003** | **Stenio: CLI-RULE.**"));
    let doc = fs::read_to_string(v.0.join("governance/area.md")).unwrap_or_default();
    assert!(doc.contains("pending: [GB-001, GB-003]"), "{doc}");

    let again = run(&add_args(&v.0, "CLI-RULE", false)
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>());
    assert!(!again.status.success(), "duplicate title must be refused");
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(
        stderr.contains("duplicate") && stderr.contains("GB-003"),
        "{stderr}"
    );
}
