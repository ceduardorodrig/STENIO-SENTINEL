//! `stenio secrets-guard --repo <path> [--baseline <file>] [--scope mirror]` (GB-285).
//!
//! Gate for a repository that mirrors host configs (the private `MNEMOCINE-CONFIGS` mirror): it
//! fails when a tracked file carries a literal secret that is not accepted in the baseline, when a
//! credential-shaped path is tracked, or when a credential-shaped / secret-carrying path was
//! committed before its `.gitignore` rule. SECURITY: the report names paths, line numbers and rule
//! ids only; no value, no snippet, no key name is ever printed or returned.

use clap::Parser;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_FILE_BYTES: u64 = 1_048_576;
/// Mirrors the `is_text_or_config` set of `infra::audit_infrastructure`.
const SCANNED_EXTENSIONS: &[&str] = &[
    "yml", "yaml", "env", "json", "sh", "conf", "service", "md", "php", "htaccess", "pem", "key",
];

#[derive(Parser, Debug)]
#[command(
    name = "stenio secrets-guard",
    about = "Fail when secrets or credential-shaped files are tracked in a repository (paths only, never values)"
)]
struct GuardArgs {
    #[arg(long, help = "Repository to check")]
    repo: PathBuf,
    #[arg(
        long,
        help = "File with one repo-relative path per line (# comments): paths whose SEC-PLAINTEXT-SECRET findings are accepted"
    )]
    baseline: Option<PathBuf>,
    #[arg(long, help = "Scope label; only `mirror` is accepted")]
    scope: Option<String>,
}

/// Outcome of one run; every string is already free of values.
pub struct GuardReport {
    pub lines: Vec<String>,
    pub fails: usize,
}

/// True for a basename that names credential material (`*.env` except examples, `.env.*`,
/// `*.pem`, `*.key`, `id_rsa*`/`id_ed25519*` private halves, `*.kdbx`, `*.p12`, `*.pfx`, `*.ovpn`,
/// `secrets.*.{yml,yaml,json,env}` unless sops-encrypted `*.enc.*`).
pub fn credential_shaped_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let example = |s: &str| {
        ["example", "sample", "template"]
            .iter()
            .any(|e| s.ends_with(e))
    };
    if example(&n) {
        return false;
    }
    if n == ".env" || n.ends_with(".env") || n.starts_with(".env.") {
        return true;
    }
    if [".pem", ".key", ".kdbx", ".p12", ".pfx", ".ovpn"]
        .iter()
        .any(|e| n.ends_with(e))
    {
        return true;
    }
    if (n.starts_with("id_rsa") || n.starts_with("id_ed25519")) && !n.ends_with(".pub") {
        return true;
    }
    n.starts_with("secrets.")
        && !n.contains(".enc.")
        && [".yml", ".yaml", ".json", ".env"]
            .iter()
            .any(|e| n.ends_with(e))
}

fn git_list(repo: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {} failed", args.join(" ")));
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect())
}

fn read_baseline(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("baseline: {e}"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Lines (1-based) of `rel` with a SEC-PLAINTEXT-SECRET finding; values are dropped here.
fn finding_lines(repo: &Path, rel: &str) -> Vec<usize> {
    let p = repo.join(rel);
    // Same file types the engine's infrastructure audit reads: source code (`*.rs`, `*.py`) is
    // out of scope for SEC-PLAINTEXT-SECRET and would only add identifier noise.
    let ext = crate::rule::effective_extension(&p);
    if !SCANNED_EXTENSIONS.contains(&ext.as_str()) {
        return Vec::new();
    }
    let Ok(meta) = std::fs::symlink_metadata(&p) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&p) else {
        return Vec::new();
    };
    if rel.contains(".template") || rel.contains(".example") || rel.contains("templates/") {
        return Vec::new();
    }
    let sops_doc = content.contains("sops:") && content.contains("mac:");
    crate::infra::plaintext_secret_violations(rel, &content, sops_doc)
        .into_iter()
        .map(|v| v.line_number)
        .collect()
}

pub fn evaluate(repo: &Path, baseline: &BTreeSet<String>) -> Result<GuardReport, String> {
    let tracked = git_list(repo, &["ls-files", "-z"])?;
    let ignored = git_list(repo, &["ls-files", "-ci", "--exclude-standard", "-z"])?;
    let mut lines = Vec::new();
    let mut fails = 0usize;
    let base_name = |p: &str| p.rsplit('/').next().unwrap_or(p).to_string();
    let mut findings = std::collections::BTreeMap::new();
    for rel in &tracked {
        let hits = finding_lines(repo, rel);
        if !hits.is_empty() {
            findings.insert(rel.clone(), hits);
        }
    }
    for (rel, hits) in &findings {
        if !baseline.contains(rel) {
            for l in hits {
                fails += 1;
                lines.push(format!(
                    "FAIL (a) SEC-PLAINTEXT-SECRET not in baseline: {rel}:{l}"
                ));
            }
        }
    }
    let ignored_set: BTreeSet<&String> = ignored.iter().collect();
    let mut harmless = 0usize;
    for rel in &ignored {
        let cred = credential_shaped_name(&base_name(rel));
        let leaks = findings.contains_key(rel) && !baseline.contains(rel);
        if cred || leaks {
            fails += 1;
            lines.push(format!(
                "FAIL (b) tracked but ignored (committed before the rule): {rel}"
            ));
        } else {
            harmless += 1;
            lines.push(format!("info (b) tracked but ignored, harmless: {rel}"));
        }
    }
    for rel in &tracked {
        if credential_shaped_name(&base_name(rel)) {
            fails += 1;
            let ign = if ignored_set.contains(rel) {
                " (also ignored)"
            } else {
                ""
            };
            lines.push(format!(
                "FAIL (c) credential-shaped path tracked: {rel}{ign}"
            ));
        }
    }
    let verdict = if fails == 0 { "PASS" } else { "FAIL" };
    lines.push(format!(
        "stenio: {verdict} secrets-guard files={} fails={fails} tracked-ignored-harmless={harmless} baseline={}",
        tracked.len(),
        baseline.len()
    ));
    Ok(GuardReport { lines, fails })
}

pub fn run_cli(argv: &[String]) -> i32 {
    let args = match GuardArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    if args.scope.as_deref().is_some_and(|s| s != "mirror") {
        eprintln!("stenio: secrets-guard --scope accepts only `mirror`");
        return 2;
    }
    let baseline = match args.baseline.as_deref().map(read_baseline) {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            eprintln!("stenio: secrets-guard {e}");
            return 2;
        }
        None => BTreeSet::new(),
    };
    match evaluate(&args.repo, &baseline) {
        Ok(r) => {
            for l in &r.lines {
                println!("{l}");
            }
            i32::from(r.fails > 0)
        }
        Err(e) => {
            eprintln!("stenio: secrets-guard {e}");
            2
        }
    }
}

// ── self-test fixtures: every case pairs a red (defect) with a green (good) tree ──────────────

const FAKE: &str = "Zq81xLm4Qp7vRt8zKd";

fn git(repo: &Path, args: &[&str]) {
    let _ = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output();
}

fn fixture(tag: &str, files: &[(&str, &str)], ignore_after: Option<&str>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stenio-sg-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    git(&dir, &["init", "-q"]);
    for (n, c) in files {
        let _ = std::fs::write(dir.join(n), c);
    }
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "x"]);
    if let Some(rule) = ignore_after {
        let _ = std::fs::write(dir.join(".gitignore"), format!("{rule}\n"));
    }
    dir
}

fn run(dir: &Path, baseline: &[&str]) -> GuardReport {
    let b = baseline.iter().map(|s| s.to_string()).collect();
    let r = evaluate(dir, &b).unwrap_or(GuardReport {
        lines: vec!["error".to_string()],
        fails: 99,
    });
    let _ = std::fs::remove_dir_all(dir);
    r
}

fn has(r: &GuardReport, needle: &str) -> bool {
    r.lines.iter().any(|l| l.contains(needle))
}

/// True when no 6-character window of the fake secret appears anywhere in the output.
fn leaks_value(r: &GuardReport) -> bool {
    let all = r.lines.join("\n");
    FAKE.as_bytes()
        .windows(6)
        .any(|w| all.contains(&*String::from_utf8_lossy(w)))
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let secret = format!("DB_PASS={FAKE}\n");
    let r1 = run(&fixture("a", &[("app.env", &secret)], None), &[]);
    let r2 = run(&fixture("b", &[("app.env", &secret)], None), &["app.env"]);
    let r3 = run(
        &fixture(
            "c",
            &[("leak.conf", &secret), ("ok.txt", "hello\n")],
            Some("leak.conf"),
        ),
        &[],
    );
    let r4 = run(
        &fixture("d", &[("README.md", "DB_PASS=${DB_PASS}\n")], None),
        &[],
    );
    let r5 = run(
        &fixture(
            "e",
            &[("logo.png", "PNG\n"), ("a.txt", "x\n")],
            Some("logo.png"),
        ),
        &[],
    );
    let r6 = run(&fixture("f", &[("app.env", "A=1\n")], Some("app.env")), &[]);
    let r7 = run(
        &fixture("g", &[("app.env.example", "A=1\n"), ("k.pem", "x\n")], None),
        &[],
    );
    let outputs_clean = !leaks_value(&r1) && !leaks_value(&r2) && !leaks_value(&r3);
    vec![
        (
            "secrets-guard: secret in app.env fails (a)+(c)".to_string(),
            r1.fails > 0 && has(&r1, "(a)") && has(&r1, "(c)") && has(&r1, "app.env:1"),
        ),
        (
            "secrets-guard: baseline accepts (a) but (c) still fails".to_string(),
            r2.fails > 0 && !has(&r2, "(a)") && has(&r2, "(c)"),
        ),
        (
            "secrets-guard: committed-then-ignored secret fails (b)".to_string(),
            has(&r3, "(b) tracked but ignored (committed") && r3.fails > 0,
        ),
        (
            "secrets-guard: clean repo passes".to_string(),
            r4.fails == 0
                && r4
                    .lines
                    .last()
                    .is_some_and(|l| l.starts_with("stenio: PASS secrets-guard")),
        ),
        (
            "secrets-guard: harmless tracked-but-ignored png passes".to_string(),
            r5.fails == 0 && has(&r5, "harmless: logo.png"),
        ),
        (
            "secrets-guard: tracked-but-ignored app.env fails".to_string(),
            r6.fails > 0 && has(&r6, "(b) tracked but ignored (committed") && has(&r6, "(c)"),
        ),
        (
            "secrets-guard: .env.example passes, k.pem fails".to_string(),
            r7.fails == 1 && has(&r7, "k.pem") && !has(&r7, "app.env.example"),
        ),
        (
            "secrets-guard: output never carries the secret value".to_string(),
            outputs_clean,
        ),
        (
            "secrets-guard: name shapes".to_string(),
            credential_shaped_name("n8n.env")
                && credential_shaped_name(".env.bak-2026")
                && credential_shaped_name("secrets.prod.yaml")
                && credential_shaped_name("id_ed25519")
                && !credential_shaped_name("id_ed25519.pub")
                && !credential_shaped_name("secrets.enc.yaml")
                && !credential_shaped_name(".env.example")
                && !credential_shaped_name("README.md"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures_hold() {
        let bad: Vec<_> = super::self_test_cases()
            .into_iter()
            .filter(|(_, ok)| !ok)
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }
}
