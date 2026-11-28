//! `stenio secrets-guard --repo <path> [--baseline <file>] [--scope mirror]` (GB-285).
//!
//! Gate for a repository that mirrors host configs (the private `MNEMOCINE-CONFIGS` mirror): it
//! fails when a tracked file carries a literal secret that is not accepted in the baseline, when a
//! credential-shaped path is tracked, or when a credential-shaped / secret-carrying path was
//! committed before its `.gitignore` rule. SECURITY: the report names paths, line numbers and rule
//! ids only; no value, no snippet, no key name is ever printed or returned.
//!
//! Baseline entries are `path` (accepts any number of findings, reported as unbounded) or
//! `path count=N` (accepts at most N findings, so a new secret added to an already accepted file
//! fails). `--history` also judges every commit of the repository (see [`history`]).

mod history;

use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
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
        help = "File with one repo-relative path per line (# comments), optionally `path count=N`: accepted SEC-PLAINTEXT-SECRET findings"
    )]
    baseline: Option<PathBuf>,
    #[arg(
        long,
        help = "Fail on a baseline entry without `count=N` (it would accept any new secret in that file)"
    )]
    require_counts: bool,
    #[arg(long, help = "Also judge every commit of `git log --all`")]
    history: bool,
    #[arg(
        long,
        requires = "history",
        help = "File with one accepted `commit:path` history finding per line (# comments)"
    )]
    history_baseline: Option<PathBuf>,
    #[arg(long, help = "Scope label; only `mirror` is accepted")]
    scope: Option<String>,
}

/// Accepted findings per path; `None` means "any number" (a bare path entry).
pub type Baseline = BTreeMap<String, Option<usize>>;

fn baseline_entry(line: &str) -> (String, Option<usize>) {
    if let Some((path, n)) = line.rsplit_once(" count=")
        && let Ok(n) = n.trim().parse::<usize>()
    {
        return (path.trim_end().to_string(), Some(n));
    }
    (line.to_string(), None)
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
    let out = crate::staged::git_command(repo)
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

fn read_entries(path: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("baseline: {e}"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn read_baseline(path: &Path) -> Result<Baseline, String> {
    Ok(read_entries(path)?
        .iter()
        .map(|l| baseline_entry(l))
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

pub fn evaluate(repo: &Path, baseline: &Baseline) -> Result<GuardReport, String> {
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
    let accepted = |rel: &str, n: usize| match baseline.get(rel) {
        Some(Some(max)) => n <= *max,
        Some(None) => true,
        None => false,
    };
    for (rel, hits) in &findings {
        if accepted(rel, hits.len()) {
            continue;
        }
        let why = match baseline.get(rel) {
            Some(Some(max)) => format!("over the baseline count={max}"),
            _ => "not in baseline".to_string(),
        };
        for l in hits {
            fails += 1;
            lines.push(format!("FAIL (a) SEC-PLAINTEXT-SECRET {why}: {rel}:{l}"));
        }
    }
    for (rel, max) in baseline {
        let now = findings.get(rel).map_or(0, Vec::len);
        match max {
            _ if now == 0 => lines.push(format!("info baseline stale, remove the entry: {rel}")),
            Some(m) if now < *m => lines.push(format!(
                "info baseline loose, tighten to count={now}: {rel}"
            )),
            None => lines.push(format!(
                "info baseline unbounded, pin it with count={now}: {rel}"
            )),
            Some(_) => {}
        }
    }
    let ignored_set: BTreeSet<&String> = ignored.iter().collect();
    let mut harmless = 0usize;
    for rel in &ignored {
        let cred = credential_shaped_name(&base_name(rel));
        let leaks = findings.get(rel).is_some_and(|h| !accepted(rel, h.len()));
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
    match run(&args) {
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

/// Tree gate, then the optional strict-count and history parts, with one final verdict line.
fn run(args: &GuardArgs) -> Result<GuardReport, String> {
    let baseline = args
        .baseline
        .as_deref()
        .map(read_baseline)
        .transpose()?
        .unwrap_or_default();
    let mut report = evaluate(&args.repo, &baseline)?;
    let summary = report.lines.pop().unwrap_or_default();
    let mut extra = 0usize;
    if args.require_counts {
        for (rel, max) in &baseline {
            if max.is_none() {
                extra += 1;
                report.lines.push(format!(
                    "FAIL (d) baseline entry without count=N accepts any new secret: {rel}"
                ));
            }
        }
    }
    if args.history {
        let accepted = args
            .history_baseline
            .as_deref()
            .map(read_entries)
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let (lines, fails) = history::evaluate(&args.repo, &accepted)?;
        report.lines.extend(lines);
        extra += fails;
    }
    let total = report.fails + extra;
    let verdict = if total == 0 { "PASS" } else { "FAIL" };
    let summary = summary
        .replacen(if report.fails == 0 { "PASS" } else { "FAIL" }, verdict, 1)
        .replacen(
            &format!("fails={}", report.fails),
            &format!("fails={total}"),
            1,
        );
    report.lines.push(summary);
    report.fails = total;
    Ok(report)
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

fn judge(dir: &Path, baseline: &[&str]) -> GuardReport {
    let b = baseline.iter().map(|s| baseline_entry(s)).collect();
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
    let r1 = judge(&fixture("a", &[("app.env", &secret)], None), &[]);
    let r2 = judge(&fixture("b", &[("app.env", &secret)], None), &["app.env"]);
    let r3 = judge(
        &fixture(
            "c",
            &[("leak.conf", &secret), ("ok.txt", "hello\n")],
            Some("leak.conf"),
        ),
        &[],
    );
    let r4 = judge(
        &fixture("d", &[("README.md", "DB_PASS=${DB_PASS}\n")], None),
        &[],
    );
    let r5 = judge(
        &fixture(
            "e",
            &[("logo.png", "PNG\n"), ("a.txt", "x\n")],
            Some("logo.png"),
        ),
        &[],
    );
    let r6 = judge(&fixture("f", &[("app.env", "A=1\n")], Some("app.env")), &[]);
    let r7 = judge(
        &fixture("g", &[("app.env.example", "A=1\n"), ("k.pem", "x\n")], None),
        &[],
    );
    // Counted baseline: the accepted file is green, one more secret in the same file is red.
    let two = format!("DB_PASS={FAKE}\nAPI_TOKEN={FAKE}\n");
    let c1 = judge(
        &fixture("h", &[("a.conf", &secret)], None),
        &["a.conf count=1"],
    );
    let c2 = judge(
        &fixture("i", &[("a.conf", &two)], None),
        &["a.conf count=1"],
    );
    let c3 = judge(&fixture("j", &[("a.conf", &two)], None), &["a.conf"]);
    // History: a secret removed from the tree stays in the log until its commit:path is accepted.
    let hist = fixture("k", &[("old.conf", &secret), ("x.env", "A=1\n")], None);
    let _ = std::fs::remove_file(hist.join("old.conf"));
    let _ = std::fs::remove_file(hist.join("x.env"));
    git(&hist, &["add", "-A"]);
    git(&hist, &["commit", "-q", "-m", "rm"]);
    let args = |extra: &[String]| {
        let mut v = vec![
            "g".to_string(),
            "--repo".to_string(),
            hist.display().to_string(),
        ];
        v.extend_from_slice(extra);
        GuardArgs::try_parse_from(v).ok().and_then(|a| run(&a).ok())
    };
    let tree_only = args(&[]);
    let with_history = args(&["--history".to_string()]);
    let accept: Vec<String> = with_history
        .iter()
        .flat_map(|r| &r.lines)
        .filter(|l| l.starts_with("FAIL (h)"))
        .filter_map(|l| {
            l.split(": ")
                .nth(1)
                .and_then(|t| t.split(" lines=").next())
                .map(str::to_string)
        })
        .collect();
    let list = hist.join("history.accept");
    let _ = std::fs::write(&list, accept.join("\n"));
    let accepted = args(&[
        "--history".to_string(),
        "--history-baseline".to_string(),
        list.display().to_string(),
    ]);
    let strict_list = hist.join("tree.accept");
    let _ = std::fs::write(&strict_list, "gone.conf\n");
    let strict = args(&[
        "--baseline".to_string(),
        strict_list.display().to_string(),
        "--require-counts".to_string(),
    ]);
    let _ = std::fs::remove_dir_all(&hist);
    let outputs_clean = !leaks_value(&r1)
        && !leaks_value(&r2)
        && !leaks_value(&r3)
        && !leaks_value(&c2)
        && with_history.as_ref().is_some_and(|r| !leaks_value(r));
    vec![
        (
            "secrets-guard: counted baseline accepts exactly N".to_string(),
            c1.fails == 0,
        ),
        (
            "secrets-guard: mutation, new secret in a baselined file fails".to_string(),
            c2.fails == 2 && has(&c2, "over the baseline count=1"),
        ),
        (
            "secrets-guard: bare baseline entry still accepts, reported unbounded".to_string(),
            c3.fails == 0 && has(&c3, "unbounded, pin it with count=2"),
        ),
        (
            "secrets-guard: deleted secret invisible without --history".to_string(),
            tree_only.as_ref().is_some_and(|r| r.fails == 0),
        ),
        (
            "secrets-guard: mutation, --history fails on deleted secret and env path".to_string(),
            with_history.as_ref().is_some_and(|r| {
                r.fails == 2
                    && has(r, "added in history")
                    && has(r, "credential-shaped path in history")
                    && r.lines
                        .last()
                        .is_some_and(|l| l.contains("FAIL secrets-guard"))
            }),
        ),
        (
            "secrets-guard: accepted history passes".to_string(),
            accepted.as_ref().is_some_and(|r| {
                r.fails == 0
                    && r.lines
                        .last()
                        .is_some_and(|l| l.contains("PASS secrets-guard"))
            }),
        ),
        (
            "secrets-guard: --require-counts fails a bare entry".to_string(),
            strict
                .as_ref()
                .is_some_and(|r| r.fails == 1 && has(r, "FAIL (d)")),
        ),
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
