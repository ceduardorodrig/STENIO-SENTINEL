//! `stenio compare-engines` (GB-290): the old-versus-new engine comparison over the owners'
//! repositories, which every release needs because the stenio-check action downloads the latest
//! engine. It replaces the scratch scripts of 2026-11-23 (4.38.0 recall check, 15 repos).
//!
//! For every non-archived repository of every `--owner` (and every `--repo owner/name`) it
//! shallow-clones through `gh` under `timeout 60` (a clone that hangs is skipped and reported,
//! never waited for), reads the CI scope(s) from the repository's workflows (`--scope X` in a run
//! step, `scope:` of the stenio-check action, a script a step calls; `all` when none), runs both
//! binaries with `--scope <s> --strict --compact` and prints per repository the ERROR lines the new
//! engine adds. Exit 1 when any repository gains an ERROR line, or when an engine run itself fails
//! (a crash or timeout proves nothing). Counts are derived from the lists iterated (rule 12.3).
//!
//! Not wired into `release-engine` in this version: the step order of that command is guarded by
//! `release_order` and needs its own mutation case.

use clap::Parser;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::release_engine::{Real, Runner};

const CLONE_TIMEOUT_S: u64 = 60;
const LIST_TIMEOUT: Duration = Duration::from_secs(60);
const RUN_TIMEOUT: Duration = Duration::from_secs(300);
const SHOWN: usize = 20;

#[derive(Parser, Debug)]
#[command(
    name = "stenio compare-engines",
    about = "Run an old and a new stenio binary over the owners' non-archived repos with each repo's CI scope and list the new ERROR lines"
)]
struct Args {
    #[arg(long, help = "The engine currently released")]
    old: String,
    #[arg(long, help = "The candidate engine")]
    new: String,
    #[arg(long = "owner", help = "GitHub owner or org (repeatable)")]
    owners: Vec<String>,
    #[arg(long = "repo", help = "Single owner/name repository (repeatable)")]
    repos: Vec<String>,
}

/// Distinct CI scopes of the workflows under `root`, in order of appearance; `["all"]` when no
/// step names one.
pub fn ci_scopes(root: &Path) -> Vec<String> {
    let default_scope = crate::config::SteniocheckConfig::load_from_dir(root)
        .general
        .and_then(|g| g.scope);
    let mut out: Vec<String> = Vec::new();
    for w in crate::ci::load_workflows(root) {
        for s in &w.steps {
            for sc in crate::ci::step_scopes(s, root, default_scope.as_deref()) {
                if !out.contains(&sc) {
                    out.push(sc);
                }
            }
        }
    }
    if out.is_empty() {
        out.push("all".to_string());
    }
    out
}

/// Count of every `[ERROR]` line of an engine output.
fn error_counts(out: &str) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for l in out.lines().map(str::trim).filter(|l| l.contains("[ERROR]")) {
        *m.entry(l.to_string()).or_insert(0) += 1;
    }
    m
}

/// (old total, new total, lines the new engine adds).
fn delta(old: &str, new: &str) -> (usize, usize, Vec<String>) {
    let (o, n) = (error_counts(old), error_counts(new));
    let added = n
        .iter()
        .filter(|(l, c)| **c > o.get(*l).copied().unwrap_or(0))
        .map(|(l, _)| l.clone())
        .collect();
    (o.values().sum(), n.values().sum(), added)
}

fn run_engine(r: &dyn Runner, bin: &str, scope: &str, dir: &Path) -> Result<String, String> {
    let argv = vec![
        bin.to_string(),
        "--scope".to_string(),
        scope.to_string(),
        "--path".to_string(),
        dir.display().to_string(),
        "--strict".to_string(),
        "--compact".to_string(),
    ];
    r.run(None, &argv, RUN_TIMEOUT).map(|o| o.stdout)
}

/// `owner/name` of every non-archived repository of `owner`.
fn list_repos(r: &dyn Runner, owner: &str) -> Result<Vec<String>, String> {
    let argv: Vec<String> = [
        "gh",
        "repo",
        "list",
        owner,
        "--no-archived",
        "--json",
        "nameWithOwner",
        "--limit",
        "200",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let o = r.run(None, &argv, LIST_TIMEOUT)?;
    if o.code != 0 {
        return Err(format!("gh repo list {owner}: exit {}", o.code));
    }
    let v: Value = serde_json::from_str(&o.stdout).map_err(|e| format!("bad JSON: {e}"))?;
    Ok(v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.get("nameWithOwner").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default())
}

fn clone_repo(r: &dyn Runner, full: &str, dir: &Path) -> Result<(), String> {
    let argv: Vec<String> = [
        "timeout",
        &CLONE_TIMEOUT_S.to_string(),
        "gh",
        "repo",
        "clone",
        full,
        &dir.display().to_string(),
        "--",
        "--depth",
        "1",
        "-q",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let o = r.run(None, &argv, Duration::from_secs(CLONE_TIMEOUT_S + 10))?;
    if o.code == 0 {
        Ok(())
    } else {
        Err(format!("clone exit {} (124 = timed out)", o.code))
    }
}

/// Core of the command. Returns the report lines and whether the new engine is safe to ship.
pub fn compare(
    r: &dyn Runner,
    old: &str,
    new: &str,
    owners: &[String],
    extra: &[String],
    work: &Path,
) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut ok = true;
    let mut repos: Vec<String> = Vec::new();
    for o in owners {
        match list_repos(r, o) {
            Ok(list) => {
                lines.push(format!("owner={o} repos={}", list.len()));
                repos.extend(list);
            }
            Err(e) => {
                ok = false;
                lines.push(format!("FAIL owner={o}: {e}"));
            }
        }
    }
    repos.extend(extra.iter().cloned());
    repos.sort();
    repos.dedup();
    let (mut compared, mut skipped, mut gained) = (0usize, 0usize, 0usize);
    for full in &repos {
        let dir: PathBuf = work.join(full.replace('/', "__"));
        if let Err(e) = clone_repo(r, full, &dir) {
            skipped += 1;
            lines.push(format!("SKIP {full}: {e}"));
            continue;
        }
        let scopes = ci_scopes(&dir);
        let (mut o_tot, mut n_tot, mut added) = (0, 0, Vec::new());
        let mut broken = None;
        for s in &scopes {
            match (
                run_engine(r, old, s, &dir),
                run_engine(r, new, s, &dir),
            ) {
                (Ok(a), Ok(b)) => {
                    let (x, y, add) = delta(&a, &b);
                    o_tot += x;
                    n_tot += y;
                    added.extend(add.into_iter().map(|l| format!("[{s}] {l}")));
                }
                (a, b) => {
                    broken = Some(format!(
                        "scope {s}: old={} new={}",
                        a.err().unwrap_or_else(|| "ok".to_string()),
                        b.err().unwrap_or_else(|| "ok".to_string())
                    ));
                    break;
                }
            }
        }
        compared += 1;
        if let Some(why) = broken {
            ok = false;
            lines.push(format!("FAIL {full}: engine run failed, {why}"));
            continue;
        }
        lines.push(format!(
            "{full} scope={} old_err={o_tot} new_err={n_tot} added={}",
            scopes.join(","),
            added.len()
        ));
        if !added.is_empty() {
            ok = false;
            gained += 1;
            for l in added.iter().take(SHOWN) {
                lines.push(format!("  + {l}"));
            }
            if added.len() > SHOWN {
                lines.push(format!("  + ... {} more", added.len() - SHOWN));
            }
        }
    }
    if compared + skipped != repos.len() {
        ok = false;
        lines.push(format!(
            "FAIL declared {} != compared {compared} + skipped {skipped}",
            repos.len()
        ));
    }
    lines.push(format!(
        "compare-engines: repos declared={} compared={compared} skipped={skipped} gained_error={gained} {}",
        repos.len(),
        if ok { "PASS" } else { "FAIL" }
    ));
    (lines, ok)
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
        }
    };
    if a.owners.is_empty() && a.repos.is_empty() {
        eprintln!("compare-engines: give at least one --owner or --repo");
        return 2;
    }
    let work = std::env::temp_dir().join(format!("stenio-compare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    if std::fs::create_dir_all(&work).is_err() {
        eprintln!("compare-engines: cannot create {}", work.display());
        return 2;
    }
    let (lines, ok) = compare(&Real, &a.old, &a.new, &a.owners, &a.repos, &work);
    for l in &lines {
        println!("{l}");
    }
    let _ = std::fs::remove_dir_all(&work);
    i32::from(!ok)
}

// ── self-test: stub gh, two fake engines run through `sh` ──────────────────
struct Fixture;

impl Runner for Fixture {
    fn run(
        &self,
        dir: Option<&Path>,
        argv: &[String],
        t: Duration,
    ) -> Result<crate::verify_release::Out, String> {
        let out = |stdout: &str| {
            Ok(crate::verify_release::Out {
                code: 0,
                stdout: stdout.to_string(),
            })
        };
        let key = argv.join(" ");
        if key.starts_with("gh repo list") {
            return out(
                r#"[{"nameWithOwner":"o/r1"},{"nameWithOwner":"o/r2"},{"nameWithOwner":"o/hang"}]"#,
            );
        }
        if argv.first().map(String::as_str) == Some("timeout") {
            let full = argv.get(5).cloned().unwrap_or_default();
            if full.ends_with("hang") {
                return Err("timeout after 70s".to_string());
            }
            let d = PathBuf::from(argv.get(6).cloned().unwrap_or_default());
            let wf = d.join(".github/workflows");
            std::fs::create_dir_all(&wf).map_err(|e| e.to_string())?;
            let body = if full.ends_with("r1") {
                "name: ci\non: [push]\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: stenio --scope fork --strict --compact\n"
            } else {
                "name: ci\non: [push]\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: make\n"
            };
            std::fs::write(wf.join("ci.yml"), body).map_err(|e| e.to_string())?;
            return out("");
        }
        // A fake engine is a shell script: run it through `sh` (no exec of a fresh file).
        match argv.split_first() {
            Some((bin, rest)) if bin.ends_with(".sh") => {
                let mut v = vec!["sh".to_string(), bin.clone()];
                v.extend(rest.iter().cloned());
                Real.run(dir, &v, t)
            }
            _ => Err(format!("not scripted: {key}")),
        }
    }
}

fn write_engine(path: &Path, extra_on_r2: bool) {
    let mut body = String::from("echo '[ERROR] a.rs:1: [BASE] existing'\n");
    if extra_on_r2 {
        body.push_str("case \"$*\" in *o__r2*) echo '[ERROR] b.rs:2: [NEW-RULE] fresh';; esac\n");
    }
    let _ = std::fs::write(path, body);
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let base = std::env::temp_dir().join(format!("stenio-cmpeng-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::create_dir_all(&base);
    let (old, new) = (base.join("old.sh"), base.join("new.sh"));
    write_engine(&old, false);
    write_engine(&new, true);
    let (o, n) = (
        old.display().to_string(),
        new.display().to_string(),
    );
    let owners = vec!["o".to_string()];
    let w1 = base.join("w1");
    let w2 = base.join("w2");
    let _ = std::fs::create_dir_all(&w1);
    let _ = std::fs::create_dir_all(&w2);
    let (red, red_ok) = compare(&Fixture, &o, &n, &owners, &[], &w1);
    let red = red.join("\n");
    let (green, green_ok) = compare(&Fixture, &o, &o, &owners, &[], &w2);
    let green = green.join("\n");
    let _ = std::fs::remove_dir_all(&base);
    vec![
        (
            "compare-engines: mutation, a repo that gains an ERROR line fails and names it"
                .to_string(),
            !red_ok
                && red.contains("o/r2 scope=all old_err=1 new_err=2 added=1")
                && red.contains("+ [all] [ERROR] b.rs:2: [NEW-RULE] fresh")
                && red.contains("gained_error=1 FAIL"),
        ),
        (
            "compare-engines: identical engines pass with zero deltas".to_string(),
            green_ok && green.contains("gained_error=0 PASS"),
        ),
        (
            "compare-engines: a hung clone is skipped and reported, not waited for".to_string(),
            red.contains("SKIP o/hang") && green.contains("skipped=1"),
        ),
        (
            "compare-engines: the CI scope comes from the workflow, default all".to_string(),
            red.contains("o/r1 scope=fork") && red.contains("o/r2 scope=all"),
        ),
        (
            "compare-engines: counts are derived (declared = compared + skipped)".to_string(),
            red.contains("declared=3 compared=2 skipped=1"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures() {
        crate::testkit::assert_cases(super::self_test_cases());
    }
}
