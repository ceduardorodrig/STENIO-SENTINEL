//! `stenio compare-engines` (GB-290): the old-versus-new engine comparison over the owners'
//! repositories, which every release needs because the stenio-check action downloads the latest
//! engine. It replaces the scratch scripts of 2026-11-23 (4.38.0 recall check, 15 repos).
//!
//! For every non-archived repository of every `--owner` (and every `--repo owner/name`) it
//! shallow-clones through `gh` under `timeout 60` (a clone that hangs is skipped and reported,
//! never waited for), reads the CI scope(s) from the repository's workflows (`--scope X` in a run
//! step, `scope:` of the stenio-check action, a script a step calls; `all` when none), runs both
//! binaries with `--scope <s> --strict --compact` and prints per target the ERROR lines the new
//! engine adds. Exit 1 when any target gains an ERROR line, or when an engine run or a branch
//! listing fails (a crash or timeout proves nothing). Counts are derived from the lists iterated
//! (rule 12.3).
//!
//! GB-298: a target is the default branch of a repository and every other remote branch its
//! workflows trigger on (`push` / `pull_request` branch filters, read from the default branch and
//! from every branch selected through them; a trigger without a filter selects every branch). The
//! first comparison of the default branch alone reported `gained_error=0` while SUMAENIMA-HUB
//! `DEVELOPMENT` would have gained 42 errors (2026-11-24). A selected branch that carries no
//! branch-triggered workflow of its own is listed as `NOCI` and not compared: no push runs there.
//!
//! GB-402: local checkouts (`--tree PATH[=scope,...]`, or a `--trees` list) are targets too, read
//! only (no `--fix`), at the named scopes (`default` passes no `--scope`), else their CI scopes.
//! Every target also compares the `--gate` verdict. A target fails the comparison when it gains an
//! error line or a passing run starts failing; an exit code other than 0 or 1 proves nothing.
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
    about = "Run an old and a new stenio binary over the owners' non-archived repos (default and CI-triggered branches) with each CI scope and list the new ERROR lines"
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
    #[arg(
        long = "tree",
        help = "Local checkout, read only, as PATH[=scope,...] (repeatable; scope `default` passes none)"
    )]
    trees: Vec<String>,
    #[arg(
        long = "trees",
        help = "File of local checkouts, one `PATH[=scope,...]` per line, relative to the file; `#` comments"
    )]
    tree_lists: Vec<PathBuf>,
}

/// A local checkout and the scopes to compare there (empty: its CI scopes).
#[derive(Debug, Clone, PartialEq)]
pub struct Tree {
    pub path: PathBuf,
    pub scopes: Vec<String>,
}

/// `PATH[=scope,...]`, a relative path resolved against `base`.
pub fn parse_tree(spec: &str, base: &Path) -> Result<Tree, String> {
    let (path, scopes) = spec.rsplit_once('=').unwrap_or((spec, ""));
    let scopes: Vec<String> = scopes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if path.trim().is_empty() || (spec.contains('=') && scopes.is_empty()) {
        return Err(format!("tree `{spec}`: expected PATH[=scope,...]"));
    }
    Ok(Tree {
        path: base.join(path.trim()),
        scopes,
    })
}

/// Every tree of a list file; an empty list is an error (it would compare nothing).
pub fn read_tree_list(file: &Path) -> Result<Vec<Tree>, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let base = file.parent().unwrap_or_else(|| Path::new("."));
    let trees = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| parse_tree(l, base))
        .collect::<Result<Vec<_>, _>>()?;
    if trees.is_empty() {
        return Err(format!("{}: no tree declared", file.display()));
    }
    Ok(trees)
}

/// Distinct CI scopes of the workflows under `root`, in order of appearance; `["all"]` when no
/// step names one.
pub fn ci_scopes(root: &Path) -> Vec<String> {
    // A broken file makes both engines fail on their own run; here it only names no scope.
    let default_scope = crate::config::SteniocheckConfig::load_from_dir(root)
        .unwrap_or_default()
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

/// The finding of a gate line (`3. [RULE] file:line: ...`) without its position in the list.
fn gate_finding(line: &str) -> Option<&str> {
    let (number, rest) = line.split_once(". [")?;
    (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
        .then(|| &line[line.len() - rest.len() - 1..])
}

/// Count of every `[ERROR]` line and gate finding of an engine output.
fn error_counts(out: &str) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for l in out.lines().map(str::trim) {
        let found = match gate_finding(l) {
            Some(finding) => Some(finding),
            None => l.contains("[ERROR]").then_some(l),
        };
        if let Some(f) = found {
            *m.entry(f.to_string()).or_insert(0) += 1;
        }
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

/// The verdict mode that runs `--gate` instead of a scope.
const GATE: &str = "gate";

/// One read-only run: exit code and standard output. Exit codes other than 0 and 1 are failures.
fn run_engine(r: &dyn Runner, bin: &str, mode: &str, dir: &Path) -> Result<(i32, String), String> {
    let mut argv = vec![bin.to_string()];
    match mode {
        GATE => argv.push("--gate".to_string()),
        "default" => {}
        scope => argv.extend(["--scope".to_string(), scope.to_string()]),
    }
    argv.extend(["--path".to_string(), dir.display().to_string()]);
    if mode != GATE {
        argv.push("--strict".to_string());
    }
    argv.push("--compact".to_string());
    let o = r.run(Some(dir), &argv, RUN_TIMEOUT)?;
    if o.code != 0 && o.code != 1 {
        return Err(format!("exit {}", o.code));
    }
    Ok((o.code, o.stdout))
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

/// Every remote branch of `full`.
fn list_branches(r: &dyn Runner, full: &str) -> Result<Vec<String>, String> {
    let argv: Vec<String> = [
        "gh",
        "api",
        "--paginate",
        &format!("repos/{full}/branches?per_page=100"),
        "--jq",
        ".[].name",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let o = r.run(None, &argv, LIST_TIMEOUT)?;
    if o.code != 0 {
        return Err(format!("gh api branches: exit {}", o.code));
    }
    Ok(o.stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// The branch the default clone checked out.
fn head_branch(r: &dyn Runner, dir: &Path) -> Result<String, String> {
    let argv: Vec<String> = [
        "git",
        "-C",
        &dir.display().to_string(),
        "branch",
        "--show-current",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let o = r.run(None, &argv, LIST_TIMEOUT)?;
    if o.code != 0 {
        return Err(format!("git branch --show-current: exit {}", o.code));
    }
    Ok(o.stdout.trim().to_string())
}

fn clone_repo(r: &dyn Runner, full: &str, branch: Option<&str>, dir: &Path) -> Result<(), String> {
    let mut argv: Vec<String> = [
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
    if let Some(b) = branch {
        argv.extend(["--branch".to_string(), b.to_string()]);
    }
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
    trees: &[Tree],
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
    let engines = Engines { old, new };
    let mut tally = Tally::default();
    for (index, full) in repos.iter().enumerate() {
        let slug = full.replace('/', "__");
        let dir: PathBuf = work.join(&slug);
        tally.declared += 1;
        if let Err(e) = clone_repo(r, full, None, &dir) {
            tally.skipped += 1;
            lines.push(format!("SKIP {full}: {e}"));
            continue;
        }
        compare_target(r, &engines, full, &dir, &[], &mut lines, &mut tally);
        let mut filters = crate::ci::load_branch_filters(&dir);
        if filters.is_empty() {
            continue;
        }
        let listed = head_branch(r, &dir).and_then(|h| list_branches(r, full).map(|b| (h, b)));
        let (head, mut pending) = match listed {
            Ok(x) => x,
            Err(e) => {
                tally.broken = true;
                lines.push(format!("FAIL {full}: CI branches unknown, {e}"));
                continue;
            }
        };
        pending.retain(|b| *b != head);
        // A selected branch carries its own workflows, which may select further branches.
        let mut number = 0usize;
        while let Some(at) = pending
            .iter()
            .position(|b| filters.iter().any(|f| f.matches(b)))
        {
            let branch = pending.remove(at);
            number += 1;
            let target = format!("{full}@{branch}");
            let dir = work.join(format!(
                "{slug}__{index}_{number}_{}",
                branch.replace('/', "_")
            ));
            tally.declared += 1;
            tally.branches += 1;
            if let Err(e) = clone_repo(r, full, Some(&branch), &dir) {
                tally.skipped += 1;
                lines.push(format!("SKIP {target}: {e}"));
                continue;
            }
            let own = crate::ci::load_branch_filters(&dir);
            if own.is_empty() {
                tally.no_ci += 1;
                lines.push(format!(
                    "NOCI {target}: no branch-triggered workflow on this branch, not compared"
                ));
                continue;
            }
            compare_target(r, &engines, &target, &dir, &[], &mut lines, &mut tally);
            filters.extend(own);
        }
    }
    for tree in trees {
        let target = format!("tree {}", tree.path.display());
        tally.declared += 1;
        // A declared tree that is not there is a blind spot, never a skip.
        if !tree.path.is_dir() {
            tally.broken = true;
            tally.skipped += 1;
            lines.push(format!("FAIL {target}: not a directory"));
            continue;
        }
        compare_target(
            r,
            &engines,
            &target,
            &tree.path,
            &tree.scopes,
            &mut lines,
            &mut tally,
        );
    }
    if tally.broken {
        ok = false;
    }
    if tally.gained > 0 {
        ok = false;
    }
    if tally.compared + tally.skipped + tally.no_ci != tally.declared {
        ok = false;
        lines.push(format!(
            "FAIL declared {} != compared {} + skipped {} + no_ci {}",
            tally.declared, tally.compared, tally.skipped, tally.no_ci
        ));
    }
    lines.push(format!(
        "compare-engines: repos={} ci_branches={} trees={} targets declared={} compared={} skipped={} no_ci={} gained_error={} {}",
        repos.len(),
        tally.branches,
        trees.len(),
        tally.declared,
        tally.compared,
        tally.skipped,
        tally.no_ci,
        tally.gained,
        if ok { "PASS" } else { "FAIL" }
    ));
    (lines, ok)
}

struct Engines<'a> {
    old: &'a str,
    new: &'a str,
}

/// Counts derived from the targets iterated.
#[derive(Default)]
struct Tally {
    declared: usize,
    branches: usize,
    compared: usize,
    skipped: usize,
    no_ci: usize,
    gained: usize,
    /// An engine run or a branch listing failed, so safety is not proven.
    broken: bool,
}

/// Runs both engines over one checkout at its scopes (else its CI scopes) and its gate, and
/// reports the added error lines and the exit codes.
fn compare_target(
    r: &dyn Runner,
    engines: &Engines<'_>,
    target: &str,
    dir: &Path,
    declared_scopes: &[String],
    lines: &mut Vec<String>,
    tally: &mut Tally,
) {
    let scopes = if declared_scopes.is_empty() {
        ci_scopes(dir)
    } else {
        declared_scopes.to_vec()
    };
    let (mut o_tot, mut n_tot, mut added) = (0, 0, Vec::new());
    let (mut codes, mut broke) = (Vec::new(), false);
    tally.compared += 1;
    for s in scopes.iter().map(String::as_str).chain([GATE]) {
        match (
            run_engine(r, engines.old, s, dir),
            run_engine(r, engines.new, s, dir),
        ) {
            (Ok((old_code, a)), Ok((new_code, b))) => {
                let (x, y, add) = delta(&a, &b);
                o_tot += x;
                n_tot += y;
                added.extend(add.into_iter().map(|l| format!("[{s}] {l}")));
                codes.push(format!("{s}:{old_code}->{new_code}"));
                if old_code == 0 && new_code != 0 {
                    broke = true;
                    added.push(format!("[{s}] exit code 0 -> {new_code}"));
                }
            }
            (a, b) => {
                tally.broken = true;
                lines.push(format!(
                    "FAIL {target}: engine run failed, scope {s}: old={} new={}",
                    a.err().unwrap_or_else(|| "ok".to_string()),
                    b.err().unwrap_or_else(|| "ok".to_string())
                ));
                return;
            }
        }
    }
    lines.push(format!(
        "{target} scope={} old_err={o_tot} new_err={n_tot} added={} rc {}",
        scopes.join(","),
        added.len(),
        codes.join(" ")
    ));
    if broke || !added.is_empty() {
        tally.gained += 1;
        for l in added.iter().take(SHOWN) {
            lines.push(format!("  + {l}"));
        }
        if added.len() > SHOWN {
            lines.push(format!("  + ... {} more", added.len() - SHOWN));
        }
    }
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
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let listed = a
        .trees
        .iter()
        .map(|t| parse_tree(t, &cwd).map(|t| vec![t]))
        .chain(a.tree_lists.iter().map(|f| read_tree_list(f)))
        .collect::<Result<Vec<_>, _>>();
    let trees: Vec<Tree> = match listed {
        Ok(t) => t.into_iter().flatten().collect(),
        Err(e) => {
            eprintln!("compare-engines: {e}");
            return 2;
        }
    };
    if a.owners.is_empty() && a.repos.is_empty() && trees.is_empty() {
        eprintln!("compare-engines: give at least one --owner, --repo, --tree or --trees");
        return 2;
    }
    // The runs start inside each target, so a relative binary path would stop resolving.
    let absolute = |bin: &str| {
        if bin.contains('/') {
            cwd.join(bin).display().to_string()
        } else {
            bin.to_string()
        }
    };
    let work = std::env::temp_dir().join(format!("stenio-compare-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    if std::fs::create_dir_all(&work).is_err() {
        eprintln!("compare-engines: cannot create {}", work.display());
        return 2;
    }
    let (lines, ok) = compare(
        &Real,
        &absolute(&a.old),
        &absolute(&a.new),
        &a.owners,
        &a.repos,
        &trees,
        &work,
    );
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
        if key.starts_with("gh api --paginate repos/o/") {
            return out("main\nDEVELOPMENT\nrelease/1.x\nrelease/stale\nfeature/x\n");
        }
        if key.starts_with("git -C ") && key.ends_with("branch --show-current") {
            return out("main\n");
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
                "name: ci\non:\n  push:\n    branches: [main, DEVELOPMENT]\n  pull_request:\n    branches: ['release/**']\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: stenio --scope fork --strict --compact\n"
            } else {
                "name: ci\non:\n  push:\n    tags: ['v*']\njobs:\n  c:\n    runs-on: x\n    steps:\n      - run: make\n"
            };
            if !argv.iter().any(|a| a == "release/stale") {
                std::fs::write(wf.join("ci.yml"), body).map_err(|e| e.to_string())?;
            }
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
    let mut body = String::from(
        "case \"$*\" in *--gate*) exit 0;; esac\necho '[ERROR] a.rs:1: [BASE] existing'\n",
    );
    if extra_on_r2 {
        body.push_str("case \"$*\" in *o__r2*) echo '[ERROR] b.rs:2: [NEW-RULE] fresh';; esac\n");
        body.push_str(
            "case \"$*\" in *o__r1*_release_stale*) echo '[ERROR] d.rs:4: [NEW-RULE] stale';; esac\n",
        );
        body.push_str(
            "case \"$*\" in *o__r1*_DEVELOPMENT*) echo '[ERROR] c.rs:3: [NEW-RULE] branch';; esac\n",
        );
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
    let (o, n) = (old.display().to_string(), new.display().to_string());
    let owners = vec!["o".to_string()];
    let w1 = base.join("w1");
    let w2 = base.join("w2");
    let _ = std::fs::create_dir_all(&w1);
    let _ = std::fs::create_dir_all(&w2);
    let (red, red_ok) = compare(&Fixture, &o, &n, &owners, &[], &[], &w1);
    let red = red.join("\n");
    let (green, green_ok) = compare(&Fixture, &o, &o, &owners, &[], &[], &w2);
    let green = green.join("\n");
    let local = base.join("tree");
    let _ = std::fs::create_dir_all(&local);
    let list = base.join("trees.txt");
    let _ = std::fs::write(&list, "# local checkouts\ntree=homelab,default\n");
    let declared = read_tree_list(&list).unwrap_or_default();
    // A fake engine whose only new defect is on the gate, with a renumbered old finding.
    let gate_old = base.join("gate_old.sh");
    let gate_new = base.join("gate_new.sh");
    let _ = std::fs::write(
        &gate_old,
        "case \"$*\" in *--gate*) echo '   1. [OLD] a.rs:1: seen';; esac\n",
    );
    let _ = std::fs::write(
        &gate_new,
        "case \"$*\" in *--gate*) echo '   1. [NEW] z.rs:9: fresh'; echo '   2. [OLD] a.rs:1: seen'; exit 1;; esac\n",
    );
    let crash = base.join("crash.sh");
    let _ = std::fs::write(&crash, "exit 2\n");
    let run_tree = |new: &Path, trees: &[Tree]| {
        let (lines, ok) = compare(
            &Fixture,
            &gate_old.display().to_string(),
            &new.display().to_string(),
            &[],
            &[],
            trees,
            &w1,
        );
        (lines.join("\n"), ok)
    };
    let (tree_red, tree_red_ok) = run_tree(&gate_new, &declared);
    let (tree_green, tree_green_ok) = run_tree(&gate_old, &declared);
    let (tree_crash, tree_crash_ok) = run_tree(&crash, &declared);
    let missing = parse_tree("absent", &base).into_iter().collect::<Vec<_>>();
    let (tree_missing, tree_missing_ok) = run_tree(&gate_old, &missing);
    let tree_name = format!("tree {}", local.display());
    let _ = std::fs::remove_dir_all(&base);
    let selected = |on: &str| -> Vec<&str> {
        let filters = crate::ci::branch_filters(on);
        [
            "main",
            "dev",
            "release/1",
            "release/1/hotfix",
            "release/old",
        ]
        .into_iter()
        .filter(|b| filters.iter().any(|f| f.matches(b)))
        .collect()
    };
    vec![
        (
            "compare-engines: GB-402 mutation, an error added on a declared local tree gate fails naming tree and line"
                .to_string(),
            !tree_red_ok
                && tree_red.contains(&format!("{tree_name} scope=homelab,default"))
                && tree_red.contains("gate:0->1")
                && tree_red.contains("+ [gate] [NEW] z.rs:9: fresh")
                && !tree_red.contains("+ [gate] [OLD]")
                && tree_red.contains("trees=1 targets declared=1 compared=1")
                && tree_red.contains("gained_error=1 FAIL"),
        ),
        (
            "compare-engines: GB-402 identical engines pass on a declared tree".to_string(),
            tree_green_ok && tree_green.contains("gate:0->0"),
        ),
        (
            "compare-engines: GB-402 an engine that exits 2 or a missing tree fails".to_string(),
            !tree_crash_ok
                && tree_crash.contains("new=exit 2")
                && !tree_missing_ok
                && tree_missing.contains("not a directory"),
        ),
        (
            "compare-engines: GB-402 a tree spec without a scope after `=` is refused".to_string(),
            parse_tree("x=", Path::new("/")).is_err()
                && parse_tree("x", Path::new("/")).is_ok_and(|t| t.scopes.is_empty()),
        ),
        (
            "compare-engines: GB-298 branch filters follow the GitHub pattern syntax".to_string(),
            selected("on:\n  push:\n    branches: ['release/*', '!release/old']\n") == ["release/1"]
                && selected("on:\n  push:\n    branches: ['release/**']\n")
                    == ["release/1", "release/1/hotfix", "release/old"]
                && selected("on:\n  push:\n    branches-ignore: ['release/**']\n")
                    == ["main", "dev"]
                && selected("on: [push]\n").len() == 5
                && selected("on:\n  pull_request:\n").len() == 5
                && selected("on:\n  push:\n    tags: ['v*']\n").is_empty()
                && selected("on:\n  schedule:\n    - cron: '0 0 * * *'\n").is_empty(),
        ),
        (
            "compare-engines: mutation, a repo that gains an ERROR line fails and names it"
                .to_string(),
            !red_ok
                && red.contains("o/r2 scope=all old_err=1 new_err=2 added=1")
                && red.contains("+ [all] [ERROR] b.rs:2: [NEW-RULE] fresh")
                && red.contains("gained_error=2 FAIL"),
        ),
        (
            "compare-engines: GB-298 mutation, an ERROR gained only on a non-default CI branch fails"
                .to_string(),
            red.contains("o/r1 scope=fork old_err=1 new_err=1 added=0")
                && red.contains("o/r1@DEVELOPMENT scope=fork old_err=1 new_err=2 added=1")
                && red.contains("+ [fork] [ERROR] c.rs:3: [NEW-RULE] branch"),
        ),
        (
            "compare-engines: GB-298 only branches the workflows trigger on are compared".to_string(),
            green.contains("o/r1@release/1.x ")
                && !green.contains("@feature/x")
                && !green.contains("o/r2@"),
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
            red.contains(
                "repos=3 ci_branches=3 trees=0 targets declared=6 compared=4 skipped=1 no_ci=1",
            ),
        ),
        (
            "compare-engines: GB-298 a branch without a workflow runs no CI and is only listed"
                .to_string(),
            red.contains("NOCI o/r1@release/stale") && !red.contains("[NEW-RULE] stale"),
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
