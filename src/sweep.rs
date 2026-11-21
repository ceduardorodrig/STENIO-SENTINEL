//! `stenio sweep` (GB-267, GB-264 a and c): one pass over the authenticated GitHub account and
//! every organisation it belongs to, so a "nothing is red" answer cannot come from a listing that
//! only saw the personal repositories (failure-patterns.md pattern 10).
//!
//! It shells out to `gh api` through the engine's [`Runner`], so every decision is made on JSON
//! that the self-test feeds from a script; only the manual run touches the network. Per owner it
//! prints one line with a count *derived* from the repositories actually iterated (rule 12.3),
//! per repository the findings, and a final `PASS`/`FAIL` line.
//!
//! A workflow run is red when it is the latest completed run of its workflow on a branch or tag
//! inside the window and its conclusion is not success/skipped/neutral: a failure that a later run
//! of the same workflow and ref already superseded is history, not state.

use clap::Parser;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::release_engine::{Real, Runner};

const TIMEOUT: Duration = Duration::from_secs(60);
const PAGE: usize = 100;
const MAX_PAGES: usize = 20;
const LOCKFILES: [&str; 10] = [
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "bun.lock",
];

#[derive(Parser, Debug)]
#[command(
    name = "stenio sweep",
    about = "Sweep the gh account and every org: red runs, red PR checks, Dependabot alerts without a PR, conflicting lockfile PRs"
)]
struct Args {
    #[arg(long, default_value_t = 7, help = "Window of workflow runs, in days")]
    days: i64,
    #[arg(
        long = "owner",
        help = "Restrict to this owner (repeatable); it must be the account or one of its orgs"
    )]
    owners: Vec<String>,
}

/// String at `path` inside `v`, or `""`.
fn st<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    path.iter()
        .try_fold(v, |cur, k| cur.get(*k))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn gh(r: &dyn Runner, path: &str) -> Result<Value, String> {
    let argv: Vec<String> = ["gh", "api", path].iter().map(|s| s.to_string()).collect();
    let o = r.run(None, &argv, TIMEOUT)?;
    if o.code != 0 {
        return Err(format!("gh api {path}: exit {}", o.code));
    }
    serde_json::from_str(&o.stdout).map_err(|e| format!("gh api {path}: bad JSON: {e}"))
}

/// Every item of a paginated list; `key` names the array inside an object response.
fn gh_list(r: &dyn Runner, path: &str, key: Option<&str>) -> Result<Vec<Value>, String> {
    let sep = if path.contains('?') { '&' } else { '?' };
    let mut out = Vec::new();
    for page in 1..=MAX_PAGES {
        let v = gh(r, &format!("{path}{sep}per_page={PAGE}&page={page}"))?;
        let items = match key {
            Some(k) => v.get(k),
            None => Some(&v),
        }
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
        let n = items.len();
        out.extend(items);
        if n < PAGE {
            break;
        }
    }
    Ok(out)
}

/// The account login followed by every org login, in that order.
fn owners(r: &dyn Runner) -> Result<Vec<String>, String> {
    let me = gh(r, "user")?;
    let login = st(&me, &["login"]).to_string();
    if login.is_empty() {
        return Err("gh api user returned no login (not authenticated?)".to_string());
    }
    let mut all = vec![login];
    for org in gh_list(r, "user/orgs", None)? {
        let name = st(&org, &["login"]);
        if !name.is_empty() {
            all.push(name.to_string());
        }
    }
    Ok(all)
}

#[derive(Default)]
struct Repo {
    red_runs: Vec<String>,
    red_prs: Vec<String>,
    alerts: Option<usize>,
    alerts_no_pr: Vec<String>,
    conflicts: Vec<String>,
    errors: Vec<String>,
}

impl Repo {
    fn red(&self) -> usize {
        self.red_runs.len()
            + self.red_prs.len()
            + self.alerts_no_pr.len()
            + self.conflicts.len()
            + self.errors.len()
    }
}

fn red_runs(r: &dyn Runner, full: &str, since: &str) -> Result<Vec<String>, String> {
    let path = format!("repos/{full}/actions/runs?status=completed&created=>={since}");
    let runs = gh_list(r, &path, Some("workflow_runs"))?;
    let mut seen: BTreeSet<(i64, String)> = BTreeSet::new();
    let mut red = Vec::new();
    for run in &runs {
        let wf = run.get("workflow_id").and_then(Value::as_i64).unwrap_or(0);
        let branch = st(run, &["head_branch"]);
        if !seen.insert((wf, branch.to_string())) {
            continue; // newest first: an older run of the same workflow and ref is superseded
        }
        let concl = st(run, &["conclusion"]);
        if !matches!(concl, "success" | "skipped" | "neutral") {
            red.push(format!("{} on {branch}: {concl}", st(run, &["name"])));
        }
    }
    Ok(red)
}

fn bad_check(r: &dyn Runner, full: &str, pr: &Value) -> Result<Option<String>, String> {
    let sha = st(pr, &["head", "sha"]);
    let checks = gh_list(
        r,
        &format!("repos/{full}/commits/{sha}/check-runs"),
        Some("check_runs"),
    )?;
    let bad: Vec<&str> = checks
        .iter()
        .filter(|c| {
            matches!(
                st(c, &["conclusion"]),
                "failure" | "cancelled" | "timed_out" | "startup_failure"
            )
        })
        .map(|c| st(c, &["name"]))
        .collect();
    Ok((!bad.is_empty()).then(|| {
        format!(
            "PR #{} {}: failing check(s) {}",
            pr.get("number").and_then(Value::as_i64).unwrap_or(0),
            st(pr, &["title"]),
            bad.join(", ")
        )
    }))
}

fn is_dependabot(pr: &Value) -> bool {
    st(pr, &["user", "login"]).contains("dependabot")
}

/// Packages of open alerts that no open Dependabot PR mentions (GB-264 a).
fn alerts_without_pr(alerts: &[Value], prs: &[Value]) -> Vec<String> {
    let texts: Vec<String> = prs
        .iter()
        .filter(|p| is_dependabot(p))
        .map(|p| format!("{} {}", st(p, &["title"]), st(p, &["head", "ref"])).to_lowercase())
        .collect();
    let mut missing = BTreeSet::new();
    for a in alerts {
        let pkg = st(a, &["dependency", "package", "name"]).to_lowercase();
        if !pkg.is_empty() && !texts.iter().any(|t| t.contains(&pkg)) {
            missing.insert(pkg);
        }
    }
    missing.into_iter().collect()
}

/// Lockfile paths touched by two or more open PRs where one of them reports a merge conflict
/// (GB-264 c).
fn lockfile_conflicts(r: &dyn Runner, full: &str, prs: &[Value]) -> Result<Vec<String>, String> {
    let mut by_path: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for pr in prs {
        let n = pr.get("number").and_then(Value::as_i64).unwrap_or(0);
        for f in gh_list(r, &format!("repos/{full}/pulls/{n}/files"), None)? {
            let name = st(&f, &["filename"]);
            let base = name.rsplit('/').next().unwrap_or(name);
            if LOCKFILES.contains(&base) {
                by_path.entry(name.to_string()).or_default().push(n);
            }
        }
    }
    let mut out = Vec::new();
    for (path, nums) in by_path.iter().filter(|(_, n)| n.len() > 1) {
        let mut dirty = Vec::new();
        for n in nums {
            let one = gh(r, &format!("repos/{full}/pulls/{n}"))?;
            if st(&one, &["mergeable_state"]) == "dirty" {
                dirty.push(format!("#{n}"));
            }
        }
        if !dirty.is_empty() {
            let all: Vec<String> = nums.iter().map(|n| format!("#{n}")).collect();
            out.push(format!(
                "{path}: PRs {} share it, conflicting {}",
                all.join(", "),
                dirty.join(", ")
            ));
        }
    }
    Ok(out)
}

fn sweep_repo(r: &dyn Runner, full: &str, since: &str) -> Repo {
    let mut rep = Repo::default();
    match red_runs(r, full, since) {
        Ok(v) => rep.red_runs = v,
        Err(e) => rep.errors.push(e),
    }
    let prs = match gh_list(r, &format!("repos/{full}/pulls?state=open"), None) {
        Ok(p) => p,
        Err(e) => {
            rep.errors.push(e);
            Vec::new()
        }
    };
    for pr in &prs {
        match bad_check(r, full, pr) {
            Ok(Some(m)) => rep.red_prs.push(m),
            Ok(None) => {}
            Err(e) => rep.errors.push(e),
        }
    }
    // Alerts can be disabled on a repository: that is "n/a", not a failed sweep.
    if let Ok(alerts) = gh_list(
        r,
        &format!("repos/{full}/dependabot/alerts?state=open"),
        None,
    ) {
        rep.alerts = Some(alerts.len());
        rep.alerts_no_pr = alerts_without_pr(&alerts, &prs);
    }
    match lockfile_conflicts(r, full, &prs) {
        Ok(v) => rep.conflicts = v,
        Err(e) => rep.errors.push(e),
    }
    rep
}

/// Runs the whole sweep; returns the output lines and whether everything is green.
pub fn sweep(r: &dyn Runner, since: &str, only: &[String]) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let all = match owners(r) {
        Ok(o) => o,
        Err(e) => {
            return (
                vec![format!("FAIL sweep: cannot enumerate owners: {e}")],
                false,
            );
        }
    };
    let mut ok = true;
    for want in only {
        if !all.iter().any(|o| o.eq_ignore_ascii_case(want)) {
            lines.push(format!(
                "FAIL owner {want} is neither the account nor one of its orgs"
            ));
            ok = false;
        }
    }
    let chosen: Vec<&String> = all
        .iter()
        .filter(|o| only.is_empty() || only.iter().any(|w| w.eq_ignore_ascii_case(o)))
        .collect();
    let declared = chosen.len();
    let mut iterated = 0usize;
    let mut repos_total = 0usize;
    for owner in &chosen {
        iterated += 1;
        let list_path = if all.first() == Some(*owner) {
            "user/repos?affiliation=owner".to_string()
        } else {
            format!("orgs/{owner}/repos?type=all")
        };
        let repos = match gh_list(r, &list_path, None) {
            Ok(v) => v,
            Err(e) => {
                lines.push(format!("owner={owner} FAIL cannot list repositories: {e}"));
                ok = false;
                continue;
            }
        };
        let live: Vec<&Value> = repos
            .iter()
            .filter(|v| v.get("archived").and_then(Value::as_bool) != Some(true))
            .filter(|v| !st(v, &["name"]).is_empty())
            .collect();
        let mut detail = Vec::new();
        let (mut runs, mut prs, mut alerts, mut nopr, mut conf, mut errs) = (0, 0, 0, 0, 0, 0);
        for repo in &live {
            let name = st(repo, &["name"]);
            let rep = sweep_repo(r, &format!("{owner}/{name}"), since);
            runs += rep.red_runs.len();
            prs += rep.red_prs.len();
            alerts += rep.alerts.unwrap_or(0);
            nopr += rep.alerts_no_pr.len();
            conf += rep.conflicts.len();
            errs += rep.errors.len();
            let items = rep
                .red_runs
                .iter()
                .map(|m| format!("red run {m}"))
                .chain(rep.red_prs.iter().map(|m| format!("red {m}")))
                .chain(
                    rep.alerts_no_pr
                        .iter()
                        .map(|p| format!("alert without PR: {p}")),
                )
                .chain(
                    rep.conflicts
                        .iter()
                        .map(|m| format!("lockfile conflict {m}")),
                )
                .chain(rep.errors.iter().map(|m| format!("unverified {m}")));
            for m in items {
                detail.push(format!("  {owner}/{name}: {m}"));
            }
            if rep.red() > 0 {
                ok = false;
            }
        }
        repos_total += live.len();
        lines.push(format!(
            "owner={owner} repos={} red_runs={runs} red_prs={prs} alerts={alerts} alerts_no_pr={nopr} lockfile_conflicts={conf} unverified={errs}",
            live.len()
        ));
        lines.extend(detail);
    }
    if declared != iterated {
        lines.push(format!(
            "FAIL declared {declared} owner(s), iterated {iterated}"
        ));
        ok = false;
    }
    lines.push(format!(
        "{} sweep: owners declared={declared} iterated={iterated} repos={repos_total} since={since}",
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
    let since = (chrono::Utc::now() - chrono::Duration::days(a.days.max(1)))
        .format("%Y-%m-%d")
        .to_string();
    let (lines, ok) = sweep(&Real, &since, &a.owners);
    for l in &lines {
        println!("{l}");
    }
    i32::from(!ok)
}

// ── self-test: canned gh JSON, no network ──────────────────────────────────
struct Canned(Vec<(String, String)>);

impl Runner for Canned {
    fn run(
        &self,
        _dir: Option<&std::path::Path>,
        argv: &[String],
        _t: Duration,
    ) -> Result<crate::verify_release::Out, String> {
        let key = argv.join(" ");
        self.0
            .iter()
            .find(|(needle, _)| key.starts_with(needle.as_str()))
            .map(|(_, body)| crate::verify_release::Out {
                code: 0,
                stdout: body.clone(),
            })
            .ok_or_else(|| format!("not scripted: {key}"))
    }
}

/// `red`: the org repo carries a red run, a red PR check, an alert with no PR and two PRs on one
/// conflicting lockfile. `orgs`: whether `user/orgs` lists the organisation.
fn fixture(red: bool, orgs: bool) -> Canned {
    let g = |n: &str, b: &str| (format!("gh api {n}"), b.to_string());
    let run = |wf: i64, br: &str, c: &str| {
        format!(r#"{{"workflow_id":{wf},"name":"ci","head_branch":"{br}","conclusion":"{c}"}}"#)
    };
    let main_c = if red { "failure" } else { "success" };
    let runs = format!(
        r#"{{"workflow_runs":[{},{},{},{}]}}"#,
        run(1, "main", main_c),
        run(1, "main", "success"),
        run(2, "dev", "success"),
        run(2, "dev", "failure")
    );
    let pr = |n: i64, sha: &str, login: &str, title: &str| {
        format!(
            r#"{{"number":{n},"title":"{title}","head":{{"sha":"{sha}","ref":"dependabot/x/{title}"}},"user":{{"login":"{login}"}}}}"#
        )
    };
    let prs = format!(
        "[{},{}]",
        pr(1, "s1", "dependabot[bot]", "lodash"),
        pr(2, "s2", "dependabot[bot]", "axios")
    );
    let s2 = if red { "failure" } else { "success" };
    let alerts = if red {
        r#"[{"dependency":{"package":{"name":"lodash"}}},{"dependency":{"package":{"name":"glob"}}}]"#
    } else {
        r#"[{"dependency":{"package":{"name":"lodash"}}}]"#
    };
    let f2 = if red {
        "package-lock.json"
    } else {
        "other.txt"
    };
    let state1 = if red { "dirty" } else { "clean" };
    Canned(vec![
        g(
            "user/orgs",
            if orgs { r#"[{"login":"orgx"}]"# } else { "[]" },
        ),
        g("user/repos", r#"[{"name":"p1","archived":false}]"#),
        g(
            "orgs/orgx/repos",
            r#"[{"name":"r1","archived":false},{"name":"old","archived":true}]"#,
        ),
        g("repos/me/p1/actions/runs", r#"{"workflow_runs":[]}"#),
        g("repos/me/p1/pulls", "[]"),
        g("repos/me/p1/dependabot/alerts", "[]"),
        g("repos/orgx/r1/actions/runs", &runs),
        g("repos/orgx/r1/pulls?state=open", &prs),
        g(
            "repos/orgx/r1/commits/s1/check-runs",
            r#"{"check_runs":[{"name":"build","conclusion":"success"}]}"#,
        ),
        g(
            "repos/orgx/r1/commits/s2/check-runs",
            &format!(r#"{{"check_runs":[{{"name":"test","conclusion":"{s2}"}}]}}"#),
        ),
        g("repos/orgx/r1/dependabot/alerts", alerts),
        g(
            "repos/orgx/r1/pulls/1/files",
            r#"[{"filename":"package-lock.json"}]"#,
        ),
        g(
            "repos/orgx/r1/pulls/2/files",
            &format!(r#"[{{"filename":"{f2}"}}]"#),
        ),
        g(
            "repos/orgx/r1/pulls/1",
            &format!(r#"{{"mergeable_state":"{state1}"}}"#),
        ),
        g("repos/orgx/r1/pulls/2", r#"{"mergeable_state":"clean"}"#),
        g("user", r#"{"login":"me"}"#),
    ])
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let go = |red: bool, orgs: bool| sweep(&fixture(red, orgs), "2026-11-14", &[]);
    let (red, red_ok) = go(true, true);
    let red = red.join("\n");
    let (no_org, no_org_ok) = go(true, false);
    let no_org = no_org.join("\n");
    let (green, green_ok) = go(false, true);
    let (filtered, filtered_ok) = sweep(&fixture(true, true), "2026-11-14", &["orgx".to_string()]);
    let (_, missing_ok) = sweep(&fixture(true, true), "2026-11-14", &["nope".to_string()]);
    vec![
        (
            "sweep reports a red run of an org repo".to_string(),
            !red_ok && red.contains("orgx/r1: red run ci on main: failure"),
        ),
        (
            "sweep without the org enumeration misses the org repo".to_string(),
            no_org_ok && !no_org.contains("orgx"),
        ),
        (
            "sweep owner count is derived from the owners iterated".to_string(),
            red.contains("owners declared=2 iterated=2")
                && no_org.contains("declared=1 iterated=1"),
        ),
        (
            "sweep skips archived repos and superseded runs".to_string(),
            red.contains("owner=orgx repos=1 red_runs=1") && !red.contains("on dev"),
        ),
        (
            "sweep flags an alert with no Dependabot PR".to_string(),
            red.contains("alert without PR: glob") && !red.contains("without PR: lodash"),
        ),
        (
            "sweep flags two PRs conflicting on one lockfile".to_string(),
            red.contains(
                "lockfile conflict package-lock.json: PRs #1, #2 share it, conflicting #1",
            ),
        ),
        (
            "sweep flags a red PR check".to_string(),
            red.contains("red PR #2 axios: failing check(s) test"),
        ),
        (
            "sweep passes a clean account".to_string(),
            green_ok && green.last().is_some_and(|l| l.starts_with("PASS sweep")),
        ),
        (
            "sweep --owner restricts and rejects an unknown owner".to_string(),
            filtered.iter().all(|l| !l.starts_with("owner=me")) && !filtered_ok && !missing_ok,
        ),
    ]
}
