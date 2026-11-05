//! `stenio release-engine` (GB-034): one deterministic pass from a tag to both hosts.
//!
//! Replaces the hand-typed release sequence: local tag, origin tag, CI/Docker/Release runs,
//! release build, install with a rollback copy, kuaray image retag/pull/up and version parity,
//! then the engine self-test and the two delivery scopes. Every step prints one PASS/FAIL/SKIP
//! line and the command exits non-zero on any FAIL. Commands are argv vectors (never a shell),
//! every value is validated first, and the [`Runner`] trait keeps the sequence testable offline.

use clap::Parser;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::verify_release::{Out, safe};

const DEFAULT_IMAGE_REPO: &str = "ghcr.io/ceduardorodrig/stenio-sentinel";
/// The three workflows GitHub must conclude successfully for a release tag.
const REQUIRED_RUNS: usize = 3;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "stenio release-engine",
    about = "Waits for CI, installs the engine with a rollback copy and redeploys the kuaray container (PASS/FAIL per step)"
)]
struct RelArgs {
    #[arg(long, help = "Release tag, e.g. v4.18.0")]
    tag: String,
    #[arg(
        long,
        default_value = ".",
        help = "Engine repository, checked out at the tag"
    )]
    repo: PathBuf,
    #[arg(long, default_value = "kuaray")]
    host: String,
    #[arg(long, default_value = "miracena-stenio")]
    container: String,
    #[arg(long, default_value = "/srv/data/miracena")]
    compose_dir: String,
    #[arg(long, default_value = "stenio")]
    service: String,
    #[arg(long, default_value = DEFAULT_IMAGE_REPO)]
    image_repo: String,
    #[arg(long, default_value_t = 1200, help = "Seconds to wait for the CI runs")]
    wait_secs: u64,
    #[arg(long, default_value_t = 900, help = "Seconds for the release build")]
    build_timeout_secs: u64,
    #[arg(long, help = "Installation directory (default: $HOME/.cargo/bin)")]
    install_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Do not wait for the GitHub runs (offline or already green)"
    )]
    skip_ci: bool,
    #[arg(
        long,
        help = "Print the plan and the commands without running anything"
    )]
    dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
    /// Not a failure: the built binary plans *fewer* steps than the engine running the release.
    Warn,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

fn pass(name: &'static str, detail: impl Into<String>) -> Line {
    Line {
        status: Status::Pass,
        name,
        detail: detail.into(),
    }
}

fn fail(name: &'static str, detail: impl Into<String>) -> Line {
    Line {
        status: Status::Fail,
        name,
        detail: detail.into(),
    }
}

fn skip(name: &'static str, detail: impl Into<String>) -> Line {
    Line {
        status: Status::Skip,
        name,
        detail: detail.into(),
    }
}

fn warn(name: &'static str, detail: impl Into<String>) -> Line {
    Line {
        status: Status::Warn,
        name,
        detail: detail.into(),
    }
}

/// Runs one argv vector in an optional directory. `Real` shells out; the offline tests script it.
pub trait Runner {
    fn run(&self, dir: Option<&Path>, argv: &[String], timeout: Duration) -> Result<Out, String>;
}

pub struct Real;

impl Runner for Real {
    fn run(&self, dir: Option<&Path>, argv: &[String], timeout: Duration) -> Result<Out, String> {
        let (program, rest) = argv.split_first().ok_or("empty command")?;
        let mut c = Command::new(program);
        c.args(rest)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(d) = dir {
            c.current_dir(d);
        }
        crate::verify_release::spawn_with_timeout(c, timeout)
    }
}

fn short(s: &str) -> &str {
    &s[..s.len().min(12)]
}

fn out_ok(o: &Out) -> bool {
    o.code == 0
}

fn one_line(o: &Out) -> String {
    o.stdout.trim().to_string()
}

fn version_of(o: &Out) -> String {
    o.stdout
        .split_whitespace()
        .last()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn tag_commit(r: &dyn Runner, repo: &Path, tag: &str) -> Result<String, String> {
    let rev = format!("{tag}^{{commit}}");
    let argv = vec![
        "git".to_string(),
        "-C".to_string(),
        repo.display().to_string(),
        "rev-parse".to_string(),
        "--verify".to_string(),
        "-q".to_string(),
        rev,
    ];
    let o = r.run(None, &argv, Duration::from_secs(30))?;
    if !out_ok(&o) || one_line(&o).is_empty() {
        return Err(format!(
            "tag {tag} does not exist in {}: create and push it first",
            repo.display()
        ));
    }
    Ok(one_line(&o))
}

fn head_commit(r: &dyn Runner, repo: &Path) -> Result<String, String> {
    let argv = vec![
        "git".to_string(),
        "-C".to_string(),
        repo.display().to_string(),
        "rev-parse".to_string(),
        "HEAD".to_string(),
    ];
    let o = r.run(None, &argv, Duration::from_secs(30))?;
    if !out_ok(&o) {
        return Err("cannot read HEAD".to_string());
    }
    Ok(one_line(&o))
}

fn ci_runs(
    r: &dyn Runner,
    commit: &str,
    wait: Duration,
) -> Result<Vec<(String, String, String)>, String> {
    let start = Instant::now();
    loop {
        let argv = vec![
            "gh".to_string(),
            "run".to_string(),
            "list".to_string(),
            "--commit".to_string(),
            commit.to_string(),
            "--json".to_string(),
            "workflowName,status,conclusion".to_string(),
            "--limit".to_string(),
            "50".to_string(),
        ];
        let o = r.run(None, &argv, Duration::from_secs(60))?;
        if !out_ok(&o) {
            return Err("gh run list failed (authenticate gh or use --skip-ci)".to_string());
        }
        let parsed: Value = serde_json::from_str(one_line(&o).as_str())
            .map_err(|e| format!("cannot parse gh output: {e}"))?;
        let mut runs: Vec<(String, String, String)> = Vec::new();
        for run in parsed.as_array().map(Vec::as_slice).unwrap_or_default() {
            let text = |k: &str| run.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            runs.push((text("workflowName"), text("status"), text("conclusion")));
        }
        let pending = runs.iter().any(|(_, s, _)| s != "completed");
        // An empty list is not "CI already finished": GitHub registers the runs a few seconds
        // after the push, and treating it as done ended the wait instantly (v4.19.0, step ci).
        let appearing = runs.is_empty() && start.elapsed() <= wait;
        if !pending && !appearing {
            return Ok(runs);
        }
        if start.elapsed() > wait {
            return Err(format!(
                "timeout after {}s waiting for {} run(s) of {}",
                wait.as_secs(),
                runs.iter().filter(|(_, s, _)| s != "completed").count(),
                short(commit)
            ));
        }
        std::thread::park_timeout(Duration::from_secs(15));
    }
}

fn check_tag(r: &dyn Runner, a: &RelArgs) -> Result<String, String> {
    let c = tag_commit(r, &a.repo, &a.tag)?;
    let head = head_commit(r, &a.repo)?;
    if head != c {
        return Err(format!(
            "HEAD is {} but {} is {}: check out the tag first",
            short(&head),
            a.tag,
            short(&c)
        ));
    }
    Ok(c)
}

fn check_origin(r: &dyn Runner, a: &RelArgs, commit: &str) -> Line {
    let argv = vec![
        "git".to_string(),
        "-C".to_string(),
        a.repo.display().to_string(),
        "ls-remote".to_string(),
        "--tags".to_string(),
        "origin".to_string(),
        format!("refs/tags/{}", a.tag),
    ];
    match r.run(None, &argv, Duration::from_secs(60)) {
        Ok(o) if out_ok(&o) && one_line(&o).starts_with(commit) => pass(
            "tag-origin",
            format!("origin has {} at {}", a.tag, short(commit)),
        ),
        Ok(o) if out_ok(&o) && one_line(&o).is_empty() => {
            fail("tag-origin", format!("{} is not pushed to origin", a.tag))
        }
        Ok(o) if out_ok(&o) => fail(
            "tag-origin",
            format!(
                "origin {} differs from local {}",
                short(&one_line(&o)),
                short(commit)
            ),
        ),
        Ok(_) => fail("tag-origin", "git ls-remote failed"),
        Err(e) => fail("tag-origin", e),
    }
}

fn check_ci(r: &dyn Runner, a: &RelArgs, commit: &str) -> Line {
    if a.skip_ci {
        return skip("ci", "--skip-ci: runs not checked");
    }
    match ci_runs(r, commit, Duration::from_secs(a.wait_secs)) {
        Ok(runs) => {
            let failed: Vec<&str> = runs
                .iter()
                .filter(|(_, _, c)| c != "success")
                .map(|(n, _, c)| if c.is_empty() { n.as_str() } else { c.as_str() })
                .collect();
            if runs.len() < REQUIRED_RUNS {
                fail(
                    "ci",
                    format!(
                        "{} run(s) for {}; expected at least {REQUIRED_RUNS}",
                        runs.len(),
                        short(commit)
                    ),
                )
            } else if failed.is_empty() {
                pass("ci", format!("{} workflow(s) succeeded", runs.len()))
            } else {
                fail("ci", format!("not successful: {}", failed.join(", ")))
            }
        }
        Err(e) => fail("ci", e),
    }
}

fn check_build(r: &dyn Runner, a: &RelArgs) -> Line {
    let argv = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--release".to_string(),
        "--locked".to_string(),
    ];
    match r.run(
        Some(&a.repo),
        &argv,
        Duration::from_secs(a.build_timeout_secs),
    ) {
        Ok(o) if out_ok(&o) => pass("build", "cargo build --release --locked"),
        Ok(o) => fail("build", format!("cargo exited {}", o.code)),
        Err(e) => fail("build", e),
    }
}

/// The argv of the freshly built binary's own plan, the one [`check_plan_parity`] reads.
fn dry_run_argv(a: &RelArgs) -> Vec<String> {
    vec![
        a.repo.join("target/release/stenio").display().to_string(),
        "release-engine".to_string(),
        "--tag".to_string(),
        a.tag.clone(),
        "--dry-run".to_string(),
    ]
}

/// The step names the `--dry-run` output announces (`PLAN <name> <command>`). Only the names are
/// compared: the commands carry absolute paths and versions that legitimately differ between the
/// two binaries and would turn every release into noise.
fn plan_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("PLAN "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// One line, so a FAIL row never breaks the one-row-per-step output.
fn flat(s: &str) -> String {
    let parts: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if parts.is_empty() {
        "<no output>".to_string()
    } else {
        parts.join(" | ")
    }
}

/// The release that introduces a gate must be verified by that same gate. The engine executing a
/// release is always the one installed *before* it, so the checks a tag adds are only enforced from
/// the next tag on: the facts are that `integrity` never ran on the very 4.20.0 that introduced it,
/// and `lockfile`/`binary-version` only gated from 4.22.0 on. Each release was approved by a weaker
/// standard than the one it shipped.
///
/// The freshly built binary knows its own sequence, so it is asked for `--dry-run` and the step
/// names are compared with the plan of the engine doing the work: a name the built binary plans and
/// this engine does not know means the tag would be approved without that gate → FAIL. A name only
/// this engine knows means the built binary dropped a step → WARN, the sequence still runs.
fn check_plan_parity(r: &dyn Runner, a: &RelArgs) -> Line {
    let bin = a.repo.join("target/release/stenio");
    if !bin.is_file() {
        return fail(
            "plan-parity",
            format!("{} missing: the build produced no binary", bin.display()),
        );
    }
    let o = match r.run(Some(&a.repo), &dry_run_argv(a), Duration::from_secs(120)) {
        Ok(o) => o,
        Err(e) => return fail("plan-parity", format!("cannot run the built binary: {e}")),
    };
    if !out_ok(&o) {
        return fail(
            "plan-parity",
            format!("--dry-run exited {}: {}", o.code, flat(&o.stdout)),
        );
    }
    let fresh = plan_names(&o.stdout);
    if fresh.is_empty() {
        return fail(
            "plan-parity",
            format!("--dry-run printed no PLAN line: {}", flat(&o.stdout)),
        );
    }
    let current_plan = plan(a);
    let fresh_set: std::collections::BTreeSet<&str> = fresh.iter().map(String::as_str).collect();
    let current_set: std::collections::BTreeSet<&str> =
        current_plan.iter().map(|(n, _)| *n).collect();
    let added: Vec<&str> = fresh_set.difference(&current_set).copied().collect();
    if !added.is_empty() {
        // Advisory on purpose: this is the release that introduces the step, and the engine
        // running the sequence is the previous one, so it cannot apply what it does not know.
        // Failing here would make adding a gate impossible — every future step would be blocked
        // by its own absence. The price of the advisory is one release graded by the older
        // standard; the price of failing is no new gates at all.
        return warn(
            "plan-parity",
            format!(
                "{} introduces step(s) this engine does not run: {} — graded by the previous standard, enforced from the next release",
                a.tag,
                added.join(", ")
            ),
        );
    }
    let dropped: Vec<&str> = current_set.difference(&fresh_set).copied().collect();
    if !dropped.is_empty() {
        // The dangerous direction: a release that removes a gate silently raises the standard
        // of proof it accepts. Losing protection is a FAIL.
        return fail(
            "plan-parity",
            format!(
                "the built binary no longer plans step(s) this engine runs: {} — the release would drop a gate the current engine still applies",
                dropped.join(", ")
            ),
        );
    }
    pass(
        "plan-parity",
        format!("{} step(s) match the built binary's plan", fresh.len()),
    )
}

/// `cargo metadata --locked --offline --no-deps`: parses `Cargo.toml` without the network.
/// `--no-deps` stays because resolving the full graph offline downloads every target's crates
/// (a macOS-only `fsevent-sys` is absent from this machine's cache), and the version parity below
/// is what actually matters here.
fn lockfile_argv() -> Vec<String> {
    [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--no-deps",
        "--format-version",
        "1",
    ]
    .map(String::from)
    .to_vec()
}

/// The `name`/`version` pairs pinned by `Cargo.lock`, read straight from its `[[package]]` blocks.
fn lockfile_versions(lock: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut current = String::new();
    for line in lock.lines() {
        let l = line.trim();
        if l == "[[package]]" {
            current.clear();
        } else if current.is_empty()
            && let Some(v) = l.strip_prefix("name = \"")
            && let Some(v) = v.strip_suffix('"')
        {
            current = v.to_string();
        } else if !current.is_empty()
            && let Some(v) = l.strip_prefix("version = \"")
            && let Some(v) = v.strip_suffix('"')
        {
            out.insert(std::mem::take(&mut current), v.to_string());
        }
    }
    out
}

/// `cargo build --locked` refuses to build when `Cargo.lock` is behind `Cargo.toml` — but it
/// refuses *after* leaving the previous `target/release/stenio` untouched, so a failed build
/// looks like a successful one to every step downstream. Bumping `version` in `Cargo.toml` and
/// running `cargo build --release --locked` exits non-zero while `target/release/stenio` still
/// answers the old version (observed on 4.19.1 → 4.20.0). This proves the lockfile is in sync
/// before anything is built and a FAIL stops the sequence.
///
/// The exit code alone is not enough: `--no-deps` skips resolution, so `cargo metadata --locked`
/// exits 0 on a 0.1.0 manifest / 0.2.0 lockfile while `cargo build --locked` exits 101 (measured
/// on a scratch crate). The JSON carries the manifest truth and `Cargo.lock` the pinned truth,
/// so both are compared here, offline and without building.
fn check_lockfile(r: &dyn Runner, a: &RelArgs) -> Line {
    let meta = match r.run(Some(&a.repo), &lockfile_argv(), Duration::from_secs(120)) {
        Ok(o) if out_ok(&o) => o.stdout,
        Ok(o) => {
            return fail(
                "lockfile",
                format!(
                    "cargo metadata --locked exited {}: Cargo.lock is stale; run `cargo update --workspace` (or any command without --locked), commit Cargo.lock and recreate the tag",
                    o.code
                ),
            );
        }
        Err(e) => return fail("lockfile", e),
    };
    let parsed: Value = match serde_json::from_str(&meta) {
        Ok(v) => v,
        Err(e) => return fail("lockfile", format!("cannot parse cargo metadata: {e}")),
    };
    let lock_path = a.repo.join("Cargo.lock");
    let lock = match std::fs::read_to_string(&lock_path) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                "lockfile",
                format!("cannot read {}: {e}", lock_path.display()),
            );
        }
    };
    let pinned = lockfile_versions(&lock);
    let mut drift = Vec::new();
    let mut members = 0usize;
    for pkg in parsed
        .get("packages")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let name = pkg.get("name").and_then(Value::as_str).unwrap_or_default();
        let ver = pkg
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        members += 1;
        match pinned.get(name) {
            Some(p) if p == ver => {}
            Some(p) => drift.push(format!("{name} {ver} in Cargo.toml, {p} in Cargo.lock")),
            None => drift.push(format!("{name} {ver} is not in Cargo.lock")),
        }
    }
    if members == 0 {
        return fail(
            "lockfile",
            format!("cargo metadata lists no package in {}", a.repo.display()),
        );
    }
    if drift.is_empty() {
        pass(
            "lockfile",
            format!("Cargo.lock pins the {members} workspace version(s) of Cargo.toml"),
        )
    } else {
        fail(
            "lockfile",
            format!(
                "Cargo.lock is stale ({}): run `cargo update --workspace` (or any command without --locked), commit Cargo.lock and recreate the tag",
                drift.join(", ")
            ),
        )
    }
}

/// The version a string stands for, or "nothing" when it is empty.
fn shown(v: &str) -> &str {
    if v.is_empty() { "nothing" } else { v }
}

/// The artifact must declare the version the tag names. `check_install` compares the *installed*
/// binary, which is exactly the one that hides a stale build: after a refused `cargo build
/// --locked` the installed 4.19.1 still matches an old install record while the tag says 4.20.0.
/// Reading `target/release/stenio --version` right after the build and stopping before install
/// keeps a refused build from being published under a newer tag.
fn check_binary_version(r: &dyn Runner, a: &RelArgs, version: &str) -> Line {
    let bin = a.repo.join("target/release/stenio");
    if !bin.is_file() {
        return fail(
            "binary-version",
            format!("{} missing: the build produced no binary", bin.display()),
        );
    }
    let argv = vec![bin.display().to_string(), "--version".to_string()];
    match r.run(Some(&a.repo), &argv, Duration::from_secs(30)) {
        Ok(o) if out_ok(&o) && version_of(&o) == version => {
            pass("binary-version", format!("built binary declares {version}"))
        }
        Ok(o) if out_ok(&o) => fail(
            "binary-version",
            format!(
                "the build declares '{}' but {} is {version}: stale target/release (the build failed earlier); nothing installed",
                shown(&version_of(&o)),
                a.tag
            ),
        ),
        Ok(o) => fail("binary-version", format!("--version exited {}", o.code)),
        Err(e) => fail("binary-version", e),
    }
}

/// The artifact being released must pass its own tamper check. The anchors in `guardian.rs` are
/// the only thing that tells a reflowed comment from a removed invariant, and this step exists
/// because that gate used to run only by hand — which is to say it never ran. A comment that
/// reflowed across two lines broke `frappe.rs` "no suppression directive" for several releases
/// and nothing noticed until a release was about to ship.
fn check_integrity(r: &dyn Runner, a: &RelArgs) -> Line {
    let bin = a.repo.join("target/release/stenio");
    let argv = vec![bin.display().to_string(), "--guardian".to_string()];
    match r.run(Some(&a.repo), &argv, Duration::from_secs(120)) {
        Ok(o) if out_ok(&o) => pass("integrity", "guardian: core modules and anchors intact"),
        Ok(o) => fail(
            "integrity",
            format!("guardian exited {}: {}", o.code, one_line(&o)),
        ),
        Err(e) => fail("integrity", e),
    }
}

fn install_dir(a: &RelArgs) -> Result<PathBuf, String> {
    match &a.install_dir {
        Some(p) => Ok(p.clone()),
        None => std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".cargo/bin"))
            .map_err(|_| "HOME is not set; pass --install-dir".to_string()),
    }
}

fn installed_version(r: &dyn Runner, bin: &Path) -> String {
    if !bin.is_file() {
        return String::new();
    }
    let argv = vec![bin.display().to_string(), "--version".to_string()];
    match r.run(None, &argv, Duration::from_secs(30)) {
        Ok(o) if out_ok(&o) => version_of(&o),
        _ => String::new(),
    }
}

fn check_install(r: &dyn Runner, a: &RelArgs, version: &str) -> Line {
    let dir = match install_dir(a) {
        Ok(d) => d,
        Err(e) => return fail("install", e),
    };
    let installed = dir.join("stenio");
    let old = installed_version(r, &installed);
    let fresh = a.repo.join("target/release/stenio");
    if !fresh.is_file() {
        return fail(
            "install",
            format!("{} missing: run the build step first", fresh.display()),
        );
    }
    let mut notes = Vec::new();
    if !old.is_empty() && old != version {
        let backup = dir.join(format!("stenio.prev-{old}"));
        if backup.is_file() {
            notes.push(format!("rollback copy {} kept", backup.display()));
        } else {
            match std::fs::copy(&installed, &backup) {
                Ok(_) => notes.push(format!("rollback copy {}", backup.display())),
                Err(e) => return fail("install", format!("cannot keep the rollback copy: {e}")),
            }
        }
    }
    // Write next to the target and rename: a running binary cannot be overwritten in place
    // (ETXTBSY), and the rename swaps the inode atomically.
    let tmp = dir.join(format!(".stenio.new.{}", std::process::id()));
    let written = std::fs::copy(&fresh, &tmp).and_then(|_| std::fs::rename(&tmp, &installed));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return fail(
            "install",
            format!("cannot install {}: {e}", installed.display()),
        );
    }
    let now = installed_version(r, &installed);
    if now == version {
        notes.insert(0, format!("{} -> {now}", installed.display()));
        pass("install", notes.join("; "))
    } else {
        fail(
            "install",
            format!(
                "installed binary reports '{}' instead of {version}",
                shown(&now)
            ),
        )
    }
}

fn remote(r: &dyn Runner, a: &RelArgs, script: &str, timeout: Duration) -> Result<Out, String> {
    let argv = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        a.host.clone(),
        script.to_string(),
    ];
    r.run(None, &argv, timeout)
}

fn check_retag(r: &dyn Runner, a: &RelArgs, version: &str, old: &str) -> Line {
    if old.is_empty() || old == version {
        return skip("kuaray-retag", "no previous version to keep");
    }
    let script = format!(
        "docker tag $(docker inspect -f '{{{{.Image}}}}' {}) stenio-sentinel:prev-{old}",
        a.container
    );
    match remote(r, a, &script, Duration::from_secs(120)) {
        Ok(o) if out_ok(&o) => pass("kuaray-retag", format!("stenio-sentinel:prev-{old}")),
        Ok(o) => fail("kuaray-retag", format!("docker tag exited {}", o.code)),
        Err(e) => fail("kuaray-retag", e),
    }
}

fn check_pull(r: &dyn Runner, a: &RelArgs, version: &str) -> Line {
    let image = format!("{}:{version}", a.image_repo);
    let target = format!("{}:{}", a.image_repo, tag_major(version));
    let script = format!("docker pull {image} && docker tag {image} {target}");
    match remote(r, a, &script, Duration::from_secs(600)) {
        Ok(o) if out_ok(&o) => pass("kuaray-pull", format!("{image} -> {target}")),
        Ok(o) => fail("kuaray-pull", format!("docker pull/tag exited {}", o.code)),
        Err(e) => fail("kuaray-pull", e),
    }
}

/// The moving major tag a compose file references (`4` for `4.18.0`).
fn tag_major(version: &str) -> &str {
    version.split('.').next().unwrap_or(version)
}

fn check_up(r: &dyn Runner, a: &RelArgs) -> Line {
    let script = format!("cd {} && docker compose up -d {}", a.compose_dir, a.service);
    match remote(r, a, &script, Duration::from_secs(300)) {
        Ok(o) if out_ok(&o) => pass("kuaray-up", format!("service {} recreated", a.service)),
        Ok(o) => fail("kuaray-up", format!("docker compose exited {}", o.code)),
        Err(e) => fail("kuaray-up", e),
    }
}

fn check_remote_version(r: &dyn Runner, a: &RelArgs, version: &str) -> Line {
    let script = format!("docker exec {} stenio --version", a.container);
    match remote(r, a, &script, Duration::from_secs(120)) {
        Ok(o) if out_ok(&o) && version_of(&o) == version => {
            pass("kuaray-version", format!("{} {version}", a.container))
        }
        Ok(o) if out_ok(&o) => fail(
            "kuaray-version",
            format!(
                "DRIFT {} {} != {version}: the container still runs the previous image",
                a.container,
                version_of(&o)
            ),
        ),
        Ok(o) => fail("kuaray-version", format!("docker exec exited {}", o.code)),
        Err(e) => fail("kuaray-version", e),
    }
}

fn check_self_test(r: &dyn Runner, a: &RelArgs) -> Line {
    let dir = match install_dir(a) {
        Ok(d) => d,
        Err(e) => return fail("self-test", e),
    };
    let argv = vec![
        dir.join("stenio").display().to_string(),
        "--self-test".to_string(),
    ];
    match r.run(None, &argv, Duration::from_secs(300)) {
        Ok(o) if out_ok(&o) => pass("self-test", "engine self-test passed"),
        Ok(o) => fail("self-test", format!("self-test exited {}", o.code)),
        Err(e) => fail("self-test", e),
    }
}

fn check_scope(r: &dyn Runner, a: &RelArgs, scope: &str, vault: &Path) -> Line {
    let name: &'static str = if scope == "vault" {
        "scope-vault"
    } else {
        "scope-homelab"
    };
    let dir = match install_dir(a) {
        Ok(d) => d,
        Err(e) => return fail(name, e),
    };
    let argv = vec![
        dir.join("stenio").display().to_string(),
        "--scope".to_string(),
        scope.to_string(),
        "--path".to_string(),
        vault.display().to_string(),
    ];
    match r.run(None, &argv, Duration::from_secs(300)) {
        Ok(o) if out_ok(&o) => pass(name, format!("--scope {scope}: 0 errors")),
        Ok(o) => fail(name, format!("--scope {scope} exited {}", o.code)),
        Err(e) => fail(name, e),
    }
}

/// The whole sequence. Stops at the first failing prerequisite (tag), at a stale lockfile (before
/// the build), at a build that declares another version (before the install) and at a plan the
/// running engine does not know (before the install).
fn run_steps(r: &dyn Runner, a: &RelArgs) -> Vec<Line> {
    let version = a.tag.trim_start_matches('v').to_string();
    let mut out = Vec::new();
    let commit = match check_tag(r, a) {
        Ok(c) => {
            out.push(pass("tag-local", format!("{} = HEAD {}", a.tag, short(&c))));
            c
        }
        Err(e) => {
            out.push(fail("tag-local", e));
            return out;
        }
    };
    out.push(check_origin(r, a, &commit));
    out.push(check_ci(r, a, &commit));
    let lock = check_lockfile(r, a);
    let lock_ok = lock.status == Status::Pass;
    out.push(lock);
    if !lock_ok {
        return out;
    }
    out.push(check_build(r, a));
    let declared = check_binary_version(r, a, &version);
    let declared_ok = declared.status == Status::Pass;
    out.push(declared);
    if !declared_ok {
        return out;
    }
    // After `binary-version` on purpose: the parity check trusts what the built binary prints, so
    // a stale `target/release/stenio` (a refused build) would answer with the *previous* plan and
    // pass vacuously. Only a binary that declares the tag version is worth asking.
    let parity = check_plan_parity(r, a);
    let parity_ok = parity.status != Status::Fail;
    out.push(parity);
    if !parity_ok {
        return out;
    }
    out.push(check_integrity(r, a));
    let old = install_dir(a)
        .map(|d| installed_version(r, &d.join("stenio")))
        .unwrap_or_default();
    let install = check_install(r, a, &version);
    let install_ok = install.status == Status::Pass;
    out.push(install);
    if !install_ok {
        return out;
    }
    out.push(check_retag(r, a, &version, &old));
    out.push(check_pull(r, a, &version));
    out.push(check_up(r, a));
    out.push(check_remote_version(r, a, &version));
    out.push(check_self_test(r, a));
    let vault = crate::opportunity::vault_root(None);
    out.push(check_scope(r, a, "vault", &vault));
    out.push(check_scope(r, a, "homelab", &vault));
    out
}

fn valid(a: &RelArgs) -> bool {
    safe(&a.tag, ".")
        && !a.tag.starts_with('-')
        && safe(&a.host, "")
        && !a.host.starts_with('-')
        && safe(&a.container, "")
        && !a.container.starts_with('-')
        && safe(&a.service, "")
        && !a.service.starts_with('-')
        && safe(&a.image_repo, "/._-:")
        && !a.image_repo.starts_with('-')
        && safe(&a.compose_dir, "/._-")
        && a.compose_dir.starts_with('/')
}

/// The commands the run would execute, for `--dry-run`.
fn plan(a: &RelArgs) -> Vec<(&'static str, String)> {
    let version = a.tag.trim_start_matches('v').to_string();
    vec![
        ("tag-local", format!("git -C {} rev-parse --verify -q {}^{{commit}}", a.repo.display(), a.tag)),
        ("tag-origin", format!("git -C {} ls-remote --tags origin refs/tags/{}", a.repo.display(), a.tag)),
        ("ci", "gh run list --commit <tag sha> --json workflowName,status,conclusion".to_string()),
        ("lockfile", format!("cargo metadata --locked --offline --no-deps --format-version 1 (in {})", a.repo.display())),
        ("build", format!("cargo build --release --locked (in {})", a.repo.display())),
        ("binary-version", format!("{}/target/release/stenio --version == {version}", a.repo.display())),
        ("plan-parity", format!("{}/target/release/stenio release-engine --tag {} --dry-run (step names vs this engine)", a.repo.display(), a.tag)),
        ("integrity", format!("{}/target/release/stenio --guardian", a.repo.display())),
        ("install", "cp target/release/stenio <install-dir>/stenio (previous binary kept as stenio.prev-<version>)".to_string()),
        ("kuaray-retag", format!("ssh {} docker tag <running image> stenio-sentinel:prev-<previous>", a.host)),
        ("kuaray-pull", format!("ssh {} docker pull {}:{version} && docker tag {}:{version} {}:{}", a.host, a.image_repo, a.image_repo, a.image_repo, tag_major(&version))),
        ("kuaray-up", format!("ssh {} cd {} && docker compose up -d {}", a.host, a.compose_dir, a.service)),
        ("kuaray-version", format!("ssh {} docker exec {} stenio --version", a.host, a.container)),
        ("self-test", "~/.cargo/bin/stenio --self-test".to_string()),
        ("scope-vault", "~/.cargo/bin/stenio --scope vault".to_string()),
        ("scope-homelab", "~/.cargo/bin/stenio --scope homelab".to_string()),
    ]
}

/// The `--dry-run` text a plan prints: one `PLAN <name> <command>` per step.
fn plan_text(steps: &[(&str, String)]) -> String {
    steps
        .iter()
        .map(|(n, c)| format!("PLAN {n:<16} {c}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match RelArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    if !valid(&a) {
        eprintln!("unsafe characters in a tag, host, container, service or path: refusing to run");
        return 2;
    }
    if a.dry_run {
        for (name, cmd) in plan(&a) {
            println!("PLAN {:<16} {cmd}", name);
        }
        return 0;
    }
    println!(
        "stenio release-engine tag={} repo={} host={} container={}",
        a.tag,
        a.repo.display(),
        a.host,
        a.container
    );
    let lines = run_steps(&Real, &a);
    for l in &lines {
        let tag = match l.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
            Status::Warn => "WARN",
        };
        println!("{tag} {:<16} {}", l.name, l.detail);
    }
    let bad = lines.iter().filter(|l| l.status == Status::Fail).count();
    println!("{} step(s): {} FAIL", lines.len(), bad);
    i32::from(bad > 0)
}

// ── offline tests with a scripted runner ───────────────────────────────────
pub struct Fake(std::collections::BTreeMap<String, (i32, String)>);

fn key(argv: &[String]) -> String {
    argv.join(" ")
}

impl Runner for Fake {
    fn run(&self, _dir: Option<&Path>, argv: &[String], _t: Duration) -> Result<Out, String> {
        if let Some((code, s)) = self.0.get(&key(argv)) {
            return Ok(Out {
                code: *code,
                stdout: s.clone(),
            });
        }
        // The installed binary answers with whatever the file on disk says, so the copy that the
        // install step performs is observable without touching the real installation.
        if argv.len() == 2
            && argv[1] == "--version"
            && let Ok(s) = std::fs::read_to_string(&argv[0])
        {
            return Ok(Out {
                code: 0,
                stdout: format!("stenio {}\n", s.trim()),
            });
        }
        Err(format!("not scripted: {}", key(argv)))
    }
}

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One `[[package]]` block of a `Cargo.lock`, enough for [`lockfile_versions`].
fn package_entry(name: &str, version: &str) -> String {
    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
}

/// A throwaway repo/install tree, so the install step copies real files it owns.
fn fixture_tree(old: &str, new: &str) -> (RelArgs, PathBuf) {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("stenio-releng-{}-{n}", std::process::id()));
    let repo = root.join("repo");
    let install = root.join("install");
    let _ = std::fs::create_dir_all(repo.join("target/release"));
    let _ = std::fs::create_dir_all(&install);
    let a = RelArgs {
        tag: "v4.18.0".to_string(),
        repo: repo.clone(),
        host: "kuaray".into(),
        container: "miracena-stenio".into(),
        compose_dir: "/srv/data/miracena".into(),
        service: "stenio".into(),
        image_repo: DEFAULT_IMAGE_REPO.into(),
        wait_secs: 0,
        build_timeout_secs: 1,
        install_dir: Some(install.clone()),
        skip_ci: true,
        dry_run: false,
    };
    let _ = std::fs::write(repo.join("target/release/stenio"), new);
    let _ = std::fs::write(install.join("stenio"), old);
    // The lockfile the metadata step is compared against: it pins the tag version, and the cases
    // that need it stale rewrite it.
    let _ = std::fs::write(
        repo.join("Cargo.lock"),
        package_entry("stenio", a.tag.trim_start_matches('v')),
    );
    (a, root)
}

fn scripted(
    a: &RelArgs,
    remote_version: &str,
) -> std::collections::BTreeMap<String, (i32, String)> {
    let repo = a.repo.display().to_string();
    let tag = a.tag.clone();
    let version = a.tag.trim_start_matches('v');
    let bin = a
        .install_dir
        .as_ref()
        .map(|d| d.join("stenio").display().to_string())
        .unwrap_or_default();
    let vault = crate::opportunity::vault_root(None).display().to_string();
    let mut m = std::collections::BTreeMap::new();
    let ok = |s: &str| (0, format!("{s}\n"));
    let ssh =
        |script: &str| key(&["ssh", "-o", "BatchMode=yes", "kuaray", script].map(String::from));
    m.insert(
        key(&[
            "git",
            "-C",
            &repo,
            "rev-parse",
            "--verify",
            "-q",
            &format!("{tag}^{{commit}}"),
        ]
        .map(String::from)),
        ok(SHA_A),
    );
    m.insert(
        key(&["git", "-C", &repo, "rev-parse", "HEAD"].map(String::from)),
        ok(SHA_A),
    );
    m.insert(
        key(&[
            "git",
            "-C",
            &repo,
            "ls-remote",
            "--tags",
            "origin",
            &format!("refs/tags/{tag}"),
        ]
        .map(String::from)),
        ok(&format!("{SHA_A}\trefs/tags/{tag}")),
    );
    m.insert(
        key(&["cargo", "build", "--release", "--locked"].map(String::from)),
        ok(""),
    );
    // The freshly built binary announces the same plan this engine has, so `plan-parity` passes.
    // The mutation cases below rewrite exactly this entry to drive the FAIL and WARN paths.
    m.insert(key(&dry_run_argv(a)), ok(&plan_text(&plan(a))));
    m.insert(
        key(&lockfile_argv()),
        ok(&format!(
            "{{\"packages\":[{{\"name\":\"stenio\",\"version\":\"{version}\",\"manifest_path\":\"{repo}/Cargo.toml\"}}]}}"
        )),
    );
    m.insert(
        key(&[&format!("{repo}/target/release/stenio"), "--guardian"].map(String::from)),
        ok("Guardian: 15 Stenio core modules audited with Zero Tampering."),
    );
    m.insert(
        ssh("docker tag $(docker inspect -f '{{.Image}}' miracena-stenio) stenio-sentinel:prev-4.17.0"),
        ok(""),
    );
    m.insert(
        ssh(&format!(
            "docker pull {DEFAULT_IMAGE_REPO}:4.18.0 && docker tag {DEFAULT_IMAGE_REPO}:4.18.0 {DEFAULT_IMAGE_REPO}:4"
        )),
        ok(""),
    );
    m.insert(
        ssh("cd /srv/data/miracena && docker compose up -d stenio"),
        ok(""),
    );
    m.insert(
        ssh("docker exec miracena-stenio stenio --version"),
        ok(&format!("stenio {remote_version}")),
    );
    m.insert(
        key(&[&bin, "--self-test"].map(String::from)),
        ok("self-test ok"),
    );
    m.insert(
        key(&[&bin, "--scope", "vault", "--path", &vault].map(String::from)),
        ok("0 error(s), 6 warning(s)"),
    );
    m.insert(
        key(&[&bin, "--scope", "homelab", "--path", &vault].map(String::from)),
        ok("0 error(s), 23 warning(s)"),
    );
    m
}

/// Cases for `--self-test`: the sequence passes when both hosts agree, fails on version drift,
/// and stops at the first failing prerequisite.
pub fn self_test_cases() -> Vec<(String, bool)> {
    let (a, tree) = fixture_tree("4.17.0", "4.18.0");
    let good = run_steps(&Fake(scripted(&a, "4.18.0")), &a);
    let rollback = a
        .install_dir
        .as_ref()
        .is_some_and(|d| d.join("stenio.prev-4.17.0").is_file());
    let _ = std::fs::remove_dir_all(&tree);
    let (a2, tree2) = fixture_tree("4.17.0", "4.18.0");
    let drift = run_steps(&Fake(scripted(&a2, "4.17.0")), &a2);
    let _ = std::fs::remove_dir_all(&tree2);
    let (a3, tree3) = fixture_tree("4.17.0", "4.18.0");
    let missing = run_steps(&Fake(std::collections::BTreeMap::new()), &a3);
    let _ = std::fs::remove_dir_all(&tree3);
    // A refused `cargo build --locked` leaves the previous binary in target/release: the tag says
    // 4.18.0 while the file still declares 4.19.0. That is a FAIL before anything is installed.
    let (a4, tree4) = fixture_tree("4.17.0", "4.19.0");
    let stale = run_steps(&Fake(scripted(&a4, "4.18.0")), &a4);
    let untouched = a4.install_dir.as_ref().is_some_and(|d| {
        std::fs::read_to_string(d.join("stenio")).is_ok_and(|s| s.trim() == "4.17.0")
            && !d.join("stenio.prev-4.17.0").is_file()
    });
    let _ = std::fs::remove_dir_all(&tree4);
    // A stale Cargo.lock stops the sequence before the build is even attempted: both the easier
    // path (metadata refuses) and the one that actually bit us (metadata --no-deps exits 0 while
    // the lock pins another version).
    let (a5, tree5) = fixture_tree("4.17.0", "4.18.0");
    let mut stale_lock = scripted(&a5, "4.18.0");
    stale_lock.insert(key(&lockfile_argv()), (101, String::new()));
    let lockfail = run_steps(&Fake(stale_lock), &a5);
    let _ = std::fs::remove_dir_all(&tree5);
    let (a6, tree6) = fixture_tree("4.17.0", "4.18.0");
    let _ = std::fs::write(
        a6.repo.join("Cargo.lock"),
        package_entry("stenio", "4.19.0"),
    );
    let driftlock = run_steps(&Fake(scripted(&a6, "4.18.0")), &a6);
    let _ = std::fs::remove_dir_all(&tree6);
    // The whole point of GB-073: a release that adds a gate used to be approved by the engine that
    // lacked it. Here the built binary plans one step this engine does not know, so the sequence
    // must FAIL by name and stop before installing.
    let (a7, tree7) = fixture_tree("4.17.0", "4.18.0");
    let mut ahead_steps = plan(&a7);
    ahead_steps.push((
        "new-gate",
        "target/release/stenio --gate --strict".to_string(),
    ));
    let mut ahead = scripted(&a7, "4.18.0");
    ahead.insert(key(&dry_run_argv(&a7)), (0, plan_text(&ahead_steps)));
    let ahead_run = run_steps(&Fake(ahead), &a7);
    let _ = std::fs::remove_dir_all(&tree7);
    // The other direction is not a failure: the built binary dropped a step this engine knows.
    let (a8, tree8) = fixture_tree("4.17.0", "4.18.0");
    let mut behind_steps = plan(&a8);
    behind_steps.retain(|(n, _)| *n != "integrity");
    let mut behind = scripted(&a8, "4.18.0");
    behind.insert(key(&dry_run_argv(&a8)), (0, plan_text(&behind_steps)));
    let behind_run = run_steps(&Fake(behind), &a8);
    let _ = std::fs::remove_dir_all(&tree8);
    // A binary whose `--dry-run` fails cannot prove parity: FAIL with the raw output, never PASS.
    let (a9, tree9) = fixture_tree("4.17.0", "4.18.0");
    let mut broken = scripted(&a9, "4.18.0");
    broken.insert(
        key(&dry_run_argv(&a9)),
        (
            2,
            "error: unrecognized subcommand 'release-engine'".to_string(),
        ),
    );
    let broken_run = run_steps(&Fake(broken), &a9);
    let _ = std::fs::remove_dir_all(&tree9);
    let unsafe_tag = !valid(&RelArgs {
        tag: "v1;rm".into(),
        ..a.clone()
    });
    // GB-079: the two vault scopes close the release, in this order. CI
    // (`.github/workflows/ci.yml`) runs fmt/clippy/build/--self-test/--guardian and no `--scope`, so
    // a PR can break the vault's governance and nothing notices until a release; this plan test is
    // the engine's half — dropping or swapping either scope turns it red.
    let planned: Vec<&str> = plan(&a).iter().map(|(n, _)| *n).collect();
    let scopes_last = planned.ends_with(&["scope-vault", "scope-homelab"]);
    // GB-078: `plan()` (what `--dry-run` announces) and `run_steps()` are two hand-kept lists, and
    // during 4.23.0 one listed plan-parity where the other ran binary-version. The parity fixture
    // could not see it: it compares `plan()` with the plan text `plan()` produced. The good fixture
    // walks every step, so its Line names must equal the plan's names — same set, same order.
    let executed: Vec<&str> = good.iter().map(|l| l.name).collect();
    let same_sequence = executed == planned;
    vec![
        (
            "release-engine bad tag stops the sequence".to_string(),
            missing.len() == 1 && missing.first().is_some_and(|l| l.status == Status::Fail),
        ),
        (
            "release-engine plan covers every step".to_string(),
            plan(&a).len() == 16,
        ),
        (
            "release-engine refuses an unsafe tag".to_string(),
            unsafe_tag,
        ),
        (
            "release-engine version drift is a FAIL".to_string(),
            drift
                .iter()
                .any(|l| l.name == "kuaray-version" && l.status == Status::Fail),
        ),
        (
            "release-engine good run passes every step".to_string(),
            good.iter().all(|l| l.status != Status::Fail) && good.len() == 16,
        ),
        (
            "release-engine fails when the built binary declares another version".to_string(),
            stale
                .iter()
                .any(|l| l.name == "binary-version" && l.status == Status::Fail)
                && !stale.iter().any(|l| l.name == "install")
                && untouched,
        ),
        (
            "release-engine stops before the build on a stale lockfile".to_string(),
            lockfail
                .last()
                .is_some_and(|l| l.name == "lockfile" && l.status == Status::Fail)
                && !lockfail.iter().any(|l| l.name == "build"),
        ),
        (
            "release-engine compares the lock version when cargo metadata accepts it".to_string(),
            driftlock
                .last()
                .is_some_and(|l| l.name == "lockfile" && l.status == Status::Fail)
                && driftlock
                    .iter()
                    .any(|l| l.detail.contains("4.19.0") && l.detail.contains("4.18.0"))
                && !driftlock.iter().any(|l| l.name == "build"),
        ),
        ("release-engine keeps a rollback copy".to_string(), rollback),
        (
            "release-engine warns when the built binary plans a step this engine lacks".to_string(),
            ahead_run.iter().any(|l| {
                l.name == "plan-parity" && l.status == Status::Warn && l.detail.contains("new-gate")
            }) && ahead_run
                .iter()
                .any(|l| l.name == "install" && l.status == Status::Pass),
        ),
        (
            "release-engine fails when the built binary drops a step".to_string(),
            behind_run
                .iter()
                .any(|l| l.name == "plan-parity" && l.status == Status::Fail)
                && !behind_run.iter().any(|l| l.name == "install"),
        ),
        (
            "release-engine fails when the built binary cannot print its plan".to_string(),
            broken_run.iter().any(|l| {
                l.name == "plan-parity"
                    && l.status == Status::Fail
                    && l.detail.contains("unrecognized subcommand")
            }) && !broken_run.iter().any(|l| l.name == "install"),
        ),
        (
            "release-engine plan keeps the vault scopes last, in order".to_string(),
            scopes_last,
        ),
        (
            "release-engine run order matches the dry-run plan".to_string(),
            same_sequence,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures() {
        crate::testkit::assert_cases(self_test_cases());
    }
}
