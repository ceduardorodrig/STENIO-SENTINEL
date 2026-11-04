//! `stenio pre-release`: every deterministic check that runs before a Frappe release is built.
//!
//! One process, parallel where it pays: the Frappe, fork and custom-rule scopes, version/tag
//! consistency, git state, scope classification (FULL or TEXT-ONLY, fail-safe FULL), new
//! translations, secrets in the diff, Dockerfile consistency and (after the build) the
//! `.built-from` of the local image. One PASS/FAIL/WARN line each; exit 1 on any FAIL.
//!
//! `--static-only` (exposed as `stenio preflight`) keeps just the part that decides without a
//! site, a git history, Docker or a tag: the scope checks and the engine's own self-tests.

use clap::Parser;
use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{FrappeConfig, SteniocheckConfig};
use crate::frappe;
use crate::i18n;
use crate::rule::{Severity, TOKEN_SHAPES};
use crate::verify_release::{Check, Status};

#[derive(Parser, Debug)]
#[command(
    name = "stenio pre-release",
    about = "Deterministic pre-release checks of a Frappe app repository"
)]
struct PreArgs {
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[arg(
        long,
        required_unless_present = "static_only",
        help = "Release tag, e.g. v0.1.0-rc76"
    )]
    tag: Option<String>,
    #[arg(
        long,
        help = "Previous tag (diff base for scope, translations and secrets)"
    )]
    prev: Option<String>,
    #[arg(
        long,
        help = "Check the local image and its .built-from (after docker build)"
    )]
    after_build: bool,
    #[arg(
        long,
        help = "The tag already exists and must point at HEAD (release-checks.sh mode)"
    )]
    tagged: bool,
    #[arg(
        long,
        help = "Static only: scope checks and engine self-tests; no tag, git, Docker or site"
    )]
    static_only: bool,
    #[arg(
        long,
        help = "steniocheck.toml with the [frappe] table (default <repo>/steniocheck.toml)"
    )]
    config: Option<PathBuf>,
}

pub struct Opts {
    pub repo: PathBuf,
    pub tag: String,
    pub prev: Option<String>,
    pub after_build: bool,
    pub tagged: bool,
    pub run_scopes: bool,
    pub static_only: bool,
    pub fc: FrappeConfig,
}

fn mk(status: Status, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        status,
        name,
        detail: detail.into(),
    }
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).to_string())
}

fn app_of(o: &Opts) -> Option<String> {
    o.fc.app.clone().or_else(|| frappe::infer_app(&o.repo))
}

fn check_version(o: &Opts, app: &str) -> Check {
    let text = fs::read_to_string(o.repo.join(app).join("__init__.py")).unwrap_or_default();
    let found = Regex::new(r#"__version__\s*=\s*["']([^"']+)["']"#)
        .ok()
        .and_then(|re| re.captures(&text).map(|c| c[1].to_string()));
    let want = o.tag.trim_start_matches('v');
    match found {
        Some(v) if v == want => mk(Status::Pass, "version", format!("__version__ = {v}")),
        Some(v) => mk(
            Status::Fail,
            "version",
            format!("__version__ is '{v}', the tag needs '{want}'"),
        ),
        None => mk(
            Status::Fail,
            "version",
            format!("no __version__ in {app}/__init__.py"),
        ),
    }
}

fn check_git(o: &Opts) -> Vec<Check> {
    let r = &o.repo;
    let mut out = Vec::new();
    let head = git(r, &["rev-parse", "HEAD"]).map(|s| s.trim().to_string());
    let tag_commit = git(
        r,
        &[
            "rev-parse",
            "-q",
            "--verify",
            &format!("{}^{{commit}}", o.tag),
        ],
    )
    .map(|s| s.trim().to_string());
    out.push(match (&tag_commit, o.tagged) {
        (None, false) => mk(
            Status::Pass,
            "tag-free",
            format!("{} does not exist yet", o.tag),
        ),
        (Some(_), false) => mk(
            Status::Fail,
            "tag-free",
            format!(
                "{} already exists: never reuse a tag, pick the next number",
                o.tag
            ),
        ),
        (Some(t), true) if Some(t) == head.as_ref() => {
            mk(Status::Pass, "tag-at-head", format!("{} = HEAD", o.tag))
        }
        (Some(_), true) => mk(
            Status::Fail,
            "tag-at-head",
            format!("{} is not HEAD", o.tag),
        ),
        (None, true) => mk(
            Status::Fail,
            "tag-at-head",
            format!("{} does not exist", o.tag),
        ),
    });
    out.push(match git(r, &["status", "--porcelain"]) {
        Some(s) if s.trim().is_empty() => mk(Status::Pass, "tree-clean", "working tree clean"),
        Some(s) => mk(
            Status::Fail,
            "tree-clean",
            format!("{} uncommitted path(s)", s.lines().count()),
        ),
        None => mk(Status::Fail, "tree-clean", "git status failed"),
    });
    let remote = git(r, &["ls-remote", "origin", "refs/heads/main"])
        .and_then(|s| s.split_whitespace().next().map(str::to_string));
    out.push(match (&remote, &head) {
        (Some(a), Some(b)) if a == b => mk(Status::Pass, "pushed", "HEAD = origin/main"),
        (Some(_), Some(_)) => mk(
            Status::Fail,
            "pushed",
            "HEAD is not origin/main: push first",
        ),
        _ => mk(Status::Fail, "pushed", "cannot read origin/main"),
    });
    out
}

/// FULL or TEXT-ONLY, with the files that decided it (same rules as release-scope.sh, fail-safe FULL).
pub fn classify(repo: &Path, app: &str, prev: &str) -> (bool, Vec<String>) {
    let Some(names) = git(repo, &["diff", "--name-only", prev, "HEAD"]) else {
        return (true, vec!["git diff failed".into()]);
    };
    let files: Vec<&str> = names.lines().filter(|l| !l.is_empty()).collect();
    if files.is_empty() {
        return (true, vec!["no diff found: refusing to skip".into()]);
    }
    let mut full = Vec::new();
    for f in files {
        let is_po = f.starts_with(&format!("{app}/locale/")) && f.ends_with(".po");
        let text_only = is_po
            || f.starts_with(&format!("{app}/public/"))
            || (f.starts_with(&format!("{app}/www/")) && f.ends_with(".html"))
            || f.ends_with(".md");
        if text_only {
            continue;
        }
        if f == format!("{app}/__init__.py") {
            let diff = git(repo, &["diff", "-U0", prev, "HEAD", "--", f]).unwrap_or_default();
            let other = diff
                .lines()
                .filter(|l| {
                    (l.starts_with('+') || l.starts_with('-'))
                        && !l.starts_with("+++")
                        && !l.starts_with("---")
                })
                .any(|l| !l.contains("__version__"));
            if !other {
                continue;
            }
        }
        full.push(f.to_string());
    }
    (!full.is_empty(), full)
}

fn check_classification(o: &Opts, app: &str) -> Check {
    let Some(prev) = &o.prev else {
        return mk(
            Status::Warn,
            "scope",
            "no --prev: classification skipped, treat the release as FULL",
        );
    };
    let (full, files) = classify(&o.repo, app, prev);
    if full {
        mk(
            Status::Pass,
            "scope",
            format!(
                "FULL (rehearsal needed): {}",
                files.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
            ),
        )
    } else {
        mk(
            Status::Pass,
            "scope",
            "TEXT-ONLY (translations, assets, templates, docs)",
        )
    }
}

fn check_translations(o: &Opts, app: &str) -> Check {
    let Some(prev) = &o.prev else {
        return mk(Status::Warn, "new-translations", "no --prev: skipped");
    };
    let Some(names) = git(
        &o.repo,
        &[
            "diff",
            "--name-only",
            prev,
            "HEAD",
            "--",
            &format!("{app}/locale"),
        ],
    ) else {
        return mk(Status::Fail, "new-translations", "git diff failed");
    };
    let (mut new_count, mut problems) = (0usize, Vec::new());
    for po in names.lines().filter(|f| f.ends_with(".po")) {
        let head = fs::read_to_string(o.repo.join(po)).unwrap_or_default();
        let before = git(&o.repo, &["show", &format!("{prev}:{po}")]).unwrap_or_default();
        let old: BTreeSet<(String, String)> = i18n::parse_po(&before)
            .into_iter()
            .map(|e| (e.ctx.unwrap_or_default(), e.msgid))
            .collect();
        let fresh: Vec<i18n::PoEntry> = i18n::parse_po(&head)
            .into_iter()
            .filter(|e| {
                !e.obsolete
                    && !e.msgid.is_empty()
                    && !old.contains(&(e.ctx.clone().unwrap_or_default(), e.msgid.clone()))
            })
            .collect();
        new_count += fresh.len();
        let lines: BTreeSet<usize> = fresh.iter().map(|e| e.line).collect();
        let (viol, _) = i18n::audit_catalogue(po, &head);
        for v in viol.iter().filter(|v| lines.contains(&v.line_number)) {
            problems.push(format!(
                "{}:{} {}",
                po,
                v.line_number,
                v.message.split(':').next().unwrap_or("")
            ));
        }
    }
    if problems.is_empty() {
        mk(
            Status::Pass,
            "new-translations",
            format!("{new_count} new msgid(s), all translated and cased"),
        )
    } else {
        mk(
            Status::Fail,
            "new-translations",
            format!(
                "{} problem(s): {}",
                problems.len(),
                problems
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )
    }
}

fn modified_of(v: &serde_json::Value) -> Option<String> {
    v.get("modified")
        .and_then(|m| m.as_str())
        .map(str::to_string)
}

fn entry_key(v: &serde_json::Value) -> String {
    let f = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    format!("{}/{}", f("doctype"), f("name"))
}

/// `FRAPPE-JSON-MODIFIED-BUMP`: Frappe imports a JSON only when its `modified` is newer.
pub fn modified_problems(
    repo: &Path,
    app: &str,
    prev: &str,
    allow: &[String],
) -> Result<Vec<String>, String> {
    let names = git(
        repo,
        &[
            "diff",
            "--name-only",
            "--diff-filter=M",
            prev,
            "HEAD",
            "--",
            &format!("{app}/"),
        ],
    )
    .ok_or("git diff failed")?;
    let kinds = [
        "/doctype/",
        "/sidebar/",
        "/workspace/",
        "/number_card/",
        "/dashboard_chart/",
        "/fixtures/",
    ];
    let mut problems = Vec::new();
    for f in names
        .lines()
        .filter(|f| f.ends_with(".json") && kinds.iter().any(|k| f.contains(k)))
    {
        if allow.iter().any(|a| f.contains(a.as_str())) {
            continue;
        }
        let old: serde_json::Value =
            serde_json::from_str(&git(repo, &["show", &format!("{prev}:{f}")]).unwrap_or_default())
                .unwrap_or_default();
        let new: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(repo.join(f)).unwrap_or_default())
                .unwrap_or_default();
        if old == new {
            continue;
        }
        let pairs: Vec<(String, &serde_json::Value, Option<&serde_json::Value>)> =
            match (&new, &old) {
                (serde_json::Value::Array(n), serde_json::Value::Array(o)) => n
                    .iter()
                    .map(|e| {
                        (
                            entry_key(e),
                            e,
                            o.iter().find(|x| entry_key(x) == entry_key(e)),
                        )
                    })
                    .collect(),
                _ => vec![(String::new(), &new, Some(&old))],
            };
        for (key, n, o) in pairs {
            let Some(o) = o else { continue };
            if n == o {
                continue;
            }
            if let (Some(nm), Some(om)) = (modified_of(n), modified_of(o))
                && nm <= om
            {
                {
                    problems.push(format!(
                        "{f}{} modified {nm} is not newer than {om}",
                        if key.is_empty() {
                            String::new()
                        } else {
                            format!(" [{key}]")
                        }
                    ));
                }
            }
        }
    }
    Ok(problems)
}

fn check_modified(o: &Opts, app: &str) -> Check {
    let Some(prev) = &o.prev else {
        return mk(Status::Warn, "json-modified", "no --prev: skipped");
    };
    let allow = o.fc.modified_allowlist.clone().unwrap_or_default();
    match modified_problems(&o.repo, app, prev, &allow) {
        Ok(p) if p.is_empty() => mk(
            Status::Pass,
            "json-modified",
            "every changed DocType/sidebar/workspace/card/chart/fixture JSON has a newer `modified`",
        ),
        Ok(p) => mk(
            Status::Fail,
            "json-modified",
            format!(
                "FRAPPE-JSON-MODIFIED-BUMP {}: {}",
                p.len(),
                p.iter().take(3).cloned().collect::<Vec<_>>().join("; ")
            ),
        ),
        Err(e) => mk(Status::Fail, "json-modified", e),
    }
}

fn check_secrets(o: &Opts) -> Check {
    let Some(prev) = &o.prev else {
        return mk(Status::Warn, "diff-secrets", "no --prev: skipped");
    };
    let Some(diff) = git(&o.repo, &["diff", "-U0", prev, "HEAD"]) else {
        return mk(Status::Fail, "diff-secrets", "git diff failed");
    };
    let pat = format!(
        r#"({TOKEN_SHAPES}|sk-[A-Za-z0-9]{{48}})|(?i)(api_key|secret_key)\s*=\s*['"][A-Za-z0-9_\-]{{20,}}['"]"#
    );
    let Ok(re) = Regex::new(&pat) else {
        return mk(
            Status::Fail,
            "diff-secrets",
            "secret pattern does not compile",
        );
    };
    let (mut file, mut hits) = (String::new(), BTreeSet::new());
    for l in diff.lines() {
        if let Some(f) = l.strip_prefix("+++ b/") {
            file = f.to_string();
        } else if l.starts_with('+') && !l.starts_with("+++") && re.is_match(l) {
            hits.insert(file.clone());
        }
    }
    if hits.is_empty() {
        mk(
            Status::Pass,
            "diff-secrets",
            "no credential shape in the added lines",
        )
    } else {
        mk(
            Status::Fail,
            "diff-secrets",
            format!(
                "credential shape in: {}",
                hits.into_iter().collect::<Vec<_>>().join(", ")
            ),
        )
    }
}

fn check_dockerfile(o: &Opts) -> Check {
    let path = o.repo.join("Dockerfile");
    let Ok(text) = fs::read_to_string(&path) else {
        return mk(
            Status::Pass,
            "dockerfile",
            "no Dockerfile: nothing to check",
        );
    };
    let arg = text
        .lines()
        .find(|l| l.trim_start().starts_with("ARG APP_REF"));
    match arg {
        None => mk(
            Status::Fail,
            "dockerfile",
            "no `ARG APP_REF`: the image would not be tied to a tag",
        ),
        Some(l) => match l.split_once('=') {
            Some((_, d)) if d.trim() != o.tag => mk(
                Status::Fail,
                "dockerfile",
                format!("APP_REF default '{}' != {}", d.trim(), o.tag),
            ),
            _ if !text.contains("${APP_REF}") => mk(
                Status::Fail,
                "dockerfile",
                "APP_REF declared but never used",
            ),
            _ => mk(
                Status::Pass,
                "dockerfile",
                "APP_REF declared and used; passed by the build",
            ),
        },
    }
}

fn check_after_build(o: &Opts, app: &str) -> Check {
    let Some(image) = o.fc.image.as_ref() else {
        return mk(
            Status::Warn,
            "built-image",
            "[frappe] image not configured: skipped",
        );
    };
    let reference = format!("{image}:{}", o.tag.trim_start_matches('v'));
    let want = git(&o.repo, &["rev-parse", &format!("{}^{{commit}}", o.tag)])
        .map(|s| s.trim().to_string());
    let path = format!("/home/frappe/frappe-bench/apps/{app}/.built-from");
    let run = Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "cat", &reference, &path])
        .output();
    match (run, want) {
        (Ok(r), Some(w))
            if r.status.success() && String::from_utf8_lossy(&r.stdout).trim() == w =>
        {
            mk(
                Status::Pass,
                "built-image",
                format!("{reference} built from {}", &w[..w.len().min(12)]),
            )
        }
        (Ok(r), Some(w)) if r.status.success() => mk(
            Status::Fail,
            "built-image",
            format!(
                "{reference} .built-from differs from {}",
                &w[..w.len().min(12)]
            ),
        ),
        (Ok(_), _) => mk(
            Status::Fail,
            "built-image",
            format!("{reference} missing or unreadable (tag exists?)"),
        ),
        (Err(e), _) => mk(Status::Fail, "built-image", format!("docker: {e}")),
    }
}

fn scope_checks(o: &Opts) -> Vec<Check> {
    let (frappe_c, fork_c, custom_c) = std::thread::scope(|s| {
        let a = s.spawn(|| match frappe::audit(&o.repo, &o.fc) {
            Ok(v) => {
                let e = v.iter().filter(|x| x.severity == Severity::Error).count();
                let first = v
                    .iter()
                    .find(|x| x.severity == Severity::Error)
                    .map(|x| format!("{} {}:{}", x.rule_id, x.file_path, x.line_number))
                    .unwrap_or_default();
                if e == 0 {
                    mk(
                        Status::Pass,
                        "scope-frappe",
                        format!("0 errors, {} warning(s)", v.len()),
                    )
                } else {
                    mk(
                        Status::Fail,
                        "scope-frappe",
                        format!("{e} error(s), first {first}"),
                    )
                }
            }
            Err(e) => mk(Status::Fail, "scope-frappe", e),
        });
        let sub = |name: &'static str, args: Vec<String>| {
            let repo = o.repo.clone();
            move || match std::env::current_exe().ok().and_then(|exe| {
                Command::new(exe)
                    .args(&args)
                    .arg("--path")
                    .arg(&repo)
                    .output()
                    .ok()
            }) {
                Some(r) if r.status.success() => mk(Status::Pass, name, "0 errors"),
                Some(_) => mk(
                    Status::Fail,
                    name,
                    "errors found: run the same scope by hand to list them",
                ),
                None => mk(Status::Fail, name, "cannot run the engine"),
            }
        };
        let b = s.spawn(sub("scope-fork", vec!["--scope".into(), "fork".into()]));
        let tag = o.fc.custom_rules_tag.clone();
        let c = s.spawn(move || match tag {
            Some(t) => sub(
                "custom-rules",
                vec!["--tag".into(), t, "--strict".into(), "--compact".into()],
            )(),
            None => mk(
                Status::Warn,
                "custom-rules",
                "[frappe] custom_rules_tag not configured: skipped",
            ),
        });
        (a.join(), b.join(), c.join())
    });
    [frappe_c, fork_c, custom_c]
        .into_iter()
        .map(|r| r.unwrap_or_else(|_| mk(Status::Fail, "scopes", "check panicked")))
        .collect()
}

/// `preflight`: the checks that decide without a tag, git history, Docker or a site.
///
/// Order is the precedence order of the failure: the Frappe scope names the offending rule first,
/// then the fork scope and the custom-rule tag, and only then the engine's own fixtures. The
/// self-test suite runs in its own thread: it costs about as much as the scopes, so it overlaps.
fn static_checks(o: &Opts, engine_self_test: impl FnOnce() -> Check + Send) -> Vec<Check> {
    std::thread::scope(|s| {
        let engine = s.spawn(engine_self_test);
        let mut out = if o.run_scopes {
            scope_checks(o)
        } else {
            Vec::new()
        };
        out.push(
            engine
                .join()
                .unwrap_or_else(|_| mk(Status::Fail, "self-test", "check panicked")),
        );
        out
    })
}

/// Runs this same binary with `--self-test`: the engine proves its rules before judging the app.
fn check_self_test() -> Check {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            return mk(
                Status::Fail,
                "self-test",
                format!("engine path unknown: {e}"),
            );
        }
    };
    match Command::new(exe).arg("--self-test").output() {
        Ok(r) if r.status.success() => mk(Status::Pass, "self-test", "every engine fixture green"),
        Ok(_) => mk(
            Status::Fail,
            "self-test",
            "engine fixtures failed: run `stenio --self-test` for the list",
        ),
        Err(e) => mk(
            Status::Fail,
            "self-test",
            format!("cannot run the engine: {e}"),
        ),
    }
}

/// The one actionable line printed after the first blocking FAIL of `preflight`.
fn remedy(name: &str) -> &'static str {
    match name {
        "scope-frappe" => {
            "run `stenio --scope frappe --path <repo>`: every violation carries its own suggestion"
        }
        "scope-fork" => "run `stenio --scope fork --path <repo>` and fix the listed violations",
        "custom-rules" => {
            "run `stenio --tag <custom_rules_tag> --strict --compact --path <repo>` to list them"
        }
        _ => "run `stenio --self-test` and fix the engine fixture that broke before shipping",
    }
}

pub fn run_checks(o: &Opts) -> Vec<Check> {
    if o.static_only {
        return static_checks(o, check_self_test);
    }
    let mut out = Vec::new();
    if o.run_scopes {
        out.extend(scope_checks(o));
    }
    match app_of(o) {
        Some(app) => {
            out.push(check_version(o, &app));
            out.extend(check_git(o));
            out.push(check_classification(o, &app));
            out.push(check_translations(o, &app));
            out.push(check_modified(o, &app));
            out.push(check_secrets(o));
            out.push(check_dockerfile(o));
            if o.after_build {
                out.push(check_after_build(o, &app));
            }
        }
        None => out.push(mk(
            Status::Fail,
            "app",
            "no Frappe app found: set `app` in [frappe]",
        )),
    }
    out
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match PreArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let cfg = a
        .config
        .clone()
        .unwrap_or_else(|| a.repo.join("steniocheck.toml"));
    let o = Opts {
        fc: SteniocheckConfig::load_from_file(&cfg)
            .frappe
            .unwrap_or_default(),
        repo: a.repo,
        tag: a.tag.unwrap_or_default(),
        prev: a.prev,
        after_build: a.after_build,
        tagged: a.tagged,
        run_scopes: true,
        static_only: a.static_only,
    };
    let started = std::time::Instant::now();
    if o.static_only {
        println!("stenio preflight repo={}", o.repo.display());
    } else {
        println!("stenio pre-release repo={} tag={}", o.repo.display(), o.tag);
    }
    let results = run_checks(&o);
    let fails = results.iter().filter(|r| r.status == Status::Fail).count();
    for r in &results {
        let l = match r.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
        };
        println!("{l} {:<18} {}", r.name, r.detail);
        // `preflight` stops at the first blocking error and leaves one line saying what to run.
        if o.static_only && r.status == Status::Fail {
            println!("REMEDY {:<16} {}", r.name, remedy(r.name));
            break;
        }
    }
    if o.static_only {
        println!(
            "{} check(s): {} FAIL in {} ms",
            results.len(),
            fails,
            started.elapsed().as_millis()
        );
    } else {
        println!("{} check(s): {} FAIL", results.len(), fails);
    }
    i32::from(fails > 0)
}

// ── fixtures: a clean repository and failing variants ──────────────────────
#[derive(Clone, Copy, PartialEq)]
enum Variant {
    Clean,
    StaleVersion,
    ReusedTag,
    Dirty,
    MissingTranslation,
    StaleModified,
}

fn sh(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn build_repo(v: Variant) -> Option<(PathBuf, PathBuf)> {
    let base = std::env::temp_dir().join(format!("stenio-pre-{}-{}", std::process::id(), v as u8));
    let _ = fs::remove_dir_all(&base);
    let (work, origin) = (base.join("work"), base.join("origin.git"));
    fs::create_dir_all(&work).ok()?;
    fs::create_dir_all(&origin).ok()?;
    let mut ok = sh(&origin, &["init", "-q", "--bare", "-b", "main"])
        && sh(&work, &["init", "-q", "-b", "main"]);
    for (p, t) in frappe::fixture_files(false) {
        let path = work.join(&p);
        fs::create_dir_all(path.parent()?).ok()?;
        fs::write(
            path,
            t.replace("__version__ = \"0.1.0\"", "__version__ = \"0.1.0-rc1\"")
                .replace(
                    "\"fields\":[]}",
                    "\"fields\":[],\"modified\":\"2026-01-01 00:00:00.000000\"}",
                ),
        )
        .ok()?;
    }
    ok &= sh(&work, &["add", "-A"])
        && sh(&work, &["commit", "-q", "-m", "one"])
        && sh(&work, &["tag", "v0.1.0-rc1"]);
    let init = work.join("demoapp/__init__.py");
    if v != Variant::StaleVersion {
        fs::write(&init, "__version__ = \"0.1.0-rc2\"\n").ok()?;
    }
    let part = work.join("demoapp/demo/doctype/part/part.json");
    let bumped = if v == Variant::StaleModified {
        "2026-01-01 00:00:00.000000"
    } else {
        "2026-02-02 00:00:00.000000"
    };
    let part_text = fs::read_to_string(&part).ok()?;
    fs::write(
        &part,
        part_text.replace(
            "\"modified\":\"2026-01-01 00:00:00.000000\"",
            &format!("\"modified\":\"{bumped}\",\"x\":1"),
        ),
    )
    .ok()?;
    let po = work.join("demoapp/locale/pt_BR.po");
    let mut text = fs::read_to_string(&po).ok()?;
    text.push_str(if v == Variant::MissingTranslation {
        "\nmsgid \"New text\"\nmsgstr \"\"\n"
    } else {
        "\nmsgid \"New text\"\nmsgstr \"Texto novo\"\n"
    });
    fs::write(&po, text).ok()?;
    ok &= sh(&work, &["add", "-A"]) && sh(&work, &["commit", "-q", "-m", "two"]);
    ok &= sh(&work, &["remote", "add", "origin", origin.to_str()?])
        && sh(&work, &["push", "-q", "origin", "main"]);
    if v == Variant::ReusedTag {
        ok &= sh(&work, &["tag", "v0.1.0-rc2"]);
    }
    if v == Variant::Dirty {
        fs::write(work.join("scratch.txt"), "x").ok()?;
    }
    ok.then_some((base, work))
}

fn opts_for(work: &Path) -> Opts {
    Opts {
        repo: work.to_path_buf(),
        tag: "v0.1.0-rc2".into(),
        prev: Some("v0.1.0-rc1".into()),
        after_build: false,
        tagged: false,
        run_scopes: false,
        static_only: false,
        fc: frappe::fixture_config(),
    }
}

fn failed(v: Variant) -> Option<BTreeSet<&'static str>> {
    let (base, work) = build_repo(v)?;
    let r = run_checks(&opts_for(&work));
    let _ = fs::remove_dir_all(&base);
    Some(
        r.iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.name)
            .collect(),
    )
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let want = |v: Variant, name: &str| {
        failed(v)
            .map(|f| f.len() == 1 && f.contains(name))
            .unwrap_or(false)
    };
    vec![
        (
            "pre-release clean".to_string(),
            failed(Variant::Clean)
                .map(|f| f.is_empty())
                .unwrap_or(false),
        ),
        (
            "pre-release stale version".to_string(),
            want(Variant::StaleVersion, "version"),
        ),
        (
            "pre-release reused tag".to_string(),
            want(Variant::ReusedTag, "tag-free"),
        ),
        (
            "pre-release dirty tree".to_string(),
            want(Variant::Dirty, "tree-clean"),
        ),
        (
            "pre-release missing translation".to_string(),
            want(Variant::MissingTranslation, "new-translations"),
        ),
        (
            "pre-release stale modified".to_string(),
            want(Variant::StaleModified, "json-modified"),
        ),
        ("pre-release classify".to_string(), classify_case()),
        (
            "preflight parses without tag".to_string(),
            preflight_args_case(),
        ),
        (
            "preflight drops tag and git".to_string(),
            preflight_static_case(),
        ),
        ("preflight remedy line".to_string(), preflight_remedy_case()),
    ]
}

/// `preflight` parses without `--tag`; plain `pre-release` still refuses to run without one.
fn preflight_args_case() -> bool {
    let preflight = PreArgs::try_parse_from(["stenio preflight", "--repo", ".", "--static-only"]);
    let tagless = PreArgs::try_parse_from(["stenio pre-release", "--repo", "."]);
    let tagged = PreArgs::try_parse_from(["stenio pre-release", "--repo", ".", "--tag", "v1"]);
    preflight.is_ok() && tagless.is_err() && tagged.is_ok()
}

/// The static path never reaches the version/git checks: they need a tag and a real history.
fn preflight_static_case() -> bool {
    let Some(root) = frappe::write_fixture("frappe-preflight", &frappe::fixture_files(false))
    else {
        return false;
    };
    let base = Opts {
        repo: root.clone(),
        tag: String::new(),
        prev: None,
        after_build: false,
        tagged: false,
        run_scopes: false,
        static_only: true,
        fc: frappe::fixture_config(),
    };
    let stub = || mk(Status::Pass, "self-test", "stub");
    let names: Vec<&str> = static_checks(&base, stub).iter().map(|c| c.name).collect();
    let dynamic = [
        "version",
        "tag-free",
        "tree-clean",
        "pushed",
        "dockerfile",
        "new-translations",
    ];
    let leaked = names.iter().any(|n| dynamic.contains(n));
    let judged = run_checks(&Opts {
        static_only: false,
        ..base
    })
    .iter()
    .any(|c| c.name == "version" && c.status == Status::Fail);
    let _ = fs::remove_dir_all(&root);
    !leaked && names == ["self-test"] && judged
}

/// Every blocking check must leave one runnable remedy behind.
fn preflight_remedy_case() -> bool {
    ["scope-frappe", "scope-fork", "custom-rules", "self-test"]
        .iter()
        .all(|n| remedy(n).contains("stenio"))
        && remedy("unknown-check").contains("--self-test")
}

/// TEXT-ONLY needs a diff of translations only: compare the first commit with a po-only change.
fn classify_text_only(work: &Path) -> bool {
    let po = work.join("demoapp/locale/pt_BR.po");
    let text = fs::read_to_string(&po).unwrap_or_default();
    if fs::write(&po, format!("{text}\nmsgid \"Extra\"\nmsgstr \"Extra\"\n")).is_err()
        || !sh(work, &["commit", "-q", "-am", "po only"])
    {
        return true;
    }
    classify(work, "demoapp", "HEAD~1").0
}

fn classify_case() -> bool {
    let Some((base, work)) = build_repo(Variant::Clean) else {
        return false;
    };
    let (full, _) = classify(&work, "demoapp", "v0.1.0-rc1");
    let (bad, _) = classify(&work, "demoapp", "no-such-ref");
    let text_only = !classify_text_only(&work);
    let _ = fs::remove_dir_all(&base);
    full && bad && text_only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures() {
        crate::testkit::assert_cases(self_test_cases());
    }
}
