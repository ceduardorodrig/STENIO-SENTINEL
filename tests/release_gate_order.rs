//! The entrance gate has to be able to refuse a release **before the tag is published**.
//!
//! `release.sh` used to demand a pushed tag in its preconditions and only then run `stenio
//! pre-release --tagged`, so `__version__` was compared with the tag after the number was already
//! public and the only remedy left was burning it. The engine side of that fix is a property, not
//! a new flag: with the tag created locally at HEAD and `HEAD == origin/main`, the gate already
//! decides — including the `version` line — while origin carries no tag at all. These cases pin
//! that property, so a later change to the git checks cannot quietly reintroduce the ordering.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_stenio")
}

struct Repo(PathBuf);

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) -> bool {
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

/// A release-ready repository: one app, one commit on `main` pushed to a bare origin, and (when
/// `tag` is set) the release tag created **locally only**.
fn fixture(label: &str, version: &str, tag: bool) -> Option<Repo> {
    let base = std::env::temp_dir().join(format!("stenio-gate-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let (work, origin) = (base.join("work"), base.join("origin.git"));
    fs::create_dir_all(work.join("miracena")).ok()?;
    fs::create_dir_all(&origin).ok()?;
    fs::write(
        work.join("miracena/__init__.py"),
        format!("__version__ = \"{version}\"\n"),
    )
    .ok()?;
    fs::write(work.join("miracena/hooks.py"), "app_name = \"miracena\"\n").ok()?;
    if !git(&origin, &["init", "-q", "--bare", "-b", "main"]) {
        return None;
    }
    if !(git(&work, &["init", "-q", "-b", "main"])
        && git(&work, &["add", "-A"])
        && git(&work, &["commit", "-q", "-m", "init"])
        && git(
            &work,
            &["remote", "add", "origin", &origin.to_string_lossy()],
        )
        && git(&work, &["push", "-q", "origin", "main"])
        && (!tag || git(&work, &["tag", "v0.1.0-rc9"])))
    {
        return None;
    }
    Some(Repo(work))
}

fn gate(repo: &Path, tagged: bool) -> Output {
    let mut args = vec!["pre-release", "--repo", ".", "--tag", "v0.1.0-rc9"];
    if tagged {
        args.push("--tagged");
    }
    Command::new(bin())
        .args(&args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", bin()))
}

fn line(out: &Output, verdict: &str, name: &str) -> bool {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with(&format!("{verdict} {name}")))
}

/// The tag exists only here: nothing about this run can have published it.
fn origin_has_no_tag(repo: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["ls-remote", "--tags", "origin"])
        .output()
        .map(|o| o.status.success() && o.stdout.is_empty())
        .unwrap_or(false)
}

#[test]
fn stale_version_fails_before_the_tag_is_pushed() {
    let Some(repo) = fixture("stale", "0.1.0", true) else {
        panic!("cannot build the fixture repository")
    };
    let out = gate(&repo.0, true);
    assert!(
        line(&out, "FAIL", "version"),
        "__version__ 0.1.0 must not pass a v0.1.0-rc9 gate:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        origin_has_no_tag(&repo.0),
        "the gate must decide without the tag being published"
    );
}

#[test]
fn stale_version_fails_before_the_tag_even_exists() {
    // The invocation that can run first: no tag anywhere, `--tag` is only the proposed number.
    let Some(repo) = fixture("pre-tag", "0.1.0", false) else {
        panic!("cannot build the fixture repository")
    };
    let out = gate(&repo.0, false);
    assert!(
        line(&out, "FAIL", "version"),
        "a proposed tag must be compared before it is created:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        line(&out, "PASS", "tag-free"),
        "a gate that runs before `git tag` must accept a tag that does not exist yet:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn matching_version_passes_with_the_tag_still_local() {
    let Some(repo) = fixture("match", "0.1.0-rc9", true) else {
        panic!("cannot build the fixture repository")
    };
    let out = gate(&repo.0, true);
    assert!(
        line(&out, "PASS", "version"),
        "__version__ 0.1.0-rc9 must pass its own tag:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        line(&out, "PASS", "tag-at-head"),
        "the local tag must be accepted at HEAD:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(origin_has_no_tag(&repo.0));
}
