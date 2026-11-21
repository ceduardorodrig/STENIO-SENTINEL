//! `DEPENDABOT-LOCKFILE-COVERAGE` (GB-264 part b): every lockfile needs a Dependabot entry.
//!
//! WHY IT EXISTS (2026-11-21, Hub repository): `.github/dependabot.yml` had no `cargo`
//! ecosystem while seven `Cargo.lock` files existed, so advisories on those crates never
//! produced a pull request. The check is deterministic and offline: it walks the repository for
//! `Cargo.lock` next to a `Cargo.toml` and `package-lock.json` next to a `package.json`, reads
//! the `updates:` list of `.github/dependabot.yml` (or `.yaml`) and fails for every lockfile
//! directory that no entry of the same ecosystem covers.
//!
//! MATCHING (GitHub, "Dependabot options reference"): `directory` is a single literal path;
//! `directories` accepts several paths and supports globbing (`*` for one segment, `**` for
//! recursive matching). Both forms accept the `/`-rooted spelling; a leading `/` or `./` and a
//! trailing `/` are normalised away. A glob written in `directory` is NOT expanded, exactly as
//! Dependabot treats it, so it does not count as coverage.
//!
//! SANCTIONED EXCLUSION: a directory that is deliberately left out (a vendored crate, a
//! throwaway WASM build) is declared in the repository's `steniocheck.toml`, never in a comment:
//!
//! ```toml
//! [[dependabot.exclude]]
//! directory = "app/dependencies/asciline/asciline-rs"
//! ecosystem = "cargo"            # optional; omitted means every ecosystem
//! reason = "vendored upstream crate, updated by hand"
//! ```
//!
//! An exclusion without a `reason` is itself a finding, and an exclusion that no longer matches
//! an uncovered lockfile is a warning, so the list cannot rot silently. The rule is inert when
//! the repository has no Dependabot configuration at all (nothing to compare against).

use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::config::{DependabotExclude, SteniocheckConfig};
use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "DEPENDABOT-LOCKFILE-COVERAGE";
const RULE_NAME: &str = "Dependabot Lockfile Coverage";
const CONFIG_FILES: [&str; 2] = [".github/dependabot.yml", ".github/dependabot.yaml"];

/// Lockfile name, the manifest that must sit next to it, and the Dependabot ecosystem.
const LOCKFILES: [(&str, &str, &str); 2] = [
    ("Cargo.lock", "Cargo.toml", "cargo"),
    ("package-lock.json", "package.json", "npm"),
];

/// A lockfile found in the tree: directory (rooted, `/` is the repository root) and ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lockfile {
    pub dir: String,
    pub file: &'static str,
    pub ecosystem: &'static str,
}

/// One `updates:` entry reduced to what coverage needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Update {
    pub ecosystem: String,
    /// Paths from `directory:` (literal, never expanded).
    pub literal: Vec<String>,
    /// Paths from `directories:` (globbing allowed).
    pub globs: Vec<String>,
}

pub struct DependabotReport {
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

/// Rooted, slash-normalised form: `app/server/`, `./app/server` and `/app/server` all become
/// `/app/server`; the repository root is `/`.
fn normalize_dir(raw: &str) -> String {
    let t = raw.trim().trim_start_matches("./");
    let t = t.trim_matches('/');
    format!("/{t}")
}

/// `*` matches any run of characters inside one path segment.
fn segment_match(pat: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Segment-wise glob: `**` spans zero or more whole segments, `*` stays inside one.
fn glob_match(pattern: &[&str], dir: &[&str]) -> bool {
    match pattern.split_first() {
        None => dir.is_empty(),
        Some((&"**", rest)) => (0..=dir.len()).any(|skip| glob_match(rest, &dir[skip..])),
        Some((seg, rest)) => dir
            .split_first()
            .is_some_and(|(d, tail)| segment_match(seg, d) && glob_match(rest, tail)),
    }
}

fn segments(rooted: &str) -> Vec<&str> {
    rooted.split('/').filter(|s| !s.is_empty()).collect()
}

fn covers(update: &Update, lock: &Lockfile) -> bool {
    if !update.ecosystem.eq_ignore_ascii_case(lock.ecosystem) {
        return false;
    }
    let dir = segments(&lock.dir);
    update.literal.iter().any(|l| normalize_dir(l) == lock.dir)
        || update.globs.iter().any(|g| {
            let g = normalize_dir(g);
            glob_match(&segments(&g), &dir)
        })
}

/// Reads the `updates:` list. A document with no `updates` key yields an empty list.
pub fn parse_updates(yaml: &str) -> Result<Vec<Update>, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    let strings = |v: Option<&serde_yaml::Value>| -> Vec<String> {
        v.and_then(|s| s.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let Some(items) = doc.get("updates").and_then(|u| u.as_sequence()) else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .map(|item| Update {
            ecosystem: item
                .get("package-ecosystem")
                .and_then(|e| e.as_str())
                .unwrap_or_default()
                .to_string(),
            literal: item
                .get("directory")
                .and_then(|d| d.as_str())
                .map(|d| vec![d.to_string()])
                .unwrap_or_default(),
            globs: strings(item.get("directories")),
        })
        .collect())
}

/// Walks the repository (git-ignore aware, skipping `node_modules` and cargo build output) for
/// lockfiles that have their manifest next to them.
pub fn find_lockfiles(root: &Path) -> Vec<Lockfile> {
    let walker = WalkBuilder::new(root)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            let cargo_output = name == "target" && e.path().join("CACHEDIR.TAG").exists();
            name != "node_modules" && !cargo_output
        })
        .build();
    let found: BTreeSet<Lockfile> = walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let (file, manifest, ecosystem) =
                LOCKFILES.iter().find(|(lock, _, _)| *lock == name)?;
            let parent = e.path().parent()?;
            parent.join(manifest).is_file().then_some(())?;
            let rel = parent.strip_prefix(root).ok()?.to_string_lossy();
            Some(Lockfile {
                dir: normalize_dir(&rel),
                file,
                ecosystem,
            })
        })
        .collect();
    found.into_iter().collect()
}

fn lock_path(lock: &Lockfile) -> String {
    match lock.dir.trim_start_matches('/') {
        "" => lock.file.to_string(),
        dir => format!("{dir}/{}", lock.file),
    }
}

fn violation(severity: Severity, file: &str, message: String, suggestion: &str) -> Violation {
    Violation {
        rule_id: RULE_ID.to_string(),
        rule_name: RULE_NAME.to_string(),
        severity,
        file_path: file.to_string(),
        line_number: 1,
        snippet: String::new(),
        message,
        suggestion: Some(suggestion.to_string()),
    }
}

fn excludes(ex: &DependabotExclude, lock: &Lockfile) -> bool {
    normalize_dir(&ex.directory) == lock.dir
        && ex
            .ecosystem
            .as_deref()
            .is_none_or(|e| e.eq_ignore_ascii_case(lock.ecosystem))
}

/// Pure decision: lockfiles, parsed updates and declared exclusions in, findings out.
pub fn evaluate(
    locks: &[Lockfile],
    updates: &[Update],
    exclusions: &[DependabotExclude],
) -> Vec<Violation> {
    let mut out = Vec::new();
    for ex in exclusions.iter().filter(|e| e.reason.trim().is_empty()) {
        out.push(violation(
            Severity::Error,
            "steniocheck.toml",
            format!(
                "[[dependabot.exclude]] for '{}' has no reason, so the exclusion is ignored",
                ex.directory
            ),
            "Add a non-empty `reason` stating why Dependabot must not cover this directory.",
        ));
    }
    let valid: Vec<&DependabotExclude> = exclusions
        .iter()
        .filter(|e| !e.reason.trim().is_empty())
        .collect();
    let mut used = vec![false; valid.len()];
    for lock in locks {
        let hit = valid.iter().position(|ex| excludes(ex, lock));
        let covered = updates.iter().any(|u| covers(u, lock));
        match (covered, hit) {
            (false, Some(i)) => used[i] = true,
            (false, None) => out.push(violation(
                Severity::Error,
                &lock_path(lock),
                format!(
                    "{} in '{}' is not covered by any `{}` entry of .github/dependabot.yml, \
                     so advisories on it never open a pull request",
                    lock.file, lock.dir, lock.ecosystem
                ),
                &format!(
                    "Add `package-ecosystem: {}` with `directory: \"{}\"` (or list it under \
                     `directories`), or declare it in steniocheck.toml with [[dependabot.exclude]] \
                     and a reason.",
                    lock.ecosystem, lock.dir
                ),
            )),
            (true, _) => {}
        }
    }
    for (ex, was_used) in valid.iter().zip(used) {
        if !was_used {
            out.push(violation(
                Severity::Warning,
                "steniocheck.toml",
                format!(
                    "[[dependabot.exclude]] for '{}' matches no uncovered lockfile (stale or now covered)",
                    ex.directory
                ),
                "Remove the exclusion, or fix its directory/ecosystem.",
            ));
        }
    }
    out
}

/// The directory to audit: `path` when it holds a Dependabot config, else the scope target.
pub fn repo_root<'a>(path: &'a Path, scan_target: &'a Path) -> &'a Path {
    if CONFIG_FILES.iter().any(|rel| path.join(rel).is_file()) {
        path
    } else {
        scan_target
    }
}

/// Repository audit: needs `.github/dependabot.yml`; with none the rule is inert.
pub fn audit(root: &Path, cfg: &SteniocheckConfig) -> DependabotReport {
    let mut report = DependabotReport {
        messages: Vec::new(),
        violations: Vec::new(),
    };
    let Some((rel, text)) = CONFIG_FILES
        .iter()
        .find_map(|rel| fs::read_to_string(root.join(rel)).ok().map(|t| (*rel, t)))
    else {
        report
            .messages
            .push(format!("{RULE_ID}: no .github/dependabot.yml, rule inert"));
        return report;
    };
    let updates = match parse_updates(&text) {
        Ok(u) => u,
        Err(e) => {
            report.violations.push(violation(
                Severity::Error,
                rel,
                format!("{rel} is not valid YAML: {e}"),
                "Fix the YAML so Dependabot and Stenio can read the `updates:` list.",
            ));
            return report;
        }
    };
    let locks = find_lockfiles(root);
    let exclusions = cfg
        .dependabot
        .as_ref()
        .and_then(|d| d.exclude.clone())
        .unwrap_or_default();
    report.violations = evaluate(&locks, &updates, &exclusions);
    report.messages.push(format!(
        "{RULE_ID}: {} lockfile(s), {} update entr(ies), {} finding(s)",
        locks.len(),
        updates.len(),
        report.violations.len()
    ));
    report
}

const FIXTURE_COVERED: &str = "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directories:\n      - \"/app/*\"\n      - \"/scripts/st-transcribe\"\n    schedule: {interval: weekly}\n  - package-ecosystem: npm\n    directory: \"/\"\n    schedule: {interval: weekly}\n";
const FIXTURE_NO_CARGO: &str = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: \"/\"\n    schedule: {interval: weekly}\n";

fn fixture_locks() -> Vec<Lockfile> {
    let lock = |dir: &str, file, ecosystem| Lockfile {
        dir: dir.to_string(),
        file,
        ecosystem,
    };
    vec![
        lock("/", "package-lock.json", "npm"),
        lock("/app/server", "Cargo.lock", "cargo"),
        lock("/app/arandu-sync", "Cargo.lock", "cargo"),
        lock("/scripts/st-transcribe", "Cargo.lock", "cargo"),
    ]
}

fn fixture_exclusion(reason: &str) -> DependabotExclude {
    DependabotExclude {
        directory: "app/server".to_string(),
        ecosystem: Some("cargo".to_string()),
        reason: reason.to_string(),
    }
}

/// End to end over a temp tree: the same lockfile, once with the cargo entry and once without.
fn tree_findings(yaml: &str, tag: &str) -> Option<usize> {
    let files = vec![
        ("Cargo.toml".to_string(), "[package]\n".to_string()),
        ("Cargo.lock".to_string(), "# lock\n".to_string()),
        (".github/dependabot.yml".to_string(), yaml.to_string()),
    ];
    let root = crate::frappe::write_fixture(tag, &files)?;
    let found = audit(&root, &SteniocheckConfig::default()).violations.len();
    let _ = fs::remove_dir_all(&root);
    Some(found)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let locks = fixture_locks();
    let run = |yaml: &str, ex: &[DependabotExclude]| {
        parse_updates(yaml).map(|u| evaluate(&locks, &u, ex))
    };
    let green = run(FIXTURE_COVERED, &[]).map(|v| v.is_empty());
    let red = run(FIXTURE_NO_CARGO, &[]).map(|v| v.len());
    let excluded = run(FIXTURE_NO_CARGO, &[fixture_exclusion("vendored crate")]).map(|v| {
        v.iter()
            .filter(|x| x.file_path == "app/server/Cargo.lock")
            .count()
    });
    let no_reason = run(FIXTURE_NO_CARGO, &[fixture_exclusion("  ")]).map(|v| {
        v.iter()
            .any(|x| x.severity == Severity::Error && x.file_path == "steniocheck.toml")
    });
    vec![
        (
            "dependabot: all lockfiles covered".to_string(),
            green == Ok(true),
        ),
        (
            "dependabot: mutation, cargo entry removed".to_string(),
            red == Ok(3),
        ),
        (
            "dependabot: declared exclusion is green".to_string(),
            excluded == Ok(0),
        ),
        (
            "dependabot: exclusion needs a reason".to_string(),
            no_reason == Ok(true),
        ),
        (
            "dependabot: tree with cargo entry".to_string(),
            tree_findings(
                "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: \"/\"\n",
                "dependabot-good",
            ) == Some(0),
        ),
        (
            "dependabot: tree mutation fires".to_string(),
            tree_findings(FIXTURE_NO_CARGO, "dependabot-bad") == Some(1),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(dir: &str, ecosystem: &'static str) -> Lockfile {
        Lockfile {
            dir: dir.to_string(),
            file: if ecosystem == "cargo" {
                "Cargo.lock"
            } else {
                "package-lock.json"
            },
            ecosystem,
        }
    }

    fn update(eco: &str, literal: &[&str], globs: &[&str]) -> Update {
        Update {
            ecosystem: eco.to_string(),
            literal: literal.iter().map(|s| s.to_string()).collect(),
            globs: globs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn synthetic_cases_pass() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn normalisation_accepts_every_spelling() {
        for raw in ["/app/server", "app/server", "./app/server/", "/app/server/"] {
            assert_eq!(normalize_dir(raw), "/app/server");
        }
        assert_eq!(normalize_dir("/"), "/");
        assert_eq!(normalize_dir(""), "/");
    }

    #[test]
    fn root_directory_covers_only_the_root() {
        let u = update("cargo", &["/"], &[]);
        assert!(covers(&u, &lock("/", "cargo")));
        assert!(!covers(&u, &lock("/app", "cargo")));
    }

    #[test]
    fn glob_star_stays_in_one_segment_and_double_star_recurses() {
        let one = update("cargo", &[], &["/app/*"]);
        assert!(covers(&one, &lock("/app/server", "cargo")));
        assert!(!covers(&one, &lock("/app/deps/asciline-rs", "cargo")));
        let deep = update("cargo", &[], &["/app/**"]);
        assert!(covers(&deep, &lock("/app/deps/asciline-rs", "cargo")));
        let infix = update("cargo", &[], &["/app/arandu-*"]);
        assert!(covers(&infix, &lock("/app/arandu-sync", "cargo")));
        assert!(!covers(&infix, &lock("/app/server", "cargo")));
    }

    #[test]
    fn glob_in_directory_is_not_expanded() {
        let u = update("cargo", &["/app/*"], &[]);
        assert!(!covers(&u, &lock("/app/server", "cargo")));
    }

    #[test]
    fn ecosystem_must_match() {
        let u = update("npm", &["/app/server"], &[]);
        assert!(!covers(&u, &lock("/app/server", "cargo")));
    }

    #[test]
    fn exclusion_without_matching_lockfile_is_a_warning() {
        let ex = DependabotExclude {
            directory: "/gone".to_string(),
            ecosystem: None,
            reason: "was vendored".to_string(),
        };
        let v = evaluate(&[], &[], &[ex]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Warning);
    }

    #[test]
    fn exclusion_ecosystem_is_respected() {
        let ex = DependabotExclude {
            directory: "/app".to_string(),
            ecosystem: Some("npm".to_string()),
            reason: "x".to_string(),
        };
        let v = evaluate(&[lock("/app", "cargo")], &[], &[ex]);
        assert!(
            v.iter()
                .any(|x| x.severity == Severity::Error && x.file_path == "app/Cargo.lock")
        );
    }

    #[test]
    fn invalid_yaml_and_missing_updates_are_handled() {
        assert!(parse_updates("updates: [").is_err());
        assert_eq!(parse_updates("version: 2\n"), Ok(Vec::new()));
    }

    #[test]
    fn path_with_config_wins_over_the_scope_target() {
        let files = vec![(
            ".github/dependabot.yml".to_string(),
            "version: 2\n".to_string(),
        )];
        let root = crate::frappe::write_fixture("dependabot-root", &files);
        assert!(root.is_some());
        if let Some(root) = root {
            let other = Path::new("/nonexistent-scope-target");
            assert_eq!(repo_root(&root, other), root.as_path());
            assert_eq!(repo_root(other, &root), root.as_path());
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn lockfile_without_manifest_is_ignored() {
        let files = vec![("a/Cargo.lock".to_string(), "x".to_string())];
        let root = crate::frappe::write_fixture("dependabot-nomanifest", &files);
        assert!(root.is_some());
        if let Some(root) = root {
            assert!(find_lockfiles(&root).is_empty());
            let _ = fs::remove_dir_all(&root);
        }
    }
}
