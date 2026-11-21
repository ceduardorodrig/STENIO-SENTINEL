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
//! CARGO WORKSPACES (GB-270, 2026-11-21): a crate that is a MEMBER of a workspace whose root
//! directory holds a `Cargo.lock` is resolved by that root lock and needs no directory of its own
//! (https://doc.rust-lang.org/cargo/reference/workspaces.html: "All packages share a common
//! Cargo.lock file which resides in the workspace root"). Members are the `[workspace] members`
//! entries (globs `*`/`?` expanded) minus `exclude`, the `path` dependencies that live inside the
//! workspace directory (automatic members) and every crate whose `package.workspace` points at
//! the root. Consequences: a `Cargo.lock` inside a member is an inert ORPHAN (WARNING, cargo
//! ignores it, delete it), it is never demanded as "uncovered", and listing a member directory in
//! `dependabot.yml` is an ERROR (Dependabot fails with `dependency_file_not_resolvable` when the
//! member inherits fields from the root manifest, KURURU run 44873311270). A standalone crate
//! (not a member) keeps needing its own entry.
//!
//! An exclusion without a `reason` is itself a finding, and an exclusion that no longer matches
//! an uncovered lockfile is a warning, so the list cannot rot silently. The rule is inert when
//! the repository has no Dependabot configuration at all (nothing to compare against).

use ignore::WalkBuilder;
use std::collections::{BTreeMap, BTreeSet};
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

/// `*` matches any run of characters inside one path segment, `?` exactly one character.
fn segment_match(pat: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && (p[pi] == t[ti] || p[pi] == '?') {
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

fn walk_files(root: &Path) -> impl Iterator<Item = ignore::DirEntry> {
    WalkBuilder::new(root)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            let cargo_output = name == "target" && e.path().join("CACHEDIR.TAG").exists();
            name != "node_modules" && !cargo_output
        })
        .build()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
}

fn rel_dir(root: &Path, entry: &ignore::DirEntry) -> Option<String> {
    let parent = entry.path().parent()?;
    Some(normalize_dir(
        &parent.strip_prefix(root).ok()?.to_string_lossy(),
    ))
}

/// Walks the repository (git-ignore aware, skipping `node_modules` and cargo build output) for
/// lockfiles that have their manifest next to them.
pub fn find_lockfiles(root: &Path) -> Vec<Lockfile> {
    let found: BTreeSet<Lockfile> = walk_files(root)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let (file, manifest, ecosystem) =
                LOCKFILES.iter().find(|(lock, _, _)| *lock == name)?;
            e.path().parent()?.join(manifest).is_file().then_some(())?;
            Some(Lockfile {
                dir: rel_dir(root, &e)?,
                file,
                ecosystem,
            })
        })
        .collect();
    found.into_iter().collect()
}

/// `base` + relative `rel` (`..` and `.` resolved), rooted; `None` when it escapes the repository.
fn resolve_dir(base: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = segments(base);
    for seg in rel.split('/').filter(|s| !s.is_empty() && *s != ".") {
        if seg == ".." {
            parts.pop()?;
        } else {
            parts.push(seg);
        }
    }
    Some(format!("/{}", parts.join("/")))
}

fn toml_strings(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Directories of the `path` dependencies of one manifest (all dependency tables, targets included).
fn path_deps(base: &str, manifest: &toml::Value) -> Vec<String> {
    fn collect(m: &toml::Value) -> Vec<&toml::Value> {
        ["dependencies", "dev-dependencies", "build-dependencies"]
            .iter()
            .filter_map(|key| m.get(key))
            .collect()
    }
    let mut tables = collect(manifest);
    if let Some(targets) = manifest.get("target").and_then(|t| t.as_table()) {
        tables.extend(targets.values().flat_map(collect));
    }
    tables
        .iter()
        .filter_map(|t| t.as_table())
        .flat_map(|t| t.values())
        .filter_map(|d| d.get("path").and_then(|p| p.as_str()))
        .filter_map(|p| resolve_dir(base, p))
        .collect()
}

/// Pure decision over parsed manifests (rooted dir -> manifest) and the dirs whose `Cargo.lock`
/// exists: which crate directories are members of a workspace whose root has a lockfile.
pub fn workspace_members(
    manifests: &BTreeMap<String, toml::Value>,
    lock_dirs: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    for (root, manifest) in manifests {
        let Some(ws) = manifest.get("workspace") else {
            continue;
        };
        if !lock_dirs.contains(root) {
            continue;
        }
        let pats = |key: &str| -> Vec<Vec<String>> {
            toml_strings(ws.get(key))
                .iter()
                .filter_map(|p| resolve_dir(root, p))
                .map(|p| segments(&p).iter().map(|s| s.to_string()).collect())
                .collect()
        };
        let (include, exclude) = (pats("members"), pats("exclude"));
        let matches = |pats: &[Vec<String>], dir: &str| {
            let d = segments(dir);
            pats.iter().any(|p| {
                let p: Vec<&str> = p.iter().map(String::as_str).collect();
                glob_match(&p, &d)
            })
        };
        let excluded = |dir: &str| matches(&exclude, dir);
        let mut found: BTreeSet<String> = manifests
            .keys()
            .filter(|d| *d != root && matches(&include, d) && !excluded(d))
            .cloned()
            .collect();
        // `package.workspace = "<path>"` names its root explicitly.
        for (dir, m) in manifests {
            let target = m
                .get("package")
                .and_then(|p| p.get("workspace"))
                .and_then(|w| w.as_str())
                .and_then(|w| resolve_dir(dir, w));
            if dir != root && target.as_deref() == Some(root.as_str()) {
                found.insert(dir.clone());
            }
        }
        // Path dependencies inside the workspace directory are automatic members (transitively).
        let prefix = segments(root);
        let inside = |d: &str| segments(d).starts_with(&prefix);
        let mut queue: Vec<String> = std::iter::once(root.clone())
            .chain(found.iter().cloned())
            .collect();
        while let Some(dir) = queue.pop() {
            let Some(m) = manifests.get(&dir) else {
                continue;
            };
            for dep in path_deps(&dir, m) {
                let known = manifests.contains_key(&dep);
                if known
                    && inside(&dep)
                    && dep != *root
                    && !excluded(&dep)
                    && found.insert(dep.clone())
                {
                    queue.push(dep);
                }
            }
        }
        members.extend(found);
    }
    members
}

/// Reads every `Cargo.toml` of the tree and returns the member crate directories.
pub fn find_workspace_members(root: &Path) -> BTreeSet<String> {
    let mut manifests = BTreeMap::new();
    let mut lock_dirs = BTreeSet::new();
    for e in walk_files(root) {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(dir) = rel_dir(root, &e) else {
            continue;
        };
        match name.as_str() {
            "Cargo.lock" => {
                lock_dirs.insert(dir);
            }
            "Cargo.toml" => {
                if let Some(v) = fs::read_to_string(e.path())
                    .ok()
                    .and_then(|t| t.parse::<toml::Value>().ok())
                {
                    manifests.insert(dir, v);
                }
            }
            _ => {}
        }
    }
    workspace_members(&manifests, &lock_dirs)
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
    members: &BTreeSet<String>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for dir in members {
        let listed = updates.iter().any(|u| {
            let probe = Lockfile {
                dir: dir.clone(),
                file: "Cargo.lock",
                ecosystem: "cargo",
            };
            covers(u, &probe)
        });
        if listed {
            out.push(violation(
                Severity::Error,
                ".github/dependabot.yml",
                format!(
                    "workspace member '{dir}' is listed as a `cargo` directory; Dependabot cannot \
                     resolve a member alone (dependency_file_not_resolvable when it inherits \
                     fields from the workspace root)"
                ),
                "Remove the member directory (or narrow the glob); list only the workspace root, \
                 whose Cargo.lock covers every member.",
            ));
        }
    }
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
        if lock.ecosystem == "cargo" && members.contains(&lock.dir) {
            if let Some(i) = hit {
                used[i] = true;
            }
            out.push(violation(
                Severity::Warning,
                &lock_path(lock),
                format!(
                    "orphan lockfile: '{}' is a member of a Cargo workspace whose root Cargo.lock \
                     resolves it, so cargo ignores this file",
                    lock.dir
                ),
                "Delete the nested Cargo.lock; the workspace root lockfile is the only one used.",
            ));
            continue;
        }
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
    let members = find_workspace_members(root);
    report.violations = evaluate(&locks, &updates, &exclusions, &members);
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

const WS_ROOT: &str = "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/solo\"]\n";
const MEMBER: &str = "[package]\nname = \"m\"\nedition.workspace = true\n";
const ROOT_ONLY: &str =
    "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: \"/\"\n";
const LISTS_MEMBER: &str =
    "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directories: [\"/\", \"/crates/m\"]\n";

fn tree_violations(files: &[(&str, &str)], tag: &str) -> Option<Vec<Violation>> {
    let files: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect();
    let root = crate::frappe::write_fixture(tag, &files)?;
    let found = audit(&root, &SteniocheckConfig::default()).violations;
    let _ = fs::remove_dir_all(&root);
    Some(found)
}

fn count(v: &Option<Vec<Violation>>, sev: Severity, needle: &str) -> Option<usize> {
    let v = v.as_ref()?;
    Some(
        v.iter()
            .filter(|x| {
                x.severity == sev && format!("{} {}", x.file_path, x.message).contains(needle)
            })
            .count(),
    )
}

/// GB-270 cases: workspace members, nested orphan locks, listed members, standalone crates.
fn workspace_cases() -> Vec<(String, bool)> {
    let base = [
        ("Cargo.toml", WS_ROOT),
        ("Cargo.lock", "# root\n"),
        ("crates/m/Cargo.toml", MEMBER),
        ("crates/m/Cargo.lock", "# nested\n"),
        (".github/dependabot.yml", ROOT_ONLY),
    ];
    let orphan = tree_violations(&base, "dependabot-ws-orphan");
    let mut listed_files = base.to_vec();
    listed_files[4] = (".github/dependabot.yml", LISTS_MEMBER);
    let listed = tree_violations(&listed_files, "dependabot-ws-listed");
    let mut solo_files = base.to_vec();
    solo_files.push(("crates/solo/Cargo.toml", "[package]\nname = \"s\"\n"));
    solo_files.push(("crates/solo/Cargo.lock", "# own\n"));
    let solo = tree_violations(&solo_files, "dependabot-ws-solo");
    let mut explicit = base.to_vec();
    explicit[0] = ("Cargo.toml", "[workspace]\n");
    explicit[2] = (
        "crates/m/Cargo.toml",
        "[package]\nname = \"m\"\nworkspace = \"../..\"\n",
    );
    let by_key = tree_violations(&explicit, "dependabot-ws-key");
    let mut path_dep = base.to_vec();
    path_dep[0] = (
        "Cargo.toml",
        "[package]\nname = \"r\"\n[dependencies]\nm = { path = \"crates/m\" }\n[workspace]\n",
    );
    let auto = tree_violations(&path_dep, "dependabot-ws-pathdep");
    let mut no_root_lock = base.to_vec();
    no_root_lock.remove(1);
    let no_lock = tree_violations(&no_root_lock, "dependabot-ws-nolock");
    vec![
        (
            "dependabot: workspace member with nested lock is an orphan WARN, not uncovered"
                .to_string(),
            count(&orphan, Severity::Warning, "orphan lockfile") == Some(1)
                && orphan.as_ref().map(Vec::len) == Some(1),
        ),
        (
            "dependabot: mutation, member directory listed in dependabot.yml is an ERROR"
                .to_string(),
            count(&listed, Severity::Error, "workspace member '/crates/m'") == Some(1),
        ),
        (
            "dependabot: standalone excluded crate with its own lock still needs an entry"
                .to_string(),
            count(&solo, Severity::Error, "crates/solo/Cargo.lock") == Some(1)
                && count(&solo, Severity::Warning, "orphan") == Some(1),
        ),
        (
            "dependabot: member declared by package.workspace is a member".to_string(),
            count(&by_key, Severity::Warning, "orphan lockfile") == Some(1)
                && by_key.as_ref().map(Vec::len) == Some(1),
        ),
        (
            "dependabot: path dependency inside the workspace is a member".to_string(),
            count(&auto, Severity::Warning, "orphan lockfile") == Some(1)
                && auto.as_ref().map(Vec::len) == Some(1),
        ),
        (
            "dependabot: without a root Cargo.lock the member lock is still uncovered".to_string(),
            count(&no_lock, Severity::Error, "crates/m/Cargo.lock") == Some(1),
        ),
    ]
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let locks = fixture_locks();
    let run = |yaml: &str, ex: &[DependabotExclude]| {
        parse_updates(yaml).map(|u| evaluate(&locks, &u, ex, &BTreeSet::new()))
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
    let mut cases = workspace_cases();
    cases.extend(vec![
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
    ]);
    cases
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
        let v = evaluate(&[], &[], &[ex], &BTreeSet::new());
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
        let v = evaluate(&[lock("/app", "cargo")], &[], &[ex], &BTreeSet::new());
        assert!(
            v.iter()
                .any(|x| x.severity == Severity::Error && x.file_path == "app/Cargo.lock")
        );
    }

    fn manifests(items: &[(&str, &str)]) -> BTreeMap<String, toml::Value> {
        items
            .iter()
            .map(|(d, t)| {
                (
                    d.to_string(),
                    t.parse::<toml::Value>()
                        .unwrap_or(toml::Value::Boolean(false)),
                )
            })
            .collect()
    }

    fn lock_set(dirs: &[&str]) -> BTreeSet<String> {
        dirs.iter().map(|d| d.to_string()).collect()
    }

    #[test]
    fn members_expand_globs_and_honour_exclude() {
        let m = manifests(&[
            (
                "/",
                "[workspace]\nmembers = [\"crates/*\", \"tools/t?\"]\nexclude = [\"crates/skip\"]\n",
            ),
            ("/crates/a", "[package]\nname = \"a\"\n"),
            ("/crates/skip", "[package]\nname = \"s\"\n"),
            ("/tools/t1", "[package]\nname = \"t\"\n"),
            ("/tools/other", "[package]\nname = \"o\"\n"),
        ]);
        let got = workspace_members(&m, &lock_set(&["/"]));
        assert_eq!(got, lock_set(&["/crates/a", "/tools/t1"]));
    }

    #[test]
    fn members_need_a_root_lockfile_and_nested_workspaces_resolve_on_their_own() {
        let m = manifests(&[
            ("/", "[workspace]\nmembers = [\"a\"]\n"),
            ("/a", "[package]\nname = \"a\"\n"),
        ]);
        assert!(workspace_members(&m, &lock_set(&[])).is_empty());
        let sub = manifests(&[
            ("/ws", "[workspace]\nmembers = [\"a\"]\n"),
            ("/ws/a", "[package]\nname = \"a\"\n"),
            ("/other", "[package]\nname = \"o\"\n"),
        ]);
        assert_eq!(
            workspace_members(&sub, &lock_set(&["/ws"])),
            lock_set(&["/ws/a"])
        );
    }

    #[test]
    fn package_workspace_key_can_point_outside_the_subtree() {
        let m = manifests(&[
            ("/ws", "[workspace]\n"),
            (
                "/elsewhere/x",
                "[package]\nname = \"x\"\nworkspace = \"../../ws\"\n",
            ),
        ]);
        assert_eq!(
            workspace_members(&m, &lock_set(&["/ws"])),
            lock_set(&["/elsewhere/x"])
        );
    }

    #[test]
    fn resolve_dir_handles_dots_and_escape() {
        assert_eq!(resolve_dir("/a/b", "../c").as_deref(), Some("/a/c"));
        assert_eq!(resolve_dir("/", "./x").as_deref(), Some("/x"));
        assert_eq!(resolve_dir("/a", "../.."), None);
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
