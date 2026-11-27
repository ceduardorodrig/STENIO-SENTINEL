//! `stenio secrets-guard --history` (GB-285, history part): deleting a secret from the tree does not
//! remove it from the repository. Every added line and every added path of `git log --all` is judged
//! with the same detectors as the tracked tree. Accepted old findings are listed as `commit:path` in
//! `--history-baseline`, so history that cannot be rewritten stays counted while a new leak fails.
//! SECURITY: only commit ids, paths and line counts leave this module.

use super::{SCANNED_EXTENSIONS, credential_shaped_name};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

const COMMIT_MARK: &str = "@@stenio-commit ";

/// Calls `line` for every stdout line of `git log` with `args`.
fn git_lines(repo: &Path, args: &[&str], mut line: impl FnMut(&str)) -> Result<(), String> {
    let mark = format!("--pretty=format:{COMMIT_MARK}%H");
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.quotepath=false", "log", "--all", "--no-renames"])
        .arg(mark)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("git: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git produced no stdout".to_string())?;
    for raw in BufReader::new(stdout).split(b'\n') {
        let raw = raw.map_err(|e| format!("git log read: {e}"))?;
        line(&String::from_utf8_lossy(&raw));
    }
    let status = child.wait().map_err(|e| format!("git: {e}"))?;
    if !status.success() {
        return Err("git log failed".to_string());
    }
    Ok(())
}

fn scanned_path(path: &str) -> bool {
    if path.contains(".template") || path.contains(".example") || path.contains("templates/") {
        return false;
    }
    let ext = crate::rule::effective_extension(Path::new(path));
    SCANNED_EXTENSIONS.contains(&ext.as_str())
}

/// `(commit12, path) -> number of added lines with a finding` plus the credential-shaped adds.
type Hits = BTreeMap<(String, String), usize>;

fn scan(repo: &Path) -> Result<(Hits, BTreeSet<(String, String)>), String> {
    let short = |h: &str| h.chars().take(12).collect::<String>();

    let mut shaped = BTreeSet::new();
    let mut commit = String::new();
    git_lines(repo, &["-m", "--diff-filter=AM", "--name-only"], |l| {
        if let Some(h) = l.strip_prefix(COMMIT_MARK) {
            commit = short(h.split_whitespace().next().unwrap_or(""));
        } else if !l.is_empty() {
            let name = l.rsplit('/').next().unwrap_or(l);
            if credential_shaped_name(name) {
                shaped.insert((commit.clone(), l.to_string()));
            }
        }
    })?;

    let mut hits: Hits = BTreeMap::new();
    let mut commit = String::new();
    let mut file = String::new();
    let mut in_header = false;
    let args = [
        "-m",
        "-p",
        "-U0",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
    ];
    git_lines(repo, &args, |l| {
        if let Some(h) = l.strip_prefix(COMMIT_MARK) {
            commit = short(h.split_whitespace().next().unwrap_or(""));
            file.clear();
        } else if l.starts_with("diff --git ") {
            in_header = true;
            file.clear();
        } else if in_header {
            if let Some(p) = l.strip_prefix("+++ b/") {
                file = p.trim_end_matches('\t').to_string();
            } else if l.starts_with("@@") {
                in_header = false;
            }
        } else if let Some(added) = l.strip_prefix('+')
            && !file.is_empty()
            && scanned_path(&file)
            && !crate::infra::plaintext_secret_violations(&file, added, false).is_empty()
        {
            *hits.entry((commit.clone(), file.clone())).or_insert(0) += 1;
        }
    })?;
    Ok((hits, shaped))
}

/// Report lines and the number of failures for the whole history; `accepted` holds `commit:path`.
pub fn evaluate(repo: &Path, accepted: &BTreeSet<String>) -> Result<(Vec<String>, usize), String> {
    let (hits, shaped) = scan(repo)?;
    let is_accepted = |c: &str, p: &str| {
        accepted.iter().any(|e| {
            e.split_once(':')
                .is_some_and(|(ec, ep)| ep == p && ec.len() >= 7 && c.starts_with(ec))
        })
    };
    let mut lines = Vec::new();
    let mut fails = 0usize;
    let mut old = 0usize;
    for (c, p) in &shaped {
        if is_accepted(c, p) {
            old += 1;
        } else {
            fails += 1;
            lines.push(format!(
                "FAIL (h) credential-shaped path in history: {c}:{p}"
            ));
        }
    }
    for ((c, p), n) in &hits {
        if is_accepted(c, p) {
            old += 1;
        } else {
            fails += 1;
            lines.push(format!(
                "FAIL (h) SEC-PLAINTEXT-SECRET added in history: {c}:{p} lines={n}"
            ));
        }
    }
    lines.push(format!(
        "info (h) history: findings={} accepted={old} new={fails}",
        shaped.len() + hits.len()
    ));
    Ok((lines, fails))
}
