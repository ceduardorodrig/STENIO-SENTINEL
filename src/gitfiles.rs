//! The one list of Git-selected files behind `--diff`, `--fast` and the changed-file rules.
//! Names are read NUL separated and relative to the scanned directory; any Git failure is an
//! error, never an empty change set.

use std::path::{Path, PathBuf};

/// Directory Git runs in and, when the scan target is a single file, that file.
fn split(root: &Path) -> (PathBuf, Option<PathBuf>) {
    if root.is_file() {
        let dir = root
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        (dir.to_path_buf(), Some(root.to_path_buf()))
    } else {
        (root.to_path_buf(), None)
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = crate::staged::git_command(dir)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git in {}: {e}", dir.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            dir.display(),
            stderr.lines().next().unwrap_or("no message")
        ));
    }
    Ok(out.stdout)
}

fn names(raw: &[u8]) -> impl Iterator<Item = PathBuf> + '_ {
    use std::os::unix::ffi::OsStrExt;
    raw.split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .map(|n| PathBuf::from(std::ffi::OsStr::from_bytes(n)))
}

const DIFF: [&str; 5] = [
    "diff",
    "--name-only",
    "-z",
    "--relative",
    "--diff-filter=ACMRT",
];

fn diff(dir: &Path, extra: &[&str]) -> Result<Vec<PathBuf>, String> {
    let mut args: Vec<&str> = DIFF.to_vec();
    args.extend_from_slice(extra);
    args.push("--");
    Ok(names(&git(dir, &args)?).collect())
}

fn untracked(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let raw = git(
        dir,
        &["ls-files", "-z", "--others", "--exclude-standard", "--"],
    )?;
    Ok(names(&raw).collect())
}

/// The tracked files below `dir`; empty outside a work tree.
pub fn tracked(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let inside =
        git(dir, &["rev-parse", "--is-inside-work-tree"]).map(|raw| raw.starts_with(b"true"));
    if inside != Ok(true) {
        return Ok(Vec::new());
    }
    let raw = git(dir, &["ls-files", "-z", "--cached", "--"])?;
    Ok(names(&raw)
        .map(|name| dir.join(name))
        .filter(|p| p.is_file() && !p.is_symlink())
        .collect())
}

/// Everything that differs from `HEAD` (or is tracked, before the first commit) plus the
/// untracked files.
fn working(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = if git(dir, &["rev-parse", "--verify", "-q", "HEAD"]).is_ok() {
        diff(dir, &["HEAD"])?
    } else {
        names(&git(dir, &["ls-files", "-z", "--cached", "--"])?).collect()
    };
    found.extend(untracked(dir)?);
    Ok(found)
}

fn from_stdin(dir: &Path, input: impl std::io::BufRead) -> Result<Vec<PathBuf>, String> {
    let mut listed = Vec::new();
    for line in input.lines() {
        let line = line.map_err(|e| format!("cannot read the file list from stdin: {e}"))?;
        if !line.trim().is_empty() {
            listed.push(PathBuf::from(line.trim()));
        }
    }
    let top = git(dir, &["rev-parse", "--show-toplevel"])
        .ok()
        .map(|raw| PathBuf::from(String::from_utf8_lossy(&raw).trim_end()));
    let found: Vec<PathBuf> = listed
        .iter()
        .filter_map(|name| {
            let here = dir.join(name);
            if here.is_file() {
                return Some(here);
            }
            top.as_ref().map(|t| t.join(name)).filter(|p| p.is_file())
        })
        .collect();
    if found.is_empty() && !listed.is_empty() {
        return Err(format!(
            "none of the {} path(s) read from stdin exists under {}",
            listed.len(),
            dir.display()
        ));
    }
    Ok(found)
}

/// The existing files selected by `target`: `""` the working changes, `staged`/`cached` the
/// index (the working changes when nothing is staged), `-` a list on stdin, else a revision or
/// range handed to `git diff`.
pub fn changed(root: &Path, target: &str) -> Result<Vec<PathBuf>, String> {
    let (dir, only) = split(root);
    let target = target.trim();
    if target == "-" {
        return from_stdin(&dir, std::io::stdin().lock());
    }
    let inside =
        git(&dir, &["rev-parse", "--is-inside-work-tree"]).map(|raw| raw.starts_with(b"true"));
    if inside != Ok(true) {
        return Err(format!(
            "{} is not inside a git work tree: --diff and --fast need one (run a full scan instead)",
            dir.display()
        ));
    }
    let found = match target {
        "" => working(&dir)?,
        "staged" | "cached" => {
            let staged = diff(&dir, &["--cached"])?;
            if staged.is_empty() {
                working(&dir)?
            } else {
                staged
            }
        }
        rev if rev.starts_with('-') => return Err(format!("not a revision: {rev}")),
        rev => {
            let mut found = diff(&dir, &[rev])?;
            if !rev.contains("..") {
                found.extend(untracked(&dir)?);
            }
            found
        }
    };
    let mut files: Vec<PathBuf> = found
        .into_iter()
        .map(|name| dir.join(name))
        .filter(|p| p.is_file())
        .filter(|p| only.as_ref().is_none_or(|o| p.file_name() == o.file_name()))
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}
