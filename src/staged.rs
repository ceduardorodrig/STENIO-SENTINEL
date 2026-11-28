//! The staged content as a tree of its own. When the working copy differs from the index,
//! `--diff staged` and `--pre-commit check` audit a private checkout of the index, so every rule
//! judges what the commit will hold. The real repository is only read.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Present in the Git directory of a snapshot only.
const MARKER: &str = "stenio-index-snapshot";

/// A `git` command for `dir`. Inside a snapshot the variables a hook exports must not apply:
/// they point back to the real repository.
pub fn git_command(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(dir);
    let absolute = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    if absolute
        .ancestors()
        .any(|a| a.join(".git").join(MARKER).is_file())
    {
        for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            command.env_remove(name);
        }
    }
    command
}

fn output(command: &mut Command, what: &str) -> Result<String, String> {
    let out = command
        .output()
        .map_err(|e| format!("cannot run git {what}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {what} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("no message")
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    output(git_command(dir).args(args), &args.join(" "))
}

pub struct Snapshot {
    /// Private temporary directory, removed on drop.
    base: PathBuf,
    /// Top of the checkout: the real top mirrored below `base`, so path rules still match.
    root: PathBuf,
    top: PathBuf,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

impl Snapshot {
    /// The same place inside the snapshot.
    pub fn map(&self, path: &Path) -> PathBuf {
        let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        absolute
            .strip_prefix(&self.top)
            .map_or_else(|_| path.to_path_buf(), |rest| self.root.join(rest))
    }

    /// The real place of a snapshot path.
    pub fn unmap(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root)
            .map_or_else(|_| path.to_path_buf(), |rest| self.top.join(rest))
    }

    /// Replaces the snapshot location in a printed text.
    pub fn restore(&self, text: &str) -> String {
        text.replace(
            self.root.to_string_lossy().as_ref(),
            self.top.to_string_lossy().as_ref(),
        )
    }
}

/// `None` when the working copy already is the staged content, when nothing is staged under
/// `path` (the selection then falls back to the working changes) or outside a work tree (the
/// selection reports that).
pub fn snapshot(path: &Path) -> Result<Option<Snapshot>, String> {
    let dir = match path.parent() {
        Some(parent) if path.is_file() => parent,
        _ => path,
    };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Ok(top) = git(dir, &["rev-parse", "--show-toplevel"]) else {
        return Ok(None);
    };
    let top = PathBuf::from(top);
    let staged = git(
        dir,
        &["diff", "--cached", "--name-only", "--relative", "--"],
    )?;
    if staged.is_empty() {
        return Ok(None);
    }
    let unstaged = git(&top, &["diff", "--name-only", "--"])?;
    let untracked = git(&top, &["ls-files", "--others", "--exclude-standard", "--"])?;
    if unstaged.is_empty() && untracked.is_empty() {
        return Ok(None);
    }
    create(top).map(Some)
}

fn create(top: PathBuf) -> Result<Snapshot, String> {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    let fail = |e: std::io::Error| format!("cannot build the staged snapshot: {e}");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let base = std::env::temp_dir().join(format!(
        "stenio-index-{}-{}-{stamp}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .map_err(fail)?;
    let base = base.canonicalize().map_err(fail)?;
    let root = base.join(top.strip_prefix("/").unwrap_or(&top));
    let snapshot = Snapshot { base, root, top };
    let (root, top) = (&snapshot.root, &snapshot.top);
    fs::create_dir_all(root).map_err(fail)?;
    output(
        git_command(top)
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .args(["checkout-index", "--all", "--force"])
            .arg(format!("--prefix={}/", root.display())),
        "checkout-index",
    )?;
    // Both honour the variables of the calling hook (`GIT_INDEX_FILE` of a partial commit).
    let index = top.join(git(top, &["rev-parse", "--git-path", "index"])?);
    let objects = top
        .join(git(top, &["rev-parse", "--git-path", "objects"])?)
        .canonicalize()
        .map_err(fail)?;
    let format = git(top, &["rev-parse", "--show-object-format"])?;
    let head = git(top, &["rev-parse", "--verify", "-q", "HEAD"]).ok();
    let mut init = Command::new("git");
    init.current_dir(root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(["init", "--quiet", "--template="])
        .arg(format!("--object-format={format}"));
    output(&mut init, "init")?;
    let own = root.join(".git");
    fs::write(own.join(MARKER), "").map_err(fail)?;
    fs::copy(index, own.join("index")).map_err(fail)?;
    fs::create_dir_all(own.join("objects/info")).map_err(fail)?;
    fs::write(
        own.join("objects/info/alternates"),
        format!("{}\n", objects.display()),
    )
    .map_err(fail)?;
    if let Some(head) = head {
        fs::write(own.join("HEAD"), format!("{head}\n")).map_err(fail)?;
    }
    Ok(snapshot)
}
