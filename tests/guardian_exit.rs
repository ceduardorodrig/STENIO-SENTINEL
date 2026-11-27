//! GB-035: `--guardian` has to fail the step that runs it. It printed a tamper alert and exited 0,
//! so neither CI nor `release-engine` could ever go red on it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A copy of the engine's own `src/` directory.
fn copy_of_sources(label: &str) -> std::io::Result<Tree> {
    let tree =
        Tree(std::env::temp_dir().join(format!("stenio-guardian-{}-{label}", std::process::id())));
    let _ = fs::remove_dir_all(&tree.0);
    let to = tree.0.join("src");
    fs::create_dir_all(&to)?;
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &to)?;
    Ok(tree)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn guardian(tree: &Tree, strict: bool) -> Option<(i32, String)> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stenio"));
    cmd.arg("--guardian").arg("--path").arg(&tree.0);
    if strict {
        cmd.arg("--strict");
    }
    let out = cmd.env_remove("STENIO_HUMAN_AUTHORIZATION").output().ok()?;
    Some((
        out.status.code()?,
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

#[test]
fn an_intact_tree_exits_zero() -> std::io::Result<()> {
    let tree = copy_of_sources("intact")?;
    let run = guardian(&tree, false);
    assert!(matches!(run, Some((0, _))), "{run:?}");
    Ok(())
}

#[test]
fn a_removed_anchor_exits_one_with_and_without_strict() -> std::io::Result<()> {
    let tree = copy_of_sources("anchor")?;
    let module = tree.0.join("src/ci.rs");
    let text = fs::read_to_string(&module)?.replace("load_branch_filters", "renamed");
    fs::write(&module, text)?;
    for strict in [false, true] {
        let run = guardian(&tree, strict);
        assert!(
            matches!(&run, Some((1, out)) if out.contains("TAMPER ALERT [ci.rs]")),
            "strict={strict}: {run:?}"
        );
    }
    Ok(())
}

#[test]
fn a_deleted_module_exits_one() -> std::io::Result<()> {
    let tree = copy_of_sources("module")?;
    fs::remove_file(tree.0.join("src/comments.rs"))?;
    let run = guardian(&tree, false);
    assert!(matches!(run, Some((1, _))), "{run:?}");
    Ok(())
}
