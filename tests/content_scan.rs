//! What is judged: dot files Git does not ignore, the staged content of `--diff staged`, and a
//! duplication report that does not change between runs. `STENIO_TEST_BIN` points the suite at
//! another build.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type Fallible<T = ()> = Result<T, Box<dyn std::error::Error>>;

const DIRTY: &str = concat!("fn f(x: Option<u8>) { x.", "unwrap(); }\n");
const CLEAN: &str = "fn f() {}\n";
const KEY: &str = concat!("AK", "IAABCDEFGHIJKLMNOP");
const PASSWORD: &str = "q7Rk2mZp9Xw4";

fn binary() -> String {
    std::env::var("STENIO_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_stenio").to_string())
}

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Tree {
    fn new(label: &str) -> Fallible<Self> {
        let root = std::env::temp_dir().join(format!("stenio-cs-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        Ok(Self(root))
    }

    fn repo(label: &str) -> Fallible<Self> {
        let tree = Self::new(label)?;
        tree.git(&["init"])?;
        Ok(tree)
    }

    fn put(&self, name: &str, body: &str) -> Fallible {
        let file = self.0.join(name);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(file, body)?;
        Ok(())
    }

    fn git(&self, args: &[&str]) -> Fallible {
        let out = Command::new("git")
            .current_dir(&self.0)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()?;
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Fallible<(i32, String)> {
        let mut command = Command::new(binary());
        command.current_dir(&self.0).args(args);
        for (name, value) in env {
            command.env(name, value);
        }
        let out = command.output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok((out.status.code().unwrap_or(-1), text))
    }

    fn scan(&self, extra: &[&str]) -> Fallible<(i32, String)> {
        let mut args = vec!["--path", ".", "--scope", "project", "--strict", "--compact"];
        args.extend_from_slice(extra);
        self.run(&args, &[])
    }
}

fn assert_found(result: &(i32, String), rule: &str, file: &str) {
    let (code, text) = result;
    assert!(
        *code == 1 && text.contains(rule) && text.contains(file),
        "exit {code}, wanted {rule} in {file}: {text}"
    );
}

fn assert_pass(result: &(i32, String)) {
    assert!(result.0 == 0, "wanted a pass: {result:?}");
}

#[test]
fn a_dot_file_that_git_does_not_ignore_is_judged_for_credentials() -> Fallible {
    // Outside Git, untracked, tracked, and tracked although a later rule ignores it.
    for (label, git, ignored) in [
        ("plain", false, false),
        ("untracked", true, false),
        ("tracked", true, false),
        ("forced", true, true),
    ] {
        let tree = Tree::new(label)?;
        if git {
            tree.git(&["init"])?;
        }
        tree.put(".env", &format!("CLOUD_ID={KEY}\nDB_PASSWORD={PASSWORD}\n"))?;
        if ignored {
            tree.put(".gitignore", ".env\n")?;
            tree.git(&["add", "-f", ".env"])?;
        } else if label == "tracked" {
            tree.git(&["add", ".env"])?;
        }
        for extra in [&[][..], &["--json"][..]] {
            let found = tree.scan(extra)?;
            assert_found(&found, "SEC-SECRETS", ".env");
            assert_found(&found, "SEC-PLAINTEXT-SECRET", ".env");
            assert!(
                !found.1.contains(KEY) && !found.1.contains(PASSWORD),
                "{label}: a value was printed"
            );
        }
    }
    Ok(())
}

#[test]
fn a_dot_folder_is_judged_for_credentials_only() -> Fallible {
    let tree = Tree::repo("folder")?;
    tree.put(".tool/credentials", &format!("id = {KEY}\n"))?;
    tree.put(".tool/helper.rs", DIRTY)?;
    let found = tree.scan(&[])?;
    assert_found(&found, "SEC-SECRETS", ".tool/credentials");
    assert!(!found.1.contains("RUST-NO-UNWRAP"), "{}", found.1);
    Ok(())
}

#[test]
fn an_ignored_dot_file_and_an_example_file_pass() -> Fallible {
    let tree = Tree::repo("ignored")?;
    tree.put(".gitignore", ".env\n.cache/\n")?;
    tree.put(".env", &format!("CLOUD_ID={KEY}\n"))?;
    tree.put(".cache/token", &format!("{KEY}\n"))?;
    tree.put(".env.example", "DB_PASSWORD=changeme-please\n")?;
    assert_pass(&tree.scan(&[])?);
    Ok(())
}

/// A repository with one commit and `staged` added to the index.
fn staged_tree(label: &str, name: &str, staged: &str) -> Fallible<Tree> {
    let tree = Tree::repo(label)?;
    tree.put("base.txt", "base\n")?;
    tree.git(&["add", "-A"])?;
    tree.git(&["commit", "-m", "base"])?;
    tree.put(name, staged)?;
    tree.git(&["add", "-f", name])?;
    Ok(tree)
}

#[test]
fn a_staged_defect_removed_only_from_the_working_copy_is_reported() -> Fallible {
    let tree = staged_tree("cleaned", "src/a.rs", DIRTY)?;
    tree.put("src/a.rs", CLEAN)?;
    let index = fs::read(tree.0.join(".git/index"))?;
    assert_found(
        &tree.scan(&["--diff", "staged"])?,
        "RUST-NO-UNWRAP",
        "src/a.rs",
    );
    assert_found(
        &tree.run(
            &["--pre-commit", "check", "--scope", "project", "--compact"],
            &[],
        )?,
        "RUST-NO-UNWRAP",
        "src/a.rs",
    );
    assert!(
        index == fs::read(tree.0.join(".git/index"))?,
        "index changed"
    );
    fs::remove_file(tree.0.join("src/a.rs"))?;
    assert_found(
        &tree.scan(&["--diff", "staged"])?,
        "RUST-NO-UNWRAP",
        "src/a.rs",
    );
    Ok(())
}

#[test]
fn an_unstaged_defect_does_not_block_a_clean_staged_change() -> Fallible {
    let tree = staged_tree("dirty-copy", "src/a.rs", CLEAN)?;
    tree.put("src/a.rs", DIRTY)?;
    tree.put("deploy.sh", "#!/bin/sh\necho untracked\n")?;
    assert_pass(&tree.scan(&["--diff", "staged"])?);
    Ok(())
}

#[test]
fn a_staged_secret_is_reported_through_a_hook_with_its_own_index() -> Fallible {
    let tree = staged_tree("secret", ".env", &format!("CLOUD_ID={KEY}\n"))?;
    tree.put(".env", "CLOUD_ID=\n")?;
    let found = tree.scan(&["--diff", "staged"])?;
    assert_found(&found, "SEC-SECRETS", ".env");
    assert!(
        !found.1.contains(KEY) && !found.1.contains("stenio-index-"),
        "{}",
        found.1
    );
    // `git commit <paths>` hands the hook a temporary index.
    let other = tree.0.join(".git/hook-index");
    fs::copy(tree.0.join(".git/index"), &other)?;
    tree.git(&["reset", "-q"])?;
    let found = tree.run(
        &[
            "--diff",
            "staged",
            "--scope",
            "project",
            "--strict",
            "--compact",
        ],
        &[("GIT_INDEX_FILE", other.as_path())],
    )?;
    assert_found(&found, "SEC-SECRETS", ".env");
    Ok(())
}

#[test]
fn a_fix_of_staged_content_that_differs_from_the_copy_is_refused() -> Fallible {
    let tree = staged_tree("fix", "src/a.rs", DIRTY)?;
    tree.put("src/a.rs", CLEAN)?;
    let (code, text) = tree.scan(&["--diff", "staged", "--fix"])?;
    assert!(code == 2, "exit {code}: {text}");
    assert_eq!(fs::read_to_string(tree.0.join("src/a.rs"))?, CLEAN);
    Ok(())
}

#[test]
fn the_duplication_report_is_identical_for_twenty_runs() -> Fallible {
    let tree = Tree::new("dry")?;
    // Overlapping blocks: which pair is seen first decides what is already covered.
    let line = |n: usize| format!("let value_{n} = compute_{n}(input, {n});\n");
    let block = |from: usize, to: usize| (from..to).map(line).collect::<String>();
    for (file, from, to) in [
        ("a", 0, 20),
        ("b", 0, 12),
        ("c", 4, 16),
        ("d", 8, 20),
        ("e", 2, 11),
        ("f", 6, 18),
        ("g", 0, 20),
    ] {
        tree.put(
            &format!("{file}.ts"),
            &format!("function {file}() {{\n{}}}\n", block(from, to)),
        )?;
    }
    let report = || -> Fallible<String> {
        let (_, text) = tree.run(&["--path", ".", "--dry"], &[])?;
        Ok(text
            .lines()
            .filter(|l| !l.contains("Duration"))
            .collect::<Vec<_>>()
            .join("\n"))
    };
    let first = report()?;
    assert!(first.contains("duplicated"), "{first}");
    for run in 1..20 {
        assert_eq!(first, report()?, "run {run} differs");
    }
    Ok(())
}

#[test]
fn a_visible_dotenv_file_is_judged_by_the_key_name_rule() -> Fallible {
    // GB-401: `prod.env` is as published as `.env`.
    let tree = Tree::repo("visible")?;
    tree.put("deploy/prod.env", &format!("DB_PASSWORD={PASSWORD}\n"))?;
    let found = tree.scan(&[])?;
    assert_found(&found, "SEC-PLAINTEXT-SECRET", "prod.env");
    assert!(!found.1.contains(PASSWORD), "a value was printed");
    tree.put("deploy/prod.env", "DB_PASSWORD=changeme\n")?;
    tree.put(
        "deploy/prod.env.example",
        &format!("DB_PASSWORD={PASSWORD}\n"),
    )?;
    assert_pass(&tree.scan(&[])?);
    Ok(())
}
