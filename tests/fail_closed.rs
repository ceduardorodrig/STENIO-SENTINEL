//! Every case here passed (exit 0 or a silent PASS) before the engine failed closed: a run that
//! did not look must never be green. `STENIO_TEST_BIN` points the suite at another build.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

type Fallible = Result<(), Box<dyn std::error::Error>>;

const DIRTY: &str = concat!("fn f(x: Option<u8>) { x.", "unwrap(); }\n");
const KEY: &str = concat!("let k = \"AK", "IAABCDEFGHIJKLMNOP12\";\n");
const CUSTOM: &str = "[[custom_rules]]\nid = \"T-FORBIDDEN\"\nname = \"n\"\ndescription = \"d\"\npattern = \"forbidden_word\"\nextensions = [\"txt\"]\n";

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Tree {
    fn new(label: &str) -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("stenio-fc-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        Ok(Self(root))
    }

    fn put(&self, name: &str, body: impl AsRef<[u8]>) -> std::io::Result<PathBuf> {
        let file = self.0.join(name);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&file, body)?;
        Ok(file)
    }

    fn git(&self, args: &[&str]) -> Fallible {
        let status = Command::new("git")
            .current_dir(&self.0)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .output()?
            .status;
        assert!(status.success(), "git {args:?}");
        Ok(())
    }
}

fn run(root: &Path, args: &[&str]) -> Result<(i32, String), Box<dyn std::error::Error>> {
    let bin = std::env::var("STENIO_TEST_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_stenio").to_string());
    let out = Command::new(bin).current_dir(root).args(args).output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), text))
}

fn scan(root: &Path, extra: &[&str]) -> Result<(i32, String), Box<dyn std::error::Error>> {
    let mut args = vec!["--path", ".", "--scope", "project", "--strict", "--compact"];
    args.extend_from_slice(extra);
    run(root, &args)
}

fn assert_found(result: (i32, String), rule: &str) {
    let (code, text) = result;
    assert!(
        code == 1 && text.contains(rule),
        "exit {code}, wanted {rule}: {text}"
    );
}

#[test]
fn a_broken_or_missing_configuration_is_a_usage_error() -> Fallible {
    for (label, body) in [
        ("syntax", format!("{CUSTOM}oops = =\n")),
        ("type", "[general]\nscope = 42\n".to_string()),
        ("pattern", CUSTOM.replace("forbidden_word", "(")),
        ("severity", format!("{CUSTOM}severity = \"eror\"\n")),
    ] {
        let t = Tree::new(label)?;
        t.put("steniocheck.toml", body)?;
        t.put("a.txt", "forbidden_word\n")?;
        for args in [&[][..], &["--gate"][..]] {
            let (code, text) = run(&t.0, &[&["--path", "."], args].concat())?;
            assert_eq!(code, 2, "{label} {args:?}: {text}");
            assert!(text.contains("steniocheck.toml"), "{text}");
        }
        let (code, text) = run(&t.0, &["--scope", "frappe", "--path", "."])?;
        assert_eq!(code, 2, "{label} frappe: {text}");
    }
    let t = Tree::new("missing")?;
    t.put("a.txt", "x\n")?;
    for args in [
        &["--path", ".", "--config", "nope.toml"][..],
        &["--scope", "frappe", "--path", ".", "--config", "nope.toml"][..],
        &[
            "pre-release",
            "--repo",
            ".",
            "--tag",
            "v1.0.0",
            "--config",
            "nope.toml",
            "--static-only",
        ][..],
        &["verify-host", "--host", "h", "--config", "nope.toml"][..],
        &[
            "verify-release",
            "--host",
            "h",
            "--tag",
            "1",
            "--repo",
            ".",
            "--config",
            "nope.toml",
        ][..],
    ] {
        let (code, text) = run(&t.0, args)?;
        assert_eq!(code, 2, "{args:?}: {text}");
        assert!(text.contains("nope.toml"), "{args:?}: {text}");
    }
    Ok(())
}

#[test]
fn a_broken_configuration_below_or_above_the_target_is_reported() -> Fallible {
    let t = Tree::new("nested")?;
    t.put("sub/steniocheck.toml", "oops = =\n")?;
    assert_found(scan(&t.0, &[])?, "SCAN-CONFIG-INVALID");
    t.git(&["init", "-q"])?;
    t.put("steniocheck.toml", "oops = =\n")?;
    t.put("deep/a.txt", "x\n")?;
    let (code, text) = run(&t.0.join("deep"), &["--path", ".", "--strict"])?;
    assert_eq!(code, 2, "{text}");
    Ok(())
}

#[test]
fn config_names_the_file_of_a_normal_scan() -> Fallible {
    let t = Tree::new("explicit")?;
    t.put("a.txt", "forbidden_word\n")?;
    t.put("other.toml", CUSTOM)?;
    assert_found(scan(&t.0, &["--config", "other.toml"])?, "T-FORBIDDEN");
    Ok(())
}

#[test]
fn learn_cannot_corrupt_the_configuration() -> Fallible {
    let t = Tree::new("learn")?;
    t.put("steniocheck.toml", CUSTOM)?;
    t.put("a.txt", "forbidden_word\nsecond \"quoted\" word\n")?;
    let payload = r#"{"id":"T-SECOND","tag":"a\"b","name":"line\nbreak \\ \"q\"","description":"d\ne","pattern":"\"quoted\"","extensions":["txt"],"suggestion":"s\"\n"}"#;
    let (code, text) = run(&t.0, &["--path", ".", "--learn", payload])?;
    assert_eq!(code, 0, "{text}");
    let found = scan(&t.0, &[])?;
    assert!(
        found.1.contains("T-FORBIDDEN") && found.1.contains("T-SECOND"),
        "{found:?}"
    );

    let broken = t.put("steniocheck.toml", "oops = =\n")?;
    let (code, text) = run(&t.0, &["--path", ".", "--learn", r#"{"pattern":"x"}"#])?;
    assert_ne!(code, 0, "{text}");
    assert_eq!(fs::read_to_string(broken)?, "oops = =\n");
    Ok(())
}

fn repository(label: &str) -> Result<Tree, Box<dyn std::error::Error>> {
    let t = Tree::new(label)?;
    t.git(&["init", "-q"])?;
    t.put("a.rs", "fn a() {}\n")?;
    t.put("sub/b.rs", "fn b() {}\n")?;
    t.git(&["add", "-A"])?;
    t.git(&["commit", "-qm", "one"])?;
    Ok(t)
}

#[test]
fn changed_files_are_listed_whatever_their_state_or_name() -> Fallible {
    let t = repository("states")?;
    t.put("a.rs", DIRTY)?;
    for mode in [&["--fast"][..], &["--diff"][..], &["--diff", "HEAD"][..]] {
        assert_found(scan(&t.0, mode)?, "RUST-NO-UNWRAP");
    }
    t.git(&["checkout", "-q", "a.rs"])?;
    t.put("new/c.rs", DIRTY)?;
    for mode in [&["--fast"][..], &["--diff"][..], &["--diff", "HEAD"][..]] {
        assert_found(scan(&t.0, mode)?, "new/c.rs");
    }
    fs::remove_dir_all(t.0.join("new"))?;
    t.put("sub/ação.rs", DIRTY)?;
    t.git(&["add", "-A"])?;
    assert_found(scan(&t.0, &["--diff", "staged"])?, "RUST-NO-UNWRAP");
    let sub = t.0.join("sub");
    for mode in [&["--diff", "staged"][..], &["--fast"][..]] {
        let args = [
            &["--path", ".", "--scope", "project", "--strict", "--compact"],
            mode,
        ]
        .concat();
        assert_found(run(&sub, &args)?, "RUST-NO-UNWRAP");
    }
    Ok(())
}

#[test]
fn a_git_failure_is_an_error_not_an_empty_change_set() -> Fallible {
    let t = repository("failures")?;
    let (code, text) = scan(&t.0, &["--diff", "no-such-rev"])?;
    assert_eq!(code, 2, "{text}");
    let plain = Tree::new("plain")?;
    plain.put("a.rs", DIRTY)?;
    for mode in ["--diff", "--fast", "--history"] {
        let (code, text) = scan(&plain.0, &[mode])?;
        assert_eq!(code, 2, "{mode}: {text}");
    }
    Ok(())
}

#[test]
fn nothing_exempts_a_file_by_name_or_content() -> Fallible {
    let t = Tree::new("exempt")?;
    t.put("a.rs", format!("// fn run_self_tests\n{KEY}"))?;
    t.put("rule.rs", DIRTY)?;
    t.put("explain.rs", DIRTY)?;
    t.put("frontend.rs", KEY)?;
    t.put("fixtures/k.rs", KEY)?;
    t.put("archive/k.rs", KEY)?;
    let (code, text) = scan(&t.0, &[])?;
    assert_eq!(code, 1, "{text}");
    for name in [
        "a.rs",
        "rule.rs",
        "explain.rs",
        "frontend.rs",
        "fixtures/k.rs",
        "archive/k.rs",
    ] {
        assert!(text.contains(name), "{name} not judged: {text}");
    }
    Ok(())
}

#[test]
fn cfg_test_covers_only_its_item() -> Fallible {
    let t = Tree::new("cfgtest")?;
    t.put(
        "use.rs",
        format!("#[cfg(test)]\nuse std::{{fs, io}};\n{DIRTY}"),
    )?;
    t.put(
        "module.rs",
        format!("#[cfg(test)]\nmod tests {{\n    {DIRTY}}}\n{DIRTY}"),
    )?;
    t.put("clean.rs", format!("#[cfg(test)]\n#[allow(unused)]\nmod tests {{\n    {DIRTY}    #[tokio::test]\n    async fn t() {{ }}\n}}\n"))?;
    t.put(
        "one.rs",
        format!("#[test]\nfn t() {{\n    let _ = \"}}\";\n    {DIRTY}}}\n"),
    )?;
    let (code, text) = scan(&t.0, &["--only", "RUST-NO-UNWRAP"])?;
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("use.rs:3:") && text.contains("module.rs:5:"),
        "{text}"
    );
    assert!(
        !text.contains("module.rs:3:") && !text.contains("clean.rs") && !text.contains("one.rs"),
        "{text}"
    );
    Ok(())
}

#[test]
fn unknown_selectors_are_refused_and_known_ones_filter() -> Fallible {
    let t = Tree::new("selectors")?;
    t.put("a.rs", format!("{DIRTY}{KEY}"))?;
    for args in [
        &["--only", "RUST-NO-UNWRP"][..],
        &["--tag", "secx"][..],
        &["--only", "FRAPPE-LINK-TITLE"][..],
    ] {
        let (code, text) = scan(&t.0, args)?;
        assert_eq!(code, 2, "{args:?}: {text}");
    }
    let (code, text) = run(&t.0, &["--path", ".", "--scope", "homelabb"])?;
    assert_eq!(code, 2, "{text}");
    let home = Tree::new("homelab")?;
    home.put("mnemocine/compose.yaml", "services:\n  a:\n    image: x\n")?;
    for filter in [["--only", "SEC-SUDO"], ["--tag", "sec"]] {
        let args = [
            &["--path", ".", "--scope", "homelab", "--compact"],
            &filter[..],
        ]
        .concat();
        let (_, text) = run(&home.0, &args)?;
        assert!(!text.contains("[INFRA-"), "{filter:?}: {text}");
    }
    Ok(())
}

#[test]
fn a_file_that_cannot_be_read_is_reported_not_counted() -> Fallible {
    let t = Tree::new("unreadable")?;
    let mut bytes = DIRTY.as_bytes().to_vec();
    bytes.push(0xFF);
    t.put("a.rs", bytes)?;
    t.put("image.png", [0xFFu8, 0xD8, 0x00])?;
    let (code, text) = scan(&t.0, &[])?;
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("SCAN-FILE-UNREADABLE") && text.contains("skipped=1"),
        "{text}"
    );
    assert!(text.contains("files=1 "), "{text}");
    Ok(())
}

#[test]
fn fix_reports_only_what_reached_the_disk() -> Fallible {
    let t = Tree::new("fix")?;
    t.put(
        "steniocheck.toml",
        format!("{CUSTOM}fix_replacement = \"fine\"\n"),
    )?;
    let file = t.put("a.txt", "forbidden_word\n")?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o444))?;
    let (code, text) = run(&t.0, &["--path", ".", "--scope", "project", "--fix"])?;
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("SCAN-FIX-NOT-WRITTEN"), "{text}");
    assert!(!text.contains("automatically repaired"), "{text}");
    Ok(())
}

#[test]
fn the_pre_commit_check_blocks_on_an_error() -> Fallible {
    let t = repository("precommit")?;
    t.put("a.rs", DIRTY)?;
    t.git(&["add", "-A"])?;
    let (code, text) = run(
        &t.0,
        &["--path", ".", "--scope", "project", "--pre-commit", "check"],
    )?;
    assert_eq!(code, 1, "{text}");
    Ok(())
}
