//! The command line, `--gate`, `--pre-commit check` and the MCP tools judge a tree alike, and
//! the configuration of that tree resolves the same way everywhere. `STENIO_TEST_BIN` points the
//! suite at another build.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

type Fallible = Result<(), Box<dyn std::error::Error>>;

const CUSTOM: &str = "[[custom_rules]]\nid = \"T-FORBIDDEN\"\nname = \"n\"\ndescription = \"d\"\npattern = \"forbidden_word\"\nextensions = [\"txt\"]\n";

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Tree {
    fn new(label: &str) -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("stenio-op-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        Ok(Self(root))
    }

    fn put(&self, name: &str, body: &str) -> std::io::Result<()> {
        let file = self.0.join(name);
        if let Some(dir) = file.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(file, body)
    }

    fn stage(&self) -> Fallible {
        for args in [&["init", "-q"][..], &["add", "-A"][..]] {
            let ok = Command::new("git")
                .current_dir(&self.0)
                .args(args)
                .status()?
                .success();
            assert!(ok, "git {args:?}");
        }
        Ok(())
    }
}

fn binary() -> String {
    std::env::var("STENIO_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_stenio").to_string())
}

fn run(root: &Path, args: &[&str]) -> Result<(i32, String), Box<dyn std::error::Error>> {
    let out = Command::new(binary())
        .current_dir(root)
        .args(args)
        .output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok((out.status.code().unwrap_or(-1), text))
}

fn mcp(root: &Path, tool: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut child = Command::new(binary())
        .current_dir(root)
        .args(["--mcp", "--path", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(
            stdin,
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"{tool}\",\"arguments\":{{}}}}}}"
        )?;
    }
    let out = child.wait_with_output()?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// One defect per audit family; the ids every entry point must report.
const FAMILIES: [(&str, &str, &str); 4] = [
    ("custom", "T-FORBIDDEN", "a.txt"),
    ("shell", "HOOK-STDIN-UNBOUNDED", "scripts/agent-hooks/h.sh"),
    ("i18n", "I18N-PO-INCOMPLETE", "app/locale/pt.po"),
    ("deps", "DEPENDABOT-LOCKFILE-COVERAGE", "Cargo.lock"),
];

fn family_tree(family: &str) -> Result<Tree, Box<dyn std::error::Error>> {
    let t = Tree::new(family)?;
    match family {
        "custom" => {
            t.put("steniocheck.toml", CUSTOM)?;
            t.put("a.txt", "forbidden_word\n")?;
        }
        "shell" => t.put(
            "scripts/agent-hooks/h.sh",
            "#!/bin/bash\nset -euo pipefail\ninput=$(cat)\necho \"$input\"\n",
        )?,
        "i18n" => t.put(
            "app/locale/pt.po",
            "msgid \"\"\nmsgstr \"\"\n\nmsgid \"Save\"\nmsgstr \"\"\n",
        )?,
        _ => {
            t.put(
                "Cargo.toml",
                "[package]\nname = \"p\"\nversion = \"0.1.0\"\n",
            )?;
            t.put("Cargo.lock", "version = 4\n")?;
            t.put(".github/dependabot.yml", "version: 2\nupdates: []\n")?;
        }
    }
    t.stage()?;
    Ok(t)
}

#[test]
fn every_entry_point_reports_the_same_defects() -> Fallible {
    let ids: Vec<&str> = FAMILIES.iter().map(|f| f.1).collect();
    let seen = |text: &str| -> BTreeSet<String> {
        ids.iter()
            .filter(|id| text.contains(&format!("[{id}]")))
            .map(|id| id.to_string())
            .collect()
    };
    for (family, id, _) in FAMILIES {
        let t = family_tree(family)?;
        let wanted: BTreeSet<String> = [id.to_string()].into();
        let (code, scan) = run(&t.0, &["--path", ".", "--strict", "--compact"])?;
        assert_eq!(seen(&scan), wanted, "{family} scan: {scan}");
        assert_eq!(code, 1, "{family} scan");
        let (code, hook) = run(&t.0, &["--path", ".", "--pre-commit", "check", "--compact"])?;
        assert_eq!(seen(&hook), wanted, "{family} pre-commit: {hook}");
        assert_eq!(code, 1, "{family} pre-commit");
        let (code, gate) = run(&t.0, &["--path", ".", "--gate"])?;
        assert_eq!(seen(&gate), wanted, "{family} gate: {gate}");
        assert_eq!(code, 1, "{family} gate");
        for tool in ["stenio_gate", "stenio_scan", "stenio_diff"] {
            let reply = mcp(&t.0, tool)?;
            assert_eq!(seen(&reply), wanted, "{family} {tool}: {reply}");
            assert!(
                reply.contains("\"isError\":true"),
                "{family} {tool}: {reply}"
            );
        }
    }
    Ok(())
}

#[test]
fn the_nearest_configuration_up_to_the_repository_root_applies() -> Fallible {
    let t = Tree::new("discovery")?;
    t.put("steniocheck.toml", CUSTOM)?;
    t.put("sub/a.txt", "forbidden_word\n")?;
    t.stage()?;
    for args in [
        &["--path", "sub"][..],
        &["--path", "sub/a.txt"][..],
        &["--path", "sub", "--config", "steniocheck.toml"][..],
    ] {
        let (code, text) = run(&t.0, &[args, &["--strict", "--compact"]].concat())?;
        assert!(
            code == 1 && text.contains("T-FORBIDDEN"),
            "{args:?}: {text}"
        );
    }
    let (_, text) = run(&t.0.join("sub"), &["--path", ".", "--strict", "--compact"])?;
    assert!(text.contains("T-FORBIDDEN"), "{text}");
    Ok(())
}

#[test]
fn keys_without_effect_are_named() -> Fallible {
    let t = Tree::new("keys")?;
    t.put(
        "steniocheck.toml",
        "[securty]\nx = 1\n[dry]\nenabled = false\n[general]\nscope = \"project\"\nname = \"n\"\n",
    )?;
    let (code, text) = run(&t.0, &["--path", ".", "--strict", "--compact"])?;
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("SCAN-CONFIG-UNKNOWN-KEY") && text.contains("`securty`"),
        "{text}"
    );
    assert!(
        text.contains("SCAN-CONFIG-UNUSED-KEY") && text.contains("`dry.enabled`"),
        "{text}"
    );
    let (code, shown) = run(&t.0, &["config", "show", "--path", "."])?;
    assert_eq!(code, 0, "{shown}");
    assert!(
        shown.contains("general.scope = \"project\"  [applied; ./steniocheck.toml:6]")
            && shown.contains("general.name = \"n\"  [not applied; ./steniocheck.toml:7]"),
        "{shown}"
    );
    assert!(shown.contains("securty.x = 1  [unknown;"), "{shown}");
    assert!(
        shown.contains("dry.enabled = false  [not applied;"),
        "{shown}"
    );
    let (code, text) = run(&t.0, &["config", "shwo"])?;
    assert_eq!(code, 2, "{text}");
    Ok(())
}

#[test]
fn exemptions_match_exact_paths() -> Fallible {
    let t = Tree::new("exempt")?;
    t.put("a.ts", "try { f() } catch (e) {}\n")?;
    let registry = ".steniocheck-whitelist-registry.json";
    let scan = || run(&t.0, &["--path", ".", "--strict", "--compact"]);
    for bad in ["{\"\": 1}", "[1]", "not json"] {
        t.put(registry, bad)?;
        let (code, text) = scan()?;
        assert_eq!(code, 2, "{bad}: {text}");
    }
    t.put(registry, "{\"a\": 1, \"gone.py\": 1}")?;
    let (_, text) = scan()?;
    assert!(text.contains("CODE-NO-EMPTY-CATCH"), "{text}");
    assert!(
        text.contains("SCAN-EXEMPTION-STALE") && text.contains("gone.py"),
        "{text}"
    );
    t.put(registry, "{\"a.ts\": 1}")?;
    let (_, text) = scan()?;
    assert!(!text.contains("CODE-NO-EMPTY-CATCH"), "{text}");
    Ok(())
}
