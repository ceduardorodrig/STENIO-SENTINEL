//! GB-324: a build older than the one production serves is neither advised nor deployed. The
//! remote tools are stand-ins on `PATH`, so nothing leaves this machine.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, UNIX_EPOCH};

type Fallible = Result<(), Box<dyn std::error::Error>>;

/// 2026-01-10 00:00:00 UTC.
const PRODUCTION: u64 = 1_768_003_200;
const DAY: u64 = 86_400;

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn set_time(file: &Path, secs: u64) -> std::io::Result<()> {
    fs::File::options()
        .write(true)
        .open(file)?
        .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
}

/// A frontend whose `dist` was built at `built`, and a production answering `headers`.
fn tree(label: &str, built: u64, headers: &str) -> std::io::Result<Tree> {
    let root = std::env::temp_dir().join(format!("stenio-deploy-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let fe = root.join("app/frontend-v2");
    fs::create_dir_all(fe.join("dist"))?;
    fs::create_dir_all(fe.join("src"))?;
    fs::create_dir_all(root.join("bin"))?;
    fs::write(fe.join("package.json"), "{}\n")?;
    fs::write(fe.join("src/app.ts"), "export const a = 1;\n")?;
    set_time(&fe.join("src/app.ts"), PRODUCTION - 30 * DAY)?;
    fs::write(
        fe.join("dist/index.html"),
        "<script src=\"/assets/index-LOCAL.js\"></script>\n",
    )?;
    set_time(&fe.join("dist/index.html"), built)?;
    let response =
        format!("HTTP/1.1 200 OK\n{headers}\n<script src=\"/assets/index-REMOTE.js\"></script>\n");
    fs::write(root.join("response"), response)?;
    let log = root.join("calls").display().to_string();
    let answer = root.join("response").display().to_string();
    for (name, body) in [
        ("xh", format!("cat '{answer}'")),
        ("npm", "true".to_string()),
        ("rsync", format!("echo rsync >>'{log}'")),
        ("ssh", format!("echo ssh >>'{log}'")),
    ] {
        let file = root.join("bin").join(name);
        fs::write(&file, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755))?;
    }
    Ok(Tree(root))
}

fn stenio(t: &Tree, args: &[&str]) -> std::io::Result<Output> {
    let path = std::env::var("PATH").unwrap_or_default();
    Command::new(env!("CARGO_BIN_EXE_stenio"))
        .args(args)
        .arg("--path")
        .arg(&t.0)
        .env("PATH", format!("{}:{path}", t.0.join("bin").display()))
        .current_dir(&t.0)
        .output()
}

const DATED: &str = "last-modified: Sat, 10 Jan 2026 00:00:00 GMT\n";

fn advice(t: &Tree) -> Result<String, Box<dyn std::error::Error>> {
    let out = stenio(t, &["--scope", "homelab", "--compact"])?;
    let text = String::from_utf8(out.stdout)?;
    Ok(text
        .lines()
        .find(|l| l.contains("[OPS-STATIC-PARITY]"))
        .ok_or_else(|| format!("no parity finding in:\n{text}"))?
        .to_string())
}

#[test]
fn a_build_older_than_production_is_not_advised_and_not_deployed() -> Fallible {
    for (label, built, headers) in [
        ("older", PRODUCTION - DAY, DATED),
        ("undated", PRODUCTION + DAY, ""),
    ] {
        let t = tree(label, built, headers)?;
        let line = advice(&t)?;
        assert!(!line.contains("stenio --deploy front"), "{line}");
        assert!(line.contains("Do not deploy"), "{line}");
        for target in ["front", "sync"] {
            let out = stenio(&t, &["--deploy", target])?;
            assert!(!out.status.success(), "{label} {target} deployed");
            assert!(String::from_utf8_lossy(&out.stderr).contains("Deploy refused"));
        }
        assert!(!t.0.join("calls").exists(), "{label}: something was synced");
    }
    Ok(())
}

#[test]
fn a_newer_fresh_build_keeps_the_suggestion_and_deploys() -> Fallible {
    let t = tree("newer", PRODUCTION + DAY, DATED)?;
    let line = advice(&t)?;
    assert!(line.contains("stenio --deploy front"), "{line}");
    let out = stenio(&t, &["--deploy", "sync"])?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(fs::read_to_string(t.0.join("calls"))?.contains("rsync"));
    Ok(())
}
