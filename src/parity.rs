//! Two "is what runs what we built?" subcommands.
//!
//! `stenio binary-parity --installed <bin> [--built <bin>]` (GB-067): on 2026-11-05 an installed
//! binary reported 4.20.0 while `opportunity add` did not exist in it. The version string proves
//! nothing, so every subcommand of [`SUBCOMMANDS`] is asked for `--help` and the bytes are
//! compared with the built binary. `release-engine` runs it after the install.
//!
//! `stenio drift --repo <dir> --deployed <dir>` (GB-295): provisioning scripts and their deployed
//! copies compared ignoring comments and blank lines, so only behaviour differences are listed.

use clap::Parser;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The command surface of this engine: the arguments, and a text the help must carry.
const SUBCOMMANDS: [&str; 10] = [
    "backlog",
    "preflight",
    "pre-release",
    "release-engine",
    "verify-release",
    "verify-host",
    "frappe-drift",
    "compare-engines",
    "sweep",
    "opportunity add",
];

#[derive(Parser)]
#[command(name = "stenio binary-parity")]
struct BinArgs {
    /// The binary in use
    #[arg(long)]
    installed: PathBuf,
    /// The binary built from the tag (default: this one)
    #[arg(long)]
    built: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = "stenio drift")]
struct DriftArgs {
    /// Directory of the versioned scripts
    #[arg(long)]
    repo: PathBuf,
    /// Directory of the deployed copies (e.g. /usr/local/bin)
    #[arg(long)]
    deployed: PathBuf,
}

/// Whether the help of `sub` is its own: an unknown word makes the main parser answer instead.
/// The subcommand parsers exit 2 after `--help`, so the usage line decides, not the status
/// (`backlog` is rewritten to a flag of the main parser, so there the status is all there is).
fn usage_answers(sub: &str, status_ok: bool, text: &str) -> bool {
    let name = if sub == "preflight" {
        "pre-release"
    } else {
        sub
    };
    match sub {
        "backlog" => status_ok,
        _ => text
            .lines()
            .any(|l| l.starts_with("Usage:") && l.contains(name)),
    }
}

fn advertises(bin: &Path, sub: &str) -> bool {
    Command::new(bin)
        .args(sub.split_whitespace())
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| {
            let mut text = String::from_utf8_lossy(&o.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            usage_answers(sub, o.status.success(), &text)
        })
}

/// Findings of an installed binary against the built one, given a probe of one subcommand.
fn binary_findings(has: impl Fn(&str) -> bool, same_bytes: bool) -> Vec<String> {
    let mut out: Vec<String> = SUBCOMMANDS
        .iter()
        .filter(|s| !has(s))
        .map(|s| format!("installed binary has no subcommand '{s}'"))
        .collect();
    if !same_bytes {
        out.push("installed binary differs from the built binary (content)".to_string());
    }
    out
}

pub fn run_binary_parity(argv: &[String]) -> i32 {
    let a = match BinArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let Some(built) = a.built.or_else(|| std::env::current_exe().ok()) else {
        eprintln!("cannot find the built binary: pass --built");
        return 2;
    };
    let (Ok(x), Ok(y)) = (fs::read(&built), fs::read(&a.installed)) else {
        eprintln!(
            "cannot read {} or {}",
            built.display(),
            a.installed.display()
        );
        return 2;
    };
    let found = binary_findings(|s| advertises(&a.installed, s), x == y);
    for f in &found {
        println!("FAIL {f}");
    }
    println!("binary-parity: {} finding(s)", found.len());
    i32::from(!found.is_empty())
}

/// A line without its trailing `# comment` (a `#` after whitespace, outside quotes).
fn code_of(line: &str) -> &str {
    let (mut quote, mut previous) = (None, ' ');
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) if c == q && previous != '\\' => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' && previous.is_whitespace() => return line[..i].trim_end(),
            None => {}
        }
        previous = c;
    }
    line.trim_end()
}

/// The behaviour of a script: its non-comment, non-blank lines (the shebang stays).
fn behaviour(text: &str) -> Vec<&str> {
    text.lines()
        .enumerate()
        .map(|(i, l)| if i == 0 { l } else { code_of(l) })
        .map(str::trim)
        .filter(|l| !l.is_empty() && (l.starts_with("#!") || !l.starts_with('#')))
        .collect()
}

/// Lines present on one side only; `None` when both behave the same.
fn script_drift(repo: &[u8], deployed: &[u8]) -> Option<Vec<String>> {
    let (Ok(r), Ok(d)) = (std::str::from_utf8(repo), std::str::from_utf8(deployed)) else {
        return (repo != deployed).then(|| vec!["binary content differs".to_string()]);
    };
    let (r, d) = (behaviour(r), behaviour(d));
    if r == d {
        return None;
    }
    let (rs, ds): (BTreeSet<&str>, BTreeSet<&str>) =
        (r.iter().copied().collect(), d.iter().copied().collect());
    let mut out: Vec<String> = r
        .iter()
        .filter(|l| !ds.contains(*l))
        .map(|l| format!("repo only: {l}"))
        .chain(
            d.iter()
                .filter(|l| !rs.contains(*l))
                .map(|l| format!("host only: {l}")),
        )
        .collect();
    if out.is_empty() {
        out.push("same lines, different order or count".to_string());
    }
    Some(out)
}

pub fn run_drift(argv: &[String]) -> i32 {
    let a = match DriftArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let Ok(entries) = fs::read_dir(&a.repo) else {
        eprintln!("cannot read {}", a.repo.display());
        return 2;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let (mut compared, mut drifted, mut absent) = (0, 0, Vec::new());
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let other = a.deployed.join(&name);
        if !other.exists() {
            absent.push(name);
            continue;
        }
        let (Ok(r), Ok(d)) = (fs::read(&path), fs::read(&other)) else {
            println!("UNREAD {name}");
            drifted += 1;
            continue;
        };
        compared += 1;
        if let Some(lines) = script_drift(&r, &d) {
            drifted += 1;
            println!("DRIFT {name} ({} line(s))", lines.len());
            for l in lines.iter().take(20) {
                println!("  {}", l.chars().take(160).collect::<String>());
            }
        }
    }
    if !absent.is_empty() {
        println!("NOT DEPLOYED {}: {}", absent.len(), absent.join(" "));
    }
    println!("drift: {compared} compared, {drifted} with behaviour drift");
    // Nothing compared proves nothing.
    i32::from(drifted > 0 || compared == 0)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let repo = b"#!/bin/sh\n# english\nrestic backup /a  # note\necho \"# kept\"\n";
    let comments = b"#!/bin/sh\n# portugues\n\nrestic backup /a\necho \"# kept\"\n";
    let extra = b"#!/bin/sh\nrestic backup /a /host-only\necho \"# kept\"\n";
    let canary = binary_findings(|s| s != "opportunity add", true);
    vec![
        (
            "drift: comments and blank lines are not drift".to_string(),
            script_drift(repo, comments).is_none(),
        ),
        (
            "drift: a host-only path is reported".to_string(),
            script_drift(repo, extra).is_some_and(|d| {
                d.iter()
                    .any(|l| l.starts_with("host only") && l.contains("/host-only"))
            }),
        ),
        (
            "binary parity: the missing subcommand is named".to_string(),
            canary.len() == 1 && canary[0].contains("'opportunity add'"),
        ),
        (
            "binary parity: the usage line decides, not the exit status".to_string(),
            usage_answers("verify-host", false, "x\nUsage: verify-host [OPTIONS]")
                && usage_answers("preflight", false, "Usage: pre-release [OPTIONS]")
                && !usage_answers("verify-host", true, "Usage: stenio [OPTIONS]"),
        ),
        (
            "binary parity: same surface passes, other bytes fail".to_string(),
            binary_findings(|_| true, true).is_empty()
                && binary_findings(|_| true, false).len() == 1,
        ),
    ]
}
