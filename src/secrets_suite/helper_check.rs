//! `stenio secrets-helper-check` (GB-164): a secrets helper that fails silently boots its consumer
//! with no credential. Runs the helper, counts the keys it yields, compares with a floor and with the
//! last known count, and optionally checks an encrypted copy kept outside the synced vault. The
//! helper's output and error text are never printed.

use super::store::{load, parse};
use clap::Parser;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(about = "Fail loudly when a secrets helper yields no or fewer credentials")]
struct Args {
    #[arg(long, default_value_t = 1, help = "Minimum number of keys expected")]
    min: usize,
    #[arg(long, help = "File holding the last known count (created when absent)")]
    state: Option<PathBuf>,
    #[arg(
        long,
        requires = "state",
        help = "Accept a lower count as the new baseline"
    )]
    accept: bool,
    #[arg(
        long,
        help = "Encrypted copy of the store kept outside the synced vault"
    )]
    copy: Option<PathBuf>,
    #[arg(
        long,
        requires = "copy",
        help = "Vault root the copy must not live under"
    )]
    vault: Option<PathBuf>,
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,
    #[arg(
        last = true,
        required = true,
        help = "Helper program and arguments (after --)"
    )]
    helper: Vec<String>,
}

/// Number of non-empty keys printed by the helper, or why it produced none.
fn resolve(helper: &[String], timeout: Duration) -> (usize, Option<String>) {
    let Some((program, rest)) = helper.split_first() else {
        return (0, Some("no helper command".to_string()));
    };
    let mut child = match Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (0, Some(format!("cannot start ({})", e.kind()))),
    };
    let Some(mut stdout) = child.stdout.take() else {
        return (0, Some("no stdout".to_string()));
    };
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut buf = String::new();
        let read = stdout.read_to_string(&mut buf).map(|_| buf);
        let _ = tx.send(read);
    });
    let output = rx.recv_timeout(timeout);
    if output.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return (0, Some(format!("timed out after {timeout:?}")));
    }
    let status = child.wait();
    let ok = status.as_ref().is_ok_and(|s| s.success());
    match output {
        Ok(Ok(text)) if ok => {
            let n = parse(&text)
                .entries
                .values()
                .filter(|v| !v.is_empty())
                .count();
            (n, None)
        }
        _ => (
            0,
            Some(status.map_or_else(|_| "wait failed".to_string(), |s| s.to_string())),
        ),
    }
}

fn copy_problem(copy: &Path, vault: Option<&Path>, resolved: usize) -> Option<String> {
    if let Some(v) = vault
        && let (Ok(c), Ok(v)) = (copy.canonicalize(), v.canonicalize())
        && c.starts_with(v)
    {
        return Some("the copy lives inside the synced vault".to_string());
    }
    match load(copy, false) {
        Err(e) => Some(e),
        Ok(s) if !s.encrypted => Some("the copy is not encrypted".to_string()),
        Ok(s) if s.entries.len() < resolved => Some(format!(
            "the copy holds {} keys, the helper resolves {resolved}",
            s.entries.len()
        )),
        Ok(_) => None,
    }
}

fn check(args: &Args) -> Vec<String> {
    let (n, error) = resolve(&args.helper, Duration::from_millis(args.timeout_ms));
    let helper = args.helper.first().map(String::as_str).unwrap_or("");
    let last: Option<usize> = args
        .state
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse().ok());
    let floor = if args.accept {
        args.min
    } else {
        args.min.max(last.unwrap_or(0))
    };
    let mut out = Vec::new();
    if n == 0 || n < floor {
        let why = error.map(|e| format!(", {e}")).unwrap_or_default();
        out.push(format!(
            "WARN secrets helper `{helper}` resolved {n} secrets, expected at least {}{why}",
            floor.max(1)
        ));
    } else if let Some(state) = &args.state
        && std::fs::write(state, format!("{n}\n")).is_err()
    {
        out.push("WARN cannot write the state file".to_string());
    }
    if let Some(copy) = &args.copy
        && let Some(problem) = copy_problem(copy, args.vault.as_deref(), n)
    {
        out.push(format!("WARN outside-vault copy: {problem}"));
    }
    let verdict = if out.is_empty() { "PASS" } else { "FAIL" };
    out.push(format!("stenio: {verdict} secrets-helper resolved={n}"));
    out
}

pub fn run_cli(argv: &[String]) -> i32 {
    let args = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let out = check(&args);
    for l in &out {
        println!("{l}");
    }
    i32::from(out.len() > 1)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let v = super::dumps::FAKE_VALUE;
    let two = format!("A_KEY={v}\nB_KEY={v}\n");
    let one = format!("A_KEY={v}\n");
    let d = super::fixture("helper", &[("two.env", &two), ("one.env", &one)]);
    let p = |n: &str| d.join(n).display().to_string();
    let state = p("count");
    let run = |file: &str, extra: &[&str]| {
        let mut argv = vec!["h", "--state", &state];
        argv.extend_from_slice(extra);
        let file = p(file);
        argv.extend_from_slice(&["--", "cat", &file]);
        Args::try_parse_from(argv)
            .map(|a| check(&a).join("\n"))
            .unwrap_or_default()
    };
    let good = run("two.env", &[]);
    let fewer = run("one.env", &[]);
    let missing = run("gone.env", &[]);
    let copy = p("two.env");
    let plain_copy = run("two.env", &["--copy", &copy]);
    let _ = std::fs::remove_dir_all(&d);
    vec![
        (
            "secrets helper: full count passes".to_string(),
            good == "stenio: PASS secrets-helper resolved=2",
        ),
        (
            "secrets helper: mutation, fewer than last known warns".to_string(),
            fewer.contains("resolved 1 secrets, expected at least 2") && !fewer.contains(v),
        ),
        (
            "secrets helper: mutation, missing path warns with helper and zero".to_string(),
            missing.contains("`cat` resolved 0 secrets") && missing.contains("FAIL"),
        ),
        (
            "secrets helper: plaintext copy rejected".to_string(),
            plain_copy.contains("the copy is not encrypted"),
        ),
    ]
}
