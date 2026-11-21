//! `AGENT-HOOK-FIXTURES-IN-PIPELINE` (GB-275): the agent-hook fixture runner must be green.
//!
//! WHY IT EXISTS (2026-11-21): `scripts/agent-hooks/test-rust-tools-guard.sh` proves the
//! EDIT-NOOP guard of `rust-tools-guard.sh` (11 cases plus a mutation self-check) but nothing ran
//! it: no timer, no git hook, and `agent-entrypoints.toml` only checks `must_reference` strings.
//! A gate that is not on an automatic path is documentation (global rule 12.1).
//!
//! WHAT IT CHECKS: the script is executed from the scanned vault root (never from a hard-coded
//! home) and its output is read, not trusted: the exit code must be 0, the last line must start
//! with `MUTATION OK` and the last-but-one line must match `^N/N cases$` with both numbers equal
//! and non-zero. N comes from the runner's own output, it is never typed here (rule 12.3). When
//! the script does not exist under the scanned root (an external `--path`) the check is inert
//! and says why. In `--scope homelab`/`vault` it is a WARNING; the `hook-fixtures` step of
//! `stenio release-engine` turns the same verdict into a FAIL.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "AGENT-HOOK-FIXTURES-IN-PIPELINE";
const RULE_NAME: &str = "Agent Hook Fixtures Must Run And Pass";
/// Script path relative to the vault root.
pub const SCRIPT_REL: &str = "scripts/agent-hooks/test-rust-tools-guard.sh";
const TIMEOUT: Duration = Duration::from_secs(120);

pub struct HookReport {
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

/// `N/N cases` (a digit run, a slash, the same digit run, ` cases`) with N > 0, else `None`.
fn cases_total(line: &str) -> Option<u64> {
    let body = line.trim().strip_suffix(" cases")?;
    let (a, b) = body.split_once('/')?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    (digits(a) && digits(b) && a == b)
        .then(|| a.parse::<u64>().ok())
        .flatten()
        .filter(|n| *n > 0)
}

/// Pure verdict over the runner's exit code and stdout.
pub fn evaluate(code: i32, stdout: &str) -> Result<String, String> {
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    let [.., cases, last] = lines.as_slice() else {
        return Err("the runner printed fewer than two lines".to_string());
    };
    if code != 0 {
        return Err(format!("the runner exited {code}"));
    }
    let Some(n) = cases_total(cases) else {
        return Err(format!(
            "last-but-one line {cases:?} is not `N/N cases` with equal non-zero N"
        ));
    };
    if !last.trim_start().starts_with("MUTATION OK") {
        return Err(format!(
            "last line {last:?} does not start with `MUTATION OK`"
        ));
    }
    Ok(format!("{n}/{n} cases and MUTATION OK"))
}

/// The runner under `start` or one of its ancestors (the scanned vault root).
pub fn find_script(start: &Path) -> Option<PathBuf> {
    let base = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    base.ancestors()
        .map(|a| a.join(SCRIPT_REL))
        .find(|p| p.is_file())
}

/// Runs the runner and returns its verdict.
pub fn run_script(script: &Path) -> Result<String, String> {
    let mut cmd = Command::new("bash");
    cmd.arg(script);
    let out = crate::verify_release::spawn_with_timeout(cmd, TIMEOUT)?;
    evaluate(out.code, &out.stdout)
}

fn violation(file: &str, message: String) -> Violation {
    Violation {
        rule_id: RULE_ID.to_string(),
        rule_name: RULE_NAME.to_string(),
        severity: Severity::Warning,
        file_path: file.to_string(),
        line_number: 1,
        snippet: String::new(),
        message,
        suggestion: Some(
            "Run the script by hand and fix the guard or the fixture; never edit the expected lines."
                .to_string(),
        ),
    }
}

/// Audit of a scanned root: inert (INFO message) without the script.
pub fn audit(start: &Path) -> HookReport {
    let mut report = HookReport {
        messages: Vec::new(),
        violations: Vec::new(),
    };
    let Some(script) = find_script(start) else {
        report.messages.push(format!(
            "INFO {RULE_ID}: no {SCRIPT_REL} under the scanned root, check inert"
        ));
        return report;
    };
    let shown = script.display().to_string();
    match run_script(&script) {
        Ok(d) => report
            .messages
            .push(format!("PASS {RULE_ID}: {shown}: {d}")),
        Err(e) => report.violations.push(violation(
            &shown,
            format!("agent-hook fixtures are not green: {e}"),
        )),
    }
    report
}

const GOOD: &str = "echo 'PASS a'\necho '11/11 cases'\necho 'MUTATION OK: mutant fails'\n";
const NO_MUTATION: &str = "echo '11/11 cases'\necho 'MUTATION FAIL: mutant survived'\n";
const SHORT_COUNT: &str = "echo '10/11 cases'\necho 'MUTATION OK: x'\n";
const BAD_EXIT: &str = "echo '11/11 cases'\necho 'MUTATION OK: x'\nexit 1\n";

fn tree_findings(script: Option<&str>, tag: &str) -> Option<(usize, usize)> {
    let files: Vec<(String, String)> = script
        .map(|s| vec![(SCRIPT_REL.to_string(), s.to_string())])
        .unwrap_or_else(|| vec![("README.md".to_string(), "x\n".to_string())]);
    let root = crate::frappe::write_fixture(tag, &files)?;
    let rep = audit(&root);
    let _ = std::fs::remove_dir_all(&root);
    Some((rep.violations.len(), rep.messages.len()))
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let ok = |c, s| evaluate(c, s).is_ok();
    vec![
        (
            "hook-fixtures: N/N cases plus MUTATION OK passes".to_string(),
            ok(0, "x\n7/7 cases\nMUTATION OK: y\n"),
        ),
        (
            "hook-fixtures: N is derived, not typed (3/3 passes)".to_string(),
            ok(0, "3/3 cases\nMUTATION OK\n"),
        ),
        (
            "hook-fixtures: unequal count fails".to_string(),
            !ok(0, "10/11 cases\nMUTATION OK\n") && !ok(0, "0/0 cases\nMUTATION OK\n"),
        ),
        (
            "hook-fixtures: missing MUTATION OK fails".to_string(),
            !ok(0, "11/11 cases\nMUTATION FAIL\n") && !ok(0, "11/11 cases\n"),
        ),
        (
            "hook-fixtures: non-zero exit fails".to_string(),
            !ok(1, "11/11 cases\nMUTATION OK\n"),
        ),
        (
            "hook-fixtures: tree with a green runner is clean".to_string(),
            tree_findings(Some(GOOD), "hookfx-good") == Some((0, 1)),
        ),
        (
            "hook-fixtures: tree mutation (mutant survives) fires".to_string(),
            tree_findings(Some(NO_MUTATION), "hookfx-nomut") == Some((1, 0)),
        ),
        (
            "hook-fixtures: tree mutation (count short, bad exit) fires".to_string(),
            tree_findings(Some(SHORT_COUNT), "hookfx-short") == Some((1, 0))
                && tree_findings(Some(BAD_EXIT), "hookfx-exit") == Some((1, 0)),
        ),
        (
            "hook-fixtures: inert without the script".to_string(),
            tree_findings(None, "hookfx-none") == Some((0, 1)),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_cases_pass() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn cases_line_needs_equal_digits() {
        assert_eq!(cases_total("11/11 cases"), Some(11));
        assert_eq!(cases_total("11/12 cases"), None);
        assert_eq!(cases_total("a/a cases"), None);
        assert_eq!(cases_total("11/11 case"), None);
    }
}
