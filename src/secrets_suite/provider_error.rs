//! `PROVIDER-ERROR-NO-EMPTY-DETAIL` (GB-205): a provider failure whose only detail is the child's
//! stderr renders as `exit status: 1:` when the CLI reports errors on stdout. The error statement
//! must be preceded, in its function, by a read of stdout or an emptiness check of the detail.
//! Heuristic, limited to Rust files that talk about providers.

use super::violation;
use crate::engine::Violation;
use crate::rule::Severity;
use regex::Regex;
use std::path::{Path, PathBuf};

pub const RULE_ID: &str = "PROVIDER-ERROR-NO-EMPTY-DETAIL";

/// 1-based lines of error statements built from stderr alone.
fn hits(content: &str) -> Vec<usize> {
    let (Ok(open), Ok(bind), Ok(stdout_read)) = (
        Regex::new(r"\b(bail|anyhow)!\s*\(|\bErr\s*\(\s*format!"),
        Regex::new(r"let\s+(\w+)\s*=\s*String::from_utf8(?:_lossy)?\(\s*&?\s*\w+\.stderr"),
        Regex::new(r"\.stdout\b\s*(?:[^(\s]|$)"),
    ) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        if !open.is_match(line) {
            continue;
        }
        let end = (i..lines.len().min(i + 12))
            .find(|j| lines[*j].trim_end().ends_with([';', '}']))
            .unwrap_or(i);
        let statement = lines[i..=end].join("\n");
        let start = (0..=i)
            .rev()
            .find(|j| {
                let t = lines[*j].trim_start();
                t.starts_with("fn ") || t.contains(" fn ")
            })
            .unwrap_or(0);
        let body = lines[start..=end].join("\n");
        let bound = bind.captures(&body).map(|c| c[1].to_string());
        let uses_stderr = statement.contains(".stderr")
            || bound.as_ref().is_some_and(|b| {
                statement
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .any(|w| w == b)
            });
        let about_exit = statement.contains("status") || statement.contains("exit");
        if uses_stderr && about_exit && !stdout_read.is_match(&body) && !body.contains("is_empty()")
        {
            out.push(i + 1);
        }
    }
    out
}

pub fn audit(files: &[PathBuf]) -> Vec<Violation> {
    let mut out = Vec::new();
    for p in files {
        if p.extension().and_then(|e| e.to_str()) != Some("rs")
            || p.components().any(|c| c.as_os_str() == "tests")
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(p) else {
            continue;
        };
        let about_providers =
            Path::new(p).to_string_lossy().contains("provider") || content.contains("Provider");
        if !(about_providers && content.contains("Command")) {
            continue;
        }
        for line in hits(&content) {
            out.push(violation(
                RULE_ID,
                "Provider Failure Detail Can Be Empty",
                Severity::Warning,
                p,
                line,
                "This failure takes its detail from stderr alone; an error event on stdout is lost."
                    .to_string(),
                "Parse the child's stdout error event first and say `stderr empty` when it is.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let bad = "// Provider\nasync fn call() {\n    let output = Command::new(\"x\").stdin(Stdio::null()).output().await?;\n    if !output.status.success() {\n        let stderr = String::from_utf8_lossy(&output.stderr);\n        bail!(\"x exited with {}: {}\", output.status, stderr.trim());\n    }\n    parse(&output.stdout)\n}\n";
    let good = bad.replace(
        "    if !output.status.success() {\n",
        "    let stdout = String::from_utf8_lossy(&output.stdout);\n    if !output.status.success() {\n",
    );
    vec![
        (
            "provider error: mutation, stderr-only detail flagged".to_string(),
            hits(bad) == vec![6],
        ),
        (
            "provider error: stdout consulted first passes".to_string(),
            hits(&good).is_empty(),
        ),
    ]
}
