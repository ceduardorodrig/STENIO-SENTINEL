//! `SEC-SOPS-STORE-RECIPIENTS` (GB-206): the central dotenv store must stay readable by at least two
//! age recipients. Re-encrypting with `--age` on the command line silently drops the second one.
//! Recipients are public keys; they are counted, never printed.

use super::violation;
use crate::engine::Violation;
use crate::rule::Severity;
use std::collections::BTreeSet;
use std::path::Path;

pub const RULE_ID: &str = "SEC-SOPS-STORE-RECIPIENTS";
const MIN_RECIPIENTS: usize = 2;
/// Canonical store locations relative to the scanned root (vault root or `mnemocine/` itself).
const STORES: [&str; 2] = ["mnemocine/secrets.enc.env", "secrets.enc.env"];

/// Distinct age recipients declared by the sops metadata (dotenv, YAML or JSON form).
fn recipients(content: &str) -> BTreeSet<&str> {
    content
        .lines()
        .filter_map(|line| {
            let t = line.trim().trim_start_matches("- ").trim_end_matches(',');
            let (key, value) = if t.starts_with("sops_age__list_") {
                let (k, v) = t.split_once('=')?;
                (k.ends_with("__map_recipient").then_some("recipient")?, v)
            } else {
                let (k, v) = t.split_once(':')?;
                (k.trim_matches('"'), v)
            };
            let value = value.trim().trim_matches('"');
            (key == "recipient" && value.starts_with("age1")).then_some(value)
        })
        .collect()
}

pub fn audit(root: &Path) -> Vec<Violation> {
    STORES
        .iter()
        .map(|rel| root.join(rel))
        .filter_map(|path| {
            let content = std::fs::read_to_string(&path).ok()?;
            let n = recipients(&content).len();
            (n < MIN_RECIPIENTS).then(|| {
                violation(
                    RULE_ID,
                    "SOPS Store Lost A Recipient",
                    Severity::Error,
                    &path,
                    1,
                    format!(
                        "{} recipient{} in the sops store, at least {MIN_RECIPIENTS} required.",
                        n,
                        if n == 1 { "" } else { "s" }
                    ),
                    "Re-encrypt with every recipient (`sops updatekeys`, never a bare `--age` with one key).",
                )
            })
        })
        .collect()
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let line = |i: usize, k: &str| format!("sops_age__list_{i}__map_recipient=age1{k}\n");
    let two = format!("A=x\n{}{}", line(0, "aaaa"), line(1, "bbbb"));
    let one = format!("A=x\n{}", line(0, "aaaa"));
    let twice = format!("{}{}", line(0, "aaaa"), line(1, "aaaa"));
    let yaml = "sops:\n  age:\n    - recipient: age1aaaa\n    - recipient: age1bbbb\n";
    let run = |tag: &str, body: &str| {
        let d = super::fixture(tag, &[("mnemocine/secrets.enc.env", body)]);
        let v = audit(&d);
        let _ = std::fs::remove_dir_all(&d);
        v
    };
    let red = run("rc1", &one);
    vec![
        (
            "sops recipients: two is green".to_string(),
            run("rc2", &two).is_empty(),
        ),
        (
            "sops recipients: mutation, one recipient fails naming the count".to_string(),
            red.len() == 1
                && red[0].message.starts_with("1 recipient in")
                && red[0].file_path.ends_with("secrets.enc.env"),
        ),
        (
            "sops recipients: the same key twice counts once".to_string(),
            run("rc3", &twice).len() == 1,
        ),
        (
            "sops recipients: yaml metadata is counted".to_string(),
            run("rc4", yaml).is_empty(),
        ),
        (
            "sops recipients: no store, silent".to_string(),
            audit(Path::new("/nonexistent-stenio")).is_empty(),
        ),
    ]
}
