//! Secret and environment-variable gates. One entry point per kind of use so `main.rs` carries a
//! single registration: [`audit`] (static rules run by a scan), [`run_cli`] (host subcommands),
//! [`self_test_cases`] and [`explain::EXPLANATIONS`]. SECURITY: nothing here prints a secret value;
//! reports carry paths, line numbers, key names and counts only.

mod drift;
mod dumps;
mod env_example;
mod env_stack;
mod env_wired;
pub mod explain;
mod helper_check;
mod identities;
mod redact;
mod store;
mod store_recipients;
mod tree;

use crate::engine::Violation;
use crate::rule::Severity;
use std::path::{Path, PathBuf};

/// What the caller selected; an empty `tag`/`only_rule` means "everything".
pub struct Selection<'a> {
    pub scope: &'a str,
    pub tag: Option<&'a str>,
    pub only_rule: Option<&'a str>,
}

impl Selection<'_> {
    fn wants(&self, tag: &str, rule_id: &str) -> bool {
        self.tag.is_none_or(|t| t.eq_ignore_ascii_case(tag))
            && self
                .only_rule
                .is_none_or(|r| r.eq_ignore_ascii_case(rule_id))
    }

    fn scope_in(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|s| self.scope.eq_ignore_ascii_case(s))
    }
}

/// Static rules of this suite for the tree at `root`.
pub fn audit(root: &Path, sel: &Selection) -> Vec<Violation> {
    let mut out = Vec::new();
    if sel.scope_in(&["vault", "homelab"]) && sel.wants("sec", store_recipients::RULE_ID) {
        out.extend(store_recipients::audit(root));
    }
    // Captured mirrors and upstream forks are not our trees to wire.
    if sel.scope_in(&["mirror", "snapshot", "fork", "derived", "frappe"]) {
        return out;
    }
    let wired = sel.wants("env", env_wired::RULE_ID);
    let stack = sel.wants("env", env_stack::RULE_ID);
    let parity = sel.wants("env", env_example::RULE_ID);
    if !(wired || stack || parity) {
        return out;
    }
    let files = tree::files(root);
    if wired {
        out.extend(env_wired::audit(root, &files));
    }
    if parity {
        out.extend(env_example::audit(&files));
    }
    if stack {
        out.extend(env_stack::audit(root, &files));
    }
    out
}

/// Host subcommands of the suite.
const COMMANDS: &[(&str, fn(&[String]) -> i32)] = &[
    ("secrets-drift", drift::run_cli),
    ("secret-dumps", dumps::run_cli),
    ("secret-identities", identities::run_cli),
    ("redact", redact::run_cli),
    ("secrets-helper-check", helper_check::run_cli),
];

/// Runs `argv[1]` when it is a suite subcommand; `None` lets the engine parse the line.
pub fn dispatch(argv: &[String]) -> Option<i32> {
    let name = argv.get(1)?;
    let (_, run) = COMMANDS.iter().find(|(c, _)| c == name)?;
    let mut rest = vec![format!("stenio {name}")];
    rest.extend_from_slice(&argv[2..]);
    Some(run(&rest))
}

pub(crate) fn violation(
    rule_id: &str,
    rule_name: &str,
    severity: Severity,
    path: &Path,
    line: usize,
    message: String,
    suggestion: &str,
) -> Violation {
    Violation {
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        severity,
        file_path: path.display().to_string(),
        line_number: line,
        snippet: String::new(),
        message,
        suggestion: Some(suggestion.to_string()),
    }
}

/// Throw-away fixture tree for the self tests.
pub(crate) fn fixture(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stenio-ss-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    for (name, body) in files {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(p, body);
    }
    dir
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let mut cases = store_recipients::self_test_cases();
    cases.extend(drift::self_test_cases());
    cases.extend(dumps::self_test_cases());
    cases.extend(identities::self_test_cases());
    cases.extend(redact::self_test_cases());
    cases.extend(helper_check::self_test_cases());
    cases.extend(env_wired::self_test_cases());
    cases.extend(env_stack::self_test_cases());
    cases.extend(env_example::self_test_cases());
    cases
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures_hold() {
        let bad: Vec<_> = super::self_test_cases()
            .into_iter()
            .filter(|(_, ok)| !ok)
            .collect();
        assert!(bad.is_empty(), "{bad:?}");
    }
}
