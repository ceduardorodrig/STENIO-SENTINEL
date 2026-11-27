//! The owner's override: recorded at a terminal, limited to one rule, expiring, logged.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

pub const MAX_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub rule: String,
    /// Milliseconds since the epoch; 0 revokes.
    pub until: i64,
    pub reason: String,
    /// When set, only actions whose text contains it are covered.
    #[serde(default)]
    pub matching: Option<String>,
    pub at: i64,
}

pub fn file(state: &Path) -> PathBuf {
    state.join("overrides.jsonl")
}

/// The latest record of each rule decides; an unreadable file grants nothing.
pub fn covering(state: &Path, rule: &str, subject: &str, now: i64) -> Option<Grant> {
    let text = std::fs::read_to_string(file(state)).ok()?;
    let latest = text
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Grant>(l).ok())
        .find(|g| g.rule == rule)?;
    let in_time = latest.until > now && latest.until - latest.at <= MAX_SECS * 1000;
    let covers = latest
        .matching
        .as_deref()
        .is_none_or(|m| subject.contains(m));
    (in_time && covers).then_some(latest)
}

pub fn store(state: &Path, grant: &Grant) -> std::io::Result<()> {
    std::fs::create_dir_all(state)?;
    let line = serde_json::to_string(grant).map_err(std::io::Error::other)?;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(file(state))?;
    writeln!(file, "{line}")
}

/// Only a person at a terminal passes: no pipe, no harness session, and the rule typed back.
pub fn confirm_owner(rule: &str, session_vars: &[String]) -> Result<(), String> {
    if let Some(var) = session_vars.iter().find(|v| std::env::var_os(v).is_some()) {
        return Err(format!(
            "an override is the owner's decision; this shell belongs to an agent session ({var})"
        ));
    }
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return Err(
            "an override is the owner's decision and needs an interactive terminal".to_string(),
        );
    }
    print!("Type {rule} to confirm: ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut typed = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut typed)
        .map_err(|e| e.to_string())?;
    if typed.trim() == rule {
        Ok(())
    } else {
        Err("not confirmed; nothing recorded".to_string())
    }
}
