//! The declared list (`policy.toml`, embedded) plus a host file that can only add to it.

use serde::Deserialize;
use std::path::PathBuf;

pub const DEFAULTS: &str = include_str!("policy.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub why: String,
    /// The action is allowed to a caller that holds a release or deploy lease.
    #[serde(default)]
    pub lease: bool,
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    #[serde(default)]
    pub protected_trees: Vec<String>,
    #[serde(default)]
    pub protected_roots: Vec<String>,
    #[serde(default)]
    pub guard_files: Vec<String>,
    #[serde(default)]
    pub scratch: Vec<String>,
    #[serde(default)]
    pub secret_files: Vec<String>,
    #[serde(default)]
    pub secret_exempt: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(rename = "rule")]
    pub rules: Vec<Rule>,
    pub paths: Paths,
}

/// What a host may declare. Nothing here can remove an entry of the embedded list.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub audit_dir: Option<String>,
    #[serde(default)]
    pub protected_trees: Vec<String>,
    #[serde(default)]
    pub protected_roots: Vec<String>,
    #[serde(default)]
    pub guard_files: Vec<String>,
    #[serde(default)]
    pub secret_files: Vec<String>,
}

impl Policy {
    pub fn embedded() -> Result<Policy, String> {
        toml::from_str(DEFAULTS).map_err(|e| format!("embedded gate policy: {e}"))
    }

    pub fn with_host(mut self, host: &Host) -> Policy {
        let p = &mut self.paths;
        p.protected_trees.extend(host.protected_trees.clone());
        p.protected_roots.extend(host.protected_roots.clone());
        p.guard_files.extend(host.guard_files.clone());
        p.secret_files.extend(host.secret_files.clone());
        self
    }

    pub fn why(&self, id: &str) -> &str {
        self.rules
            .iter()
            .find(|r| r.id == id)
            .map_or("listed action", |r| r.why.as_str())
    }
}

fn config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|d| d.join("stenio"))
}

/// The host file. A broken one is reported and ignored: the embedded list still applies.
pub fn host() -> Host {
    let Some(file) = config_dir().map(|d| d.join("gate.toml")) else {
        return Host::default();
    };
    let Ok(text) = std::fs::read_to_string(&file) else {
        return Host::default();
    };
    toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("stenio gate: {} ignored: {e}", file.display());
        Host::default()
    })
}
