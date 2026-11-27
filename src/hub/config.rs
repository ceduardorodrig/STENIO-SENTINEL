//! Where the ledger lives and the tunable policy. No host, path or account is fixed in code:
//! paths come from the environment or the XDG base directories, policy from one declaration.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{HubError, HubResult};

pub const DB_ENV: &str = "STENIO_HUB_DB";
pub const CONFIG_ENV: &str = "STENIO_HUB_CONFIG";
pub const WORKER_ENV: &str = "STENIO_HUB_WORKER";
const DEFAULTS: &str = include_str!("defaults.toml");

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub lease: Lease,
    pub fleet: Fleet,
    pub quota: QuotaPolicy,
    #[serde(default)]
    pub accounts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub hook_beat_min_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fleet {
    pub ceiling: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaPolicy {
    pub fresh_secs: u64,
    pub stop_percent: f64,
    pub throttle_percent: f64,
    pub throttle_workers: u32,
    pub unknown_workers: u32,
    pub resume_margin_secs: u64,
    pub command_timeout_secs: u64,
    #[serde(default)]
    pub source: Vec<QuotaSource>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSource {
    pub account: String,
    pub command: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> HubResult<Self> {
        toml::from_str(text).map_err(|e| HubError::Usage(format!("invalid hub configuration: {e}")))
    }

    /// The declaration shipped inside the engine.
    pub fn embedded() -> HubResult<Self> {
        Self::parse(DEFAULTS)
    }

    /// The host override when one exists, else the embedded declaration. An override that is
    /// named but unreadable is an error: silently using other limits would be a bypass.
    pub fn load() -> HubResult<Self> {
        let named = env_path(CONFIG_ENV);
        let file = named.clone().or_else(|| {
            xdg("XDG_CONFIG_HOME", ".config")
                .map(|d| d.join("stenio/hub.toml"))
                .filter(|p| p.is_file())
        });
        match file {
            Some(p) => {
                let text = std::fs::read_to_string(&p).map_err(|e| {
                    HubError::Usage(format!(
                        "cannot read hub configuration {}: {e}",
                        p.display()
                    ))
                })?;
                Self::parse(&text)
            }
            None => Self::parse(DEFAULTS),
        }
    }

    pub fn account_of(&self, harness: &str) -> String {
        self.accounts
            .get(harness)
            .cloned()
            .unwrap_or_else(|| harness.to_string())
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// An XDG base directory: the variable when absolute, else `$HOME/<fallback>`.
fn xdg(variable: &str, fallback: &str) -> Option<PathBuf> {
    env_path(variable)
        .filter(|p| p.is_absolute())
        .or_else(|| env_path("HOME").map(|h| h.join(fallback)))
}

/// `STENIO_HUB_DB`, else `$XDG_STATE_HOME/stenio/hub.db`.
pub fn db_path() -> HubResult<PathBuf> {
    env_path(DB_ENV)
        .or_else(|| xdg("XDG_STATE_HOME", ".local/state").map(|d| d.join("stenio/hub.db")))
        .ok_or_else(|| {
            HubError::Store(format!(
                "no ledger location: set {DB_ENV}, XDG_STATE_HOME or HOME"
            ))
        })
}

/// The vault or repository that holds the queues: the explicit path, else the nearest ancestor of
/// the current directory with at least one declared queue. There is no built-in fallback.
pub fn discover_root(given: Option<&Path>) -> Option<PathBuf> {
    let start = match given {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().ok()?,
    };
    let start = start.canonicalize().ok()?;
    start
        .ancestors()
        .find(|a| !crate::backlog::queue_index::present_queues(a).is_empty())
        .map(Path::to_path_buf)
}

/// The worker id from the argument, else from `STENIO_HUB_WORKER`.
pub fn worker_or_env(given: Option<&str>) -> Option<String> {
    given
        .map(str::to_string)
        .or_else(|| std::env::var(WORKER_ENV).ok())
        .filter(|w| !w.trim().is_empty())
}
