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
    #[serde(default)]
    pub session: Session,
    #[serde(default)]
    pub backup: Backup,
    #[serde(default)]
    pub attempts: Attempts,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempts {
    /// Expired or failed attempts after which a row needs the owner.
    pub limit: u32,
}

impl Default for Attempts {
    fn default() -> Self {
        Attempts { limit: 3 }
    }
}

/// Where a harness exposes its session id, to its shell commands and to its hooks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub env: Vec<String>,
    pub fields: Vec<String>,
    /// Payload fields that name the sub-agent inside a session.
    #[serde(default = "agent_fields")]
    pub agent_fields: Vec<String>,
    /// The one variable of each listed harness.
    #[serde(default)]
    pub harness: BTreeMap<String, String>,
}

fn agent_fields() -> Vec<String> {
    vec!["agent_id".to_string()]
}

impl Default for Session {
    fn default() -> Self {
        // An override without this section keeps the embedded declaration's behaviour.
        // The embedded declaration has the section, so this cannot recurse.
        Config::embedded().map_or_else(
            |_| Session {
                env: Vec::new(),
                fields: Vec::new(),
                agent_fields: agent_fields(),
                harness: BTreeMap::new(),
            },
            |c| c.session,
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub max_age_secs: u64,
}

impl Default for Backup {
    fn default() -> Self {
        Backup {
            max_age_secs: 26 * 3600,
        }
    }
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
    /// From this percentage a claim answers with a warning.
    #[serde(default = "advisory_percent")]
    pub advisory_percent: f64,
    #[serde(default)]
    pub source: Vec<QuotaSource>,
    #[serde(default)]
    pub limit: Vec<QuotaLimit>,
}

fn advisory_percent() -> f64 {
    80.0
}

/// Limits of one account, or of one window of it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaLimit {
    pub account: String,
    pub window: Option<String>,
    pub stop_percent: Option<f64>,
    pub advisory_percent: Option<f64>,
}

impl QuotaPolicy {
    /// `(stop, advisory)` of a window: its own entry, else the account's, else the general value.
    pub fn limits(&self, account: &str, window: &str) -> (f64, f64) {
        let find = |window: Option<&str>, pick: fn(&QuotaLimit) -> Option<f64>| {
            self.limit
                .iter()
                .filter(|l| l.account == account && l.window.as_deref() == window)
                .find_map(pick)
        };
        let value = |pick: fn(&QuotaLimit) -> Option<f64>, general: f64| {
            find(Some(window), pick)
                .or_else(|| find(None, pick))
                .unwrap_or(general)
        };
        (
            value(|l| l.stop_percent, self.stop_percent),
            value(|l| l.advisory_percent, self.advisory_percent),
        )
    }

    /// One line per value in force, for `config show`.
    pub fn describe(&self, source: &str) -> String {
        let mut out = String::new();
        for (key, value) in [
            ("stop_percent", self.stop_percent),
            ("advisory_percent", self.advisory_percent),
            ("throttle_percent", self.throttle_percent),
            ("throttle_workers", f64::from(self.throttle_workers)),
            ("unknown_workers", f64::from(self.unknown_workers)),
        ] {
            out.push_str(&format!("hub.quota.{key} = {value}  [applied; {source}]\n"));
        }
        for (n, l) in self.limit.iter().enumerate() {
            out.push_str(&format!(
                "hub.quota.limit.{n} = account {} window {} stop {:?} advisory {:?}  [applied; {source}]\n",
                l.account,
                l.window.as_deref().unwrap_or("every"),
                l.stop_percent,
                l.advisory_percent
            ));
        }
        out
    }
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
    /// The override file in force on this host, if any.
    pub fn override_file() -> Option<PathBuf> {
        env_path(CONFIG_ENV).or_else(|| {
            xdg("XDG_CONFIG_HOME", ".config")
                .map(|d| d.join("stenio/hub.toml"))
                .filter(|p| p.is_file())
        })
    }

    pub fn load() -> HubResult<Self> {
        let file = Self::override_file();
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
