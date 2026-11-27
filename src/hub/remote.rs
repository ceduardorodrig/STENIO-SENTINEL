//! The client side of a shared ledger served by `stenio hub serve`. One declaration selects it for
//! the CLI, the stdio MCP server, the hooks and the backlog writers; no host is named in code.
//! Anything that needs this machine (queue files, tree paths, quota sources) happens here, the
//! rest is one request. A broken declaration or an unreachable server is "ledger unavailable":
//! nothing is claimed and no queue is written.

use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use super::config::{self, Config, DB_ENV};
use super::resource::{self, Resource};
use super::store::Store;
use super::{HubError, HubResult, quota};

pub const URL_ENV: &str = "STENIO_HUB_URL";
pub const TOKEN_FILE_ENV: &str = "STENIO_HUB_TOKEN_FILE";
const FILE: &str = "stenio/hub-remote.toml";
const SYSTEM_FILE: &str = "/etc/stenio/hub-remote.toml";
const TIMEOUT_SECS: u64 = 20;
/// A hook runs after every tool call: it must not hold the session when the server is away.
pub const HOOK_TIMEOUT_SECS: u64 = 4;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    url: String,
    token_file: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Remote {
    url: String,
    token_file: PathBuf,
    timeout: Duration,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn home() -> Option<PathBuf> {
    var("HOME").map(PathBuf::from)
}

fn config_home() -> Option<PathBuf> {
    var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home().map(|h| h.join(".config")))
}

fn expand(path: &str) -> HubResult<PathBuf> {
    match path.strip_prefix("~/") {
        Some(rest) => home()
            .map(|h| h.join(rest))
            .ok_or_else(|| HubError::Store("HOME is not set".to_string())),
        None => Ok(PathBuf::from(path)),
    }
}

/// Only TLS leaves the machine; plain HTTP is accepted for loopback.
fn checked_url(url: &str) -> HubResult<String> {
    let url = url.trim().trim_end_matches('/');
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|p| {
            url.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
        });
    if url.starts_with("https://") || loopback {
        return Ok(url.to_string());
    }
    Err(HubError::Store(format!(
        "the ledger URL must be https (or http on loopback): {url}"
    )))
}

fn build(url: &str, token_file: &str, timeout: Option<u64>) -> HubResult<Remote> {
    Ok(Remote {
        url: checked_url(url)?,
        token_file: expand(token_file)?,
        timeout: Duration::from_secs(timeout.unwrap_or(TIMEOUT_SECS).clamp(1, 120)),
    })
}

fn from_file(path: &Path) -> HubResult<Remote> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| HubError::Store(format!("cannot read {}: {e}", path.display())))?;
    let d: Declaration = toml::from_str(&text)
        .map_err(|e| HubError::Store(format!("invalid {}: {e}", path.display())))?;
    build(&d.url, &d.token_file, d.timeout_secs)
}

/// The declared server, if any: `STENIO_HUB_URL`, else nothing when `STENIO_HUB_DB` names a
/// local ledger, else the user file, else the system file.
pub fn declared() -> HubResult<Option<Remote>> {
    if let Some(url) = var(URL_ENV) {
        let token = var(TOKEN_FILE_ENV)
            .ok_or_else(|| HubError::Store(format!("{URL_ENV} is set without {TOKEN_FILE_ENV}")))?;
        return build(&url, &token, None).map(Some);
    }
    if var(DB_ENV).is_some() {
        return Ok(None);
    }
    let user = config_home().map(|d| d.join(FILE));
    for path in user.into_iter().chain([PathBuf::from(SYSTEM_FILE)]) {
        // A file that exists but cannot be inspected must not silently select the local ledger.
        match path.try_exists() {
            Ok(false) => {}
            Ok(true) => return from_file(&path).map(Some),
            Err(e) => {
                return Err(HubError::Store(format!(
                    "cannot inspect {}: {e}",
                    path.display()
                )));
            }
        }
    }
    Ok(None)
}

/// Refusal codes are static in the engine; the few distinct ones of a server are interned.
fn intern(code: &str) -> &'static str {
    static CODES: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let Ok(mut codes) = CODES.lock() else {
        return "refused";
    };
    if let Some(known) = codes.get(code) {
        return known;
    }
    if codes.len() >= 64 || code.len() > 40 {
        return "refused";
    }
    let leaked: &'static str = Box::leak(code.to_string().into_boxed_str());
    codes.insert(leaked);
    leaked
}

/// The result carried by a reply `{"exit": n, "body": {...}}`.
fn outcome(reply: &Value) -> HubResult<Value> {
    let body = reply["body"].clone();
    let message = || body["message"].as_str().unwrap_or("no message").to_string();
    match reply["exit"].as_i64() {
        Some(0) => Ok(body),
        Some(1) => {
            let code = intern(body["code"].as_str().unwrap_or("refused"));
            let next = body["next"].as_str().unwrap_or("").to_string();
            let mut error = HubError::refused(code, message(), next);
            if let Some(map) = body.as_object() {
                for (k, v) in map {
                    if !["ok", "code", "message", "next"].contains(&k.as_str()) {
                        error = error.with(k, v.clone());
                    }
                }
            }
            Err(error)
        }
        Some(2) => Err(HubError::Usage(message())),
        _ => Err(HubError::Store(format!("ledger server: {}", message()))),
    }
}

impl Remote {
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    /// One operation. Never retried: a repeated claim or write is not the same request.
    pub fn call(&self, op: &str, args: Value) -> HubResult<Value> {
        let token = std::fs::read_to_string(&self.token_file).map_err(|e| {
            HubError::Store(format!(
                "cannot read the token file {}: {e}",
                self.token_file.display()
            ))
        })?;
        let agent = ureq::AgentBuilder::new()
            .timeout(self.timeout)
            .redirects(0)
            .build();
        let sent = agent
            .post(&format!("{}/v1/op", self.url))
            .set("Authorization", &format!("Bearer {}", token.trim()))
            .send_json(json!({"op": op, "args": args}));
        let unavailable = |why: String| {
            HubError::Store(format!(
                "the ledger server {} did not answer: {why}",
                self.url
            ))
        };
        match sent {
            Ok(response) => {
                let reply: Value = response
                    .into_json()
                    .map_err(|e| unavailable(e.to_string()))?;
                outcome(&reply)
            }
            Err(ureq::Error::Status(status, _)) => Err(unavailable(format!("HTTP {status}"))),
            Err(e) => Err(unavailable(e.to_string())),
        }
    }
}

/// Resources as this machine sees them: tree paths are resolved here, before they are sent.
fn local_names(raw: &[String]) -> HubResult<Vec<String>> {
    Ok(resource::parse_list(raw)?
        .into_iter()
        .map(|r| r.name)
        .collect())
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Reads the quota sources of this machine into a scratch ledger and sends the samples.
fn push_quota(server: &Remote, cfg: &Config, account: Option<&str>) -> HubResult<Value> {
    let mut policy = cfg.quota.clone();
    if let Some(account) = account {
        policy.source.retain(|s| s.account == account);
    }
    if policy.source.is_empty() {
        return Ok(json!({"ok": true, "refreshed": {}}));
    }
    let scratch = std::env::temp_dir().join(format!(
        "stenio-quota-{}-{}",
        std::process::id(),
        super::now_ms()
    ));
    let result = (|| {
        let mut store = Store::open(&scratch.join("hub.db"))?;
        let report = quota::refresh(&mut store, &policy)?;
        for sample in quota::wire_samples(&mut store)? {
            server.call("quota_put", sample)?;
        }
        Ok(report)
    })();
    if scratch.exists() {
        std::fs::remove_dir_all(&scratch)
            .map_err(|e| HubError::Store(format!("cannot remove {}: {e}", scratch.display())))?;
    }
    result
}

/// An operation of the CLI or of the stdio MCP server, run against the declared server.
pub fn operate(server: &Remote, op: &str, mut args: Map<String, Value>) -> HubResult<Value> {
    args.retain(|_, v| !v.is_null());
    let needs_worker = [
        "hub_claim",
        "hub_beat",
        "hub_release",
        "hub_event",
        "hub_handback",
        "hub_ask",
    ];
    if needs_worker.contains(&op) && !args.contains_key("worker") {
        let worker = config::worker_or_env(None)
            .ok_or_else(|| HubError::Usage("missing argument 'worker'".to_string()))?;
        args.insert("worker".to_string(), json!(worker));
    }
    match op {
        "hub_join" => {
            let cfg = Config::load()?;
            if !args.contains_key("session")
                && let Some(session) = super::hooks::session_of(&cfg, &Value::Null)
            {
                args.insert("session".to_string(), json!(session));
            }
            if !args.contains_key("account")
                && let Some(harness) = args.get("harness").and_then(Value::as_str)
            {
                let account = cfg.account_of(&harness.trim().to_lowercase());
                args.insert("account".to_string(), json!(account));
            }
        }
        "hub_claim" => {
            let raw = strings(args.get("resources").unwrap_or(&Value::Null));
            let wanted = resource::parse_list(&raw)?;
            if wanted.iter().any(Resource::starts_work) {
                let worker = args.get("worker").cloned().unwrap_or_default();
                let need = server.call("quota_need", json!({"worker": worker}))?;
                if need["stale"] == json!(true) {
                    let cfg = Config::load()?;
                    push_quota(server, &cfg, need["account"].as_str())?;
                }
            }
            args.insert("resources".to_string(), json!(local_names(&raw)?));
            // A queue directory of this machine means nothing to the server: the claim covers
            // every directory, which is the stricter reading.
            args.remove("path");
        }
        "hub_release" => {
            if let Some(one) = args.get("resource").and_then(Value::as_str) {
                let names = local_names(&[one.to_string()])?;
                args.insert("resource".to_string(), json!(names.first()));
            }
        }
        "stenio_quota" => {
            if args.remove("refresh") == Some(json!(true)) {
                let report = push_quota(server, &Config::load()?, None)?;
                let mut out = server.call(op, Value::Object(args))?;
                out["refreshed"] = report["refreshed"].clone();
                return Ok(out);
            }
        }
        "quota_refresh" => return push_quota(server, &Config::load()?, None),
        _ => {}
    }
    server.call(op, Value::Object(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tls_leaves_the_machine() {
        assert!(checked_url("https://h.example:8443/").is_ok());
        assert!(checked_url("http://127.0.0.1:8797").is_ok());
        assert!(checked_url("http://127.0.0.1.example").is_err());
        assert!(checked_url("http://h.example").is_err());
    }

    #[test]
    fn replies_keep_refusals_and_exit_codes() {
        let held = json!({"exit": 1, "body": {"ok": false, "code": "held", "message": "m",
            "next": "n", "holder": "w"}});
        let error = outcome(&held).err();
        assert_eq!(error.as_ref().map(HubError::exit_code), Some(1));
        assert_eq!(
            error.map(|e| e.to_json()["holder"].clone()),
            Some(json!("w"))
        );
        let garbled = outcome(&json!({})).err();
        assert_eq!(garbled.map(|e| e.exit_code()), Some(3));
    }
}
