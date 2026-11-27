//! `stenio hub`: the shared work ledger (first release, local, no daemon).
//!
//! One SQLite database, written only by the engine, reached by every harness through the same CLI
//! and stdio MCP tools. The markdown backlogs stay the record of *items*; the ledger records *who
//! is working on what, what happened and what was asked*.
//!
//! Guarantees: claims are all-or-nothing `BEGIN IMMEDIATE` transactions, one live holder per
//! resource (a unique index), fence tokens only grow, an expired lease can be taken over and the
//! old fence is then refused, and every state change appends one hash-chained event. Limit: every
//! process of the same Unix user can open the file, so the chain detects edits, it does not
//! prevent them.

pub mod audit;
pub mod cli;
pub mod config;
pub mod guard;
pub mod ledger;
pub mod mcp;
pub mod quota;
pub mod resource;
mod selftest;
pub mod store;
pub mod view;

use serde_json::{Map, Value, json};

pub use selftest::self_test_cases;

/// Why an operation did not happen.
#[derive(Debug, Clone)]
pub enum HubError {
    /// The ledger said no (exit 1).
    Refused(Box<Refusal>),
    /// The request itself is malformed (exit 2).
    Usage(String),
    /// The ledger cannot be read or written, so nothing may be assumed (exit 3).
    Store(String),
}

#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
    /// The command or action that resolves the refusal.
    pub next: String,
    pub extra: Map<String, Value>,
}

pub type HubResult<T> = Result<T, HubError>;

impl HubError {
    pub fn refused(
        code: &'static str,
        message: impl Into<String>,
        next: impl Into<String>,
    ) -> Self {
        HubError::Refused(Box::new(Refusal {
            code,
            message: message.into(),
            next: next.into(),
            extra: Map::new(),
        }))
    }

    /// Attaches a machine-readable field to a refusal; other errors are returned unchanged.
    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        if let HubError::Refused(r) = &mut self {
            r.extra.insert(key.to_string(), value.into());
        }
        self
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            HubError::Refused(_) => 1,
            HubError::Usage(_) => 2,
            HubError::Store(_) => 3,
        }
    }

    pub fn code(&self) -> &str {
        match self {
            HubError::Refused(r) => r.code,
            HubError::Usage(_) => "usage",
            HubError::Store(_) => "store_unavailable",
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            HubError::Refused(r) => {
                let mut out = r.extra.clone();
                out.insert("ok".into(), json!(false));
                out.insert("code".into(), json!(r.code));
                out.insert("message".into(), json!(r.message));
                out.insert("next".into(), json!(r.next));
                Value::Object(out)
            }
            HubError::Usage(m) => json!({"ok": false, "code": "usage", "message": m,
                "next": "stenio hub --help"}),
            HubError::Store(m) => json!({"ok": false, "code": "store_unavailable", "message": m,
                "next": "claim nothing; check `stenio hub audit` and the database path"}),
        }
    }
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HubError::Refused(r) => {
                write!(f, "refused [{}]: {}; next: {}", r.code, r.message, r.next)
            }
            HubError::Usage(m) => write!(f, "usage: {m}"),
            HubError::Store(m) => write!(f, "ledger unavailable: {m}"),
        }
    }
}

impl From<rusqlite::Error> for HubError {
    fn from(e: rusqlite::Error) -> Self {
        HubError::Store(e.to_string())
    }
}

/// RFC 3339 (UTC, seconds) of a millisecond timestamp.
pub fn iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
