//! Account quota: read from a real source or reported as unknown, never as zero. Stenio runs the
//! declared read-only commands and accepts samples pushed by a harness; it reads no key files.

use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::Duration;

use super::config::{QuotaPolicy, QuotaSource};
use super::ledger::Worker;
use super::store::{NewEvent, Store, append, meta, set_meta};
use super::{HubError, HubResult, iso, now_ms};

/// The window name of an entry that only explains why nothing is known.
const NO_WINDOW: &str = "-";

#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    pub window: String,
    pub used_pct: f64,
    pub resets_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct Sample {
    account: String,
    window: String,
    used_pct: Option<f64>,
    resets_at: Option<i64>,
    observed_at: i64,
    source: String,
    reason: Option<String>,
}

impl Sample {
    fn confidence(&self, policy: &QuotaPolicy, now: i64) -> &'static str {
        let fresh_ms = (policy.fresh_secs as i64).saturating_mul(1000);
        match self.used_pct {
            None => "unknown",
            // A window that has reset says nothing about the new one.
            Some(_) if self.resets_at.is_some_and(|r| r <= now) => "unknown",
            Some(_) if now - self.observed_at <= fresh_ms => "measured",
            Some(_) => "stale",
        }
    }
}

fn samples(conn: &Connection) -> HubResult<Vec<Sample>> {
    let mut stmt = conn.prepare(
        "SELECT account, window, used_pct, resets_at, observed_at, source, reason \
         FROM quota ORDER BY account, window",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Sample {
            account: r.get(0)?,
            window: r.get(1)?,
            used_pct: r.get(2)?,
            resets_at: r.get(3)?,
            observed_at: r.get(4)?,
            source: r.get(5)?,
            reason: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Other workers of the account that hold a row or a slot.
fn busy_workers(conn: &Connection, who: &Worker) -> HubResult<u32> {
    Ok(conn.query_row(
        "SELECT COUNT(DISTINCT w.id) FROM claims c JOIN workers w ON w.id = c.holder \
         WHERE c.released IS NULL AND w.account = ?1 AND w.id <> ?2 \
         AND (c.resource LIKE 'row:%' OR c.resource LIKE 'fleet:%')",
        params![who.account, who.id],
        |r| r.get(0),
    )?)
}

/// Longest time one owner decision lifts the gate.
pub const OVERRIDE_MAX_SECS: u64 = 24 * 3600;

fn override_key(account: &str) -> String {
    format!("quota_override:{account}")
}

/// The live owner override of `account`, if any.
pub fn owner_override(conn: &Connection, account: &str, now: i64) -> HubResult<Option<Value>> {
    Ok(meta(conn, &override_key(account))?
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(|o| o["until_ms"].as_i64().is_some_and(|until| until > now)))
}

/// Every live override, for `status`.
pub fn overridden(conn: &Connection) -> HubResult<Vec<Value>> {
    let mut stmt =
        conn.prepare("SELECT substr(key, 16) FROM meta WHERE key LIKE 'quota_override:%'")?;
    let accounts = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    for account in accounts {
        if let Some(mut live) = owner_override(conn, &account, now_ms())? {
            live["kind"] = json!("quota_override");
            out.push(live);
        }
    }
    Ok(out)
}

/// Records the owner's decision to lift the quota gate of `account` for a limited time; zero
/// seconds revokes it. `terminal` says the request comes from an interactive terminal: agents
/// run without one. A process of the same Unix user can fake it, so the event is the record.
pub fn set_override(
    store: &mut Store,
    account: &str,
    secs: u64,
    reason: &str,
    terminal: bool,
) -> HubResult<Value> {
    if !terminal {
        return Err(HubError::refused(
            "owner_only",
            "a quota override is the owner's decision and needs an interactive terminal",
            "ask the owner (stenio hub ask)",
        ));
    }
    if secs > OVERRIDE_MAX_SECS || reason.trim().is_empty() {
        return Err(HubError::Usage(
            "--for is at most 24h and --reason is not empty".to_string(),
        ));
    }
    let until = now_ms().saturating_add((secs as i64).saturating_mul(1000));
    let record = json!({"account": account, "until_ms": until, "until": iso(until),
        "reason": reason.trim()});
    store.write(|tx| {
        set_meta(tx, &override_key(account), &record.to_string())?;
        append(
            tx,
            NewEvent {
                worker: "owner",
                run: None,
                kind: "quota_override",
                resource: account,
                payload: record.clone(),
            },
        )?;
        Ok(())
    })?;
    Ok(json!({"ok": true, "account": account, "until": iso(until)}))
}

/// Refuses new work when the account is too full, or when too many of its workers already hold
/// work for what is known about it.
pub fn gate(conn: &Connection, policy: &QuotaPolicy, who: &Worker) -> HubResult<()> {
    let now = now_ms();
    if owner_override(conn, &who.account, now)?.is_some() {
        return Ok(());
    }
    let current: Vec<Sample> = samples(conn)?
        .into_iter()
        .filter(|s| s.account == who.account && s.confidence(policy, now) != "unknown")
        .collect();
    // A stale high reading still blocks: usage does not fall before the window resets.
    let over: Vec<&Sample> = current
        .iter()
        .filter(|s| s.used_pct.is_some_and(|u| u >= policy.stop_percent))
        .collect();
    if !over.is_empty() {
        let worst = over
            .iter()
            .filter_map(|s| s.used_pct)
            .fold(0.0_f64, f64::max);
        let resume = over
            .iter()
            .filter_map(|s| s.resets_at)
            .max()
            .map(|r| iso(r + (policy.resume_margin_secs as i64) * 1000));
        return Err(HubError::refused(
            "quota",
            format!(
                "account {} used {worst:.0}% (limit {:.0}%)",
                who.account, policy.stop_percent
            ),
            format!(
                "checkpoint and resume after resume_after; only the owner may authorize more, at a \
                 terminal: stenio hub quota override --account {} --for 4h --reason <why>",
                who.account
            ),
        )
        .with("account", who.account.clone())
        .with("resume_after", resume));
    }
    let fresh: Vec<f64> = current
        .iter()
        .filter(|s| s.confidence(policy, now) == "measured")
        .filter_map(|s| s.used_pct)
        .collect();
    let (limit, why) = if fresh.is_empty() {
        (
            policy.unknown_workers,
            "its quota is unknown or stale".to_string(),
        )
    } else if fresh.iter().any(|u| *u >= policy.throttle_percent) {
        (
            policy.throttle_workers,
            format!("it used {:.0}% or more", policy.throttle_percent),
        )
    } else {
        return Ok(());
    };
    let busy = busy_workers(conn, who)?;
    if busy >= limit {
        return Err(HubError::refused(
            "quota",
            format!(
                "account {} already has {busy} working worker(s) and allows {limit} while {why}",
                who.account
            ),
            "stenio hub quota refresh, or join with another --account",
        )
        .with("account", who.account.clone())
        .with("resume_after", Value::Null));
    }
    Ok(())
}

/// Every window of every account that is sampled, declared or used by a worker.
pub fn show(conn: &Connection, policy: &QuotaPolicy) -> HubResult<Vec<Value>> {
    let now = now_ms();
    let all = samples(conn)?;
    let mut out: Vec<Value> = all
        .iter()
        .map(|s| {
            let confidence = s.confidence(policy, now);
            let reason = match (&s.reason, s.used_pct) {
                (Some(r), _) => Some(r.clone()),
                (None, Some(_)) if confidence == "unknown" => {
                    Some("the window has reset since the last reading".to_string())
                }
                _ => None,
            };
            json!({
                "account": s.account,
                "window": s.window,
                "used_pct": if confidence == "unknown" { None } else { s.used_pct },
                "resets_at": s.resets_at.map(iso),
                "observed_at": iso(s.observed_at),
                "age_secs": (now - s.observed_at) / 1000,
                "source": s.source,
                "confidence": confidence,
                "reason": reason,
            })
        })
        .collect();
    let mut expected: BTreeSet<String> = policy.source.iter().map(|s| s.account.clone()).collect();
    let mut stmt = conn.prepare("SELECT DISTINCT account FROM workers")?;
    let used = stmt.query_map([], |r| r.get::<_, String>(0))?;
    for account in used {
        expected.insert(account?);
    }
    let sampled: BTreeSet<&str> = all.iter().map(|s| s.account.as_str()).collect();
    for account in expected.iter().filter(|a| !sampled.contains(a.as_str())) {
        let declared = policy.source.iter().any(|s| &s.account == account);
        out.push(json!({
            "account": account,
            "window": NO_WINDOW,
            "used_pct": Value::Null,
            "confidence": "unknown",
            "reason": if declared {
                "never read: run stenio hub quota refresh"
            } else {
                "no source declared for this account"
            },
        }));
    }
    Ok(out)
}

/// Stores the windows of one account, replacing what was known about it.
pub fn put(store: &mut Store, account: &str, source: &str, windows: &[Window]) -> HubResult<Value> {
    if windows.is_empty() {
        return Err(HubError::Usage("no quota window to store".to_string()));
    }
    for w in windows {
        if !(w.used_pct.is_finite() && w.used_pct >= 0.0) || w.window == NO_WINDOW {
            return Err(HubError::Usage(format!(
                "invalid quota window '{}'",
                w.window
            )));
        }
    }
    let now = now_ms();
    store.write(|tx| {
        // A manual or partial push replaces only the windows it names.
        tx.execute(
            "DELETE FROM quota WHERE account = ?1 AND window = ?2",
            params![account, NO_WINDOW],
        )?;
        for w in windows {
            tx.execute(
                "INSERT OR REPLACE INTO quota(account, window, used_pct, resets_at, \
                 observed_at, source, reason) VALUES(?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![account, w.window, w.used_pct, w.resets_at, now, source],
            )?;
        }
        let listed: Vec<Value> = windows
            .iter()
            .map(|w| json!({"window": w.window, "used_pct": w.used_pct, "resets_at": w.resets_at}))
            .collect();
        append(
            tx,
            NewEvent {
                worker: "",
                run: None,
                kind: "quota",
                resource: account,
                payload: json!({"source": source, "windows": listed}),
            },
        )?;
        Ok(json!({"ok": true, "account": account, "windows": listed.len()}))
    })
}

/// Records why an account could not be read. Earlier readings stay and age into "stale".
pub fn put_unknown(store: &mut Store, account: &str, source: &str, reason: &str) -> HubResult<()> {
    store.write(|tx| {
        tx.execute(
            "INSERT OR REPLACE INTO quota(account, window, used_pct, resets_at, observed_at, \
             source, reason) VALUES(?1, ?2, NULL, NULL, ?3, ?4, ?5)",
            params![account, NO_WINDOW, now_ms(), source, reason],
        )?;
        append(
            tx,
            NewEvent {
                worker: "",
                run: None,
                kind: "quota_unknown",
                resource: account,
                payload: json!({"source": source, "reason": reason}),
            },
        )?;
        Ok(())
    })
}

fn rfc3339_ms(value: &Value) -> Option<i64> {
    value
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.timestamp_millis())
}

/// The JSON of `hermes usage --json`: `windows[].{label, used_percent, resets_at}`.
pub fn parse_usage(text: &str) -> Result<Vec<Window>, String> {
    let body: Value =
        serde_json::from_str(text.trim()).map_err(|_| "the output is not JSON".to_string())?;
    if let Some(reason) = body["unavailable_reason"].as_str() {
        return Err(format!("the source reports: {reason}"));
    }
    let windows: Vec<Window> = body["windows"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|w| {
            Some(Window {
                window: w["label"].as_str()?.to_string(),
                used_pct: w["used_percent"].as_f64()?,
                resets_at: rfc3339_ms(&w["resets_at"]),
            })
        })
        .collect();
    if windows.is_empty() {
        Err("the source returned no window with a percentage".to_string())
    } else {
        Ok(windows)
    }
}

/// The status line input of Claude Code: `rate_limits.<window>.{used_percentage, resets_at}`,
/// with `resets_at` in Unix seconds. Each window may be absent.
pub fn parse_statusline(text: &str) -> Result<Vec<Window>, String> {
    let body: Value =
        serde_json::from_str(text.trim()).map_err(|_| "the input is not JSON".to_string())?;
    let limits = body["rate_limits"]
        .as_object()
        .ok_or("the status line input carries no rate_limits")?;
    let windows: Vec<Window> = limits
        .iter()
        .filter_map(|(name, w)| {
            Some(Window {
                window: name.clone(),
                used_pct: w["used_percentage"].as_f64()?,
                resets_at: w["resets_at"].as_i64().map(|s| s.saturating_mul(1000)),
            })
        })
        .collect();
    if windows.is_empty() {
        Err("rate_limits has no window with used_percentage".to_string())
    } else {
        Ok(windows)
    }
}

/// Runs one declared command. Its error output is discarded: it may contain credentials.
fn read_source(source: &QuotaSource, timeout: Duration) -> Result<Vec<Window>, String> {
    let (program, args) = source.command.split_first().ok_or("empty command")?;
    let mut command = Command::new(program);
    command.args(args);
    let out = crate::verify_release::spawn_with_timeout(command, timeout)
        .map_err(|e| format!("{program}: {e}"))?;
    if out.code != 0 {
        return Err(format!("{program} exited {}", out.code));
    }
    parse_usage(&out.stdout)
}

/// Reads one declared source and stores what it says. The command runs outside any transaction.
fn read_into(store: &mut Store, policy: &QuotaPolicy, source: &QuotaSource) -> HubResult<String> {
    let timeout = Duration::from_secs(policy.command_timeout_secs);
    let label = source.command.join(" ");
    match read_source(source, timeout) {
        Ok(windows) => {
            store.write(|tx| {
                tx.execute("DELETE FROM quota WHERE account = ?1", [&source.account])?;
                Ok(())
            })?;
            put(store, &source.account, &label, &windows)?;
            Ok(format!("{} window(s)", windows.len()))
        }
        Err(reason) => {
            put_unknown(store, &source.account, &label, &reason)?;
            Ok(format!("unknown: {reason}"))
        }
    }
}

/// Reads every declared source.
pub fn refresh(store: &mut Store, policy: &QuotaPolicy) -> HubResult<Value> {
    let mut report = BTreeMap::new();
    for source in &policy.source {
        let said = read_into(store, policy, source)?;
        report.insert(source.account.clone(), said);
    }
    Ok(json!({"ok": true, "refreshed": report}))
}

/// Reads the sources of `account` unless every sample of it is still fresh, so a claim is judged
/// on a current reading without a manual refresh. A failing source leaves it unknown.
pub fn refresh_stale(store: &mut Store, policy: &QuotaPolicy, account: &str) -> HubResult<()> {
    let sources: Vec<&QuotaSource> = policy
        .source
        .iter()
        .filter(|s| s.account == account)
        .collect();
    if sources.is_empty() {
        return Ok(());
    }
    let now = now_ms();
    let fresh = store.read(|c| {
        let mine: Vec<Sample> = samples(c)?
            .into_iter()
            .filter(|s| s.account == account)
            .collect();
        Ok(!mine.is_empty() && mine.iter().all(|s| s.confidence(policy, now) == "measured"))
    })?;
    if !fresh {
        for source in sources {
            read_into(store, policy, source)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod override_tests {
    use super::*;
    use crate::hub::config::Config;
    use crate::hub::ledger::{self, ClaimRequest, Join};

    #[test]
    fn only_a_recorded_owner_override_lifts_the_gate() -> HubResult<()> {
        let dir = std::env::temp_dir().join(format!("stenio-override-{}", std::process::id()));
        let result = (|| {
            let mut cfg = Config::embedded()?;
            cfg.quota.source.clear();
            let mut store = Store::open(&dir.join("hub.db"))?;
            let join = Join {
                harness: "t".to_string(),
                ..Join::default()
            };
            let worker = ledger::join(&mut store, &cfg, &join)?["worker"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let window = Window {
                window: "w".to_string(),
                used_pct: 91.0,
                resets_at: None,
            };
            put(&mut store, "t", "test", &[window])?;
            let request = ClaimRequest {
                worker,
                resources: vec!["row:GB-001".to_string()],
                ttl_secs: Some(60),
                run: None,
                path: None,
            };
            let code = |r: HubResult<Value>| r.err().map(|e| e.code().to_string());
            assert_eq!(
                code(ledger::claim(&mut store, &cfg, &request)).as_deref(),
                Some("quota")
            );
            let agent = set_override(&mut store, "t", 60, "agent", false);
            assert_eq!(code(agent).as_deref(), Some("owner_only"));
            assert!(set_override(&mut store, "t", 90_000, "too long", true).is_err());
            assert_eq!(
                code(ledger::claim(&mut store, &cfg, &request)).as_deref(),
                Some("quota")
            );
            set_override(&mut store, "t", 60, "owner says go", true)?;
            ledger::claim(&mut store, &cfg, &request)?;
            let recorded = store.read(crate::hub::store::events)?;
            assert!(recorded.iter().any(|e| e.kind == "quota_override"));
            let report = crate::hub::audit::audit(&mut store, None, false)?;
            assert_eq!(report["ok"], json!(true), "{report}");
            set_override(&mut store, "t", 0, "revoked", true)?;
            let now = store.read(|c| owner_override(c, "t", now_ms()))?;
            assert!(now.is_none());
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}
