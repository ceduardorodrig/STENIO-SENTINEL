//! `hub audit`: the chain is intact, and the state tables say exactly what the events say.

use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::store::{self, Event, GENESIS, Store};
use super::{HubResult, ledger, view};

/// Longest list of problems returned; the count is always complete.
const SHOWN: usize = 20;

#[derive(Debug, Default, PartialEq)]
struct ClaimState {
    holder: String,
    expires: i64,
    reason: Option<String>,
    checkpoint: Option<Value>,
}

#[derive(Debug, Default)]
struct Replay {
    claims: BTreeMap<(i64, String), ClaimState>,
    /// `(row, fence)` to `(verdict, current, worker)`.
    results: BTreeMap<(String, i64), (String, bool, String)>,
    answers: BTreeMap<i64, Option<String>>,
}

impl Replay {
    fn apply(&mut self, event: &Event) {
        let payload: Value = serde_json::from_str(&event.payload).unwrap_or(Value::Null);
        let fence = payload["fence"].as_i64().unwrap_or(-1);
        let key = (fence, event.resource.clone());
        let row = event.resource.trim_start_matches("row:").to_string();
        match event.kind.as_str() {
            "claim" => {
                self.claims.insert(
                    key,
                    ClaimState {
                        holder: event.worker.clone(),
                        expires: payload["expires"].as_i64().unwrap_or(0),
                        ..ClaimState::default()
                    },
                );
            }
            "beat" => {
                if let Some(c) = self.claims.get_mut(&key) {
                    c.expires = payload["expires"].as_i64().unwrap_or(0);
                }
            }
            "release" | "lease_expired" => {
                if let Some(c) = self.claims.get_mut(&key) {
                    c.reason = payload["reason"].as_str().map(str::to_string);
                }
            }
            "checkpoint" => {
                if let Some(c) = self.claims.get_mut(&key) {
                    let mut body = payload.clone();
                    if let Some(map) = body.as_object_mut() {
                        map.remove("fence");
                    }
                    c.checkpoint = Some(body);
                }
            }
            "handback" => {
                let verdict = payload["verdict"].as_str().unwrap_or("").to_string();
                self.results
                    .insert((row, fence), (verdict, true, event.worker.clone()));
            }
            "result_superseded" => {
                if let Some(r) = self.results.get_mut(&(row, fence)) {
                    r.1 = false;
                }
            }
            "question" => {
                if let Some(id) = payload["id"].as_i64() {
                    self.answers.insert(id, None);
                }
            }
            "answer" => {
                if let Some(id) = payload["id"].as_i64() {
                    self.answers
                        .insert(id, payload["answer"].as_str().map(str::to_string));
                }
            }
            _ => {}
        }
    }
}

/// The first broken link of the chain, as `(seq, why)`.
fn chain_break(events: &[Event], head: Option<(String, String)>) -> Option<(i64, String)> {
    let mut prev = GENESIS.to_string();
    for (n, e) in events.iter().enumerate() {
        let expected_seq = n as i64 + 1;
        if e.seq != expected_seq {
            return Some((expected_seq, "an event is missing".to_string()));
        }
        if e.prev_hash != prev {
            return Some((e.seq, "it does not link to the previous event".to_string()));
        }
        if e.hash != e.expected_hash() {
            return Some((e.seq, "its content does not match its hash".to_string()));
        }
        prev.clone_from(&e.hash);
    }
    let (seq, hash) = head.unwrap_or_else(|| ("0".to_string(), GENESIS.to_string()));
    if seq != events.len().to_string() || hash != prev {
        return Some((
            events.len() as i64 + 1,
            "the chain is shorter than the recorded head".to_string(),
        ));
    }
    None
}

fn compare_claims(conn: &Connection, replay: &Replay) -> HubResult<Vec<String>> {
    let mut problems = Vec::new();
    let stored = ledger::claims(conn, "", [])?;
    let mut live: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &stored {
        if c.released.is_none() {
            *live.entry(c.resource.as_str()).or_default() += 1;
        }
        let actual = ClaimState {
            holder: c.holder.clone(),
            expires: c.expires,
            reason: c.reason.clone(),
            checkpoint: c
                .checkpoint
                .as_deref()
                .and_then(|t| serde_json::from_str(t).ok()),
        };
        if replay.claims.get(&(c.fence, c.resource.clone())) != Some(&actual)
            || c.released.is_none() != c.reason.is_none()
        {
            problems.push(format!(
                "claim {} fence {} differs from its events",
                c.resource, c.fence
            ));
        }
    }
    if stored.len() != replay.claims.len() {
        problems.push(format!(
            "{} claims stored, {} in the events",
            stored.len(),
            replay.claims.len()
        ));
    }
    for (resource, n) in live.into_iter().filter(|(_, n)| *n > 1) {
        problems.push(format!("{resource} has {n} live holders"));
    }
    Ok(problems)
}

fn compare_results(conn: &Connection, replay: &Replay) -> HubResult<Vec<String>> {
    let mut problems = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT row, fence, verdict, current, worker, IFNULL(run, '') FROM results ORDER BY id",
    )?;
    let stored = stmt
        .query_map([], |r| {
            Ok((
                (r.get::<_, String>(0)?, r.get::<_, i64>(1)?),
                (
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, String>(4)?,
                ),
                r.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut current: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (key, value, run) in &stored {
        if value.1 {
            *current.entry((key.0.clone(), run.clone())).or_default() += 1;
        }
        if replay.results.get(key) != Some(value) {
            problems.push(format!(
                "result of {} fence {} differs from its events",
                key.0, key.1
            ));
        }
    }
    if stored.len() != replay.results.len() {
        problems.push(format!(
            "{} results stored, {} in the events",
            stored.len(),
            replay.results.len()
        ));
    }
    for ((row, _), n) in current.into_iter().filter(|(_, n)| *n > 1) {
        problems.push(format!("{row} has {n} accepted results"));
    }
    for q in view::questions(conn, false)? {
        let id = q["id"].as_i64().unwrap_or(-1);
        let answer = q["answer"].as_str().map(str::to_string);
        if replay.answers.get(&id) != Some(&answer) {
            problems.push(format!("question {id} differs from its events"));
        }
    }
    Ok(problems)
}

/// Verifies the ledger. `ok` is false on any integrity problem and, with `require_final`, while
/// a row of the run has no final state.
pub fn audit(store: &mut Store, run: Option<&str>, require_final: bool) -> HubResult<Value> {
    store.read(|conn| {
        let events = store::events(conn)?;
        let head = store::meta(conn, "head_seq")?.zip(store::meta(conn, "head_hash")?);
        let broken = chain_break(&events, head);
        let mut problems = Vec::new();
        let sound: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if sound != "ok" {
            problems.push(format!("database integrity: {sound}"));
        }
        let mut replay = Replay::default();
        for e in &events {
            replay.apply(e);
        }
        problems.extend(compare_claims(conn, &replay)?);
        problems.extend(compare_results(conn, &replay)?);
        let mut rows = Vec::new();
        if let Some(run) = run {
            for row in ledger::run_rows(conn, run)? {
                let state = view::row_state(conn, &row, Some(run))?;
                rows.push(json!({"row": row, "state": state["state"]}));
            }
            if rows.is_empty() {
                problems.push(format!("run {run} has no rows"));
            }
        }
        let open = rows
            .iter()
            .filter(|r| !view::is_final(r["state"].as_str().unwrap_or("")))
            .count();
        let complete = run.is_some() && open == 0 && !rows.is_empty();
        let ok = broken.is_none() && problems.is_empty() && (!require_final || complete);
        let total = problems.len();
        problems.truncate(SHOWN);
        let mut out = json!({"ok": ok, "events": events.len(), "chain": broken.is_none(),
            "first_bad_seq": broken.as_ref().map(|b| b.0),
            "chain_problem": broken.map(|b| b.1),
            "problems": problems, "problem_count": total});
        if let Some(run) = run {
            out["run"] = json!(run);
            out["rows"] = json!(rows);
            out["rows_without_final_state"] = json!(open);
            out["complete"] = json!(complete);
        }
        if !ok {
            out["code"] = json!("audit_failed");
        }
        Ok(out)
    })
}
