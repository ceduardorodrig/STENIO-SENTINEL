//! Read-only views: status, run state, questions, backlog rows and the event export. Every list
//! is paged, so a result never grows past what an agent can read.

use rusqlite::Connection;
use serde_json::{Value, json};
use std::path::Path;

use super::config::Config;
use super::ledger::{self, Claim, EXPIRED};
use super::store::{self, Store};
use super::{HubError, HubResult, iso, now_ms, quota};
use crate::backlog::queue_index::{present_queues, row_line};

/// Serialized size one page of items aims to stay under.
const PAGE_BYTES: usize = 5_000;
/// Longest single text field of a backlog result.
const TEXT_BYTES: usize = 4_000;

/// The items from `cursor` that fit one page, and the cursor of the next page.
pub fn paginate(items: Vec<Value>, cursor: usize) -> (Vec<Value>, Option<usize>) {
    let total = items.len();
    let mut size = 0;
    let mut page = Vec::new();
    for item in items.into_iter().skip(cursor) {
        size += item.to_string().len() + 1;
        if !page.is_empty() && size > PAGE_BYTES {
            break;
        }
        page.push(item);
    }
    let end = cursor + page.len();
    (page, (end < total).then_some(end))
}

/// A UTF-8 safe window of `text` from byte `from`, with the offset of the rest.
fn slice(text: &str, from: usize) -> (&str, Option<usize>) {
    let mut start = from.min(text.len());
    while !text.is_char_boundary(start) {
        start += 1;
    }
    let mut end = (start + TEXT_BYTES).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[start..end], (end < text.len()).then_some(end))
}

/// The state of one row inside a run (`None`: rows claimed outside any run).
pub fn row_state(conn: &Connection, row: &str, run: Option<&str>) -> HubResult<Value> {
    let now = now_ms();
    let name = format!("row:{row}");
    let claim: Option<Claim> = ledger::claims(
        conn,
        "WHERE resource = ?1 AND IFNULL(run, '') = ?2",
        [name.as_str(), run.unwrap_or_default()],
    )?
    .pop();
    let mut stmt = conn.prepare(
        "SELECT verdict, worker, fence, proof, remaining FROM results \
         WHERE row = ?1 AND IFNULL(run, '') = ?2 AND current = 1",
    )?;
    let results = stmt
        .query_map([row, run.unwrap_or_default()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let waiting: i64 = conn.query_row(
        "SELECT COUNT(*) FROM questions WHERE row = ?1 AND state = 'waiting'",
        [row],
        |r| r.get(0),
    )?;
    let mut out = json!({"kind": "row", "row": row, "run": run});
    let live = claim.as_ref().filter(|c| c.live(now));
    let result = results.first();
    let state = if let Some(c) = live {
        out["holder"] = json!(c.holder);
        out["fence"] = json!(c.fence);
        out["expires"] = json!(iso(c.expires));
        "claimed"
    } else if let Some(c) = claim.as_ref().filter(|c| {
        // An expired lease newer than the last result: someone started again and vanished.
        (c.released.is_none() || c.reason.as_deref() == Some(EXPIRED))
            && result.is_none_or(|(_, _, fence)| c.fence > *fence)
    }) {
        out["holder"] = json!(c.holder);
        out["fence"] = json!(c.fence);
        out["checkpoint"] = c
            .checkpoint
            .as_deref()
            .and_then(|t| serde_json::from_str(t).ok())
            .unwrap_or(Value::Null);
        "stale"
    } else if let Some((verdict, worker, fence)) = result {
        out["by"] = json!(worker);
        out["fence"] = json!(fence);
        // "done" is the worker's claim: nothing replayed it yet.
        match verdict.as_str() {
            "done" => "review",
            other => other,
        }
    } else if waiting > 0 {
        "needs-owner"
    } else {
        "ready"
    };
    out["state"] = json!(state);
    out["questions_waiting"] = json!(waiting);
    Ok(out)
}

/// Whether a row state ends the work of a run.
pub fn is_final(state: &str) -> bool {
    matches!(
        state,
        "review" | "partial" | "blocked" | "needs-owner" | "failed"
    )
}

pub fn questions(conn: &Connection, only_waiting: bool) -> HubResult<Vec<Value>> {
    let filter = if only_waiting {
        "WHERE state = 'waiting'"
    } else {
        ""
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT id, run, row, worker, text, options, recommendation, state, answer, asked \
         FROM questions {filter} ORDER BY id"
    ))?;
    let rows = stmt.query_map([], |r| {
        let options: String = r.get(5)?;
        Ok(json!({
            "kind": "question",
            "id": r.get::<_, i64>(0)?,
            "run": r.get::<_, Option<String>>(1)?,
            "row": r.get::<_, Option<String>>(2)?,
            "worker": r.get::<_, String>(3)?,
            "text": r.get::<_, String>(4)?,
            "options": serde_json::from_str::<Value>(&options).unwrap_or(Value::Null),
            "recommendation": r.get::<_, Option<String>>(6)?,
            "state": r.get::<_, String>(7)?,
            "answer": r.get::<_, Option<String>>(8)?,
            "asked": iso(r.get(9)?),
        }))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn run_items(conn: &Connection, run: &str) -> HubResult<Vec<Value>> {
    ledger::run_rows(conn, run)?
        .iter()
        .map(|row| row_state(conn, row, Some(run)))
        .collect()
}

/// Who holds what, the rows of the open runs (or of `run`), waiting questions and quota.
pub fn status(
    store: &mut Store,
    cfg: &Config,
    run: Option<&str>,
    cursor: usize,
) -> HubResult<Value> {
    ledger::sweep_now(store)?;
    store.read(|conn| {
        let runs = ledger::open_runs(conn)?;
        let wanted: Vec<String> = match run {
            Some(run) => vec![run.to_string()],
            None => runs
                .iter()
                .filter_map(|r| r["run"].as_str().map(str::to_string))
                .collect(),
        };
        let mut items = Vec::new();
        for claim in ledger::claims(conn, "WHERE released IS NULL", [])? {
            let mut item = claim.to_json();
            item["kind"] = json!("claim");
            item["harness"] = json!(ledger::worker(conn, &claim.holder)?.harness);
            items.push(item);
        }
        for run in &wanted {
            items.extend(run_items(conn, run)?);
        }
        items.extend(questions(conn, true)?);
        for mut entry in quota::show(conn, &cfg.quota)? {
            entry["kind"] = json!("quota");
            items.push(entry);
        }
        let mut counts = serde_json::Map::new();
        for item in &items {
            let key = match item["kind"].as_str() {
                Some("row") => format!("rows_{}", item["state"].as_str().unwrap_or("?")),
                Some(kind) => kind.to_string(),
                None => continue,
            };
            let n = counts.get(&key).and_then(Value::as_u64).unwrap_or(0);
            counts.insert(key, json!(n + 1));
        }
        let (page, next) = paginate(items, cursor);
        Ok(
            json!({"ok": true, "open_runs": runs.len(), "counts": counts, "items": page,
            "next_cursor": next}),
        )
    })
}

pub fn run_show(store: &mut Store, run: &str, cursor: usize) -> HubResult<Value> {
    ledger::sweep_now(store)?;
    store.read(|conn| {
        let (goal, vault, slots, state): (String, String, i64, String) = conn
            .query_row(
                "SELECT goal, vault, slots, state FROM runs WHERE id = ?1",
                [run],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => HubError::refused(
                    "unknown_run",
                    format!("run '{run}' does not exist"),
                    "stenio hub status",
                ),
                other => other.into(),
            })?;
        let (page, next) = paginate(run_items(conn, run)?, cursor);
        Ok(
            json!({"ok": true, "run": run, "goal": goal, "vault": vault, "slots": slots,
            "state": state, "items": page, "next_cursor": next}),
        )
    })
}

/// One row of a queue by id, or the rows that contain `query` (active and archive).
pub fn backlog(
    root: &Path,
    id: Option<&str>,
    query: Option<&str>,
    queue: Option<&str>,
    cursor: usize,
) -> HubResult<Value> {
    let wanted = queue.map(|q| q.trim_end_matches('-').to_uppercase());
    let queues: Vec<_> = present_queues(root)
        .into_iter()
        .filter(|q| wanted.as_ref().is_none_or(|w| *w == q.prefix))
        .collect();
    if queues.is_empty() {
        return Err(HubError::refused(
            "no_queue",
            format!("no matching queue under {}", root.display()),
            "pass --path <vault or repository root>",
        ));
    }
    let id = id.map(super::resource::row_id).transpose()?;
    let needle = query
        .map(str::to_lowercase)
        .filter(|q| !q.trim().is_empty());
    if id.is_none() && needle.is_none() {
        return Err(HubError::Usage("give --id or --query".to_string()));
    }
    let mut found = Vec::new();
    for q in &queues {
        for (file, archived) in [(q.active(), false), (q.archive(), true)] {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            match (&id, &needle) {
                (Some(id), _) => {
                    if let Some(line) = row_line(&text, id) {
                        let (part, rest) = slice(line, cursor);
                        return Ok(json!({"ok": true, "id": id, "archived": archived,
                            "file": file.display().to_string(), "row": part,
                            "next_cursor": rest}));
                    }
                }
                (None, Some(needle)) => {
                    let prefix = format!("| **{}-", q.prefix);
                    for line in text.lines().filter(|l| l.starts_with(&prefix)) {
                        if !line.to_lowercase().contains(needle) {
                            continue;
                        }
                        let cell = line.split('|').nth(1).unwrap_or("").trim();
                        let title: String = line
                            .split('|')
                            .nth(2)
                            .unwrap_or("")
                            .trim()
                            .chars()
                            .take(140)
                            .collect();
                        found.push(json!({"id": cell.trim_matches('*'),
                            "archived": archived, "title": title}));
                    }
                }
                (None, None) => {}
            }
        }
    }
    if let Some(id) = id {
        return Err(HubError::refused(
            "unknown_row",
            format!("{id} is in no queue under {}", root.display()),
            "stenio hub backlog --query <words>",
        ));
    }
    let total = found.len();
    let (page, next) = paginate(found, cursor);
    Ok(json!({"ok": true, "matches": total, "items": page, "next_cursor": next}))
}

/// The event chain as one JSON object per line; enough on its own to rebuild the order.
pub fn export(store: &mut Store, run: Option<&str>) -> HubResult<String> {
    store.read(|conn| {
        let mut out = String::new();
        for e in store::events(conn)? {
            if run.is_some_and(|r| e.run != r) {
                continue;
            }
            let payload = serde_json::from_str::<Value>(&e.payload).unwrap_or(Value::Null);
            let line = json!({"seq": e.seq, "at": iso(e.at), "at_ms": e.at, "worker": e.worker,
                "run": e.run, "type": e.kind, "resource": e.resource, "payload": payload,
                "payload_text": e.payload, "prev_hash": e.prev_hash, "hash": e.hash});
            out.push_str(&line.to_string());
            out.push('\n');
        }
        Ok(out)
    })
}

/// The queue root: the given or current directory when it holds queues, else the vault of the
/// open runs when they all agree.
pub fn resolve_root(
    store: Option<&mut Store>,
    given: Option<&Path>,
) -> HubResult<std::path::PathBuf> {
    if let Some(root) = super::config::discover_root(given) {
        return Ok(root);
    }
    if given.is_none()
        && let Some(store) = store
    {
        let mut vaults: Vec<String> = store
            .read(ledger::open_runs)?
            .iter()
            .filter_map(|r| r["vault"].as_str().map(str::to_string))
            .collect();
        vaults.sort();
        vaults.dedup();
        if let [only] = vaults.as_slice() {
            return Ok(only.into());
        }
    }
    Err(HubError::refused(
        "no_queue",
        "no backlog queue found from here",
        "pass --path <vault or repository root>",
    ))
}

/// The quota windows, paged.
pub fn quota_view(store: &mut Store, cfg: &Config, cursor: usize) -> HubResult<Value> {
    let all = store.read(|conn| quota::show(conn, &cfg.quota))?;
    let (page, next) = paginate(all, cursor);
    Ok(json!({"ok": true, "items": page, "next_cursor": next}))
}

pub fn questions_view(store: &mut Store, all: bool, cursor: usize) -> HubResult<Value> {
    let found = store.read(|conn| questions(conn, !all))?;
    let (page, next) = paginate(found, cursor);
    Ok(json!({"ok": true, "items": page, "next_cursor": next}))
}
