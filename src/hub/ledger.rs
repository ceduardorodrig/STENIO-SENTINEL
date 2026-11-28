//! The state changes: join, runs, claims, heartbeats, hand-backs, checkpoints and questions.
//! Every one of them runs in one write transaction and appends its events inside it.

use rusqlite::{Connection, OptionalExtension, Params, Row, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::config::Config;
use super::resource::{self, Resource};
use super::store::{NewEvent, Store, append, next_counter};
use super::{HubError, HubResult, iso, now_ms, quota};
use crate::backlog::queue_index::{present_queues, row_line};

pub const VERDICTS: [&str; 5] = ["done", "partial", "blocked", "needs-owner", "failed"];
pub const EVENT_KINDS: [&str; 3] = ["checkpoint", "progress", "note"];

/// Release reasons recorded on a claim.
pub const EXPIRED: &str = "expired";
const RELEASED: &str = "released";
const HANDBACK: &str = "handback";

#[derive(Debug, Clone)]
pub struct Claim {
    pub id: i64,
    pub resource: String,
    pub holder: String,
    pub fence: i64,
    pub run: Option<String>,

    pub ttl_ms: i64,
    pub expires: i64,
    pub released: Option<i64>,
    pub reason: Option<String>,
    pub checkpoint: Option<String>,
}

impl Claim {
    pub fn live(&self, now: i64) -> bool {
        self.released.is_none() && self.expires > now
    }

    pub fn to_json(&self) -> Value {
        json!({
            "resource": self.resource,
            "holder": self.holder,
            "fence": self.fence,
            "run": self.run,
            "expires": iso(self.expires),
        })
    }

    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Claim {
            id: r.get(0)?,
            resource: r.get(1)?,
            holder: r.get(2)?,
            fence: r.get(3)?,
            run: r.get(4)?,

            ttl_ms: r.get(5)?,
            expires: r.get(6)?,
            released: r.get(7)?,
            reason: r.get(8)?,
            checkpoint: r.get(9)?,
        })
    }
}

/// Claims matching `filter` (a `WHERE ...` clause of fixed text), oldest first.
pub fn claims<P: Params>(conn: &Connection, filter: &str, args: P) -> HubResult<Vec<Claim>> {
    let sql = format!(
        "SELECT id, resource, holder, fence, run, ttl_ms, expires, released, reason, \
         checkpoint FROM claims {filter} ORDER BY id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(args, Claim::from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn latest_claim(conn: &Connection, resource: &str) -> HubResult<Option<Claim>> {
    Ok(claims(conn, "WHERE resource = ?1", [resource])?.pop())
}

#[derive(Debug, Clone)]
pub struct Worker {
    pub id: String,
    pub harness: String,
    pub account: String,
    pub last_beat: i64,
    pub host: Option<String>,
    pub parent: Option<String>,
}

pub fn worker(conn: &Connection, id: &str) -> HubResult<Worker> {
    conn.query_row(
        "SELECT id, harness, account, last_beat, host, parent FROM workers WHERE id = ?1",
        [id],
        |r| {
            Ok(Worker {
                id: r.get(0)?,
                harness: r.get(1)?,
                account: r.get(2)?,
                last_beat: r.get(3)?,
                host: r.get(4)?,
                parent: r.get(5)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| {
        HubError::refused(
            "unknown_worker",
            format!("worker '{id}' never joined this ledger"),
            "stenio hub join --harness <name>",
        )
    })
}

fn touch(conn: &Connection, worker: &str) -> HubResult<()> {
    conn.execute(
        "UPDATE workers SET last_beat = ?1 WHERE id = ?2",
        params![now_ms(), worker],
    )?;
    Ok(())
}

/// Marks a live claim as released and records the event that replay needs.
pub fn end_claim(
    conn: &Connection,
    claim: &Claim,
    reason: &str,
    note: Option<&str>,
) -> HubResult<()> {
    let now = now_ms();
    conn.execute(
        "UPDATE claims SET released = ?1, reason = ?2 WHERE id = ?3",
        params![now, reason, claim.id],
    )?;
    let checkpoint = claim
        .checkpoint
        .as_deref()
        .and_then(|c| serde_json::from_str::<Value>(c).ok());
    // Only an expiry has "expired"; a voluntary end names when the lease would have ended.
    let ends = if reason == EXPIRED {
        "expired_at"
    } else {
        "lease_until"
    };
    let mut payload = json!({"fence": claim.fence, "reason": reason, "note": note,
        "checkpoint": checkpoint});
    payload[ends] = json!(iso(claim.expires));
    append(
        conn,
        NewEvent {
            worker: &claim.holder,
            run: claim.run.as_deref(),
            kind: if reason == EXPIRED {
                "lease_expired"
            } else {
                "release"
            },
            resource: &claim.resource,
            payload,
        },
    )?;
    Ok(())
}

/// Ends every lease whose expiry has passed.
pub fn sweep(conn: &Connection) -> HubResult<usize> {
    let due = claims(conn, "WHERE released IS NULL AND expires <= ?1", [now_ms()])?;
    for claim in &due {
        end_claim(conn, claim, EXPIRED, None)?;
    }
    Ok(due.len())
}

/// Expiry is recorded on its own, so a refused operation does not roll it back.
pub fn sweep_now(store: &mut Store) -> HubResult<usize> {
    store.write(|tx| sweep(tx))
}

#[derive(Debug, Clone, Default)]
pub struct Join {
    pub harness: String,
    pub harness_version: Option<String>,
    pub model: Option<String>,
    pub host: Option<String>,
    pub parent: Option<String>,
    pub account: Option<String>,
    /// Harness session this worker belongs to; default: the declared session variables.
    pub session: Option<String>,
}

fn session_key(worker: &str) -> String {
    format!("session:{worker}")
}

fn agent_key(worker: &str) -> String {
    format!("agent:{worker}")
}

/// The sub-agent of a session that a worker belongs to (empty for the main thread), once a hook
/// has seen its join.
pub fn worker_agent(conn: &Connection, worker: &str) -> HubResult<Option<String>> {
    super::store::meta(conn, &agent_key(worker))
}

/// Binds a worker to the sub-agent that joined it. The first binding stays.
pub fn bind_agent(conn: &Connection, worker: &str, agent: &str) -> HubResult<()> {
    if worker_agent(conn, worker)?.is_none() {
        super::store::set_meta(conn, &agent_key(worker), agent)?;
    }
    Ok(())
}

/// Whether a worker joined with a harness session.
pub fn session_bound(conn: &Connection, worker: &str) -> HubResult<bool> {
    Ok(super::store::meta(conn, &session_key(worker))?.is_some())
}

/// The workers bound to a harness session.
pub fn session_workers(conn: &Connection, session: &str) -> HubResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT substr(key, 9) FROM meta WHERE key LIKE 'session:%' AND value = ?1 ORDER BY key",
    )?;
    let rows = stmt.query_map([session], |r| r.get(0))?;
    Ok(rows.collect::<Result<Vec<String>, _>>()?)
}

fn name_like(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn local_host() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

pub fn join(store: &mut Store, cfg: &Config, request: &Join) -> HubResult<Value> {
    let harness = request.harness.trim().to_lowercase();
    if !name_like(&harness) {
        return Err(HubError::Usage(
            "--harness is a short name (letters, digits, - _ .)".to_string(),
        ));
    }
    let account = request
        .account
        .clone()
        .unwrap_or_else(|| cfg.account_of(&harness));
    if !name_like(&account) {
        return Err(HubError::Usage("invalid account label".to_string()));
    }
    let host = request.host.clone().or_else(local_host);
    let session = request
        .session
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| super::hooks::join_session(cfg, &harness));
    store.write(|tx| {
        if let Some(parent) = &request.parent {
            worker(tx, parent)?;
        }
        let suffix: String = tx.query_row("SELECT lower(hex(randomblob(4)))", [], |r| r.get(0))?;
        let id = format!("{harness}-{suffix}");
        let now = now_ms();
        tx.execute(
            "INSERT INTO workers(id, harness, harness_version, model, host, parent, account, \
             joined, last_beat) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                id,
                harness,
                request.harness_version,
                request.model,
                host,
                request.parent,
                account,
                now
            ],
        )?;
        if let Some(session) = &session {
            super::store::set_meta(tx, &session_key(&id), session)?;
        }
        append(
            tx,
            NewEvent {
                worker: &id,
                run: None,
                kind: "join",
                resource: "",
                payload: json!({"harness": harness, "model": request.model, "host": host,
                    "parent": request.parent, "account": account, "session": session}),
            },
        )?;
        let runs = open_runs(tx)?;
        let mut out = json!({"ok": true, "worker": id, "account": account, "open_runs": runs,
            "lease_secs": cfg.lease.default_ttl_secs, "bound": session.is_some(),
            "next": "stenio hub status, then claim; beat before the lease expires"});
        if session.is_none() {
            out["warning"] = json!(unbound_warning(cfg, &harness, &id));
        }
        Ok(out)
    })
}

fn unbound_warning(cfg: &Config, harness: &str, worker: &str) -> String {
    let wanted = match cfg.session.harness.get(harness) {
        Some(name) => name.clone(),
        None => cfg.session.env.join(", "),
    };
    format!(
        "WORKER NOT BOUND to a harness session ({wanted} unset): no hook will EVER renew its \
         leases and the edit guard cannot protect its trees. Join again with --session <id>, or \
         export STENIO_HUB_WORKER={worker} in the harness environment, or run `stenio hub beat` \
         yourself before every lease ends."
    )
}

pub fn open_runs(conn: &Connection) -> HubResult<Vec<Value>> {
    let mut stmt = conn.prepare(
        "SELECT id, goal, vault, slots FROM runs WHERE state = 'open' ORDER BY created, id",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(
            json!({"run": r.get::<_, String>(0)?, "goal": r.get::<_, String>(1)?,
            "vault": r.get::<_, String>(2)?, "slots": r.get::<_, i64>(3)?}),
        )
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn run_state(conn: &Connection, run: &str) -> HubResult<(String, u32)> {
    conn.query_row("SELECT state, slots FROM runs WHERE id = ?1", [run], |r| {
        Ok((r.get(0)?, r.get(1)?))
    })
    .optional()?
    .ok_or_else(|| {
        HubError::refused(
            "unknown_run",
            format!("run '{run}' does not exist"),
            "stenio hub status",
        )
    })
}

pub fn run_rows(conn: &Connection, run: &str) -> HubResult<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT row FROM run_rows WHERE run = ?1 ORDER BY position, row")?;
    let rows = stmt.query_map([run], |r| r.get(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn open_runs_with_row(conn: &Connection, row: &str) -> HubResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT r.id FROM runs r JOIN run_rows w ON w.run = r.id \
         WHERE r.state = 'open' AND w.row = ?1",
    )?;
    let rows = stmt.query_map([row], |r| r.get(0))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// The listed rows by their canonical ids, each present in an active queue under `vault`.
pub fn run_row_ids(vault: &Path, rows: &[String]) -> HubResult<Vec<String>> {
    let queues = present_queues(vault);
    let mut ids: Vec<String> = Vec::new();
    for raw in rows.iter().flat_map(|r| r.split(',')) {
        if raw.trim().is_empty() {
            continue;
        }
        let id = resource::row_id(raw)?;
        if ids.contains(&id) {
            return Err(HubError::Usage(format!("{id} is listed twice")));
        }
        let found = queues.iter().any(|q| {
            std::fs::read_to_string(q.active()).is_ok_and(|text| row_line(&text, &id).is_some())
        });
        if !found {
            return Err(HubError::refused(
                "unknown_row",
                format!("{id} is not in an active queue under {}", vault.display()),
                "stenio hub backlog --id <ID>",
            ));
        }
        ids.push(id);
    }
    if ids.is_empty() {
        return Err(HubError::Usage("--rows must name at least one row".into()));
    }
    Ok(ids)
}

pub fn run_start(
    store: &mut Store,
    cfg: &Config,
    vault: &Path,
    rows: &[String],
    slots: Option<u32>,
    goal: &str,
) -> HubResult<Value> {
    let ids = run_row_ids(vault, rows)?;
    run_insert(store, cfg, &vault.display().to_string(), &ids, slots, goal)
}

/// Opens the run over rows that [`run_row_ids`] already found.
pub fn run_insert(
    store: &mut Store,
    cfg: &Config,
    vault: &str,
    ids: &[String],
    slots: Option<u32>,
    goal: &str,
) -> HubResult<Value> {
    let slots = slots.unwrap_or(cfg.fleet.ceiling);
    if slots == 0 || slots > cfg.fleet.ceiling {
        return Err(HubError::Usage(format!(
            "--slots must be between 1 and the fleet ceiling {}",
            cfg.fleet.ceiling
        )));
    }
    if ids.is_empty() {
        return Err(HubError::Usage("--rows must name at least one row".into()));
    }
    store.write(|tx| {
        for id in ids {
            if let Some(run) = open_runs_with_row(tx, id)?.first() {
                return Err(HubError::refused(
                    "row_in_run",
                    format!("{id} already belongs to the open run {run}"),
                    format!("stenio hub run close --run {run}"),
                ));
            }
        }
        let run = format!("run-{}", next_counter(tx, "run")?);
        tx.execute(
            "INSERT INTO runs(id, goal, vault, slots, state, created) \
             VALUES(?1, ?2, ?3, ?4, 'open', ?5)",
            params![run, goal, vault, slots, now_ms()],
        )?;
        for (position, id) in ids.iter().enumerate() {
            tx.execute(
                "INSERT INTO run_rows(run, row, position) VALUES(?1, ?2, ?3)",
                params![run, id, position as i64],
            )?;
        }
        append(
            tx,
            NewEvent {
                worker: "",
                run: Some(&run),
                kind: "run_started",
                resource: "",
                payload: json!({"goal": goal, "vault": vault, "slots": slots, "rows": ids}),
            },
        )?;
        Ok(json!({"ok": true, "run": run, "rows": ids, "slots": slots}))
    })
}

pub fn run_close(store: &mut Store, run: &str) -> HubResult<Value> {
    sweep_now(store)?;
    store.write(|tx| {
        let (state, _) = run_state(tx, run)?;
        if state != "open" {
            return Err(HubError::refused(
                "run_closed",
                format!("run {run} is already {state}"),
                "stenio hub run show --run <id>",
            ));
        }
        let live = claims(tx, "WHERE released IS NULL AND run = ?1", [run])?;
        if !live.is_empty() {
            let held: Vec<Value> = live.iter().map(Claim::to_json).collect();
            return Err(HubError::refused(
                "claims_open",
                format!("{} claim(s) of {run} are still held", live.len()),
                "hand back or release them, or wait for the leases to expire",
            )
            .with("claims", held));
        }
        tx.execute(
            "UPDATE runs SET state = 'closed', closed = ?1 WHERE id = ?2",
            params![now_ms(), run],
        )?;
        append(
            tx,
            NewEvent {
                worker: "",
                run: Some(run),
                kind: "run_closed",
                resource: "",
                payload: json!({}),
            },
        )?;
        Ok(json!({"ok": true, "run": run, "state": "closed"}))
    })
}

fn held(conn: &Connection, resource: &str) -> HubError {
    let holder = claims(conn, "WHERE released IS NULL AND resource = ?1", [resource])
        .ok()
        .and_then(|mut c| c.pop());
    match holder {
        Some(c) => HubError::refused(
            "held",
            format!(
                "{resource} is held by {} until {}",
                c.holder,
                iso(c.expires)
            ),
            "claim another resource (stenio hub status) or retry after the lease expires",
        )
        .with("resource", resource)
        .with("holder", c.holder.clone())
        .with("expires", iso(c.expires)),
        None => HubError::Store(format!("constraint failed on {resource} without a holder")),
    }
}

/// The one run in which the coordinator of `who` holds claims, if there is exactly one.
fn parent_run(conn: &Connection, who: &Worker) -> HubResult<Option<String>> {
    let Some(parent) = who.parent.as_deref() else {
        return Ok(None);
    };
    let mut runs: Vec<String> = claims(conn, "WHERE released IS NULL AND holder = ?1", [parent])?
        .into_iter()
        .filter_map(|c| c.run)
        .collect();
    runs.sort();
    runs.dedup();
    Ok(match runs.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    })
}

/// The run a claim belongs to: the named one, else the single open run that lists its rows. A
/// claim without a row joins a run only through its coordinator, never because one run happens
/// to be open (GB-422).
fn resolve_run(
    conn: &Connection,
    who: &Worker,
    named: Option<&str>,
    wanted: &[Resource],
) -> HubResult<Option<String>> {
    let rows: Vec<&str> = wanted
        .iter()
        .filter(|r| r.kind == "row")
        .map(Resource::value)
        .collect();
    let run = match named {
        Some(run) => {
            let (state, _) = run_state(conn, run)?;
            if state != "open" {
                return Err(HubError::refused(
                    "run_closed",
                    format!("run {run} is {state}"),
                    "stenio hub status",
                ));
            }
            Some(run.to_string())
        }
        None => {
            let mut found: Vec<String> = Vec::new();
            for row in &rows {
                found.extend(open_runs_with_row(conn, row)?);
            }
            found.dedup();
            if found.len() > 1 {
                return Err(HubError::Usage(
                    "the rows belong to different runs; claim them separately".to_string(),
                ));
            }
            match found.pop() {
                Some(run) => Some(run),
                None if rows.is_empty() => parent_run(conn, who)?,
                None => None,
            }
        }
    };
    if let Some(run) = &run {
        let listed = run_rows(conn, run)?;
        if let Some(row) = rows.iter().find(|r| !listed.iter().any(|l| l == *r)) {
            return Err(HubError::refused(
                "not_in_run",
                format!("{row} is not part of {run}"),
                format!("stenio hub run show --run {run}"),
            ));
        }
    }
    Ok(run)
}

/// The resource name to insert for a fleet claim: the first free slot under the ceiling.
fn fleet_slot(conn: &Connection, wanted: &Resource, ceiling: u32) -> HubResult<String> {
    let live = claims(
        conn,
        "WHERE released IS NULL AND resource LIKE 'fleet:%'",
        [],
    )?;
    let full = || {
        HubError::refused(
            "fleet_full",
            format!("{} of {ceiling} fleet slot(s) are taken", live.len()),
            "wait for a slot to be released (stenio hub status)",
        )
        .with("slots", ceiling)
    };
    if live.len() >= ceiling as usize {
        return Err(full());
    }
    if wanted.name != resource::ANY_SLOT {
        let number = wanted
            .name
            .rsplit('/')
            .next()
            .and_then(|n| n.parse::<u32>().ok());
        return match number {
            Some(n) if n <= ceiling => Ok(wanted.name.clone()),
            _ => Err(full()),
        };
    }
    (1..=ceiling)
        .map(|n| format!("{}/{n}", resource::ANY_SLOT))
        .find(|name| !live.iter().any(|c| &c.resource == name))
        .ok_or_else(full)
}

#[derive(Debug, Clone, Default)]
pub struct ClaimRequest {
    pub worker: String,
    pub resources: Vec<String>,
    pub run: Option<String>,
    pub ttl_secs: Option<u64>,
    /// Binds the `backlog:` claims of this request to the queues under this directory.
    pub path: Option<PathBuf>,
}

/// The queue directory a `backlog:` claim is bound to, as recorded in its event.
pub fn claim_scope(conn: &Connection, fence: i64, resource: &str) -> HubResult<Option<PathBuf>> {
    let mut stmt = conn.prepare(
        "SELECT payload FROM events WHERE type = 'claim' AND resource = ?1 ORDER BY seq DESC",
    )?;
    let payloads = stmt.query_map([resource], |r| r.get::<_, String>(0))?;
    for payload in payloads {
        let body: Value = serde_json::from_str(&payload?).unwrap_or(Value::Null);
        if body["fence"].as_i64() == Some(fence) {
            return Ok(body["scope"].as_str().map(PathBuf::from));
        }
    }
    Ok(None)
}

/// `name -> queue directory` for the `backlog:` resources of a request that names a path.
fn scopes(
    wanted: &[Resource],
    path: Option<&Path>,
) -> HubResult<std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    let Some(path) = path else {
        return Ok(out);
    };
    for resource in wanted.iter().filter(|r| r.kind == "backlog") {
        let prefix = resource.value().trim_end_matches(":write");
        let dir = super::guard::queue_dir(path, prefix).ok_or_else(|| {
            HubError::Usage(format!("no {prefix} queue under {}", path.display()))
        })?;
        out.insert(resource.name.clone(), dir.display().to_string());
    }
    if out.is_empty() {
        return Err(HubError::Usage(
            "--path binds a backlog:<P>:write claim; none was requested".to_string(),
        ));
    }
    Ok(out)
}

/// A refusal is part of what happened (GB-416): it is recorded under the worker, and under the
/// run of the request, after the refused transaction rolled back. A ledger that cannot take the
/// record keeps the refusal as it was.
fn noted(
    store: &mut Store,
    worker_id: &str,
    operation: &str,
    wanted: &[String],
    run: Option<&str>,
    outcome: HubResult<Value>,
) -> HubResult<Value> {
    if let Err(HubError::Refused(r)) = &outcome {
        let (code, message) = (r.code, r.message.clone());
        let _unrecorded = store.write(|tx| {
            worker(tx, worker_id)?;
            let mut runs: Vec<String> = run.map(str::to_string).into_iter().collect();
            if runs.is_empty() {
                for row in wanted.iter().filter_map(|w| w.strip_prefix("row:")) {
                    runs.extend(open_runs_with_row(tx, row)?);
                }
            }
            append(
                tx,
                NewEvent {
                    worker: worker_id,
                    run: runs.first().map(String::as_str),
                    kind: "refused",
                    resource: wanted.first().map_or("", String::as_str),
                    payload: json!({"operation": operation, "code": code, "message": message,
                        "requested": wanted}),
                },
            )
            .map(|_| ())
        });
    }
    outcome
}

/// All-or-nothing claim of every listed resource under one new fence.
pub fn claim(store: &mut Store, cfg: &Config, request: &ClaimRequest) -> HubResult<Value> {
    let outcome = claim_once(store, cfg, request);
    noted(
        store,
        &request.worker,
        "claim",
        &request.resources,
        request.run.as_deref(),
        outcome,
    )
}

fn claim_once(store: &mut Store, cfg: &Config, request: &ClaimRequest) -> HubResult<Value> {
    let wanted = resource::parse_list(&request.resources)?;
    let ttl = request.ttl_secs.unwrap_or(cfg.lease.default_ttl_secs);
    if ttl == 0 || ttl > cfg.lease.max_ttl_secs {
        return Err(HubError::Usage(format!(
            "the lease must last between 1 and {} seconds",
            cfg.lease.max_ttl_secs
        )));
    }
    let ttl_ms = i64::try_from(ttl.saturating_mul(1000))
        .map_err(|_| HubError::Usage("the lease is too long".to_string()))?;
    let bound = scopes(&wanted, request.path.as_deref())?;
    if wanted.iter().any(Resource::starts_work) {
        // The source command runs here, outside any write transaction.
        let account = store.read(|c| Ok(worker(c, &request.worker)?.account))?;
        quota::refresh_stale(store, &cfg.quota, &account)?;
    }
    sweep_now(store)?;
    let skip_budget = store.faults.skip_attempt_budget;
    store.write(|tx| {
        sweep(tx)?;
        let who = worker(tx, &request.worker)?;
        let run = resolve_run(tx, &who, request.run.as_deref(), &wanted)?;
        if wanted.iter().any(Resource::starts_work) {
            quota::gate(tx, &cfg.quota, &who)?;
        }
        // The slots of the only open run still bound the fleet, even for a claim outside it.
        let bounding = match &run {
            Some(run) => Some(run.clone()),
            None => match open_runs(tx)?.as_slice() {
                [only] => only["run"].as_str().map(str::to_string),
                _ => None,
            },
        };
        let ceiling = match &bounding {
            Some(run) => run_state(tx, run)?.1.min(cfg.fleet.ceiling),
            None => cfg.fleet.ceiling,
        };
        let fence = next_counter(tx, "fence")?;
        let now = now_ms();
        let expires = now + ttl_ms;
        let mut taken = Vec::new();
        let mut takeovers = Vec::new();
        for wanted in &wanted {
            let name = match wanted.kind {
                "fleet" => fleet_slot(tx, wanted, ceiling)?,
                _ => wanted.name.clone(),
            };
            if wanted.kind == "row" {
                refuse_final_row(tx, wanted.value(), run.as_deref())?;
                if !skip_budget {
                    refuse_spent_row(tx, wanted.value(), cfg.attempts.limit)?;
                }
            }
            if wanted.kind == "tree" {
                let trees = claims(tx, "WHERE released IS NULL AND resource LIKE 'tree:%'", [])?;
                if let Some(other) = trees.iter().find(|c| {
                    c.resource
                        .strip_prefix("tree:")
                        .is_some_and(|path| resource::nested(path, wanted.value()))
                }) {
                    return Err(held(tx, &other.resource).with("requested", name.clone()));
                }
            }
            let previous = latest_claim(tx, &name)?;
            let inserted = tx.execute(
                "INSERT INTO claims(resource, holder, fence, run, acquired, ttl_ms, expires) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![name, who.id, fence, run, now, ttl_ms, expires],
            );
            match inserted {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Err(held(tx, &name));
                }
                Err(e) => return Err(e.into()),
            }
            if let Some(old) = previous.filter(|c| c.reason.as_deref() == Some(EXPIRED)) {
                let mut told = json!({"resource": name, "previous_holder": old.holder,
                    "previous_fence": old.fence, "checkpoint": Value::Null});
                // GB-417: the newest checkpoint of the resource, even when later holders
                // expired without recording one.
                if let Some((checkpoint, by)) = last_checkpoint(tx, &name)? {
                    told["checkpoint"] = checkpoint;
                    told["checkpoint_by"] = json!(by.id);
                    told["checkpoint_host"] = json!(by.host);
                }
                takeovers.push(told);
            }
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run: run.as_deref(),
                    kind: "claim",
                    resource: &name,
                    payload: json!({"fence": fence, "expires": expires, "ttl_ms": ttl_ms,
                        "scope": bound.get(&name)}),
                },
            )?;
            taken.push(name);
        }
        touch(tx, &who.id)?;
        let mut answer = json!({"ok": true, "fence": fence, "resources": taken, "run": run,
            "expires": iso(expires), "takeover": takeovers});
        let told = quota::advisories(tx, &cfg.quota, &who.account)?;
        if !told.is_empty() {
            answer["warning"] = json!(told.join("; "));
        }
        Ok(answer)
    })
}

/// The newest checkpoint recorded on `resource` since the last claim that ended with a result.
fn last_checkpoint(conn: &Connection, resource: &str) -> HubResult<Option<(Value, Worker)>> {
    let history = claims(
        conn,
        "WHERE resource = ?1 AND released IS NOT NULL",
        [resource],
    )?;
    for old in history.iter().rev() {
        if old.reason.as_deref() == Some(HANDBACK) {
            break;
        }
        if let Some(found) = old
            .checkpoint
            .as_deref()
            .and_then(|c| serde_json::from_str::<Value>(c).ok())
        {
            return Ok(Some((found, worker(conn, &old.holder)?)));
        }
    }
    Ok(None)
}

fn refuse_final_row(conn: &Connection, row: &str, run: Option<&str>) -> HubResult<()> {
    let done: Option<String> = conn
        .query_row(
            "SELECT worker FROM results WHERE row = ?1 AND IFNULL(run, '') = ?2 \
             AND current = 1 AND verdict = 'done'",
            params![row, run.unwrap_or_default()],
            |r| r.get(0),
        )
        .optional()?;
    match done {
        Some(by) => Err(HubError::refused(
            "row_final",
            format!("{row} was already handed back as done by {by}"),
            "review that result (stenio hub audit); a new attempt needs a new run",
        )
        .with("resource", format!("row:{row}"))),
        None => Ok(()),
    }
}

/// Attempts of a row since the owner last reset it: distinct fences whose lease expired or that
/// were handed back as failed. Derived from the events, so it spans runs and needs no counter.
pub fn row_attempts(conn: &Connection, row: &str) -> HubResult<u32> {
    let mut stmt = conn.prepare(
        "SELECT type, payload FROM events WHERE resource = ?1 \
         AND type IN ('lease_expired', 'handback', 'attempts_reset') ORDER BY seq",
    )?;
    let found = stmt.query_map([format!("row:{row}")], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut spent = std::collections::BTreeSet::new();
    for event in found {
        let (kind, payload) = event?;
        let body: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
        match kind.as_str() {
            "attempts_reset" => spent.clear(),
            "handback" if body["verdict"] != "failed" => {}
            _ => {
                spent.insert(body["fence"].as_i64().unwrap_or_default());
            }
        }
    }
    Ok(u32::try_from(spent.len()).unwrap_or(u32::MAX))
}

fn refuse_spent_row(conn: &Connection, row: &str, limit: u32) -> HubResult<()> {
    let spent = row_attempts(conn, row)?;
    if spent < limit {
        return Ok(());
    }
    Err(HubError::refused(
        "attempts",
        format!("{row} used {spent} of {limit} attempts (expired or failed); it needs the owner"),
        format!(
            "ask the owner (stenio hub ask --row {row}); only the owner runs `stenio hub \
             reset-attempts --row {row} --reason <why>`"
        ),
    )
    .with("resource", format!("row:{row}"))
    .with("attempts", spent))
}

/// The owner gives a row a new budget. Like a quota override: terminal or owner client only.
pub fn reset_attempts(store: &mut Store, row: &str, reason: &str, owner: bool) -> HubResult<Value> {
    if !owner {
        return Err(HubError::refused(
            "owner_only",
            "resetting attempts is the owner's decision and needs an interactive terminal",
            "ask the owner (stenio hub ask)",
        ));
    }
    if reason.trim().is_empty() {
        return Err(HubError::Usage("--reason must not be empty".to_string()));
    }
    let row = resource::row_id(row)?;
    sweep_now(store)?;
    store.write(|tx| {
        let before = row_attempts(tx, &row)?;
        append(
            tx,
            NewEvent {
                worker: "",
                run: None,
                kind: "attempts_reset",
                resource: &format!("row:{row}"),
                payload: json!({"reason": reason, "attempts": before}),
            },
        )?;
        Ok(json!({"ok": true, "row": row, "attempts_cleared": before}))
    })
}

fn stale_fence(resource: &str, latest: Option<&Claim>, fence: i64) -> HubError {
    let detail = match latest {
        Some(c) if c.released.is_some() => format!(
            "the latest claim (fence {}, {}) ended: {}",
            c.fence,
            c.holder,
            c.reason.as_deref().unwrap_or(RELEASED)
        ),
        Some(c) => format!("it is now held by {} with fence {}", c.holder, c.fence),
        None => "it was never claimed".to_string(),
    };
    HubError::refused(
        "stale_fence",
        format!("fence {fence} does not own {resource}: {detail}"),
        "stop writing; run stenio hub status and claim again",
    )
    .with("resource", resource)
    .with("current_fence", latest.map(|c| c.fence))
}

/// The live claims of one fence group, all owned by `worker`.
fn owned_group(conn: &Connection, worker_id: &str, fence: i64) -> HubResult<Vec<Claim>> {
    let group = claims(conn, "WHERE released IS NULL AND fence = ?1", [fence])?;
    if group.is_empty() || group.iter().any(|c| c.holder != worker_id) {
        let any = claims(conn, "WHERE fence = ?1", [fence])?;
        let name = any.first().map_or("that fence", |c| c.resource.as_str());
        let latest = latest_claim(conn, name)?;
        return Err(stale_fence(name, latest.as_ref(), fence));
    }
    Ok(group)
}

#[derive(Debug, Clone, Default)]
pub struct BeatRequest {
    pub worker: String,
    pub fence: Option<i64>,
    /// Sent by a harness hook: throttled, so a hook after every tool call stays cheap.
    pub from_hook: bool,
}

/// Claims this worker lost to expiry, has neither taken again nor handed back, and has not been
/// told about. With `acknowledge` they are marked as told.
fn lost_leases(conn: &Connection, worker_id: &str, acknowledge: bool) -> HubResult<Vec<Value>> {
    let lost = claims(
        conn,
        "WHERE holder = ?1 AND reason = 'expired' AND loss_reported = 0 AND NOT EXISTS \
         (SELECT 1 FROM claims n WHERE n.resource = claims.resource AND n.id > claims.id \
          AND n.holder = claims.holder) AND NOT EXISTS \
         (SELECT 1 FROM results r WHERE r.fence = claims.fence AND r.worker = claims.holder)",
        [worker_id],
    )?;
    let mut out = Vec::new();
    for claim in lost {
        let now_holder = latest_claim(conn, &claim.resource)?
            .filter(|c| c.id != claim.id)
            .map(|c| c.holder);
        out.push(json!({"resource": claim.resource, "fence": claim.fence, "taken_by": now_holder}));
        if acknowledge {
            // Bookkeeping about a message, not ledger state: no event.
            conn.execute(
                "UPDATE claims SET loss_reported = 1 WHERE id = ?1",
                [claim.id],
            )?;
        }
    }
    Ok(out)
}

pub fn beat(store: &mut Store, cfg: &Config, request: &BeatRequest) -> HubResult<Value> {
    sweep_now(store)?;
    let (extended, lost, skipped) = store.write(|tx| {
        let who = worker(tx, &request.worker)?;
        let group = match request.fence {
            Some(fence) => owned_group(tx, &who.id, fence)?,
            None => claims(tx, "WHERE released IS NULL AND holder = ?1", [&who.id])?,
        };
        let lost = match request.fence {
            Some(_) => Vec::new(),
            // A hook's answer may never reach the model, so it does not count as told.
            None => lost_leases(tx, &who.id, !request.from_hook)?,
        };
        let now = now_ms();
        let min_ms = (cfg.lease.hook_beat_min_secs as i64).saturating_mul(1000);
        let recent = now - who.last_beat < min_ms;
        let urgent = group.iter().any(|c| c.expires - now < 2 * min_ms);
        if request.from_hook && recent && !urgent {
            return Ok((Vec::new(), lost, true));
        }
        let mut extended = Vec::new();
        for claim in &group {
            let expires = now + claim.ttl_ms;
            tx.execute(
                "UPDATE claims SET expires = ?1 WHERE id = ?2",
                params![expires, claim.id],
            )?;
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run: claim.run.as_deref(),
                    kind: "beat",
                    resource: &claim.resource,
                    payload: json!({"fence": claim.fence, "expires": expires}),
                },
            )?;
            extended.push(json!({"resource": claim.resource, "fence": claim.fence,
                    "expires": iso(expires)}));
        }
        touch(tx, &who.id)?;
        Ok((extended, lost, false))
    })?;
    if !lost.is_empty() {
        return Err(HubError::refused(
            "lease_lost",
            format!("{} lease(s) expired", lost.len()),
            "stop writing on them; claim again (stenio hub status)",
        )
        .with("lost", lost)
        .with("extended", extended));
    }
    if extended.is_empty() && !skipped && !request.from_hook {
        return Err(HubError::refused(
            "no_claims",
            "this worker holds nothing",
            "stenio hub claim --worker <id> <resource>",
        ));
    }
    Ok(json!({"ok": true, "extended": extended, "skipped": skipped}))
}

pub fn release(
    store: &mut Store,
    worker_id: &str,
    fence: i64,
    only: Option<&str>,
    note: Option<&str>,
) -> HubResult<Value> {
    let only = only.map(Resource::parse).transpose()?;
    sweep_now(store)?;
    store.write(|tx| {
        let who = worker(tx, worker_id)?;
        let group = owned_group(tx, &who.id, fence)?;
        let mut released = Vec::new();
        for claim in &group {
            if only.as_ref().is_some_and(|o| o.name != claim.resource) {
                continue;
            }
            end_claim(tx, claim, RELEASED, note)?;
            released.push(claim.resource.clone());
        }
        if released.is_empty() {
            return Err(HubError::refused(
                "not_held",
                format!("fence {fence} does not include that resource"),
                "stenio hub status",
            ));
        }
        touch(tx, &who.id)?;
        Ok(json!({"ok": true, "released": released}))
    })
}

#[derive(Debug, Clone, Default)]
pub struct Handback {
    pub worker: String,
    pub row: String,
    pub fence: i64,
    pub verdict: String,
    pub branch: Option<String>,
    pub pr: Option<String>,
    pub proof: Option<String>,
    pub remaining: Option<String>,
    pub defects: Vec<String>,
}

fn filled(value: Option<&String>) -> bool {
    value.is_some_and(|v| !v.trim().is_empty())
}

fn check_handback(h: &Handback) -> HubResult<()> {
    if !VERDICTS.contains(&h.verdict.as_str()) {
        return Err(HubError::Usage(format!(
            "--verdict must be one of {}",
            VERDICTS.join(", ")
        )));
    }
    if h.verdict == "done" && !filled(h.proof.as_ref()) {
        return Err(HubError::Usage(
            "verdict done needs --proof (command and output line, or a link)".to_string(),
        ));
    }
    if matches!(h.verdict.as_str(), "partial" | "blocked" | "failed")
        && !filled(h.remaining.as_ref())
    {
        return Err(HubError::Usage(format!(
            "verdict {} needs --remaining (what is left or what blocks it)",
            h.verdict
        )));
    }
    Ok(())
}

/// Stores the result of a row. Accepted only from the holder of the newest fence of that row; a
/// late hand-back is still accepted when nobody took the row over.
pub fn handback(store: &mut Store, request: &Handback) -> HubResult<Value> {
    let outcome = handback_once(store, request);
    let row = Some(request.row.trim().trim_start_matches("row:"))
        .filter(|r| !r.is_empty())
        .map(|r| format!("row:{r}"));
    let wanted: Vec<String> = row.into_iter().collect();
    noted(store, &request.worker, "handback", &wanted, None, outcome)
}

fn handback_once(store: &mut Store, request: &Handback) -> HubResult<Value> {
    check_handback(request)?;
    if request.row.trim().is_empty() {
        return handback_claim(store, request);
    }
    let row = resource::row_id(request.row.trim().trim_start_matches("row:"))?;
    let name = format!("row:{row}");
    sweep_now(store)?;
    let skip_fence = store.faults.skip_fence_check;
    store.write(|tx| {
        let who = worker(tx, &request.worker)?;
        let latest = latest_claim(tx, &name)?.ok_or_else(|| {
            HubError::refused(
                "not_claimed",
                format!("{name} was never claimed"),
                "stenio hub claim before working on a row",
            )
        })?;
        let owns = latest.fence == request.fence
            && latest.holder == who.id
            && latest.reason.as_deref().is_none_or(|r| r == EXPIRED);
        if !owns && !skip_fence {
            return Err(stale_fence(&name, Some(&latest), request.fence));
        }
        let run = latest.run.clone();
        if request.verdict == "needs-owner" {
            let waiting: i64 = tx.query_row(
                "SELECT COUNT(*) FROM questions WHERE row = ?1 AND state = 'waiting'",
                [&row],
                |r| r.get(0),
            )?;
            if waiting == 0 {
                return Err(HubError::refused(
                    "no_question",
                    format!("{row} has no waiting question"),
                    "stenio hub ask --row <ID> --text <question> first",
                ));
            }
        }
        let stored: i64 = tx.query_row(
            "SELECT COUNT(*) FROM results WHERE row = ?1 AND fence = ?2",
            params![row, request.fence],
            |r| r.get(0),
        )?;
        if stored > 0 {
            return Err(HubError::refused(
                "handed_back",
                format!("fence {} of {row} already has a result", request.fence),
                "claim the row again to replace a result that is not done",
            ));
        }
        refuse_final_row(tx, &row, run.as_deref())?;
        let superseded: Vec<i64> = {
            let mut stmt = tx.prepare(
                "SELECT fence FROM results WHERE row = ?1 AND IFNULL(run, '') = ?2 \
                 AND current = 1",
            )?;
            let found = stmt.query_map(params![row, run.as_deref().unwrap_or_default()], |r| {
                r.get(0)
            })?;
            found.collect::<Result<Vec<_>, _>>()?
        };
        for old in superseded {
            tx.execute(
                "UPDATE results SET current = 0 WHERE row = ?1 AND fence = ?2",
                params![row, old],
            )?;
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run: run.as_deref(),
                    kind: "result_superseded",
                    resource: &name,
                    payload: json!({"fence": old}),
                },
            )?;
        }
        let defects = json!(request.defects).to_string();
        tx.execute(
            "INSERT INTO results(run, row, worker, fence, verdict, branch, pr, proof, \
             remaining, defects, current, at) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11)",
            params![
                run,
                row,
                who.id,
                request.fence,
                request.verdict,
                request.branch,
                request.pr,
                request.proof,
                request.remaining,
                defects,
                now_ms()
            ],
        )?;
        let late = latest.released.is_some();
        append(
            tx,
            NewEvent {
                worker: &who.id,
                run: run.as_deref(),
                kind: HANDBACK,
                resource: &name,
                payload: json!({"fence": request.fence, "verdict": request.verdict,
                    "branch": request.branch, "pr": request.pr, "proof": request.proof,
                    "remaining": request.remaining, "defects": request.defects,
                    "late": late, "replayed": false}),
            },
        )?;
        // The row is released now; the rest of the group follows its last row.
        let group = claims(tx, "WHERE released IS NULL AND fence = ?1", [latest.fence])?;
        let more_rows = group
            .iter()
            .any(|c| c.resource != name && c.resource.starts_with("row:"));
        for claim in group.iter().filter(|c| !more_rows || c.resource == name) {
            end_claim(tx, claim, HANDBACK, None)?;
        }
        touch(tx, &who.id)?;
        Ok(
            json!({"ok": true, "row": row, "verdict": request.verdict, "run": run,
            "late": late, "replayed": false,
            "note": "recorded, not replayed: a reviewer verifies the proof before closing"}),
        )
    })
}

/// The result of a claim that holds no row (a queue writer, a release, a deploy): accepted from
/// the holder of the newest fence of every resource, then those claims end.
fn handback_claim(store: &mut Store, request: &Handback) -> HubResult<Value> {
    sweep_now(store)?;
    store.write(|tx| {
        let who = worker(tx, &request.worker)?;
        let group = claims(tx, "WHERE fence = ?1", [request.fence])?;
        if group.is_empty() {
            return Err(stale_fence("that fence", None, request.fence));
        }
        if group.iter().any(|c| c.resource.starts_with("row:")) {
            return Err(HubError::Usage(format!(
                "fence {} holds a row: give --row",
                request.fence
            )));
        }
        let mut open = Vec::new();
        for claim in &group {
            let latest = latest_claim(tx, &claim.resource)?;
            let owns = latest.as_ref().is_some_and(|l| {
                l.id == claim.id
                    && l.holder == who.id
                    && l.reason.as_deref().is_none_or(|r| r == EXPIRED)
            });
            if owns {
                open.push(claim);
            }
        }
        if open.is_empty() {
            let first = &group[0].resource;
            let latest = latest_claim(tx, first)?;
            return Err(stale_fence(first, latest.as_ref(), request.fence));
        }
        let mut resources = Vec::new();
        let mut late = false;
        for claim in open {
            late |= claim.released.is_some();
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run: claim.run.as_deref(),
                    kind: "claim_handback",
                    resource: &claim.resource,
                    payload: json!({"fence": request.fence, "verdict": request.verdict,
                        "branch": request.branch, "pr": request.pr, "proof": request.proof,
                        "remaining": request.remaining, "defects": request.defects,
                        "late": claim.released.is_some()}),
                },
            )?;
            if claim.released.is_none() {
                end_claim(tx, claim, HANDBACK, None)?;
            } else {
                // Bookkeeping: the holder knows the lease ended, so it is not reported again.
                tx.execute(
                    "UPDATE claims SET loss_reported = 1 WHERE id = ?1",
                    [claim.id],
                )?;
            }
            resources.push(claim.resource.clone());
        }
        touch(tx, &who.id)?;
        Ok(
            json!({"ok": true, "resources": resources, "verdict": request.verdict,
            "late": late,
            "note": "recorded, not replayed: a reviewer verifies the proof"}),
        )
    })
}

#[derive(Debug, Clone, Default)]
pub struct Record {
    pub worker: String,
    pub kind: String,
    pub fence: Option<i64>,
    pub note: Option<String>,
    pub clone: Option<String>,
    pub branch: Option<String>,
    pub next_step: Option<String>,
}

/// Progress, notes and the checkpoint a successor receives on takeover.
pub fn record(store: &mut Store, request: &Record) -> HubResult<Value> {
    if !EVENT_KINDS.contains(&request.kind.as_str()) {
        return Err(HubError::Usage(format!(
            "--type must be one of {}",
            EVENT_KINDS.join(", ")
        )));
    }
    let checkpoint = request.kind == "checkpoint";
    if checkpoint && request.fence.is_none() {
        return Err(HubError::Usage("a checkpoint needs --fence".to_string()));
    }
    let body = json!({"note": request.note, "clone": request.clone, "branch": request.branch,
        "next_step": request.next_step});
    if body
        .as_object()
        .is_some_and(|o| o.values().all(Value::is_null))
    {
        return Err(HubError::Usage(
            "give --note, --clone, --branch or --next-step".to_string(),
        ));
    }
    sweep_now(store)?;
    store.write(|tx| {
        let who = worker(tx, &request.worker)?;
        let group = match request.fence {
            Some(fence) => owned_group(tx, &who.id, fence)?,
            None => Vec::new(),
        };
        let mut payload = body.clone();
        payload["fence"] = json!(request.fence);
        let targets: Vec<(&str, Option<&str>)> = if group.is_empty() {
            vec![("", None)]
        } else {
            group
                .iter()
                .map(|c| (c.resource.as_str(), c.run.as_deref()))
                .collect()
        };
        for (name, run) in targets {
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run,
                    kind: &request.kind,
                    resource: name,
                    payload: payload.clone(),
                },
            )?;
        }
        if checkpoint {
            for claim in &group {
                tx.execute(
                    "UPDATE claims SET checkpoint = ?1 WHERE id = ?2",
                    params![body.to_string(), claim.id],
                )?;
            }
        }
        touch(tx, &who.id)?;
        Ok(json!({"ok": true, "recorded": request.kind, "resources": group.len()}))
    })
}

#[derive(Debug, Clone, Default)]
pub struct Question {
    pub worker: String,
    pub row: Option<String>,
    pub text: String,
    pub options: Vec<String>,
    pub recommendation: Option<String>,
}

pub fn ask(store: &mut Store, request: &Question) -> HubResult<Value> {
    if request.text.trim().is_empty() {
        return Err(HubError::Usage("--text must not be empty".to_string()));
    }
    let row = request.row.as_deref().map(resource::row_id).transpose()?;
    store.write(|tx| {
        let who = worker(tx, &request.worker)?;
        let run = match &row {
            Some(row) => match latest_claim(tx, &format!("row:{row}"))?.and_then(|c| c.run) {
                Some(run) => Some(run),
                None => open_runs_with_row(tx, row)?.pop(),
            },
            None => None,
        };
        let options = json!(request.options).to_string();
        tx.execute(
            "INSERT INTO questions(run, row, worker, text, options, recommendation, state, asked) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'waiting', ?7)",
            params![
                run,
                row,
                who.id,
                request.text,
                options,
                request.recommendation,
                now_ms()
            ],
        )?;
        let id = tx.last_insert_rowid();
        let name = row.as_ref().map(|r| format!("row:{r}")).unwrap_or_default();
        append(
            tx,
            NewEvent {
                worker: &who.id,
                run: run.as_deref(),
                kind: "question",
                resource: &name,
                payload: json!({"id": id, "text": request.text, "options": request.options,
                    "recommendation": request.recommendation}),
            },
        )?;
        touch(tx, &who.id)?;
        Ok(json!({"ok": true, "question": id,
            "next": "hand the row back as needs-owner and take other work"}))
    })
}

/// Records the owner's answer. Command line only: it is never exposed to agents over MCP, and it
/// grants no permission.
pub fn answer(store: &mut Store, id: i64, text: &str, via: &str) -> HubResult<Value> {
    if text.trim().is_empty() {
        return Err(HubError::Usage("--text must not be empty".to_string()));
    }
    store.write(|tx| {
        let found: Option<(String, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT state, row, run FROM questions WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((state, row, run)) = found else {
            return Err(HubError::refused(
                "unknown_question",
                format!("question {id} does not exist"),
                "stenio hub questions",
            ));
        };
        if state != "waiting" {
            return Err(HubError::refused(
                "answered",
                format!("question {id} is already {state}"),
                "stenio hub questions",
            ));
        }
        tx.execute(
            "UPDATE questions SET state = 'answered', answer = ?1, answered_via = ?2, \
             answered = ?3 WHERE id = ?4",
            params![text, via, now_ms(), id],
        )?;
        let name = row.map(|r| format!("row:{r}")).unwrap_or_default();
        append(
            tx,
            NewEvent {
                worker: "",
                run: run.as_deref(),
                kind: "answer",
                resource: &name,
                payload: json!({"id": id, "answer": text, "via": via}),
            },
        )?;
        Ok(json!({"ok": true, "question": id, "state": "answered"}))
    })
}
