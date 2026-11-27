//! The state changes: join, runs, claims, heartbeats, hand-backs, checkpoints and questions.
//! Every one of them runs in one write transaction and appends its events inside it.

use rusqlite::{Connection, OptionalExtension, Params, Row, params};
use serde_json::{Value, json};
use std::path::Path;

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
}

pub fn worker(conn: &Connection, id: &str) -> HubResult<Worker> {
    conn.query_row(
        "SELECT id, harness, account, last_beat FROM workers WHERE id = ?1",
        [id],
        |r| {
            Ok(Worker {
                id: r.get(0)?,
                harness: r.get(1)?,
                account: r.get(2)?,
                last_beat: r.get(3)?,
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
fn end_claim(conn: &Connection, claim: &Claim, reason: &str, note: Option<&str>) -> HubResult<()> {
    let now = now_ms();
    conn.execute(
        "UPDATE claims SET released = ?1, reason = ?2 WHERE id = ?3",
        params![now, reason, claim.id],
    )?;
    let checkpoint = claim
        .checkpoint
        .as_deref()
        .and_then(|c| serde_json::from_str::<Value>(c).ok());
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
            payload: json!({"fence": claim.fence, "reason": reason, "note": note,
                "expired_at": iso(claim.expires), "checkpoint": checkpoint}),
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
        append(
            tx,
            NewEvent {
                worker: &id,
                run: None,
                kind: "join",
                resource: "",
                payload: json!({"harness": harness, "model": request.model, "host": host,
                    "parent": request.parent, "account": account}),
            },
        )?;
        let runs = open_runs(tx)?;
        Ok(
            json!({"ok": true, "worker": id, "account": account, "open_runs": runs,
            "lease_secs": cfg.lease.default_ttl_secs,
            "next": "stenio hub status, then claim; beat before the lease expires"}),
        )
    })
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

pub fn run_start(
    store: &mut Store,
    cfg: &Config,
    vault: &Path,
    rows: &[String],
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
    let vault = vault.display().to_string();
    store.write(|tx| {
        for id in &ids {
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

/// The run a claim belongs to: the named one, else the single open run that lists its rows.
fn resolve_run(
    conn: &Connection,
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
                None if rows.is_empty() => {
                    let open = open_runs(conn)?;
                    match open.as_slice() {
                        [only] => only["run"].as_str().map(str::to_string),
                        _ => None,
                    }
                }
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
}

/// All-or-nothing claim of every listed resource under one new fence.
pub fn claim(store: &mut Store, cfg: &Config, request: &ClaimRequest) -> HubResult<Value> {
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
    sweep_now(store)?;
    store.write(|tx| {
        sweep(tx)?;
        let who = worker(tx, &request.worker)?;
        let run = resolve_run(tx, request.run.as_deref(), &wanted)?;
        if wanted.iter().any(Resource::starts_work) {
            quota::gate(tx, &cfg.quota, &who)?;
        }
        let ceiling = match &run {
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
                takeovers.push(json!({"resource": name, "previous_holder": old.holder,
                    "previous_fence": old.fence,
                    "checkpoint": old.checkpoint
                        .and_then(|c| serde_json::from_str::<Value>(&c).ok())}));
            }
            append(
                tx,
                NewEvent {
                    worker: &who.id,
                    run: run.as_deref(),
                    kind: "claim",
                    resource: &name,
                    payload: json!({"fence": fence, "expires": expires, "ttl_ms": ttl_ms}),
                },
            )?;
            taken.push(name);
        }
        touch(tx, &who.id)?;
        Ok(
            json!({"ok": true, "fence": fence, "resources": taken, "run": run,
            "expires": iso(expires), "takeover": takeovers}),
        )
    })
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

/// Claims this worker lost to expiry and has neither taken again nor handed back.
fn lost_leases(conn: &Connection, worker_id: &str) -> HubResult<Vec<Value>> {
    let lost = claims(
        conn,
        "WHERE holder = ?1 AND reason = 'expired' AND NOT EXISTS \
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
            None => lost_leases(tx, &who.id)?,
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
    check_handback(request)?;
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
