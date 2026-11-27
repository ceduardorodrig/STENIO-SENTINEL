//! Entry points called by harness hooks: the lease heartbeat, the edit guard of the queue files,
//! and the release lease check. The two hooks fail open: a ledger that is missing or unusable
//! never blocks ordinary work. The release check is a hard action and fails closed, except on a
//! host that has no ledger at all.

use serde_json::{Value, json};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use super::config::{self, Config};
use super::ledger::{self, BeatRequest};
use super::store::{self, Store};
use super::{HubResult, guard, now_ms};
use crate::backlog::queue_index::present_queues;

/// Hook payloads are small; anything larger is not read further.
const INPUT_LIMIT: u64 = 4 * 1024 * 1024;

/// The hook payload on stdin, or `Null` when there is none or it is not JSON.
pub fn read_payload() -> Value {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Value::Null;
    }
    let mut text = String::new();
    if stdin
        .lock()
        .take(INPUT_LIMIT)
        .read_to_string(&mut text)
        .is_err()
    {
        return Value::Null;
    }
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// The harness session: a declared field of the payload, else a declared variable.
pub fn session_of(cfg: &Config, payload: &Value) -> Option<String> {
    cfg.session
        .fields
        .iter()
        .filter_map(|f| payload.get(f).and_then(Value::as_str))
        .map(str::to_string)
        .chain(
            cfg.session
                .env
                .iter()
                .filter_map(|name| std::env::var(name).ok()),
        )
        .find(|s| !s.trim().is_empty())
}

/// The sub-agent a payload comes from; empty for the main thread and for harnesses that do not
/// report one.
fn agent_of(cfg: &Config, payload: &Value) -> String {
    cfg.session
        .agent_fields
        .iter()
        .find_map(|f| payload.get(f).and_then(Value::as_str))
        .unwrap_or_default()
        .to_string()
}

/// Sub-agents share their parent's session id, and only the hook payload tells them apart. So the
/// hook that reports a join binds the new worker to the agent that ran it.
fn learn_join(store: &mut Store, session: &str, agent: &str, payload: &Value) -> HubResult<()> {
    let text = |key: &str| payload.get(key).map(Value::to_string).unwrap_or_default();
    if !(text("tool_input").contains("hub join") || text("tool_name").contains("hub_join")) {
        return Ok(());
    }
    let said = text("tool_response");
    store.write(|tx| {
        for worker in ledger::session_workers(tx, session)? {
            if said.contains(&worker) {
                ledger::bind_agent(tx, &worker, agent)?;
            }
        }
        Ok(())
    })
}

/// The workers of a session that `agent` may speak for: its own, plus the unbound ones when
/// `unbound` says so.
fn speakers(store: &mut Store, session: &str, agent: &str, unbound: bool) -> Vec<String> {
    store
        .read(|c| {
            let mut mine = Vec::new();
            for worker in ledger::session_workers(c, session)? {
                if ledger::worker_agent(c, &worker)?.map_or(unbound, |a| a == agent) {
                    mine.push(worker);
                }
            }
            Ok(mine)
        })
        .unwrap_or_default()
}

fn existing_ledger() -> HubResult<Option<Store>> {
    let path = config::db_path()?;
    if !path.exists() {
        return Ok(None);
    }
    Store::open(&path).map(Some)
}

fn renew(who: Option<&str>, fence: Option<i64>) -> HubResult<()> {
    let cfg = Config::load()?;
    let payload = read_payload();
    let Some(mut store) = existing_ledger()? else {
        return Ok(());
    };
    let session = session_of(&cfg, &payload);
    let agent = agent_of(&cfg, &payload);
    let workers = match (config::worker_or_env(who), session) {
        (Some(named), _) => vec![named],
        (None, Some(session)) => {
            learn_join(&mut store, &session, &agent, &payload)?;
            // An unbound worker is renewed by the main thread only, so a dead sub-agent
            // cannot be kept alive by its parent once bound, and never by a sibling.
            speakers(&mut store, &session, &agent, agent.is_empty())
        }
        (None, None) => Vec::new(),
    };
    for worker in workers {
        let request = BeatRequest {
            worker: worker.clone(),
            fence,
            from_hook: true,
        };
        if let Err(e) = ledger::beat(&mut store, &cfg, &request) {
            eprintln!("stenio hub beat ({worker}): {e}");
        }
    }
    Ok(())
}

/// `stenio hub beat --from-hook`: always exit 0 and nothing on stdout.
pub fn beat_hook(who: Option<&str>, fence: Option<i64>) -> i32 {
    if let Err(e) = renew(who, fence) {
        eprintln!("stenio hub beat: {e}");
    }
    0
}

/// The file a write tool is about to change, for the payload shapes of the wired harnesses.
fn edited_file(payload: &Value) -> Option<PathBuf> {
    let (tool, args) = match payload.get("toolCall") {
        Some(call) => (call.get("name"), call.get("args")),
        None => (payload.get("tool_name"), payload.get("tool_input")),
    };
    let tool = tool.and_then(Value::as_str)?.to_ascii_lowercase();
    if !["write", "edit", "patch", "replace", "create"]
        .iter()
        .any(|verb| tool.contains(verb))
    {
        return None;
    }
    let args = args?;
    let file = [
        "file_path",
        "path",
        "filePath",
        "TargetFile",
        "AbsolutePath",
    ]
    .iter()
    .find_map(|k| args.get(k).and_then(Value::as_str))
    .map(PathBuf::from)?;
    if file.is_absolute() {
        return Some(file);
    }
    match payload.get("cwd").and_then(Value::as_str) {
        Some(cwd) => Some(Path::new(cwd).join(file)),
        None => std::env::current_dir().ok().map(|d| d.join(file)),
    }
}

/// The queue root and prefix when `file` is a backlog or archive file of a declared queue.
fn queue_of(file: &Path) -> Option<(PathBuf, String)> {
    let name = file.file_name()?.to_str()?;
    if !(name.starts_with("backlog") && name.ends_with(".md")) {
        return None;
    }
    let real = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    let dir = real.parent()?;
    let root = config::discover_root(Some(dir))?;
    present_queues(&root)
        .into_iter()
        .find(|q| q.dir.canonicalize().is_ok_and(|d| d == dir))
        .map(|q| (root, q.prefix.to_string()))
}

fn refusal_of(payload: &Value) -> HubResult<Option<String>> {
    let Some((root, prefix)) = edited_file(payload).and_then(|f| queue_of(&f)) else {
        return Ok(None);
    };
    let cfg = Config::load()?;
    let Some(mut store) = existing_ledger()? else {
        return Ok(None);
    };
    let session = session_of(&cfg, payload);
    let agent = agent_of(&cfg, payload);
    let mut mine = match session {
        Some(session) => speakers(&mut store, &session, &agent, true),
        None => Vec::new(),
    };
    mine.extend(config::worker_or_env(None));
    store.read(|c| Ok(guard::hand_edit_refusal(c, &root, &prefix, &mine)))
}

/// `stenio hub guard`: exit 2 with the reason on stderr blocks the edit (Claude Code, Hermes); an
/// Antigravity payload gets its JSON decision. The guard never grants permission: its Antigravity
/// answer for an edit it does not block is `ask` (the normal prompt, honouring "Always Allow"),
/// because `allow` there approves the call. Any internal problem blocks nothing.
pub fn guard_hook() -> i32 {
    let payload = read_payload();
    let antigravity = payload.get("toolCall").is_some();
    let refusal = refusal_of(&payload).unwrap_or_else(|e| {
        eprintln!("stenio hub guard: not checked, edit allowed: {e}");
        None
    });
    match refusal {
        Some(reason) if antigravity => {
            println!("{}", json!({"decision": "deny", "reason": reason}));
            0
        }
        Some(reason) => {
            eprintln!("Blocked by stenio hub guard: {reason}");
            2
        }
        None => {
            if antigravity {
                println!("{}", json!({"decision": "ask"}));
            }
            0
        }
    }
}

/// A release needs a live `release:<name>` claim of the caller.
pub fn require_release(name: &str, worker: Option<&str>) -> Result<String, String> {
    let resource = format!("release:{}", name.to_ascii_lowercase());
    let cfg = Config::load().map_err(|e| e.to_string())?;
    let Some(mut store) = existing_ledger().map_err(|e| e.to_string())? else {
        return Ok(format!(
            "no ledger on this host, {resource} cannot be checked"
        ));
    };
    let session = session_of(&cfg, &Value::Null);
    let mine = match config::worker_or_env(worker) {
        Some(w) => vec![w],
        None => match &session {
            Some(session) => store
                .read(|c| ledger::session_workers(c, session))
                .map_err(|e| e.to_string())?,
            None => Vec::new(),
        },
    };
    let held = store
        .read(|c| {
            ledger::claims(
                c,
                "WHERE released IS NULL AND resource = ?1",
                [resource.as_str()],
            )
        })
        .map_err(|e| e.to_string())?;
    let now = now_ms();
    match held.iter().find(|c| c.live(now)) {
        Some(c) if mine.contains(&c.holder) => Ok(format!("{resource} held by {}", c.holder)),
        Some(c) => Err(format!("{resource} is held by {}", c.holder)),
        None => Err(format!(
            "nobody holds {resource}; claim it first: stenio hub claim --worker <id> {resource}"
        )),
    }
}

/// Whether the ledger events start more than `max_age_secs` ago.
pub fn older_than(conn: &rusqlite::Connection, max_age_secs: u64) -> HubResult<bool> {
    let limit = (max_age_secs as i64).saturating_mul(1000);
    Ok(store::events(conn)?
        .first()
        .is_some_and(|e| now_ms() - e.at > limit))
}
