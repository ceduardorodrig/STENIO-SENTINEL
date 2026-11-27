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
use super::{HubError, HubResult, guard, now_ms, remote};
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

/// The workers this hook speaks for: the named one, else every worker of the session.
fn speakers(store: &mut Store, named: Option<String>, session: Option<&str>) -> Vec<String> {
    if let Some(worker) = named {
        return vec![worker];
    }
    let Some(session) = session else {
        return Vec::new();
    };
    store
        .read(|c| ledger::session_workers(c, session))
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
    if let Some(server) = remote::declared()? {
        return renew_served(&server, &cfg, &payload, who, fence);
    }
    let Some(mut store) = existing_ledger()? else {
        return Ok(());
    };
    let session = session_of(&cfg, &payload);
    let named = config::worker_or_env(who);
    for worker in speakers(&mut store, named, session.as_deref()) {
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

/// At most one request per declared hook interval and session, so that an absent server costs a
/// session one short wait per interval and not one per tool call.
fn beat_due(cfg: &Config, key: &str) -> bool {
    let Some(db) = config::db_path().ok() else {
        return true;
    };
    let Some(dir) = db.parent() else {
        return true;
    };
    let name: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(64)
        .collect();
    let stamp = dir.join(format!("beat-{name}.stamp"));
    let recent = std::fs::metadata(&stamp)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age.as_secs() < cfg.lease.hook_beat_min_secs);
    if recent {
        return false;
    }
    if let Err(e) = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&stamp, b"")) {
        eprintln!("stenio hub beat: cannot write {}: {e}", stamp.display());
    }
    true
}

fn served_workers(server: &remote::Remote, session: Option<&str>) -> HubResult<Vec<String>> {
    let Some(session) = session else {
        return Ok(Vec::new());
    };
    let reply = server.call("session_workers", json!({"session": session}))?;
    Ok(reply["workers"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|w| w.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

fn renew_served(
    server: &remote::Remote,
    cfg: &Config,
    payload: &Value,
    who: Option<&str>,
    fence: Option<i64>,
) -> HubResult<()> {
    let server = server.clone().with_timeout(remote::HOOK_TIMEOUT_SECS);
    let session = session_of(cfg, payload);
    let named = config::worker_or_env(who);
    let Some(key) = named.as_deref().or(session.as_deref()) else {
        return Ok(());
    };
    if !beat_due(cfg, key) {
        return Ok(());
    }
    let workers = match &named {
        Some(worker) => vec![worker.clone()],
        None => served_workers(&server, session.as_deref())?,
    };
    for worker in workers {
        let request = json!({"worker": worker, "fence": fence, "from_hook": true});
        if let Err(e) = server.call("hub_beat", request) {
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
    if let Some(server) = remote::declared()? {
        let server = server.with_timeout(remote::HOOK_TIMEOUT_SECS);
        let mine: Vec<String> = config::worker_or_env(None).into_iter().collect();
        let check = json!({"prefixes": [prefix], "mine": mine,
            "session": session_of(&cfg, payload)});
        return match server.call("queue_check", check) {
            Ok(_) => Ok(None),
            Err(e @ HubError::Refused(_)) => Ok(Some(format!("{e} ({})", root.display()))),
            Err(e) => Err(e),
        };
    }
    let Some(mut store) = existing_ledger()? else {
        return Ok(None);
    };
    let session = session_of(&cfg, payload);
    let mut mine = speakers(&mut store, None, session.as_deref());
    mine.extend(config::worker_or_env(None));
    store.read(|c| Ok(guard::hand_edit_refusal(c, &root, &prefix, &mine)))
}

/// `stenio hub guard`: exit 2 with the reason on stderr blocks the edit (Claude Code, Hermes); an
/// Antigravity payload gets its JSON decision. Any internal problem allows the edit.
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
                println!("{}", json!({"decision": "allow"}));
            }
            0
        }
    }
}

fn release_verdict(
    resource: &str,
    holder: Option<&str>,
    mine: &[String],
) -> Result<String, String> {
    match holder {
        Some(h) if mine.iter().any(|m| m == h) => Ok(format!("{resource} held by {h}")),
        Some(h) => Err(format!("{resource} is held by {h}")),
        None => Err(format!(
            "nobody holds {resource}; claim it first: stenio hub claim --worker <id> {resource}"
        )),
    }
}

fn require_served_release(
    server: &remote::Remote,
    cfg: &Config,
    resource: &str,
    worker: Option<&str>,
) -> HubResult<Result<String, String>> {
    let mine = match config::worker_or_env(worker) {
        Some(w) => vec![w],
        None => served_workers(server, session_of(cfg, &Value::Null).as_deref())?,
    };
    let reply = server.call("claim_holder", json!({"resource": resource}))?;
    Ok(release_verdict(resource, reply["holder"].as_str(), &mine))
}

/// A release needs a live `release:<name>` claim of the caller.
pub fn require_release(name: &str, worker: Option<&str>) -> Result<String, String> {
    let resource = format!("release:{}", name.to_ascii_lowercase());
    let cfg = Config::load().map_err(|e| e.to_string())?;
    if let Some(server) = remote::declared().map_err(|e| e.to_string())? {
        return require_served_release(&server, &cfg, &resource, worker)
            .map_err(|e| e.to_string())?;
    }
    let Some(mut store) = existing_ledger().map_err(|e| e.to_string())? else {
        return Ok(format!(
            "no ledger on this host, {resource} cannot be checked"
        ));
    };
    let session = session_of(&cfg, &Value::Null);
    let mine = match config::worker_or_env(worker) {
        Some(w) => vec![w],
        None => speakers(&mut store, None, session.as_deref()),
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
    let holder = held.iter().find(|c| c.live(now)).map(|c| c.holder.as_str());
    release_verdict(&resource, holder, &mine)
}

/// Whether the ledger events start more than `max_age_secs` ago.
pub fn older_than(conn: &rusqlite::Connection, max_age_secs: u64) -> HubResult<bool> {
    let limit = (max_age_secs as i64).saturating_mul(1000);
    Ok(store::events(conn)?
        .first()
        .is_some_and(|e| now_ms() - e.at > limit))
}
