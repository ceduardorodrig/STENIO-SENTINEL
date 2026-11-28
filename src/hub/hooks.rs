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
use super::{HubError, HubResult, guard, now_ms, remote, resource};
use crate::backlog::queue_index::present_queues;

/// Hook payloads are small; anything larger is not read further.
const INPUT_LIMIT: u64 = 4 * 1024 * 1024;

/// The hook payload on stdin, or `Null` when there is none or it is not JSON.
pub fn read_payload() -> Value {
    read_payload_up_to(INPUT_LIMIT)
}

/// [`read_payload`] with an explicit size limit.
pub fn read_payload_up_to(limit: u64) -> Value {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Value::Null;
    }
    let mut text = String::new();
    if stdin.lock().take(limit).read_to_string(&mut text).is_err() {
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

/// The workers bound to the session of the calling shell, from the ledger in force.
pub fn workers_of_this_session() -> HubResult<Vec<String>> {
    let cfg = Config::load()?;
    let Some(session) = join_session(&cfg, "") else {
        return Ok(Vec::new());
    };
    if let Some(server) = super::remote::declared()? {
        let found = server.call("session_workers", json!({"session": session}))?;
        return Ok(found["workers"]
            .as_array()
            .map(|w| {
                w.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default());
    }
    let path = super::config::db_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    Store::open(&path)?.read(|c| super::ledger::session_workers(c, &session))
}

/// The session `join` binds a worker of `harness` to, from the declared variables.
pub fn join_session(cfg: &Config, harness: &str) -> Option<String> {
    let names = match cfg.session.harness.get(harness) {
        Some(own) => std::slice::from_ref(own),
        None => cfg.session.env.as_slice(),
    };
    names
        .iter()
        .filter_map(|name| std::env::var(name).ok())
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
pub(super) fn learn_join(
    store: &mut Store,
    session: &str,
    agent: &str,
    said: &str,
) -> HubResult<()> {
    store.write(|tx| {
        for worker in ledger::session_workers(tx, session)? {
            if said.contains(&worker) {
                ledger::bind_agent(tx, &worker, agent)?;
            }
        }
        Ok(())
    })
}

/// The answer of a tool call that ran a join, when the payload reports one.
fn join_report(payload: &Value) -> Option<String> {
    let text = |key: &str| payload.get(key).map(Value::to_string).unwrap_or_default();
    (text("tool_input").contains("hub join") || text("tool_name").contains("hub_join"))
        .then(|| text("tool_response"))
}

/// Whose trees `agent` may edit inside its session: its own workers and the unbound ones; a
/// helper that never joined also acts for the main thread.
pub(super) fn tree_speakers(
    conn: &rusqlite::Connection,
    session: &str,
    agent: &str,
) -> HubResult<Vec<String>> {
    let mut bound = Vec::new();
    for worker in ledger::session_workers(conn, session)? {
        let owner = ledger::worker_agent(conn, &worker)?;
        bound.push((worker, owner));
    }
    let joined = bound.iter().any(|(_, a)| a.as_deref() == Some(agent));
    Ok(bound
        .into_iter()
        .filter(|(_, a)| {
            a.as_deref()
                .is_none_or(|a| a == agent || (a.is_empty() && !joined))
        })
        .map(|(w, _)| w)
        .collect())
}

/// The workers of a session that `agent` may speak for: its own, plus the unbound ones when
/// `unbound` says so.
pub(super) fn speakers(
    store: &mut Store,
    session: &str,
    agent: &str,
    unbound: bool,
) -> Vec<String> {
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
    if let Some(server) = remote::declared()? {
        return renew_served(&server, &cfg, &payload, who, fence);
    }
    let Some(mut store) = existing_ledger()? else {
        return Ok(());
    };
    let session = session_of(&cfg, &payload);
    let agent = agent_of(&cfg, &payload);
    let workers = match (config::worker_or_env(who), session) {
        (Some(named), _) => vec![named],
        (None, Some(session)) => {
            if let Some(said) = join_report(&payload) {
                learn_join(&mut store, &session, &agent, &said)?;
            }
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

/// The workers of a session on the server. With `agent` the server answers only for that
/// sub-agent, after learning the join it is told about.
fn served_workers(
    server: &remote::Remote,
    session: Option<&str>,
    agent: Option<&str>,
    said: Option<String>,
) -> HubResult<Vec<String>> {
    let Some(session) = session else {
        return Ok(Vec::new());
    };
    let reply = server.call(
        "session_workers",
        json!({"session": session, "agent": agent, "said": said}),
    )?;
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
    let agent = agent_of(cfg, payload);
    let said = join_report(payload);
    // A join is reported once, so it is never throttled; each sub-agent has its own interval.
    if said.is_none() && !beat_due(cfg, &format!("{key}{agent}")) {
        return Ok(());
    }
    let workers = match &named {
        Some(worker) => vec![worker.clone()],
        None => served_workers(&server, session.as_deref(), Some(&agent), said)?,
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

/// Argument names that hold the file of a write tool, compared without case and underscores.
pub(crate) const PATH_KEYS: [&str; 6] = [
    "filepath",
    "path",
    "targetfile",
    "absolutepath",
    "notebookpath",
    "filename",
];
/// Argument names that can hold a patch, whose headers name the files.
pub(crate) const PATCH_KEYS: [&str; 4] = ["patch", "patchtext", "input", "command"];

fn patched_files(patch: &str) -> impl Iterator<Item = &str> {
    patch.lines().filter_map(|line| {
        let line = line.trim_start().strip_prefix("*** ")?;
        ["Add File:", "Update File:", "Delete File:", "Move to:"]
            .iter()
            .find_map(|head| line.strip_prefix(head))
            .map(str::trim)
            .filter(|f| !f.is_empty())
    })
}

/// The files a write tool is about to change, for the payload shapes of the wired harnesses.
pub(crate) fn edited_files(payload: &Value) -> Vec<PathBuf> {
    let (tool, args) = match payload.get("toolCall") {
        Some(call) => (call.get("name"), call.get("args")),
        None => (payload.get("tool_name"), payload.get("tool_input")),
    };
    let Some(tool) = tool.and_then(Value::as_str).map(str::to_ascii_lowercase) else {
        return Vec::new();
    };
    let writes = [
        "write", "edit", "patch", "replace", "create", "delete", "sed_file",
    ];
    if !writes.iter().any(|verb| tool.contains(verb)) {
        return Vec::new();
    }
    let Some(args) = args else {
        return Vec::new();
    };
    // An editor tool that is asked to show a file changes nothing.
    if args.get("command").and_then(Value::as_str) == Some("view") {
        return Vec::new();
    }
    let mut named: Vec<&str> = Vec::new();
    let patch_of = |key: &str, value: &str| {
        PATCH_KEYS.contains(&key) && value.trim_start().starts_with("*** ")
    };
    if let Some(text) = args.as_str() {
        named.extend(patched_files(text));
    }
    for (key, value) in args.as_object().into_iter().flatten() {
        let key = key.replace('_', "").to_ascii_lowercase();
        let Some(value) = value.as_str() else {
            continue;
        };
        if PATH_KEYS.contains(&key.as_str()) {
            named.push(value);
        } else if patch_of(&key, value) {
            named.extend(patched_files(value));
        }
    }
    let cwd = payload.get("cwd").and_then(Value::as_str);
    named
        .into_iter()
        .filter(|f| !f.is_empty())
        .filter_map(|f| {
            let file = Path::new(f);
            if file.is_absolute() {
                return Some(file.to_path_buf());
            }
            match cwd {
                Some(cwd) => Some(Path::new(cwd).join(file)),
                None => std::env::current_dir().ok().map(|d| d.join(file)),
            }
        })
        .collect()
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
    let files = edited_files(payload);
    if files.is_empty() {
        return Ok(None);
    }
    let cfg = Config::load()?;
    let server = remote::declared()?.map(|s| s.with_timeout(remote::HOOK_TIMEOUT_SECS));
    for file in &files {
        if let Some((root, prefix)) = queue_of(file)
            && let Some(reason) = queue_refusal(&cfg, server.as_ref(), payload, &root, &prefix)?
        {
            return Ok(Some(reason));
        }
    }
    let paths: Vec<String> = files
        .iter()
        .filter_map(|f| resource::resolved_path(f))
        .collect();
    tree_refusal(&cfg, server.as_ref(), payload, &paths)
}

/// Why a file lies in another worker's claimed tree. A caller that names neither a session nor a
/// worker cannot be told from the holder, so nothing is refused.
fn tree_refusal(
    cfg: &Config,
    server: Option<&remote::Remote>,
    payload: &Value,
    paths: &[String],
) -> HubResult<Option<String>> {
    let session = session_of(cfg, payload);
    let named = config::worker_or_env(None);
    if paths.is_empty() || (session.is_none() && named.is_none()) {
        return Ok(None);
    }
    let agent = agent_of(cfg, payload);
    let mut mine: Vec<String> = named.into_iter().collect();
    if let Some(server) = server {
        // This runs before every edit: after a failure the server is left alone for a while.
        if server_was_down(cfg) {
            return Ok(None);
        }
        let check = json!({"paths": paths, "mine": mine, "session": session, "agent": agent});
        return match server.call("tree_check", check) {
            Ok(_) => Ok(None),
            Err(e @ HubError::Refused(_)) => Ok(Some(e.to_string())),
            Err(e) => {
                if matches!(e, HubError::Store(_)) {
                    mark_server_down();
                }
                Err(e)
            }
        };
    }
    let Some(store) = existing_ledger()? else {
        return Ok(None);
    };
    let mut store = store;
    store.read(|c| {
        if let Some(session) = &session {
            mine.extend(tree_speakers(c, session, &agent)?);
        }
        for path in paths {
            if let Some(refused) = guard::tree_refusal(c, path, &mine)? {
                return Ok(Some(refused.to_string()));
            }
        }
        Ok(None)
    })
}

fn down_stamp() -> Option<PathBuf> {
    config::db_path()
        .ok()?
        .parent()
        .map(|d| d.join("guard-server-down.stamp"))
}

fn server_was_down(cfg: &Config) -> bool {
    down_stamp()
        .and_then(|s| std::fs::metadata(s).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age.as_secs() < cfg.lease.hook_beat_min_secs)
}

fn mark_server_down() {
    let Some(stamp) = down_stamp() else {
        return;
    };
    let made = stamp
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&stamp, b""));
    if let Err(e) = made {
        eprintln!("stenio hub guard: cannot write {}: {e}", stamp.display());
    }
}

fn queue_refusal(
    cfg: &Config,
    server: Option<&remote::Remote>,
    payload: &Value,
    root: &Path,
    prefix: &str,
) -> HubResult<Option<String>> {
    if let Some(server) = server {
        let mine: Vec<String> = config::worker_or_env(None).into_iter().collect();
        let check = json!({"prefixes": [prefix], "mine": mine,
            "session": session_of(cfg, payload)});
        return match server.call("queue_check", check) {
            Ok(_) => Ok(None),
            Err(e @ HubError::Refused(_)) => Ok(Some(format!("{e} ({})", root.display()))),
            Err(e) => Err(e),
        };
    }
    let Some(mut store) = existing_ledger()? else {
        return Ok(None);
    };
    let session = session_of(cfg, payload);
    let agent = agent_of(cfg, payload);
    let mut mine = match session {
        Some(session) => speakers(&mut store, &session, &agent, true),
        None => Vec::new(),
    };
    mine.extend(config::worker_or_env(None));
    store.read(|c| Ok(guard::hand_edit_refusal(c, root, prefix, &mine)))
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
        None => served_workers(server, session_of(cfg, &Value::Null).as_deref(), None, None)?,
    };
    let reply = server.call("claim_holder", json!({"resource": resource}))?;
    Ok(release_verdict(resource, reply["holder"].as_str(), &mine))
}

/// Whether the caller of this hook payload holds a live `release:` or `deploy:` claim. Without
/// a ledger to ask, the answer is an error and the caller must not publish.
pub fn holds_publish_lease(payload: &Value) -> Result<bool, String> {
    let said = |e: HubError| e.to_string();
    let cfg = Config::load().map_err(said)?;
    let session = session_of(&cfg, payload);
    let agent = agent_of(&cfg, payload);
    let named = config::worker_or_env(None);
    if let Some(server) = remote::declared().map_err(said)? {
        let server = server.with_timeout(remote::HOOK_TIMEOUT_SECS);
        let mine: Vec<String> = named.into_iter().collect();
        let reply = server
            .call(
                "publish_lease",
                json!({"mine": mine, "session": session, "agent": agent}),
            )
            .map_err(said)?;
        return Ok(reply["held"].as_bool().unwrap_or(false));
    }
    let Some(mut store) = existing_ledger().map_err(said)? else {
        return Err("this host has no ledger".to_string());
    };
    let mut mine: Vec<String> = named.into_iter().collect();
    if let Some(session) = session {
        mine.extend(
            store
                .read(|c| tree_speakers(c, &session, &agent))
                .map_err(said)?,
        );
    }
    store.read(|c| publish_held(c, &mine)).map_err(said)
}

/// Whether one of `mine` holds a live release or deploy claim.
pub(super) fn publish_held(conn: &rusqlite::Connection, mine: &[String]) -> HubResult<bool> {
    let live = ledger::claims(
        conn,
        "WHERE released IS NULL AND (resource LIKE 'release:%' OR resource LIKE 'deploy:%')",
        [],
    )?;
    let now = now_ms();
    Ok(live.iter().any(|c| c.live(now) && mine.contains(&c.holder)))
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
