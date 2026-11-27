//! `stenio hub serve`: the ledger over HTTP for the other machines. It listens on loopback by
//! default and is meant to be published by a TLS proxy of the private network. Every request
//! needs a per-client bearer token (only hashes are stored here), an allowed `Host` and no
//! foreign `Origin`. The client name of the token is the identity: it is the host of the workers
//! it registers, the namespace of its tree resources, and no other client may act as them.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::config::Config;
use super::resource::{self, Resource};
use super::store::{NewEvent, Store, append, meta, next_counter, set_meta};
use super::{HubError, HubResult, audit, guard, hooks, iso, ledger, mcp, now_ms, quota, view};

/// How long the queue write claim of one engine write lasts if its end never arrives.
const WRITE_LEASE_MS: i64 = 120_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub name: String,
    sha256: String,
    #[serde(default)]
    role: Role,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Worker,
    Owner,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clients {
    #[serde(default)]
    client: Vec<Client>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Comparison whose duration does not depend on where the inputs differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn read_clients(path: &Path) -> HubResult<Vec<Client>> {
    let bad = |why: String| HubError::Store(format!("client list {}: {why}", path.display()));
    let text = std::fs::read_to_string(path).map_err(|e| bad(e.to_string()))?;
    let list: Clients = toml::from_str(&text).map_err(|e| bad(e.to_string()))?;
    for c in &list.client {
        let name_ok = !c.name.is_empty()
            && c.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
        if !name_ok || c.sha256.len() != 64 {
            return Err(bad(format!("invalid entry '{}'", c.name)));
        }
    }
    Ok(list.client)
}

/// Writes a new random token to a private file and returns only its hash.
pub fn mint(name: &str, out: &Path) -> HubResult<Value> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let io = |e: std::io::Error| HubError::Store(format!("cannot mint a token: {e}"));
    let mut raw = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(io)?;
    let token = hex(&raw);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .and_then(|mut f| f.write_all(token.as_bytes()))
        .map_err(io)?;
    let sha256 = digest(&token);
    Ok(
        json!({"ok": true, "client": name, "token_file": out.display().to_string(),
        "entry": format!("[[client]]\nname = \"{name}\"\nsha256 = \"{sha256}\"\n")}),
    )
}

fn client_key(worker: &str) -> String {
    format!("client:{worker}")
}

/// A worker belongs to the client that joined it. One registered before the server existed
/// (migration) belongs to the client named like its host.
fn own_worker(store: &mut Store, client: &Client, worker: &str) -> HubResult<()> {
    let owner = store.read(|c| match meta(c, &client_key(worker))? {
        Some(name) => Ok(Some(name)),
        None => {
            ledger::worker(c, worker)?;
            let host: Option<String> =
                c.query_row("SELECT host FROM workers WHERE id = ?1", [worker], |r| {
                    r.get(0)
                })?;
            Ok(host)
        }
    })?;
    if owner.is_some_and(|o| o.eq_ignore_ascii_case(&client.name)) {
        return Ok(());
    }
    Err(HubError::refused(
        "wrong_client",
        format!("worker {worker} does not belong to client {}", client.name),
        "join from this machine and use that worker",
    ))
}

/// The same path on two machines is two trees: each client has its own namespace.
fn namespaced(client: &Client, raw: &str) -> HubResult<String> {
    let parsed = Resource::parse(raw)?;
    if parsed.kind != "tree" {
        return Ok(parsed.name);
    }
    let path = parsed.value();
    let own = format!("/@{}", client.name);
    if path.starts_with("/@") {
        if resource::nested(&own, path) {
            return Ok(parsed.name);
        }
        return Err(HubError::refused(
            "wrong_client",
            format!("{path} is in another client's namespace"),
            "name the tree by its local path",
        ));
    }
    Ok(format!("tree:{own}{path}"))
}

fn text(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

fn required(args: &Map<String, Value>, key: &str) -> HubResult<String> {
    text(args, key).ok_or_else(|| HubError::Usage(format!("missing argument '{key}'")))
}

fn strings(args: &Map<String, Value>, key: &str) -> Vec<String> {
    match args.get(key) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// A foreign live claim on one of the queues, as a refusal.
fn queue_free(conn: &rusqlite::Connection, prefixes: &[String], mine: &[String]) -> HubResult<()> {
    for prefix in prefixes {
        let name = format!("backlog:{prefix}:write");
        let live = ledger::claims(conn, "WHERE released IS NULL AND resource = ?1", [&name])?;
        let now = now_ms();
        if let Some(claim) = live
            .iter()
            .find(|c| c.live(now) && !mine.contains(&c.holder))
        {
            return Err(HubError::refused(
                "held",
                format!(
                    "{name} is held by {} until {}; nothing written",
                    claim.holder,
                    iso(claim.expires)
                ),
                "pass --worker <holder> if it is you, else wait or ask the holder",
            )
            .with("resource", name.clone())
            .with("holder", claim.holder.clone())
            .with("expires", iso(claim.expires)));
        }
    }
    Ok(())
}

/// Before an engine write of a queue: refuses a foreign holder, else holds each queue that the
/// writer does not hold yet, so nobody claims or writes in between.
fn guard_begin(store: &mut Store, writer: &str, prefixes: &[String]) -> HubResult<Value> {
    ledger::sweep_now(store)?;
    store.write(|tx| {
        queue_free(tx, prefixes, &[writer.to_string()])?;
        let fence = next_counter(tx, "fence")?;
        let now = now_ms();
        let expires = now + WRITE_LEASE_MS;
        for prefix in prefixes {
            let name = format!("backlog:{prefix}:write");
            if !ledger::claims(tx, "WHERE released IS NULL AND resource = ?1", [&name])?.is_empty()
            {
                continue;
            }
            tx.execute(
                "INSERT INTO claims(resource, holder, fence, run, acquired, ttl_ms, expires) \
                 VALUES(?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                params![name, writer, fence, now, WRITE_LEASE_MS, expires],
            )?;
            append(
                tx,
                NewEvent {
                    worker: writer,
                    run: None,
                    kind: "claim",
                    resource: &name,
                    payload: json!({"fence": fence, "expires": expires}),
                },
            )?;
        }
        Ok(json!({"ok": true, "fence": fence}))
    })
}

/// After the write: ends the claims that `guard_begin` took and records what changed.
fn guard_end(
    store: &mut Store,
    writer: &str,
    fence: i64,
    prefixes: &[String],
    written: Option<&Value>,
) -> HubResult<Value> {
    store.write(|tx| {
        let taken = ledger::claims(
            tx,
            "WHERE released IS NULL AND fence = ?1 AND holder = ?2",
            params![fence, writer],
        )?;
        for claim in &taken {
            ledger::end_claim(tx, claim, "written", None)?;
        }
        if let Some(written) = written {
            append(
                tx,
                NewEvent {
                    worker: writer,
                    run: None,
                    kind: "backlog_write",
                    resource: &prefixes.join(","),
                    payload: written.clone(),
                },
            )?;
        }
        Ok(json!({"ok": true, "released": taken.len()}))
    })
}

fn sample_window(args: &Map<String, Value>) -> Option<quota::Window> {
    Some(quota::Window {
        window: text(args, "window")?,
        used_pct: args.get("used_pct").and_then(Value::as_f64)?,
        resets_at: args.get("resets_at").and_then(Value::as_i64),
    })
}

/// One operation of an authenticated client on the ledger at `db`.
pub fn dispatch(
    db: &Path,
    client: &Client,
    op: &str,
    mut args: Map<String, Value>,
) -> HubResult<Value> {
    let mut cfg = Config::load()?;
    // Quota sources are read by the clients, with their own credentials.
    cfg.quota.source.clear();
    let mut store = Store::open(db)?;
    // A write claim made by an unjoined writer is named after the client.
    let writer_of = |store: &mut Store, args: &Map<String, Value>| -> HubResult<String> {
        match text(args, "worker") {
            Some(worker) => {
                own_worker(store, client, &worker)?;
                Ok(worker)
            }
            None => Ok(format!("writer@{}", client.name)),
        }
    };
    match op {
        "guard_begin" => {
            let writer = writer_of(&mut store, &args)?;
            return guard_begin(&mut store, &writer, &strings(&args, "prefixes"));
        }
        "guard_end" => {
            let writer = writer_of(&mut store, &args)?;
            let fence = args
                .get("fence")
                .and_then(Value::as_i64)
                .ok_or_else(|| HubError::Usage("missing argument 'fence'".to_string()))?;
            return guard_end(
                &mut store,
                &writer,
                fence,
                &strings(&args, "prefixes"),
                args.get("written").filter(|v| !v.is_null()),
            );
        }
        "queue_check" => {
            ledger::sweep_now(&mut store)?;
            let session = text(&args, "session");
            let mut mine = strings(&args, "mine");
            return store.read(|c| {
                if let Some(session) = &session {
                    mine.extend(ledger::session_workers(c, session)?);
                }
                queue_free(c, &strings(&args, "prefixes"), &mine)?;
                Ok(json!({"ok": true}))
            });
        }
        "session_workers" => {
            let session = required(&args, "session")?;
            // Without `agent` every worker of the session; with it, those the sub-agent that
            // runs the hook may renew.
            let found = match text(&args, "agent") {
                Some(agent) => {
                    if let Some(said) = text(&args, "said") {
                        hooks::learn_join(&mut store, &session, &agent, &said)?;
                    }
                    hooks::speakers(&mut store, &session, &agent, agent.is_empty())
                }
                None => store.read(|c| ledger::session_workers(c, &session))?,
            };
            return Ok(json!({"ok": true, "workers": found}));
        }
        "tree_check" => {
            ledger::sweep_now(&mut store)?;
            let session = text(&args, "session");
            let agent = text(&args, "agent").unwrap_or_default();
            let mut mine = strings(&args, "mine");
            return store.read(|c| {
                if let Some(session) = &session {
                    mine.extend(hooks::tree_speakers(c, session, &agent)?);
                }
                for path in strings(&args, "paths") {
                    let own = format!("/@{}{path}", client.name);
                    if let Some(refused) = guard::tree_refusal(c, &own, &mine)? {
                        return Err(refused);
                    }
                }
                Ok(json!({"ok": true}))
            });
        }
        "publish_lease" => {
            ledger::sweep_now(&mut store)?;
            let session = text(&args, "session");
            let agent = text(&args, "agent").unwrap_or_default();
            let mut mine = strings(&args, "mine");
            return store.read(|c| {
                if let Some(session) = &session {
                    mine.extend(hooks::tree_speakers(c, session, &agent)?);
                }
                Ok(json!({"ok": true, "held": hooks::publish_held(c, &mine)?}))
            });
        }
        "attempts_reset" => {
            if client.role != Role::Owner {
                return Err(HubError::refused(
                    "owner_only",
                    "only a client with the owner role may reset the attempts of a row",
                    "the owner runs it from an owner client or on the server host",
                ));
            }
            return ledger::reset_attempts(
                &mut store,
                &required(&args, "row")?,
                &required(&args, "reason")?,
                true,
            );
        }
        "claim_holder" => {
            ledger::sweep_now(&mut store)?;
            let name = Resource::parse(&required(&args, "resource")?)?.name;
            let live = store
                .read(|c| ledger::claims(c, "WHERE released IS NULL AND resource = ?1", [&name]))?;
            let now = now_ms();
            let holder = live.iter().find(|c| c.live(now)).map(|c| c.holder.clone());
            return Ok(json!({"ok": true, "holder": holder}));
        }
        "quota_need" => {
            let worker = required(&args, "worker")?;
            own_worker(&mut store, client, &worker)?;
            let fresh_ms = (cfg.quota.fresh_secs as i64).saturating_mul(1000);
            return store.read(|c| {
                let account = ledger::worker(c, &worker)?.account;
                let newest: Option<i64> = c.query_row(
                    "SELECT min(observed_at) FROM quota WHERE account = ?1",
                    [&account],
                    |r| r.get(0),
                )?;
                let stale = newest.is_none_or(|at| now_ms() - at > fresh_ms);
                Ok(json!({"ok": true, "account": account, "stale": stale}))
            });
        }
        "quota_put" => {
            let account = required(&args, "account")?;
            let source = format!("{}: {}", client.name, required(&args, "source")?);
            if let Some(reason) = text(&args, "unknown") {
                quota::put_unknown(&mut store, &account, &source, &reason)?;
                return Ok(json!({"ok": true, "account": account, "unknown": reason}));
            }
            let window = sample_window(&args)
                .filter(|w| (0.0..=100.0).contains(&w.used_pct))
                .ok_or_else(|| HubError::Usage("give a window and used_pct 0..100".into()))?;
            return quota::put(&mut store, &account, &source, &[window]);
        }
        "run_start" => {
            let slots = args
                .get("slots")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok());
            let ids = strings(&args, "rows")
                .iter()
                .map(|r| resource::row_id(r))
                .collect::<HubResult<Vec<_>>>()?;
            let vault = format!("{}:{}", client.name, required(&args, "vault")?);
            return ledger::run_insert(
                &mut store,
                &cfg,
                &vault,
                &ids,
                slots,
                &required(&args, "goal")?,
            );
        }
        "run_show" => {
            let cursor = args.get("cursor").and_then(Value::as_u64).unwrap_or(0);
            return view::run_show(&mut store, &required(&args, "run")?, cursor as usize);
        }
        "run_close" => return ledger::run_close(&mut store, &required(&args, "run")?),
        "questions" => {
            let cursor = args.get("cursor").and_then(Value::as_u64).unwrap_or(0);
            let all = args.get("all") == Some(&json!(true));
            return view::questions_view(&mut store, all, cursor as usize);
        }
        "answer" => {
            if client.role != Role::Owner {
                return Err(HubError::refused(
                    "owner_only",
                    "only a client with the owner role may answer",
                    "the owner answers from an owner client or on the server host",
                ));
            }
            let id = args
                .get("id")
                .and_then(Value::as_i64)
                .ok_or_else(|| HubError::Usage("missing argument 'id'".to_string()))?;
            return ledger::answer(
                &mut store,
                id,
                &required(&args, "text")?,
                &required(&args, "via")?,
            );
        }
        "quota_override" => {
            if client.role != Role::Owner {
                return Err(HubError::refused(
                    "owner_only",
                    "only a client with the owner role may lift the quota gate",
                    "the owner runs it from an owner client or on the server host",
                ));
            }
            let secs = args
                .get("secs")
                .and_then(Value::as_u64)
                .ok_or_else(|| HubError::Usage("missing argument 'secs'".to_string()))?;
            // The client refuses without a terminal; the owner role is what the server checks.
            return quota::set_override(
                &mut store,
                &required(&args, "account")?,
                secs,
                &required(&args, "reason")?,
                true,
            );
        }
        "audit" => {
            let final_only = args.get("require_final") == Some(&json!(true));
            return audit::audit(&mut store, text(&args, "run").as_deref(), final_only);
        }
        "export" => {
            let events = view::export(&mut store, text(&args, "run").as_deref())?;
            return Ok(json!({"ok": true, "events": events}));
        }
        _ => {}
    }
    // The operations shared with the MCP tools.
    if !mcp::is_ledger_tool(op) || op == "stenio_backlog" {
        return Err(HubError::Usage(format!("unknown operation '{op}'")));
    }
    if op == "hub_join" {
        args.insert("host".to_string(), json!(client.name));
        if let Some(parent) = text(&args, "parent") {
            own_worker(&mut store, client, &parent)?;
        }
    } else if let Some(worker) = text(&args, "worker") {
        own_worker(&mut store, client, &worker)?;
    } else if !["hub_status", "stenio_quota"].contains(&op) {
        return Err(HubError::Usage("missing argument 'worker'".to_string()));
    }
    if op == "stenio_quota" {
        args.remove("refresh");
    }
    if op == "hub_claim" {
        let names = strings(&args, "resources")
            .iter()
            .map(|r| namespaced(client, r))
            .collect::<HubResult<Vec<_>>>()?;
        let request = ledger::ClaimRequest {
            worker: required(&args, "worker")?,
            resources: names,
            run: text(&args, "run"),
            ttl_secs: args.get("ttl_secs").and_then(Value::as_u64),
            path: None,
        };
        return ledger::claim(&mut store, &cfg, &request);
    }
    if op == "hub_release"
        && let Some(one) = text(&args, "resource")
    {
        args.insert("resource".to_string(), json!(namespaced(client, &one)?));
    }
    let out = mcp::call_local(op, &args, db)?;
    if op == "hub_join"
        && let Some(worker) = out["worker"].as_str()
    {
        store.write(|tx| set_meta(tx, &client_key(worker), &client.name))?;
    }
    Ok(out)
}

struct Server {
    db: PathBuf,
    clients: PathBuf,
    hosts: Vec<String>,
}

/// The `Host` header without its port, keeping the brackets of an IPv6 literal.
fn host_name(value: &str) -> &str {
    if value.starts_with('[') {
        return value.find(']').map_or(value, |end| &value[..=end]);
    }
    value.rsplit_once(':').map_or(value, |(name, _)| name)
}

fn reject(status: StatusCode, why: &str) -> Response {
    (status, why.to_string()).into_response()
}

/// Transport checks, in the order that reveals the least.
fn admit(server: &Server, headers: &HeaderMap) -> Result<Client, Box<Response>> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| host_name(v).to_ascii_lowercase());
    if !host.is_some_and(|h| server.hosts.contains(&h)) {
        return Err(Box::new(reject(
            StatusCode::MISDIRECTED_REQUEST,
            "host not allowed",
        )));
    }
    // No browser is a client of this API.
    if headers.contains_key(header::ORIGIN) {
        return Err(Box::new(reject(
            StatusCode::FORBIDDEN,
            "origin not allowed",
        )));
    }
    let denied = || Box::new(reject(StatusCode::UNAUTHORIZED, "token required"));
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(denied)?;
    let given = digest(token.trim());
    let clients = read_clients(&server.clients).map_err(|e| {
        eprintln!("stenio hub serve: {e}");
        Box::new(reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "client list unusable",
        ))
    })?;
    clients
        .into_iter()
        .find(|c| same(&c.sha256.to_ascii_lowercase(), &given))
        .ok_or_else(denied)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    #[serde(default)]
    args: Map<String, Value>,
}

async fn operate(State(server): State<Arc<Server>>, headers: HeaderMap, body: Bytes) -> Response {
    let client = match admit(&server, &headers) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let Ok(request) = serde_json::from_slice::<Request>(&body) else {
        return reject(StatusCode::BAD_REQUEST, "expected {op, args}");
    };
    let db = server.db.clone();
    let done = tokio::task::spawn_blocking(move || {
        let outcome = dispatch(&db, &client, &request.op, request.args);
        match outcome {
            Ok(body) => json!({"exit": 0, "body": body}),
            Err(e) => json!({"exit": e.exit_code(), "body": e.to_json()}),
        }
    })
    .await;
    match done {
        Ok(reply) => axum::Json(reply).into_response(),
        Err(_) => reject(StatusCode::INTERNAL_SERVER_ERROR, "operation failed"),
    }
}

/// Serves the ledger at `db` until the process is stopped.
pub fn serve(
    db: PathBuf,
    clients: PathBuf,
    bind: IpAddr,
    port: u16,
    hosts: &[String],
) -> HubResult<()> {
    // Both must be usable before the port opens.
    let known = read_clients(&clients)?;
    Store::open(&db)?;
    let mut allowed: Vec<String> = hosts.iter().map(|h| h.to_ascii_lowercase()).collect();
    allowed.extend(["localhost", "127.0.0.1", "[::1]"].map(String::from));
    if !bind.is_unspecified() {
        allowed.push(match bind {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        });
    }
    let server = Arc::new(Server {
        db,
        clients,
        hosts: allowed,
    });
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/op", post(operate))
        .with_state(server);
    let failed = |e: std::io::Error| HubError::Store(format!("cannot serve: {e}"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(failed)?;
    runtime.block_on(async {
        let address = SocketAddr::new(bind, port);
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .map_err(failed)?;
        let bound = listener.local_addr().map_err(failed)?;
        eprintln!(
            "stenio hub serve: listening on {bound}, {} client(s)",
            known.len()
        );
        axum::serve(listener, app).await.map_err(failed)
    })
}
