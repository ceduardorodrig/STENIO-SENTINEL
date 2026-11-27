//! The ledger tools of the **stdio** MCP server. They are not offered over HTTP: the first release
//! is local. Owner answers and grants are deliberately not tools.

use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

use super::config::{self, Config};
use super::store::Store;
use super::{HubError, HubResult, ledger, quota, view};
use crate::mcp::{McpRequest, McpResponse};

/// Lines of the server instructions shown to a client at start.
const INSTRUCTIONS: &str = "Shared work ledger: hub_join once, then hub_status. Claim before \
touching a row, tree or repository (hub_claim, all or nothing; keep the fence). Renew with \
hub_beat, save a checkpoint with hub_event, finish with hub_handback. A refusal names who holds \
the resource and what to do next. Full rules: `stenio hub guide`.";

fn text(description: &str) -> Value {
    json!({"type": "string", "description": description})
}

fn number(description: &str) -> Value {
    json!({"type": "integer", "description": description})
}

fn list(description: &str) -> Value {
    json!({"type": "array", "items": {"type": "string"}, "description": description})
}

fn tool(name: &str, description: &str, read_only: bool, required: &[&str], props: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": props, "required": required},
        "annotations": {"readOnlyHint": read_only, "destructiveHint": false}
    })
}

pub fn tool_definitions() -> Vec<Value> {
    let worker = || text("Worker id from hub_join (default: STENIO_HUB_WORKER)");
    let fence = || number("Fence token returned by hub_claim");
    let cursor = || number("next_cursor of the previous page");
    vec![
        tool(
            "hub_join",
            "Register this agent in the shared work ledger and receive its worker id.",
            false,
            &["harness"],
            json!({"harness": text("e.g. claude, hermes, opencode"),
                "harness_version": text("Harness version"), "model": text("Model name"),
                "session": text("Harness session id that hooks report"),
                "host": text("Host name (default: this machine)"),
                "parent": text("Coordinator's worker id"),
                "account": text("Quota account")}),
        ),
        tool(
            "hub_status",
            "Who holds what, row states of the open runs, waiting owner questions and quota.",
            true,
            &[],
            json!({"run": text("Only this run"), "cursor": cursor()}),
        ),
        tool(
            "hub_claim",
            "Claim resources, all or nothing, before working on them. Returns the fence token.",
            false,
            &["resources"],
            json!({"worker": worker(),
                "resources": list("row:<ID>, tree:<abs path>, repo:<owner/name>, backlog:<P>:write, fleet:slot, ..."),
                "run": text("Run id"), "ttl_secs": number("Lease length in seconds"),
                "path": text("Bind a backlog claim to the queue under this directory")}),
        ),
        tool(
            "hub_beat",
            "Renew the leases of this worker before they expire.",
            false,
            &[],
            json!({"worker": worker(), "fence": fence()}),
        ),
        tool(
            "hub_release",
            "Give claimed resources back without a result.",
            false,
            &["fence"],
            json!({"worker": worker(), "fence": fence(),
                "resource": text("Only this resource"), "reason": text("Why")}),
        ),
        tool(
            "hub_event",
            "Record progress, or the checkpoint a successor receives if the lease expires.",
            false,
            &["type"],
            json!({"worker": worker(), "type": text("checkpoint, progress or note"),
                "fence": fence(), "note": text("What happened"),
                "clone": text("Working directory"), "branch": text("Branch"),
                "next_step": text("What comes next")}),
        ),
        tool(
            "hub_handback",
            "Return the result of a claimed row, or of a fence without a row. The engine records it; it does not replay the proof.",
            false,
            &["fence", "verdict"],
            json!({"worker": worker(), "row": text("Row id; omit for a fence without a row"), "fence": fence(),
                "verdict": text("done, partial, blocked, needs-owner or failed"),
                "branch": text("Branch"), "pr": text("Pull request"),
                "proof": text("Required for done"),
                "remaining": text("Required for partial, blocked and failed"),
                "defects": list("Newly found defects")}),
        ),
        tool(
            "hub_ask",
            "File a question for the owner. The answer cannot be given through MCP.",
            false,
            &["text"],
            json!({"worker": worker(), "row": text("Row id"), "text": text("The question"),
                "options": list("Possible answers"), "recommendation": text("Recommended answer")}),
        ),
        tool(
            "stenio_quota",
            "Account limits as read from real sources; anything not read is 'unknown', never 0.",
            false,
            &[],
            json!({"refresh": {"type": "boolean", "description": "Read the declared sources now"},
                "cursor": cursor()}),
        ),
        tool(
            "stenio_backlog",
            "Read one backlog row by id, or search the queues.",
            true,
            &[],
            json!({"id": text("Row id"), "query": text("Words to search"),
                "queue": text("Queue prefix"), "path": text("Vault or repository root"),
                "cursor": cursor()}),
        ),
    ]
}

struct Arguments<'a>(&'a Map<String, Value>);

impl Arguments<'_> {
    fn text(&self, key: &str) -> HubResult<Option<String>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(HubError::Usage(format!("'{key}' must be a string"))),
        }
    }

    fn required(&self, key: &str) -> HubResult<String> {
        self.text(key)?
            .ok_or_else(|| HubError::Usage(format!("missing argument '{key}'")))
    }

    fn number(&self, key: &str) -> HubResult<Option<i64>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_i64()
                .filter(|n| *n >= 0)
                .map(Some)
                .ok_or_else(|| HubError::Usage(format!("'{key}' must be a whole number"))),
        }
    }

    fn fence(&self) -> HubResult<i64> {
        self.number("fence")?
            .ok_or_else(|| HubError::Usage("missing argument 'fence'".to_string()))
    }

    fn cursor(&self) -> HubResult<usize> {
        Ok(self.number("cursor")?.unwrap_or(0) as usize)
    }

    fn list(&self, key: &str) -> HubResult<Vec<String>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::String(s)) => Ok(vec![s.clone()]),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| HubError::Usage(format!("'{key}' holds only strings")))
                })
                .collect(),
            Some(_) => Err(HubError::Usage(format!("'{key}' must be a list"))),
        }
    }

    fn worker(&self) -> HubResult<String> {
        config::worker_or_env(self.text("worker")?.as_deref())
            .ok_or_else(|| HubError::Usage("missing argument 'worker'".to_string()))
    }
}

fn call(name: &str, args: &Arguments<'_>, root: &Path, db: Option<&Path>) -> HubResult<Value> {
    let cfg = Config::load()?;
    let open = || -> HubResult<Store> {
        match db {
            Some(path) => Store::open(path),
            None => Store::open(&config::db_path()?),
        }
    };
    match name {
        "hub_join" => ledger::join(
            &mut open()?,
            &cfg,
            &ledger::Join {
                harness: args.required("harness")?,
                harness_version: args.text("harness_version")?,
                session: args.text("session")?,
                model: args.text("model")?,
                host: args.text("host")?,
                parent: args.text("parent")?,
                account: args.text("account")?,
            },
        ),
        "hub_status" => view::status(
            &mut open()?,
            &cfg,
            args.text("run")?.as_deref(),
            args.cursor()?,
        ),
        "hub_claim" => ledger::claim(
            &mut open()?,
            &cfg,
            &ledger::ClaimRequest {
                worker: args.worker()?,
                resources: args.list("resources")?,
                run: args.text("run")?,
                ttl_secs: args.number("ttl_secs")?.map(|n| n as u64),
                path: args.text("path")?.map(|p| root.join(p)),
            },
        ),
        "hub_beat" => ledger::beat(
            &mut open()?,
            &cfg,
            &ledger::BeatRequest {
                worker: args.worker()?,
                fence: args.number("fence")?,
                from_hook: false,
            },
        ),
        "hub_release" => ledger::release(
            &mut open()?,
            &args.worker()?,
            args.fence()?,
            args.text("resource")?.as_deref(),
            args.text("reason")?.as_deref(),
        ),
        "hub_event" => ledger::record(
            &mut open()?,
            &ledger::Record {
                worker: args.worker()?,
                kind: args.required("type")?,
                fence: args.number("fence")?,
                note: args.text("note")?,
                clone: args.text("clone")?,
                branch: args.text("branch")?,
                next_step: args.text("next_step")?,
            },
        ),
        "hub_handback" => ledger::handback(
            &mut open()?,
            &ledger::Handback {
                worker: args.worker()?,
                row: args.text("row")?.unwrap_or_default(),
                fence: args.fence()?,
                verdict: args.required("verdict")?,
                branch: args.text("branch")?,
                pr: args.text("pr")?,
                proof: args.text("proof")?,
                remaining: args.text("remaining")?,
                defects: args.list("defects")?,
            },
        ),
        "hub_ask" => ledger::ask(
            &mut open()?,
            &ledger::Question {
                worker: args.worker()?,
                row: args.text("row")?,
                text: args.required("text")?,
                options: args.list("options")?,
                recommendation: args.text("recommendation")?,
            },
        ),
        "stenio_quota" => {
            let mut store = open()?;
            let refreshed = match args.0.get("refresh") {
                Some(Value::Bool(true)) => Some(quota::refresh(&mut store, &cfg.quota)?),
                _ => None,
            };
            let mut out = view::quota_view(&mut store, &cfg, args.cursor()?)?;
            if let Some(report) = refreshed {
                out["refreshed"] = report["refreshed"].clone();
            }
            Ok(out)
        }
        "stenio_backlog" => {
            let mut store = open().ok();
            let given: Option<PathBuf> = args.text("path")?.map(|p| root.join(p));
            // The server's directory counts only when it holds queues itself.
            let fallback = given.clone().or_else(|| config::discover_root(Some(root)));
            let vault = view::resolve_root(store.as_mut(), fallback.as_deref())?;
            view::backlog(
                &vault,
                args.text("id")?.as_deref(),
                args.text("query")?.as_deref(),
                args.text("queue")?.as_deref(),
                args.cursor()?,
            )
        }
        other => Err(HubError::Usage(format!("unknown ledger tool '{other}'"))),
    }
}

fn is_ledger_tool(name: &str) -> bool {
    tool_definitions().iter().any(|t| t["name"] == name)
}

/// The tool result: a short text, the same data as `structuredContent`, and `isError`.
pub fn tool_result(outcome: &HubResult<Value>) -> Value {
    let (data, failed) = match outcome {
        Ok(v) => (v.clone(), v["ok"] == json!(false)),
        Err(e) => (e.to_json(), true),
    };
    // Clients that ignore structured content still read the data in the text.
    json!({
        "content": [{"type": "text", "text": data.to_string()}],
        "structuredContent": data,
        "isError": failed
    })
}

fn respond(req: &McpRequest, result: Value) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id.clone().unwrap_or(Value::Null),
        result: Some(result),
        error: None,
    }
}

/// Handles a call of a ledger tool; `None` lets the engine's own dispatcher answer.
pub fn intercept(req: &McpRequest, root: &Path, db: Option<&Path>) -> Option<McpResponse> {
    if req.method != "tools/call" || req.id.is_none() {
        return None;
    }
    let name = req.params.get("name").and_then(Value::as_str)?;
    if !is_ledger_tool(name) {
        return None;
    }
    let empty = Map::new();
    let args = req
        .params
        .get("arguments")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let outcome = call(name, &Arguments(args), root, db);
    Some(respond(req, tool_result(&outcome)))
}

/// Adds the ledger tools and the instructions to the stdio server's own answers.
pub fn extend(req: &McpRequest, response: &mut McpResponse) {
    let Some(result) = response.result.as_mut() else {
        return;
    };
    match req.method.as_str() {
        "tools/list" => {
            if let Some(tools) = result["tools"].as_array_mut() {
                tools.extend(tool_definitions());
            }
        }
        "initialize" => result["instructions"] = json!(INSTRUCTIONS),
        _ => {}
    }
}
