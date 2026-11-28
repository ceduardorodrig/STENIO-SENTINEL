//! `stenio hub ...`. Exit codes: 0 done, 1 refused or invalid, 2 usage, 3 ledger unavailable.

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use super::config::{self, Config, WORKER_ENV};
use super::store::Store;
use super::{
    HubError, HubResult, audit, backup, hooks, ledger, quota, receipt, remote, server, view,
};

/// The one-page instructions for workers draining a queue.
pub const GUIDE: &str = include_str!("queue-drain.md");

#[derive(Parser, Debug)]
#[command(
    name = "stenio hub",
    about = "Shared work ledger: claims with fenced leases, hand-backs, owner questions and quota",
    after_help = "Exit codes: 0 done, 1 refused or invalid, 2 usage, 3 ledger unavailable.\nLedger: $STENIO_HUB_DB, else $XDG_STATE_HOME/stenio/hub.db. Worker: --worker or $STENIO_HUB_WORKER.\nStart with `stenio hub guide`."
)]
struct HubArgs {
    #[arg(long, global = true, help = "Print one JSON document")]
    json: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Args, Debug)]
struct Who {
    #[arg(long, help = "Worker id from `hub join` (or $STENIO_HUB_WORKER)")]
    worker: Option<String>,
}

impl Who {
    fn id(&self) -> HubResult<String> {
        config::worker_or_env(self.worker.as_deref())
            .ok_or_else(|| HubError::Usage(format!("give --worker or set {WORKER_ENV}")))
    }
}

#[derive(Subcommand, Debug)]
enum RunCmd {
    /// Open a run over a list of rows
    Start {
        #[arg(long, required = true, help = "Row ids, comma separated or repeated")]
        rows: Vec<String>,
        #[arg(long, help = "Vault or repository root (default: discovered)")]
        path: Option<PathBuf>,
        #[arg(long, help = "Fleet slots of this run")]
        slots: Option<u32>,
        #[arg(long, default_value = "drain the listed rows")]
        goal: String,
    },
    /// Rows of a run and their states
    Show {
        #[arg(long)]
        run: String,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// Close a run that holds no claim
    Close {
        #[arg(long)]
        run: String,
    },
}

#[derive(Subcommand, Debug)]
enum QuotaCmd {
    /// Read every declared source
    Refresh,
    /// Store a sample (a window, or the status line input on stdin)
    Put {
        #[arg(long)]
        account: String,
        #[arg(long, requires = "used", help = "Window name, e.g. five_hour")]
        window: Option<String>,
        #[arg(long, requires = "window", help = "Percentage used, 0 to 100")]
        used: Option<f64>,
        #[arg(long, requires = "window", help = "RFC 3339 or Unix seconds")]
        resets_at: Option<String>,
        #[arg(
            long,
            value_parser = ["claude-statusline"],
            conflicts_with = "window",
            help = "Read the harness record from stdin"
        )]
        from: Option<String>,
    },
    /// Owner only, at a terminal: lift the quota gate of an account for a limited time
    Override {
        #[arg(long)]
        account: String,
        #[arg(
            long = "for",
            help = "Seconds, or with s, m, h; at most 24h; 0 revokes"
        )]
        duration: String,
        #[arg(long)]
        reason: String,
    },
    /// Known and unknown windows
    Show {
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Register a worker and receive its id
    Join {
        #[arg(long)]
        harness: String,
        #[arg(long)]
        harness_version: Option<String>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long, help = "Default: this machine's host name")]
        host: Option<String>,
        #[arg(long, help = "Worker id of the coordinator that started this one")]
        parent: Option<String>,
        #[arg(
            long,
            help = "Quota account (default: declared per harness, else its name)"
        )]
        account: Option<String>,
        #[arg(
            long,
            help = "Harness session id that hooks report (default: declared variable)"
        )]
        session: Option<String>,
    },
    /// Renew nothing, check a pending file edit (hook payload on stdin; exit 2 blocks)
    Guard,
    /// Snapshot the ledger into a directory, or check the newest snapshot there
    Backup {
        #[arg(long, required_unless_present = "check", conflicts_with = "check")]
        out: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 14, help = "Snapshots kept in --out")]
        keep: usize,
        #[arg(long, help = "Fail unless the newest snapshot is recent and restores")]
        check: Option<std::path::PathBuf>,
        #[arg(long, help = "Limit for --check: seconds, or with s, m, h")]
        max_age: Option<String>,
    },
    /// Open, inspect and close runs
    Run {
        #[command(subcommand)]
        command: RunCmd,
    },
    /// Claim resources, all or nothing
    Claim {
        #[command(flatten)]
        who: Who,
        #[arg(
            required = true,
            help = "row:<ID> tree:<path> repo:<owner/name> branch: host: release: deploy: backlog:<P>:write fleet:slot"
        )]
        resources: Vec<String>,
        #[arg(long)]
        run: Option<String>,
        #[arg(long, help = "Lease length: seconds, or with s, m, h")]
        ttl: Option<String>,
        #[arg(
            long,
            help = "Bind a backlog:<P>:write claim to the queue under this directory (default: every directory)"
        )]
        path: Option<PathBuf>,
    },
    /// Renew the leases
    Beat {
        #[command(flatten)]
        who: Who,
        #[arg(long, help = "Only the claims of this fence")]
        fence: Option<i64>,
        #[arg(long, help = "Called by a harness hook: throttled and quiet")]
        from_hook: bool,
    },
    /// Give claims back without a result
    Release {
        #[command(flatten)]
        who: Who,
        #[arg(long)]
        fence: i64,
        #[arg(long, help = "Only this resource of the fence")]
        resource: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Claims, rows of the open runs, waiting questions and quota
    Status {
        #[arg(long)]
        run: Option<String>,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// Record progress or the checkpoint a successor will receive
    Event {
        #[command(flatten)]
        who: Who,
        #[arg(long = "type", help = "checkpoint, progress or note")]
        kind: String,
        #[arg(long)]
        fence: Option<i64>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        clone: Option<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        next_step: Option<String>,
    },
    /// Return the result of a row
    Handback {
        #[command(flatten)]
        who: Who,
        #[arg(
            long,
            help = "Omit for a fence that holds no row (backlog, release, deploy)"
        )]
        row: Option<String>,
        #[arg(long)]
        fence: i64,
        #[arg(long, help = "done, partial, blocked, needs-owner or failed")]
        verdict: String,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long)]
        pr: Option<String>,
        #[arg(long)]
        proof: Option<String>,
        #[arg(long)]
        remaining: Option<String>,
        #[arg(long = "defect", help = "A newly found defect (repeatable)")]
        defects: Vec<String>,
    },
    /// File a question for the owner
    Ask {
        #[command(flatten)]
        who: Who,
        #[arg(long)]
        row: Option<String>,
        #[arg(long)]
        text: String,
        #[arg(long = "option")]
        options: Vec<String>,
        #[arg(long)]
        recommend: Option<String>,
    },
    /// Owner only, at a terminal: give a row a new attempt budget
    ResetAttempts {
        #[arg(long)]
        row: String,
        #[arg(long)]
        reason: String,
    },
    /// Record the owner's answer (command line only; grants nothing)
    Answer {
        #[arg(long)]
        id: i64,
        #[arg(long)]
        text: String,
        #[arg(long, default_value = "cli")]
        via: String,
    },
    /// Run a command on a tree and record commit, tree fingerprint, exit and output hash
    Receipt {
        #[command(flatten)]
        who: Who,
        #[arg(long)]
        row: String,
        #[arg(long, help = "Git checkout the command runs in")]
        tree: std::path::PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Fail unless the newest receipt of a row still matches its tree
    Closable {
        #[arg(long)]
        row: String,
    },
    /// Questions waiting for the owner
    Questions {
        #[arg(long, help = "Include answered ones")]
        all: bool,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// Read one backlog row, or search the queues
    Backlog {
        #[arg(long, conflicts_with = "query")]
        id: Option<String>,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        queue: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// Account limits
    Quota {
        #[command(subcommand)]
        command: QuotaCmd,
    },
    /// Verify the event chain and the state tables
    Audit {
        #[arg(long)]
        run: Option<String>,
        #[arg(long, help = "Also fail while a row of the run has no final state")]
        require_final: bool,
    },
    /// Print the events as JSON lines
    Export {
        #[arg(long)]
        run: Option<String>,
        #[arg(long, help = "Write to this new file instead of stdout")]
        out: Option<PathBuf>,
    },
    /// Serve the ledger to other machines (loopback by default, token always required)
    Serve {
        #[arg(long, help = "TOML list of clients: name, sha256 of the token, role")]
        clients: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        #[arg(long, default_value_t = 8797)]
        port: u16,
        #[arg(long = "allow-host", help = "Extra accepted Host name (repeatable)")]
        allow_host: Vec<String>,
    },
    /// Create a client token in a new private file and print the entry for the client list
    Token {
        #[arg(long)]
        client: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// The worker instructions
    Guide,
}

/// Seconds from `90`, `90s`, `20m` or `2h`.
pub fn parse_ttl(raw: &str) -> HubResult<u64> {
    let raw = raw.trim();
    let (number, factor) = match raw.char_indices().last() {
        Some((i, 's')) => (&raw[..i], 1),
        Some((i, 'm')) => (&raw[..i], 60),
        Some((i, 'h')) => (&raw[..i], 3600),
        _ => (raw, 1),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| HubError::Usage(format!("invalid duration '{raw}'")))
}

fn parse_instant(raw: &str) -> HubResult<i64> {
    raw.parse::<i64>()
        .ok()
        .map(|secs| secs.saturating_mul(1000))
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(raw)
                .ok()
                .map(|t| t.timestamp_millis())
        })
        .ok_or_else(|| HubError::Usage(format!("invalid time '{raw}'")))
}

fn open() -> HubResult<Store> {
    Store::open(&config::db_path()?)
}

fn put_quota(
    account: &str,
    window: Option<String>,
    used: Option<f64>,
    resets_at: Option<String>,
    from: Option<String>,
) -> HubResult<Value> {
    if let Some(source) = from {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| HubError::Usage(format!("cannot read stdin: {e}")))?;
        return match quota::parse_statusline(&input) {
            Ok(windows) => quota::put(&mut open()?, account, &source, &windows),
            Err(reason) => {
                quota::put_unknown(&mut open()?, account, &source, &reason)?;
                Ok(json!({"ok": true, "account": account, "unknown": reason}))
            }
        };
    }
    let (Some(window), Some(used_pct)) = (window, used) else {
        return Err(HubError::Usage(
            "give --window and --used, or --from".to_string(),
        ));
    };
    if used_pct > 100.0 {
        return Err(HubError::Usage("--used is between 0 and 100".to_string()));
    }
    let sample = quota::Window {
        window,
        used_pct,
        resets_at: resets_at.as_deref().map(parse_instant).transpose()?,
    };
    quota::put(&mut open()?, account, "put", &[sample])
}

/// The declared server decides where a command runs; serving and its tokens are always here.
fn execute(command: Cmd) -> HubResult<Value> {
    match command {
        Cmd::Serve {
            clients,
            bind,
            port,
            allow_host,
        } => {
            server::serve(config::db_path()?, clients, bind, port, &allow_host)?;
            Ok(json!({"ok": true}))
        }
        Cmd::Token { client, out } => server::mint(&client, &out),
        Cmd::Guide => Ok(Value::String(GUIDE.to_string())),
        other => match remote::declared()? {
            Some(server) => execute_remote(&server, other),
            None => execute_local(other),
        },
    }
}

fn write_export(text: &str, out: &std::path::Path) -> HubResult<Value> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| HubError::Usage(format!("cannot write {}: {e}", out.display())))?;
    Ok(json!({"ok": true, "events": text.lines().count(),
        "file": out.display().to_string()}))
}

/// The same command as one request; only what needs this machine happens here.
fn execute_remote(server: &remote::Remote, command: Cmd) -> HubResult<Value> {
    let send = |op: &str, args: Value| match args {
        Value::Object(map) => remote::operate(server, op, map),
        _ => Err(HubError::Usage("arguments must be an object".to_string())),
    };
    match command {
        Cmd::Join {
            harness,
            harness_version,
            model,
            host,
            parent,
            account,
            session,
        } => send(
            "hub_join",
            json!({"harness": harness, "harness_version": harness_version, "model": model,
                "host": host, "parent": parent, "account": account, "session": session}),
        ),
        Cmd::Run { command } => match command {
            RunCmd::Start {
                rows,
                path,
                slots,
                goal,
            } => {
                let vault = view::resolve_root(None, path.as_deref())?;
                let ids = ledger::run_row_ids(&vault, &rows)?;
                send(
                    "run_start",
                    json!({"rows": ids, "vault": vault.display().to_string(), "slots": slots,
                        "goal": goal}),
                )
            }
            RunCmd::Show { run, cursor } => send("run_show", json!({"run": run, "cursor": cursor})),
            RunCmd::Close { run } => send("run_close", json!({"run": run})),
        },
        Cmd::Claim {
            who,
            resources,
            run,
            ttl,
            path: _,
        } => send(
            "hub_claim",
            json!({"worker": who.id()?, "resources": resources, "run": run,
                "ttl_secs": ttl.as_deref().map(parse_ttl).transpose()?}),
        ),
        Cmd::Beat { who, fence, .. } => {
            send("hub_beat", json!({"worker": who.id()?, "fence": fence}))
        }
        Cmd::Release {
            who,
            fence,
            resource,
            reason,
        } => send(
            "hub_release",
            json!({"worker": who.id()?, "fence": fence, "resource": resource, "reason": reason}),
        ),
        Cmd::Status { run, cursor } => send("hub_status", json!({"run": run, "cursor": cursor})),
        Cmd::Event {
            who,
            kind,
            fence,
            note,
            clone,
            branch,
            next_step,
        } => send(
            "hub_event",
            json!({"worker": who.id()?, "type": kind, "fence": fence, "note": note,
                "clone": clone, "branch": branch, "next_step": next_step}),
        ),
        Cmd::Handback {
            who,
            row,
            fence,
            verdict,
            branch,
            pr,
            proof,
            remaining,
            defects,
        } => send(
            "hub_handback",
            json!({"worker": who.id()?, "row": row, "fence": fence, "verdict": verdict,
                "branch": branch, "pr": pr, "proof": proof, "remaining": remaining,
                "defects": defects}),
        ),
        Cmd::Ask {
            who,
            row,
            text,
            options,
            recommend,
        } => send(
            "hub_ask",
            json!({"worker": who.id()?, "row": row, "text": text, "options": options,
                "recommendation": recommend}),
        ),
        Cmd::Answer { id, text, via } => {
            send("answer", json!({"id": id, "text": text, "via": via}))
        }
        Cmd::ResetAttempts { row, reason } => {
            if !std::io::stdin().is_terminal() {
                return Err(HubError::refused(
                    "owner_only",
                    "resetting attempts is the owner's decision and needs an interactive terminal",
                    "ask the owner (stenio hub ask)",
                ));
            }
            send("attempts_reset", json!({"row": row, "reason": reason}))
        }
        Cmd::Questions { all, cursor } => send("questions", json!({"all": all, "cursor": cursor})),
        local @ Cmd::Backlog { .. } => execute_local(local),
        Cmd::Receipt {
            who,
            row,
            tree,
            command,
        } => receipt::run(
            &mut receipt::Ledger::Served(server),
            &who.id()?,
            &row,
            &tree,
            &command,
        ),
        Cmd::Closable { row } => receipt::closable(&mut receipt::Ledger::Served(server), &row),
        Cmd::Quota { command } => match command {
            QuotaCmd::Refresh => send("quota_refresh", json!({})),
            QuotaCmd::Put {
                account,
                window,
                used,
                resets_at,
                from,
            } => {
                if let Some(source) = from {
                    let mut input = String::new();
                    std::io::stdin()
                        .read_to_string(&mut input)
                        .map_err(|e| HubError::Usage(format!("cannot read stdin: {e}")))?;
                    return match quota::parse_statusline(&input) {
                        Ok(windows) => {
                            for w in &windows {
                                send(
                                    "quota_put",
                                    json!({"account": account, "source": source,
                                        "window": w.window, "used_pct": w.used_pct,
                                        "resets_at": w.resets_at}),
                                )?;
                            }
                            Ok(json!({"ok": true, "account": account,
                                "windows": windows.len()}))
                        }
                        Err(reason) => send(
                            "quota_put",
                            json!({"account": account, "source": source, "unknown": reason}),
                        ),
                    };
                }
                let resets = resets_at.as_deref().map(parse_instant).transpose()?;
                send(
                    "quota_put",
                    json!({"account": account, "source": "put", "window": window,
                        "used_pct": used, "resets_at": resets}),
                )
            }
            QuotaCmd::Show { cursor } => send("stenio_quota", json!({"cursor": cursor})),
            QuotaCmd::Override {
                account,
                duration,
                reason,
            } => {
                if !std::io::stdin().is_terminal() {
                    return Err(HubError::refused(
                        "owner_only",
                        "a quota override is the owner's decision and needs an interactive terminal",
                        "ask the owner (stenio hub ask)",
                    ));
                }
                let secs = match duration.trim() {
                    "0" => 0,
                    other => parse_ttl(other)?,
                };
                send(
                    "quota_override",
                    json!({"account": account, "secs": secs, "reason": reason}),
                )
            }
        },
        Cmd::Audit { run, require_final } => {
            send("audit", json!({"run": run, "require_final": require_final}))
        }
        Cmd::Export { run, out } => {
            let reply = send("export", json!({"run": run}))?;
            let text = reply["events"].as_str().unwrap_or_default().to_string();
            match out {
                Some(path) => write_export(&text, &path),
                None => Ok(Value::String(text)),
            }
        }
        Cmd::Backup { .. } => Err(HubError::Usage(
            "the ledger is served by a server: back it up and check it there".to_string(),
        )),
        Cmd::Guard | Cmd::Serve { .. } | Cmd::Token { .. } | Cmd::Guide => Err(HubError::Usage(
            "this command runs only on this machine".to_string(),
        )),
    }
}

fn execute_local(command: Cmd) -> HubResult<Value> {
    let cfg = Config::load()?;
    match command {
        Cmd::Join {
            harness,
            harness_version,
            model,
            host,
            parent,
            account,
            session,
        } => ledger::join(
            &mut open()?,
            &cfg,
            &ledger::Join {
                harness,
                harness_version,
                model,
                host,
                parent,
                account,
                session,
            },
        ),
        Cmd::Guard => Err(HubError::Usage("guard runs as a hook".to_string())),
        Cmd::Backup {
            out,
            keep,
            check,
            max_age,
        } => match (check, out) {
            (Some(dir), _) => {
                let limit = max_age.as_deref().map(parse_ttl).transpose()?;
                backup::check(&dir, limit.unwrap_or(cfg.backup.max_age_secs))
            }
            (None, Some(dir)) => backup::backup(&dir, keep),
            (None, None) => Err(HubError::Usage("give --out or --check".to_string())),
        },
        Cmd::Run { command } => match command {
            RunCmd::Start {
                rows,
                path,
                slots,
                goal,
            } => {
                let vault = view::resolve_root(None, path.as_deref())?;
                ledger::run_start(&mut open()?, &cfg, &vault, &rows, slots, &goal)
            }
            RunCmd::Show { run, cursor } => view::run_show(&mut open()?, &run, cursor),
            RunCmd::Close { run } => ledger::run_close(&mut open()?, &run),
        },
        Cmd::Claim {
            who,
            resources,
            run,
            ttl,
            path,
        } => {
            let request = ledger::ClaimRequest {
                worker: who.id()?,
                resources,
                run,
                ttl_secs: ttl.as_deref().map(parse_ttl).transpose()?,
                path,
            };
            ledger::claim(&mut open()?, &cfg, &request)
        }
        Cmd::Beat {
            who,
            fence,
            from_hook,
        } => {
            let request = ledger::BeatRequest {
                worker: who.id()?,
                fence,
                from_hook,
            };
            ledger::beat(&mut open()?, &cfg, &request)
        }
        Cmd::Release {
            who,
            fence,
            resource,
            reason,
        } => ledger::release(
            &mut open()?,
            &who.id()?,
            fence,
            resource.as_deref(),
            reason.as_deref(),
        ),
        Cmd::Status { run, cursor } => view::status(&mut open()?, &cfg, run.as_deref(), cursor),
        Cmd::Event {
            who,
            kind,
            fence,
            note,
            clone,
            branch,
            next_step,
        } => {
            let request = ledger::Record {
                worker: who.id()?,
                kind,
                fence,
                note,
                clone,
                branch,
                next_step,
            };
            ledger::record(&mut open()?, &request)
        }
        Cmd::Handback {
            who,
            row,
            fence,
            verdict,
            branch,
            pr,
            proof,
            remaining,
            defects,
        } => {
            let request = ledger::Handback {
                worker: who.id()?,
                row: row.unwrap_or_default(),
                fence,
                verdict,
                branch,
                pr,
                proof,
                remaining,
                defects,
            };
            ledger::handback(&mut open()?, &request)
        }
        Cmd::Ask {
            who,
            row,
            text,
            options,
            recommend,
        } => {
            let request = ledger::Question {
                worker: who.id()?,
                row,
                text,
                options,
                recommendation: recommend,
            };
            ledger::ask(&mut open()?, &request)
        }
        Cmd::Answer { id, text, via } => ledger::answer(&mut open()?, id, &text, &via),
        Cmd::Receipt {
            who,
            row,
            tree,
            command,
        } => receipt::run(
            &mut receipt::Ledger::Local(&mut open()?),
            &who.id()?,
            &row,
            &tree,
            &command,
        ),
        Cmd::Closable { row } => receipt::closable(&mut receipt::Ledger::Local(&mut open()?), &row),
        Cmd::ResetAttempts { row, reason } => {
            ledger::reset_attempts(&mut open()?, &row, &reason, std::io::stdin().is_terminal())
        }
        Cmd::Questions { all, cursor } => view::questions_view(&mut open()?, all, cursor),
        Cmd::Backlog {
            id,
            query,
            queue,
            path,
            cursor,
        } => {
            let mut store = match remote::declared()? {
                Some(_) => None,
                None => open().ok(),
            };
            let root = view::resolve_root(store.as_mut(), path.as_deref())?;
            view::backlog(
                &root,
                id.as_deref(),
                query.as_deref(),
                queue.as_deref(),
                cursor,
            )
        }
        Cmd::Quota { command } => match command {
            QuotaCmd::Refresh => quota::refresh(&mut open()?, &cfg.quota),
            QuotaCmd::Put {
                account,
                window,
                used,
                resets_at,
                from,
            } => put_quota(&account, window, used, resets_at, from),
            QuotaCmd::Override {
                account,
                duration,
                reason,
            } => {
                let secs = match duration.trim() {
                    "0" => 0,
                    other => parse_ttl(other)?,
                };
                quota::set_override(
                    &mut open()?,
                    &account,
                    secs,
                    &reason,
                    std::io::stdin().is_terminal(),
                )
            }
            QuotaCmd::Show { cursor } => view::quota_view(&mut open()?, &cfg, cursor),
        },
        Cmd::Audit { run, require_final } => {
            audit::audit(&mut open()?, run.as_deref(), require_final)
        }
        Cmd::Export { run, out } => {
            let text = view::export(&mut open()?, run.as_deref())?;
            match out {
                Some(path) => {
                    use std::io::Write;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .and_then(|mut f| f.write_all(text.as_bytes()))
                        .map_err(|e| {
                            HubError::Usage(format!("cannot write {}: {e}", path.display()))
                        })?;
                    Ok(json!({"ok": true, "events": text.lines().count(),
                        "file": path.display().to_string()}))
                }
                None => Ok(Value::String(text)),
            }
        }
        Cmd::Guide | Cmd::Serve { .. } | Cmd::Token { .. } => Err(HubError::Usage(
            "this command does not use the ledger".to_string(),
        )),
    }
}

/// `key: value` lines, and one compact line per list item.
fn plain(value: &Value) -> String {
    let scalar = |v: &Value| match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let Value::Object(map) = value else {
        return scalar(value);
    };
    let mut out = String::new();
    for (key, v) in map.iter().filter(|(k, v)| *k != "ok" && !v.is_null()) {
        match v {
            Value::Array(items) => {
                for item in items {
                    let fields = item.as_object().map(|o| {
                        o.iter()
                            .filter(|(_, v)| !v.is_null())
                            .map(|(k, v)| format!("{k}={}", scalar(v)))
                            .collect::<Vec<_>>()
                            .join(" ")
                    });
                    out.push_str(&format!(
                        "{key}: {}\n",
                        fields.unwrap_or_else(|| scalar(item))
                    ));
                }
            }
            other => out.push_str(&format!("{key}: {}\n", scalar(other))),
        }
    }
    out.trim_end().to_string()
}

/// Writes the answer. A reader that closes the pipe early (`| head`) ends the output quietly
/// instead of panicking; the command itself already happened.
fn emit(text: &str) {
    use std::io::{ErrorKind, Write};
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush())
        && e.kind() != ErrorKind::BrokenPipe
    {
        eprintln!("stenio hub: cannot write the answer: {e}");
    }
}

/// `args` are the words after `stenio hub`.
pub fn run_cli(args: &[String]) -> i32 {
    let argv = std::iter::once("stenio hub".to_string()).chain(args.iter().cloned());
    let parsed = match HubArgs::try_parse_from(argv) {
        Ok(p) => p,
        Err(e) => return crate::util::usage_exit(&e),
    };
    // Hooks have their own exit contract and never fail the tool call by accident.
    match &parsed.command {
        Cmd::Beat {
            who,
            fence,
            from_hook: true,
        } => return hooks::beat_hook(who.worker.as_deref(), *fence),
        Cmd::Guard => return hooks::guard_hook(),
        _ => {}
    }
    match execute(parsed.command) {
        Ok(Value::String(text)) => {
            emit(&text);
            0
        }
        Ok(value) => {
            let value = super::hygiene::label(value);
            // The warning of an unbound join must be seen even when stdout is captured.
            if let Some(warning) = value["warning"].as_str() {
                eprintln!("WARNING: {warning}");
            }
            if parsed.json {
                emit(&format!("{value}\n"));
            } else {
                emit(&format!("{}\n", plain(&value)));
            }
            // An audit that found a problem is a completed command with a negative answer.
            i32::from(value["ok"] == json!(false))
        }
        Err(e) => {
            if parsed.json {
                emit(&format!("{}\n", e.to_json()));
            } else {
                eprintln!("{e}");
            }
            e.exit_code()
        }
    }
}
