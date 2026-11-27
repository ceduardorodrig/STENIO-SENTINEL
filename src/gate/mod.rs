//! `stenio gate`: the command gate for unattended agents.
//!
//! Harnesses run automatically; this gate denies a short declared list of irreversible or
//! outward actions (`policy.toml`) and records every command and edit it judged. It reads text:
//! it is a guard against mistakes and plain attempts, not a sandbox. It cannot see what an
//! interpreter computes, what a script builds at run time, an alias, an MCP tool that acts by
//! itself, or a harness that does not call it. It never grants permission, evaluates the list
//! without the ledger, and lets everything else proceed.

mod audit;
mod grant;
mod judge;
mod parse;
mod paths;
mod policy;
mod selftest;

use clap::{Parser, Subcommand};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

use crate::hub::{config, hooks};
use judge::{Finding, Judge, PUBLISH};
pub use selftest::self_test_cases;

/// A write tool carries the file content, so the gate reads more than the ledger hooks do.
const INPUT_LIMIT: u64 = 32 * 1024 * 1024;

const COMMAND_TOOLS: [&str; 8] = [
    "bash",
    "terminal",
    "shell",
    "run_command",
    "execute_command",
    "run_shell_command",
    "run_in_terminal",
    "process",
];
const COMMAND_KEYS: [&str; 5] = ["command", "commandline", "cmd", "data", "script"];

/// What a tool call is about to do.
#[derive(Debug, Default)]
struct Action {
    tool: String,
    cwd: PathBuf,
    command: Option<String>,
    code: Option<String>,
    writes: Vec<String>,
    deletes: Vec<String>,
    reads: Vec<String>,
}

fn argument<'v>(args: &'v Value, names: &[&str]) -> Option<&'v str> {
    args.as_object()?.iter().find_map(|(key, value)| {
        let key = key.replace('_', "").to_ascii_lowercase();
        names
            .contains(&key.as_str())
            .then(|| value.as_str())
            .flatten()
    })
}

/// The payload shapes of Claude Code, Hermes, OpenCode (through its plugin) and Antigravity.
fn action_of(payload: &Value) -> Action {
    let (tool, args) = match payload.get("toolCall") {
        Some(call) => (call.get("name"), call.get("args")),
        None => (payload.get("tool_name"), payload.get("tool_input")),
    };
    let tool = tool
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let null = Value::Null;
    let args = args.unwrap_or(&null);
    let here = std::env::current_dir().unwrap_or_default();
    let cwd = argument(args, &["cwd", "workdir", "workingdirectory"])
        .or_else(|| payload.get("cwd").and_then(Value::as_str))
        .filter(|c| !c.is_empty())
        .map_or(here, PathBuf::from);
    let mut action = Action {
        cwd,
        ..Action::default()
    };
    if COMMAND_TOOLS.contains(&tool.as_str()) || argument(args, &["commandline"]).is_some() {
        action.command = argument(args, &COMMAND_KEYS).map(str::to_string);
    } else if tool == "execute_code" {
        action.code = argument(args, &["code"]).map(str::to_string);
    } else if tool.contains("read") || tool.contains("view") {
        action.reads = argument(args, &hooks::PATH_KEYS)
            .map(str::to_string)
            .into_iter()
            .collect();
    } else {
        let patch = args
            .as_str()
            .or_else(|| argument(args, &hooks::PATCH_KEYS))
            .unwrap_or_default();
        action.deletes = patch
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("*** Delete File:"))
            .map(|f| f.trim().to_string())
            .collect();
        action.writes = hooks::edited_files(payload)
            .into_iter()
            .map(|f| f.display().to_string())
            .collect();
    }
    action.tool = tool;
    action
}

/// The text an override and the audit entry speak about.
fn subject(action: &Action) -> String {
    action
        .command
        .clone()
        .or_else(|| action.code.clone())
        .unwrap_or_else(|| {
            let files: Vec<&str> = action
                .writes
                .iter()
                .chain(&action.deletes)
                .chain(&action.reads)
                .map(String::as_str)
                .collect();
            files.join(" ")
        })
}

fn judge_action(policy: &policy::Policy, home: &str, action: &Action) -> Vec<Finding> {
    let mut judge = Judge::new(policy, home, &action.cwd);
    if let Some(command) = &action.command {
        judge.command(command);
    }
    if let Some(code) = &action.code {
        judge.code(code);
    }
    for file in &action.writes {
        judge.file_write(file);
    }
    for file in &action.deletes {
        judge.file_delete(file);
    }
    for file in &action.reads {
        judge.file_read(file);
    }
    judge.found
}

#[derive(Debug)]
struct Decision {
    verdict: &'static str,
    /// The findings that stand.
    denied: Vec<Finding>,
    rules: Vec<&'static str>,
    notes: Vec<String>,
}

/// Applies the lease exemption and the owner's overrides to what the list matched.
fn decide(
    policy: &policy::Policy,
    found: Vec<Finding>,
    subject: &str,
    state: &Path,
    lease: impl FnOnce() -> Result<bool, String>,
) -> Decision {
    let rules: Vec<&'static str> = {
        let mut r: Vec<&'static str> = found.iter().map(|f| f.rule).collect();
        r.sort_unstable();
        r.dedup();
        r
    };
    let needs_lease = |rule: &str| policy.rules.iter().any(|r| r.id == rule && r.lease);
    let mut notes = Vec::new();
    let leased = found.iter().any(|f| needs_lease(f.rule)) && {
        match lease() {
            Ok(held) => {
                if held {
                    notes.push("allowed under a held release or deploy lease".to_string());
                }
                held
            }
            Err(why) => {
                notes.push(format!("the lease could not be checked: {why}"));
                false
            }
        }
    };
    let now = crate::hub::now_ms();
    let mut overridden = false;
    let denied: Vec<Finding> = found
        .into_iter()
        .filter(|f| !(leased && needs_lease(f.rule)))
        .filter(|f| match grant::covering(state, f.rule, subject, now) {
            Some(g) => {
                overridden = true;
                notes.push(format!("owner override of {}: {}", f.rule, g.reason));
                false
            }
            None => true,
        })
        .collect();
    let verdict = if !denied.is_empty() {
        "deny"
    } else if overridden {
        "override"
    } else if leased {
        "lease"
    } else {
        "allow"
    };
    Decision {
        verdict,
        denied,
        rules,
        notes,
    }
}

fn refusal(policy: &policy::Policy, decision: &Decision) -> String {
    let mut lines: Vec<String> = decision
        .denied
        .iter()
        .map(|f| format!("{} ({}): {}", f.rule, policy.why(f.rule), f.detail))
        .collect();
    lines.extend(decision.notes.iter().cloned());
    let first = decision.denied.first().map_or(PUBLISH, |f| f.rule);
    let way = if first == PUBLISH {
        "claim the lease first (stenio hub claim --worker <id> release:<name>), or ".to_string()
    } else {
        String::new()
    };
    format!(
        "{}. This action is on the owner's list of irreversible or outward actions. Do not work \
         around it: report the exact command and continue with other work; {way}only the owner \
         can lift it, at a terminal: stenio gate override --rule {first} --for 1h --reason <why>",
        lines.join("; ")
    )
}

fn state_dir() -> PathBuf {
    config::db_path()
        .ok()
        .and_then(|_| {
            std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("stenio/gate")
}

fn audit_dir(host: &policy::Host, home: &str) -> PathBuf {
    std::env::var_os("STENIO_GATE_AUDIT_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            host.audit_dir
                .as_ref()
                .map(|d| PathBuf::from(paths::tilde(d, home)))
        })
        .unwrap_or_else(|| state_dir().join("audit"))
}

/// Writes the entry; a record that cannot be written never changes the decision.
fn record(dir: &Path, payload: &Value, action: &Action, decision: &Decision) {
    let cfg = config::Config::load().ok();
    let session = cfg.and_then(|c| hooks::session_of(&c, payload));
    let mut entry = Map::new();
    let mut put = |k: &str, v: Value| {
        entry.insert(k.to_string(), v);
    };
    put("tool", json!(action.tool));
    put("verdict", json!(decision.verdict));
    put("rules", json!(decision.rules));
    put("cwd", json!(action.cwd.display().to_string()));
    put("session", json!(session));
    put("agent", json!(payload.get("agent_id")));
    if let Some(text) = action.command.as_ref().or(action.code.as_ref()) {
        put("command", json!(audit::redact(text)));
    }
    let files: Vec<String> = action
        .writes
        .iter()
        .chain(&action.deletes)
        .chain(&action.reads)
        .map(|f| audit::redact(f))
        .collect();
    if !files.is_empty() {
        put("files", json!(files));
    }
    if !decision.notes.is_empty() || !decision.denied.is_empty() {
        let said: Vec<String> = decision
            .denied
            .iter()
            .map(|f| audit::redact(&f.detail))
            .chain(decision.notes.iter().map(|n| audit::redact(n)))
            .collect();
        put("detail", json!(said));
    }
    if let Err(e) = audit::append(dir, entry) {
        eprintln!(
            "stenio gate: the audit entry could not be written to {}: {e}",
            dir.display()
        );
        // The local fallback keeps a trace when the declared folder is unusable.
        let fallback = state_dir().join("audit");
        if fallback != dir {
            let mut entry = Map::new();
            entry.insert("verdict".into(), json!(decision.verdict));
            entry.insert("rules".into(), json!(decision.rules));
            entry.insert("tool".into(), json!(action.tool));
            if let Err(e) = audit::append(&fallback, entry) {
                eprintln!("stenio gate: no audit at all: {e}");
            }
        }
    }
}

/// `stenio gate hook`: exit 2 with the reason on stderr blocks the call (Claude Code, Hermes,
/// the OpenCode plugin); an Antigravity payload gets its JSON decision, `deny` or `ask`.
fn hook() -> i32 {
    let payload = hooks::read_payload_up_to(INPUT_LIMIT);
    let antigravity = payload.get("toolCall").is_some();
    let allow = || {
        if antigravity {
            println!("{}", json!({"decision": "ask"}));
        }
        0
    };
    if payload.is_null() {
        eprintln!("stenio gate: no readable payload; nothing judged");
        return allow();
    }
    let policy = match policy::Policy::embedded() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("stenio gate: {e}; nothing judged");
            return allow();
        }
    };
    let host = policy::host();
    let policy = policy.with_host(&host);
    let home = std::env::var("HOME").unwrap_or_default();
    let action = action_of(&payload);
    let found = judge_action(&policy, &home, &action);
    let decision = decide(&policy, found, &subject(&action), &state_dir(), || {
        hooks::holds_publish_lease(&payload)
    });
    let changes = action.command.is_some()
        || action.code.is_some()
        || !action.writes.is_empty()
        || !action.deletes.is_empty();
    if changes || decision.verdict != "allow" {
        record(&audit_dir(&host, &home), &payload, &action, &decision);
    }
    if decision.verdict != "deny" {
        return allow();
    }
    let reason = refusal(&policy, &decision);
    if antigravity {
        println!(
            "{}",
            json!({"decision": "deny", "reason": format!("Blocked by stenio gate: {reason}")})
        );
        0
    } else {
        eprintln!("Blocked by stenio gate: {reason}");
        2
    }
}

#[derive(Parser)]
#[command(
    name = "stenio gate",
    about = "Deny the declared irreversible or outward actions; record everything judged"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The harness hook: judge the tool call given on stdin
    Hook,
    /// Judge without running or recording anything (exit 0 allowed, 2 denied)
    Check {
        #[arg(long, conflicts_with_all = ["write", "read"])]
        command: Option<String>,
        /// A shell script whose lines are judged as one command text
        #[arg(long, conflicts_with = "command")]
        script: Option<PathBuf>,
        #[arg(long)]
        write: Option<String>,
        #[arg(long)]
        read: Option<String>,
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    /// Summarise the audit record and verify its hash chain
    Report {
        /// How far back, such as 90m, 24h or 7d
        #[arg(long, default_value = "24h")]
        since: String,
        /// Read this folder instead of the configured one
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How many entries that were not simply allowed are printed
        #[arg(long, default_value_t = 20)]
        show: usize,
    },
    /// Owner only, at a terminal: lift one rule for a limited time
    Override {
        #[arg(long)]
        rule: String,
        /// Such as 30m or 2h, at most 24h; 0 revokes
        #[arg(long = "for")]
        duration: String,
        #[arg(long)]
        reason: String,
        /// Cover only actions whose text contains this
        #[arg(long = "match")]
        matching: Option<String>,
    },
    /// Print the declared list
    Policy,
}

fn seconds(text: &str) -> Result<i64, String> {
    let text = text.trim();
    if text == "0" {
        return Ok(0);
    }
    let (number, unit) = text.split_at(text.len().saturating_sub(1));
    let factor = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("{text}: use a number with s, m, h or d")),
    };
    number
        .parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| format!("{text}: use a number with s, m, h or d"))
}

fn check(action: &Action) -> Result<i32, String> {
    let host = policy::host();
    let policy = policy::Policy::embedded()?.with_host(&host);
    let home = std::env::var("HOME").unwrap_or_default();
    let found = judge_action(&policy, &home, action);
    if found.is_empty() {
        println!("allow");
        return Ok(0);
    }
    for f in &found {
        println!("deny {} ({}): {}", f.rule, policy.why(f.rule), f.detail);
    }
    Ok(2)
}

fn owner_override(
    rule: String,
    duration: &str,
    reason: String,
    matching: Option<String>,
) -> Result<i32, String> {
    let policy = policy::Policy::embedded()?;
    if !policy.rules.iter().any(|r| r.id == rule) {
        return Err(format!("{rule} is not a rule; see stenio gate policy"));
    }
    let secs = seconds(duration)?;
    if secs > grant::MAX_SECS {
        return Err("an override lasts at most 24h".to_string());
    }
    if reason.trim().is_empty() {
        return Err("--reason is required".to_string());
    }
    let cfg = config::Config::load().map_err(|e| e.to_string())?;
    grant::confirm_owner(&rule, &cfg.session.env)?;
    let now = crate::hub::now_ms();
    let record_of = grant::Grant {
        until: if secs == 0 { 0 } else { now + secs * 1000 },
        rule: rule.clone(),
        reason: reason.clone(),
        matching,
        at: now,
    };
    grant::store(&state_dir(), &record_of).map_err(|e| e.to_string())?;
    let mut entry = Map::new();
    entry.insert("verdict".into(), json!("grant"));
    entry.insert("rules".into(), json!([rule]));
    entry.insert("tool".into(), json!("owner-terminal"));
    entry.insert(
        "detail".into(),
        json!([audit::redact(&format!("for {duration}: {reason}"))]),
    );
    let host = policy::host();
    let home = std::env::var("HOME").unwrap_or_default();
    audit::append(&audit_dir(&host, &home), entry).map_err(|e| e.to_string())?;
    println!(
        "{rule} {} on this host",
        if secs == 0 {
            "override revoked".to_string()
        } else {
            format!("lifted for {duration}")
        }
    );
    Ok(0)
}

fn show_report(since: &str, dir: Option<PathBuf>, show: usize) -> Result<i32, String> {
    let host = policy::host();
    let home = std::env::var("HOME").unwrap_or_default();
    let dir = dir.unwrap_or_else(|| audit_dir(&host, &home));
    let from = chrono::Utc::now() - chrono::Duration::seconds(seconds(since)?);
    let report =
        audit::report(&dir, &from.to_rfc3339()).map_err(|e| format!("{}: {e}", dir.display()))?;
    println!(
        "audit {} since {since}: files={} entries={}",
        dir.display(),
        report.files,
        report.entries
    );
    for (verdict, n) in &report.verdicts {
        println!("  verdict {verdict}: {n}");
    }
    for (rule, n) in &report.rules {
        println!("  rule {rule}: {n}");
    }
    let skip = report.notable.len().saturating_sub(show);
    for e in report.notable.iter().skip(skip) {
        let said = |k: &str| e[k].as_str().unwrap_or_default().to_string();
        let what: String = e["command"]
            .as_str()
            .map_or_else(|| e["files"].to_string(), str::to_string)
            .replace('\n', " ")
            .chars()
            .take(160)
            .collect();
        println!(
            "{} {} {} {} {} | {what}",
            said("at"),
            said("host"),
            said("verdict"),
            e["rules"],
            said("tool")
        );
    }
    for b in &report.broken {
        println!("BROKEN {b}");
    }
    println!(
        "{}",
        if report.broken.is_empty() {
            "chain ok"
        } else {
            "chain FAIL"
        }
    );
    Ok(i32::from(!report.broken.is_empty()))
}

/// `stenio gate <command>`: exit 0, 1 on an error or a broken record, 2 on a denial or usage.
pub fn run_cli(argv: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(e) => {
            let help = !e.use_stderr();
            if let Err(shown) = e.print() {
                eprintln!("stenio gate: {shown}");
            }
            // A hook wired with a wrong argument must not look like a denial.
            return match (help, argv.iter().any(|a| a == "hook")) {
                (true, _) => 0,
                (false, true) => 1,
                (false, false) => 2,
            };
        }
    };
    let outcome = match cli.command {
        Cmd::Hook => Ok(hook()),
        Cmd::Check {
            command,
            script,
            write,
            read,
            cwd,
        } => {
            let command = match script {
                Some(file) => std::fs::read_to_string(&file)
                    .map(Some)
                    .map_err(|e| format!("{}: {e}", file.display())),
                None => Ok(command),
            };
            command.and_then(|command| {
                check(&Action {
                    cwd: cwd.unwrap_or_else(|| std::env::current_dir().unwrap_or_default()),
                    command,
                    writes: write.into_iter().collect(),
                    reads: read.into_iter().collect(),
                    ..Action::default()
                })
            })
        }
        Cmd::Report { since, dir, show } => show_report(&since, dir, show),
        Cmd::Override {
            rule,
            duration,
            reason,
            matching,
        } => owner_override(rule, &duration, reason, matching),
        Cmd::Policy => {
            print!("{}", policy::DEFAULTS);
            Ok(0)
        }
    };
    outcome.unwrap_or_else(|e| {
        eprintln!("stenio gate: {e}");
        1
    })
}
