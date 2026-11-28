//! Replay receipts (GB-354): a proof bound to the tree it ran on. The engine runs the command,
//! records commit, tree fingerprint, exit and output hash, and a later check refuses the receipt
//! when the tree moved. A command that changes the tree proves nothing about it.

use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

use super::store::{NewEvent, Store, append};
use super::{HubError, HubResult, config, ledger, resource};

pub const KIND: &str = "receipt";
/// Untracked files above this total are not hashed: the receipt is refused instead.
const UNTRACKED_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub commit: String,
    pub tree: String,
}

fn git(dir: &Path, args: &[&str]) -> HubResult<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| HubError::Usage(format!("cannot run git: {e}")))?;
    if !out.status.success() {
        return Err(HubError::Usage(format!(
            "git {} failed in {}",
            args.join(" "),
            dir.display()
        )));
    }
    Ok(out.stdout)
}

/// HEAD plus a hash of every difference from it: status, staged and unstaged changes and the
/// content of untracked files. Ignored files (build output) are left out.
pub fn snapshot(dir: &Path) -> HubResult<Snapshot> {
    let commit = String::from_utf8_lossy(&git(dir, &["rev-parse", "HEAD"])?)
        .trim()
        .to_string();
    let mut hash = Sha256::new();
    for args in [
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"][..],
        &["diff", "HEAD", "--binary", "--no-ext-diff", "--no-color"][..],
    ] {
        let part = git(dir, args)?;
        hash.update(part.len().to_le_bytes());
        hash.update(part);
    }
    let top = String::from_utf8_lossy(&git(dir, &["rev-parse", "--show-toplevel"])?)
        .trim_end()
        .to_string();
    let top = Path::new(&top);
    let listed = git(top, &["ls-files", "-o", "--exclude-standard", "-z"])?;
    let mut total = 0u64;
    for name in listed.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let path = top.join(String::from_utf8_lossy(name).as_ref());
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| HubError::Usage(format!("cannot read {}: {e}", path.display())))?;
        if !meta.is_file() {
            continue;
        }
        total += meta.len();
        if total > UNTRACKED_LIMIT {
            return Err(HubError::refused(
                "tree_too_large",
                "untracked files exceed 64 MiB, so the tree cannot be fingerprinted",
                "commit them or add them to .gitignore",
            ));
        }
        let body = std::fs::read(&path)
            .map_err(|e| HubError::Usage(format!("cannot read {}: {e}", path.display())))?;
        hash.update(name);
        hash.update(Sha256::digest(&body));
    }
    Ok(Snapshot {
        commit,
        tree: hex(&hash.finalize()),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn row_name(row: &str) -> HubResult<String> {
    let id = resource::row_id(row.trim().trim_start_matches("row:"))?;
    Ok(format!("row:{id}"))
}

/// The worker must hold the row: a receipt is part of working on it.
fn require_holder(conn: &Connection, worker: &str, name: &str) -> HubResult<()> {
    ledger::worker(conn, worker)?;
    let held = ledger::claims(conn, "WHERE released IS NULL AND resource = ?1", [name])?;
    if held.iter().any(|c| c.holder == worker) {
        return Ok(());
    }
    Err(HubError::refused(
        "not_holder",
        format!("{worker} does not hold {name}"),
        "claim the row first",
    ))
}

/// Runs `command` in `dir` and records the receipt of that run for the row.
pub fn run(
    store: &mut Store,
    worker: &str,
    row: &str,
    dir: &Path,
    command: &[String],
) -> HubResult<Value> {
    let name = row_name(row)?;
    ledger::sweep_now(store)?;
    store.read(|conn| require_holder(conn, worker, &name))?;
    let dir = dir
        .canonicalize()
        .map_err(|e| HubError::Usage(format!("--tree {}: {e}", dir.display())))?;
    let Some((program, args)) = command.split_first() else {
        return Err(HubError::Usage("give a command after `--`".to_string()));
    };
    // A command that must not be stored is refused before it runs.
    super::hygiene::check(&json!({"command": command}))?;
    let before = snapshot(&dir)?;
    let out = Command::new(program)
        .args(args)
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| HubError::Usage(format!("cannot run {program}: {e}")))?;
    let after = snapshot(&dir)?;
    let mut output = Sha256::new();
    output.update(out.stdout.len().to_le_bytes());
    output.update(&out.stdout);
    output.update(&out.stderr);
    let exit = out.status.code().unwrap_or(-1);
    let authoritative = before == after;
    let payload = json!({
        "clone": dir.display().to_string(), "commit": after.commit, "tree_hash": after.tree,
        "hash_before": before.tree, "command": command, "exit": exit,
        "output_sha256": hex(&output.finalize()), "authoritative": authoritative,
    });
    store.write(|tx| {
        require_holder(tx, worker, &name)?;
        append(
            tx,
            NewEvent {
                worker,
                run: None,
                kind: KIND,
                resource: &name,
                payload: payload.clone(),
            },
        )?;
        Ok(())
    })?;
    let mut answer = payload;
    answer["ok"] = json!(authoritative && exit == 0);
    answer["row"] = json!(name);
    Ok(answer)
}

fn latest(conn: &Connection, name: &str) -> HubResult<Option<Value>> {
    let found: Option<String> = conn
        .query_row(
            "SELECT payload FROM events WHERE type = ?1 AND resource = ?2 \
             ORDER BY seq DESC LIMIT 1",
            [KIND, name],
            |r| r.get(0),
        )
        .optional()?;
    found
        .map(|p| serde_json::from_str(&p).map_err(|e| HubError::Store(e.to_string())))
        .transpose()
}

/// Whether the newest receipt still proves its tree.
fn judge(receipt: &Value) -> HubResult<()> {
    let text = |key: &str| receipt[key].as_str().unwrap_or_default().to_string();
    let again = "run `stenio hub receipt` again on the final tree";
    if receipt["authoritative"] != json!(true) {
        return Err(HubError::refused(
            "unauthoritative_receipt",
            "the command changed the tree it ran on, so the receipt proves nothing",
            again,
        ));
    }
    if receipt["exit"] != json!(0) {
        return Err(HubError::refused(
            "failed_receipt",
            format!("the command of the receipt exited {}", receipt["exit"]),
            again,
        ));
    }
    let now = snapshot(Path::new(&text("clone")))?;
    if now.commit != text("commit") || now.tree != text("tree_hash") {
        let what = if now.commit == text("commit") {
            "the working tree changed"
        } else {
            "HEAD moved"
        };
        return Err(HubError::refused(
            "stale_receipt",
            format!("{what} since the receipt (commit {})", text("commit")),
            again,
        ));
    }
    Ok(())
}

/// `stenio hub closable --row R`: the newest receipt of the row, still valid.
pub fn closable(store: &mut Store, row: &str) -> HubResult<Value> {
    let name = row_name(row)?;
    let Some(receipt) = store.read(|conn| latest(conn, &name))? else {
        return Err(HubError::refused(
            "no_receipt",
            format!("{name} has no replay receipt"),
            "stenio hub receipt --row <ID> --tree <dir> -- <command>",
        ));
    };
    judge(&receipt)?;
    Ok(json!({"ok": true, "row": name, "commit": receipt["commit"],
        "command": receipt["command"]}))
}

/// For `backlog close`: a row that has a receipt in this ledger closes only while it is valid.
/// Rows without one, and machines without a ledger, are not judged here.
pub fn refuse_invalid(ids: &[String]) -> HubResult<()> {
    let path = config::db_path()?;
    if !path.exists() {
        return Ok(());
    }
    let store = &mut Store::open(&path)?;
    for id in ids {
        let name = row_name(id)?;
        if let Some(receipt) = store.read(|conn| latest(conn, &name))? {
            judge(&receipt).map_err(|e| e.with("row", name.clone()))?;
        }
    }
    Ok(())
}
