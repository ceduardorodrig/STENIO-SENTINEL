//! Ledger backup: an online snapshot plus the event export, each proven by restoring it into a
//! scratch directory and auditing the restored copy. A receipt beside the ledger lets
//! `hub status` report a backup that stopped happening.

use chrono::{NaiveDateTime, Utc};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::store::Store;
use super::{HubError, HubResult, audit, config, view};

const STAMP: &str = "%Y%m%dT%H%M%S%3fZ";
const PREFIX: &str = "hub-";

fn io(what: &str, path: &Path, e: std::io::Error) -> HubError {
    HubError::Store(format!("cannot {what} {}: {e}", path.display()))
}

fn receipt_of(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(".backup.json");
    PathBuf::from(name)
}

/// Restores `snapshot` into a private scratch directory and audits it there.
fn restore_test(snapshot: &Path, scratch_parent: &Path) -> HubResult<Value> {
    let scratch = scratch_parent.join(format!(
        ".restore-test-{}-{}",
        std::process::id(),
        Utc::now().timestamp_micros()
    ));
    std::fs::create_dir(&scratch).map_err(|e| io("create", &scratch, e))?;
    let result = (|| {
        let copy = scratch.join("hub.db");
        std::fs::copy(snapshot, &copy).map_err(|e| io("restore", snapshot, e))?;
        audit::audit(&mut Store::open(&copy)?, None, false)
    })();
    std::fs::remove_dir_all(&scratch).map_err(|e| io("remove", &scratch, e))?;
    let report = result?;
    if report["ok"] != json!(true) {
        return Err(HubError::refused(
            "backup_invalid",
            format!(
                "the restored copy of {} fails the audit",
                snapshot.display()
            ),
            "stenio hub audit",
        )
        .with("audit", report));
    }
    Ok(report)
}

/// Snapshots in `dir`, oldest first, with the instant their name records.
fn snapshots(dir: &Path) -> HubResult<Vec<(NaiveDateTime, PathBuf)>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io("read", dir, e))? {
        let path = entry.map_err(|e| io("read", dir, e))?.path();
        let at = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(PREFIX)?.strip_suffix(".db"))
            .and_then(|s| NaiveDateTime::parse_from_str(s, STAMP).ok());
        if let Some(at) = at {
            found.push((at, path));
        }
    }
    found.sort();
    Ok(found)
}

/// Writes a snapshot and its event export into `out`, restore-tests it and keeps the newest
/// `keep` snapshots.
pub fn backup(out: &Path, keep: usize) -> HubResult<Value> {
    let db = config::db_path()?;
    if !db.exists() {
        return Err(HubError::Store(format!("no ledger at {}", db.display())));
    }
    std::fs::create_dir_all(out).map_err(|e| io("create", out, e))?;
    let mut store = Store::open(&db)?;
    let file = out.join(format!("{PREFIX}{}.db", Utc::now().format(STAMP)));
    store.snapshot(&file)?;
    let proven = restore_test(&file, out).and_then(|report| {
        let mut copy = Store::open(&file)?;
        let events = view::export(&mut copy, None)?;
        copy.seal()?;
        let jsonl = file.with_extension("events.jsonl");
        std::fs::write(&jsonl, &events).map_err(|e| io("write", &jsonl, e))?;
        Ok((report, events.lines().count()))
    });
    let (_, events) = match proven {
        Ok(done) => done,
        Err(e) => {
            // An unproven snapshot must not pass for a backup.
            std::fs::remove_file(&file).map_err(|x| io("remove", &file, x))?;
            return Err(e);
        }
    };
    let receipt = receipt_of(&db);
    let text = json!({"file": file.display().to_string(), "at": Utc::now().timestamp()});
    std::fs::write(&receipt, text.to_string()).map_err(|e| io("write", &receipt, e))?;
    let all = snapshots(out)?;
    let mut pruned = 0;
    for (_, old) in all.iter().take(all.len().saturating_sub(keep.max(1))) {
        std::fs::remove_file(old).map_err(|e| io("remove", old, e))?;
        let jsonl = old.with_extension("events.jsonl");
        if jsonl.exists() {
            std::fs::remove_file(&jsonl).map_err(|e| io("remove", &jsonl, e))?;
        }
        pruned += 1;
    }
    Ok(
        json!({"ok": true, "file": file.display().to_string(), "events": events,
        "restore_test": "audit ok", "pruned": pruned}),
    )
}

/// Refuses unless the newest snapshot in `dir` is young enough and restores cleanly.
pub fn check(dir: &Path, max_age_secs: u64) -> HubResult<Value> {
    let stale = |message: String| {
        HubError::refused(
            "backup_stale",
            message,
            "stenio hub backup --out <dir>; check the backup timer",
        )
    };
    let Some((at, file)) = snapshots(dir)?.pop() else {
        return Err(stale(format!("no ledger backup in {}", dir.display())));
    };
    let age = (Utc::now().naive_utc() - at).num_seconds();
    if age > i64::try_from(max_age_secs).unwrap_or(i64::MAX) {
        return Err(stale(format!(
            "newest ledger backup {} is {} h old (limit {} h)",
            file.display(),
            age / 3600,
            max_age_secs / 3600
        )));
    }
    restore_test(&file, &std::env::temp_dir())?;
    Ok(
        json!({"ok": true, "file": file.display().to_string(), "age_secs": age,
        "restore_test": "audit ok"}),
    )
}

/// Why the last backup of the ledger at `db` does not count, if it does not.
pub fn overdue(db: &Path, max_age_secs: u64) -> Option<String> {
    let text = std::fs::read_to_string(receipt_of(db)).ok();
    let receipt: Option<Value> = text.and_then(|t| serde_json::from_str(&t).ok());
    let Some(receipt) = receipt else {
        return Some("this ledger was never backed up".to_string());
    };
    let file = receipt["file"].as_str().unwrap_or_default();
    if !Path::new(file).is_file() {
        return Some(format!("the last backup file is gone: {file}"));
    }
    let age = Utc::now().timestamp() - receipt["at"].as_i64().unwrap_or_default();
    (age > i64::try_from(max_age_secs).unwrap_or(i64::MAX))
        .then(|| format!("the last backup is {} h old: {file}", age / 3600))
}
