//! The backlog write lock. Every engine writer of a queue file takes (1) an OS lock on the queue
//! directories, so two writers cannot interleave, and (2) a write transaction on the ledger, in
//! which a live `backlog:<prefix>:write` claim of another worker refuses the write.

use serde_json::json;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::store::{NewEvent, Store, append};
use super::{HubError, HubResult, config, ledger};
use crate::backlog::queue_index::present_queues;

const LOCK_WAIT: Duration = Duration::from_secs(60);

/// Exclusive `flock` on directories, held until dropped. Locking the directory itself needs no
/// lock file, which would be replicated by a synchronised folder.
pub struct DirLocks {
    _held: Vec<File>,
}

pub fn lock_dirs(dirs: &[PathBuf]) -> HubResult<DirLocks> {
    let mut sorted = dirs
        .iter()
        .map(|d| {
            d.canonicalize()
                .map_err(|e| HubError::Store(format!("cannot resolve {}: {e}", d.display())))
        })
        .collect::<HubResult<Vec<_>>>()?;
    // One global order, so two writers cannot wait for each other.
    sorted.sort();
    sorted.dedup();
    let start = Instant::now();
    let mut held = Vec::new();
    for dir in sorted {
        let file = File::open(&dir)
            .map_err(|e| HubError::Store(format!("cannot open {}: {e}", dir.display())))?;
        loop {
            // SAFETY: the descriptor belongs to `file`, which is alive during the call.
            let done = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if done == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(HubError::Store(format!(
                    "cannot lock {}: {error}",
                    dir.display()
                )));
            }
            if start.elapsed() > LOCK_WAIT {
                return Err(HubError::refused(
                    "locked",
                    format!("{} is locked by another backlog writer", dir.display()),
                    "retry",
                ));
            }
            std::thread::park_timeout(Duration::from_millis(15));
        }
        held.push(file);
    }
    Ok(DirLocks { _held: held })
}

/// Runs `write` as the only backlog writer of the queues under `root`.
///
/// `prefixes` are the queues being written. Without a ledger file there can be no claim; a ledger
/// that exists but cannot be used refuses the write.
pub fn backlog_write<T>(
    root: &Path,
    prefixes: &[String],
    worker: Option<&str>,
    ledger_path: Option<&Path>,
    write: impl FnOnce() -> Result<T, String>,
) -> HubResult<T> {
    let dirs: Vec<PathBuf> = present_queues(root).into_iter().map(|q| q.dir).collect();
    let _locks = lock_dirs(&dirs)?;
    let refused = |message: String| {
        HubError::refused(
            "write_failed",
            message,
            "fix the reported problem and retry",
        )
    };
    let path = match ledger_path {
        Some(p) => p.to_path_buf(),
        None => config::db_path()?,
    };
    if !path.exists() {
        return write().map_err(refused);
    }
    let mut store = Store::open(&path)?;
    ledger::sweep_now(&mut store)?;
    store.write(|tx| {
        for prefix in prefixes {
            let name = format!("backlog:{prefix}:write");
            let live = ledger::claims(tx, "WHERE released IS NULL AND resource = ?1", [&name])?;
            let now = super::now_ms();
            let other = live
                .iter()
                .find(|c| c.live(now) && Some(c.holder.as_str()) != worker);
            if let Some(claim) = other {
                return Err(HubError::refused(
                    "held",
                    format!(
                        "{name} is held by {} until {}; nothing written",
                        claim.holder,
                        super::iso(claim.expires)
                    ),
                    "pass --worker <holder> if it is you, else wait or ask the holder",
                )
                .with("resource", name.clone())
                .with("holder", claim.holder.clone())
                .with("expires", super::iso(claim.expires)));
            }
        }
        // The ledger write lock is held while the files change: nobody can claim in between.
        let value = write().map_err(refused)?;
        append(
            tx,
            NewEvent {
                worker: worker.unwrap_or_default(),
                run: None,
                kind: "backlog_write",
                resource: &prefixes.join(","),
                payload: json!({"root": root.display().to_string()}),
            },
        )?;
        Ok(value)
    })
}

/// [`backlog_write`] for a command line: a dry run writes nothing and needs no lock. A failure is
/// printed and returned as the exit code (1 refused or failed, 3 ledger unavailable).
pub fn cli_write<T>(
    root: &Path,
    prefixes: &[String],
    worker: Option<&str>,
    dry_run: bool,
    write: impl FnOnce() -> Result<T, String>,
) -> Result<T, i32> {
    let outcome = if dry_run {
        write().map_err(|e| (e, 1))
    } else {
        let worker = config::worker_or_env(worker);
        backlog_write(root, prefixes, worker.as_deref(), None, write).map_err(|e| {
            let text = match &e {
                // The writer's own message stays as it was.
                HubError::Refused(r) if r.code == "write_failed" => r.message.clone(),
                other => other.to_string(),
            };
            (text, e.exit_code())
        })
    };
    outcome.map_err(|(message, code)| {
        eprintln!("{message}");
        code
    })
}
