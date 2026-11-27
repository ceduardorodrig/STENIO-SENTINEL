//! The backlog write lock. Every engine writer of a queue file takes (1) an OS lock on the queue
//! directories, so two writers cannot interleave, and (2) a write transaction on the ledger, in
//! which a live `backlog:<prefix>:write` claim of another worker refuses the write.

use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::store::{NewEvent, Store, append};
use super::{HubError, HubResult, config, ledger, remote};
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

/// What a writer changed, recorded in the `backlog_write` event.
#[derive(Debug, Default)]
pub struct Written {
    pub rows: Vec<String>,
    pub files: Vec<PathBuf>,
}

impl Written {
    fn files_json(&self) -> Vec<Value> {
        self.files
            .iter()
            .map(|path| {
                let hash = std::fs::read(path).ok().map(|bytes| {
                    Sha256::digest(&bytes)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                });
                json!({"path": path.display().to_string(), "sha256": hash})
            })
            .collect()
    }
}

/// The canonical directory of the `prefix` queue under `root`.
pub fn queue_dir(root: &Path, prefix: &str) -> Option<PathBuf> {
    present_queues(root)
        .into_iter()
        .find(|q| q.prefix == prefix)
        .and_then(|q| q.dir.canonicalize().ok())
}

/// Refuses when another worker holds a live `backlog:<prefix>:write` claim that covers the queue
/// being written. A claim taken with `--path` covers only that queue directory; one taken
/// without it covers every directory.
fn refuse_held(
    conn: &Connection,
    root: &Path,
    prefixes: &[String],
    worker: Option<&str>,
) -> HubResult<()> {
    for prefix in prefixes {
        let name = format!("backlog:{prefix}:write");
        let live = ledger::claims(conn, "WHERE released IS NULL AND resource = ?1", [&name])?;
        let now = super::now_ms();
        for claim in live
            .iter()
            .filter(|c| c.live(now) && Some(c.holder.as_str()) != worker)
        {
            if let Some(scope) = ledger::claim_scope(conn, claim.fence, &name)?
                && queue_dir(root, prefix).is_some_and(|dir| dir != scope)
            {
                continue;
            }
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
    Ok(())
}

/// Why a hand edit of the `prefix` queue under `root` is refused for a caller that speaks for
/// `mine`: another worker holds its write claim.
pub fn hand_edit_refusal(
    conn: &Connection,
    root: &Path,
    prefix: &str,
    mine: &[String],
) -> Option<String> {
    let prefixes = [prefix.to_string()];
    let mut last = None;
    for who in mine.iter().map(|w| Some(w.as_str())).chain([None]) {
        match refuse_held(conn, root, &prefixes, who) {
            Ok(()) => return None,
            Err(e) => last = Some(e),
        }
    }
    // A ledger that cannot answer does not block an ordinary edit.
    match last {
        Some(e @ HubError::Refused(_)) => Some(e.to_string()),
        _ => None,
    }
}

/// Why a file edit of `path` (spelled as claims are) is refused for a caller that speaks for
/// `mine`: it lies in a live tree claim of another worker. A holder that is bound to no harness
/// session is not enforced: its own edits could not be told apart, and the guard must not lock
/// the holder out.
pub fn tree_refusal(conn: &Connection, path: &str, mine: &[String]) -> HubResult<Option<HubError>> {
    let live = ledger::claims(
        conn,
        "WHERE released IS NULL AND resource LIKE 'tree:%'",
        [],
    )?;
    let now = super::now_ms();
    for claim in live
        .iter()
        .filter(|c| c.live(now) && !mine.contains(&c.holder))
    {
        let Some(tree) = claim.resource.strip_prefix("tree:") else {
            continue;
        };
        if !Path::new(path).starts_with(tree) || !ledger::session_bound(conn, &claim.holder)? {
            continue;
        }
        return Ok(Some(
            HubError::refused(
                "held",
                format!(
                    "{} is held by {} until {}; {path} not edited",
                    claim.resource,
                    claim.holder,
                    super::iso(claim.expires)
                ),
                "work in your own tree, or wait or ask the holder (stenio hub status)",
            )
            .with("resource", claim.resource.clone())
            .with("holder", claim.holder.clone())
            .with("expires", super::iso(claim.expires)),
        ));
    }
    Ok(None)
}

fn ledger_file(given: Option<&Path>) -> HubResult<PathBuf> {
    match given {
        Some(p) => Ok(p.to_path_buf()),
        None => config::db_path(),
    }
}

fn write_failed(message: String) -> HubError {
    HubError::refused(
        "write_failed",
        message,
        "fix the reported problem and retry",
    )
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
    write: impl FnOnce() -> Result<(T, Written), String>,
) -> HubResult<T> {
    let dirs: Vec<PathBuf> = present_queues(root).into_iter().map(|q| q.dir).collect();
    let _locks = lock_dirs(&dirs)?;
    if ledger_path.is_none()
        && let Some(server) = remote::declared()?
    {
        return served_write(&server, root, prefixes, worker, write);
    }
    let path = ledger_file(ledger_path)?;
    if !path.exists() {
        return write().map(|(value, _)| value).map_err(write_failed);
    }
    let mut store = Store::open(&path)?;
    ledger::sweep_now(&mut store)?;
    store.write(|tx| {
        refuse_held(tx, root, prefixes, worker)?;
        // The ledger write lock is held while the files change: nobody can claim in between.
        let (value, written) = write().map_err(write_failed)?;
        append(
            tx,
            NewEvent {
                worker: worker.unwrap_or_default(),
                run: None,
                kind: "backlog_write",
                resource: &prefixes.join(","),
                payload: json!({"root": root.display().to_string(), "rows": written.rows,
                    "files": written.files_json()}),
            },
        )?;
        Ok(value)
    })
}

/// The same lock held by the ledger server: it takes the queue claims before the files change
/// and ends them afterwards. An unreachable server refuses the write.
fn served_write<T>(
    server: &remote::Remote,
    root: &Path,
    prefixes: &[String],
    worker: Option<&str>,
    write: impl FnOnce() -> Result<(T, Written), String>,
) -> HubResult<T> {
    let begun = server.call(
        "guard_begin",
        json!({"worker": worker, "prefixes": prefixes}),
    )?;
    let outcome = write();
    let written = outcome.as_ref().ok().map(|(_, written)| {
        json!({"root": root.display().to_string(), "rows": written.rows,
            "files": written.files_json()})
    });
    let ended = server.call(
        "guard_end",
        json!({"worker": worker, "fence": begun["fence"], "prefixes": prefixes,
            "written": written}),
    );
    // The files are what counts: a lost end leaves a claim that expires by itself.
    if let Err(e) = ended {
        eprintln!("stenio: the queue write was not recorded in the ledger: {e}");
    }
    outcome.map(|(value, _)| value).map_err(write_failed)
}

/// [`backlog_write`] for a command line. A dry run writes nothing and takes no lock, but it
/// reports the same refusal the real run would.
pub fn guarded<T>(
    root: &Path,
    prefixes: &[String],
    worker: Option<&str>,
    dry_run: bool,
    write: impl FnOnce() -> Result<(T, Written), String>,
) -> HubResult<T> {
    let worker = config::worker_or_env(worker);
    if !dry_run {
        return backlog_write(root, prefixes, worker.as_deref(), None, write);
    }
    if let Some(server) = remote::declared()? {
        let mine: Vec<&str> = worker.as_deref().into_iter().collect();
        server.call("queue_check", json!({"prefixes": prefixes, "mine": mine}))?;
    } else {
        let path = ledger_file(None)?;
        if path.exists() {
            Store::open(&path)?.read(|c| refuse_held(c, root, prefixes, worker.as_deref()))?;
        }
    }
    write().map(|(value, _)| value).map_err(write_failed)
}

/// The text of a refused or failed write; the writer's own message stays as it was.
pub fn failure_text(error: &HubError) -> String {
    match error {
        HubError::Refused(r) if r.code == "write_failed" => r.message.clone(),
        other => other.to_string(),
    }
}
