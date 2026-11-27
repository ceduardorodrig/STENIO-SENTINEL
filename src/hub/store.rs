//! The database: opening (fail closed), the schema, write transactions and the event chain.

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};

use super::{HubError, HubResult, now_ms};

pub const SCHEMA_VERSION: i64 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(15);
/// Hash that precedes the first event.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Deliberate defects, settable only from code, used by the self-test to prove that the checks
/// turn red when a guarantee is removed. No flag, variable or file can reach them.
#[derive(Debug, Clone, Copy, Default)]
pub struct Faults {
    pub skip_fence_check: bool,
    pub drop_unique_claim: bool,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, goal TEXT NOT NULL, vault TEXT NOT NULL, slots INTEGER NOT NULL,
  state TEXT NOT NULL, created INTEGER NOT NULL, closed INTEGER);
CREATE TABLE IF NOT EXISTS run_rows(
  run TEXT NOT NULL, row TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY(run, row));
CREATE TABLE IF NOT EXISTS workers(
  id TEXT PRIMARY KEY, harness TEXT NOT NULL, harness_version TEXT, model TEXT, host TEXT,
  parent TEXT, account TEXT NOT NULL, joined INTEGER NOT NULL, last_beat INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS claims(
  id INTEGER PRIMARY KEY AUTOINCREMENT, resource TEXT NOT NULL, holder TEXT NOT NULL,
  fence INTEGER NOT NULL, run TEXT, acquired INTEGER NOT NULL, ttl_ms INTEGER NOT NULL,
  expires INTEGER NOT NULL, released INTEGER, reason TEXT, checkpoint TEXT,
  loss_reported INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS results(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT, row TEXT NOT NULL, worker TEXT NOT NULL,
  fence INTEGER NOT NULL, verdict TEXT NOT NULL, branch TEXT, pr TEXT, proof TEXT,
  remaining TEXT, defects TEXT, current INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS results_one_current
  ON results(row, IFNULL(run, '')) WHERE current = 1;
CREATE TABLE IF NOT EXISTS questions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT, row TEXT, worker TEXT NOT NULL,
  text TEXT NOT NULL, options TEXT NOT NULL, recommendation TEXT, state TEXT NOT NULL,
  answer TEXT, answered_via TEXT, asked INTEGER NOT NULL, answered INTEGER);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY, at INTEGER NOT NULL, worker TEXT NOT NULL, run TEXT NOT NULL,
  type TEXT NOT NULL, resource TEXT NOT NULL, payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quota(
  account TEXT NOT NULL, window TEXT NOT NULL, used_pct REAL, resets_at INTEGER,
  observed_at INTEGER NOT NULL, source TEXT NOT NULL, reason TEXT,
  PRIMARY KEY(account, window));
";

/// The one constraint that makes two live holders impossible.
const UNIQUE_CLAIM: &str = "CREATE UNIQUE INDEX IF NOT EXISTS claims_one_holder \
     ON claims(resource) WHERE released IS NULL;";

pub struct Store {
    conn: Connection,
    pub faults: Faults,
}

/// One event of the chain, as stored.
#[derive(Debug, Clone)]
pub struct Event {
    pub seq: i64,
    pub at: i64,
    pub worker: String,
    pub run: String,
    pub kind: String,
    pub resource: String,
    pub payload: String,
    pub prev_hash: String,
    pub hash: String,
}

impl Event {
    /// The hash the stored fields must produce.
    pub fn expected_hash(&self) -> String {
        // A JSON array keeps field boundaries unambiguous.
        let canonical = serde_json::json!([
            self.seq,
            self.at,
            self.worker,
            self.run,
            self.kind,
            self.resource,
            self.payload,
            self.prev_hash
        ])
        .to_string();
        Sha256::digest(canonical.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// What an event says; the chain fields are added by [`append`].
pub struct NewEvent<'a> {
    pub worker: &'a str,
    pub run: Option<&'a str>,
    pub kind: &'a str,
    pub resource: &'a str,
    pub payload: Value,
}

pub fn meta(conn: &Connection, key: &str) -> HubResult<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> HubResult<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

/// The next value of a counter kept in `meta`.
pub fn next_counter(conn: &Connection, key: &str) -> HubResult<i64> {
    let current = match meta(conn, key)? {
        Some(v) => v
            .parse::<i64>()
            .map_err(|_| HubError::Store(format!("counter '{key}' is not a number")))?,
        None => 0,
    };
    let next = current + 1;
    set_meta(conn, key, &next.to_string())?;
    Ok(next)
}

/// Appends one event to the chain. Must run inside a write transaction.
pub fn append(conn: &Connection, new: NewEvent<'_>) -> HubResult<i64> {
    let seq = next_counter(conn, "head_seq")?;
    let prev_hash = meta(conn, "head_hash")?.unwrap_or_else(|| GENESIS.to_string());
    let mut event = Event {
        seq,
        at: now_ms(),
        worker: new.worker.to_string(),
        run: new.run.unwrap_or_default().to_string(),
        kind: new.kind.to_string(),
        resource: new.resource.to_string(),
        payload: new.payload.to_string(),
        prev_hash,
        hash: String::new(),
    };
    event.hash = event.expected_hash();
    conn.execute(
        "INSERT INTO events(seq, at, worker, run, type, resource, payload, prev_hash, hash) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            event.seq,
            event.at,
            event.worker,
            event.run,
            event.kind,
            event.resource,
            event.payload,
            event.prev_hash,
            event.hash
        ],
    )?;
    set_meta(conn, "head_hash", &event.hash)?;
    Ok(seq)
}

/// All events in sequence order.
pub fn events(conn: &Connection) -> HubResult<Vec<Event>> {
    let mut stmt = conn.prepare(
        "SELECT seq, at, worker, run, type, resource, payload, prev_hash, hash \
         FROM events ORDER BY seq",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Event {
            seq: r.get(0)?,
            at: r.get(1)?,
            worker: r.get(2)?,
            run: r.get(3)?,
            kind: r.get(4)?,
            resource: r.get(5)?,
            payload: r.get(6)?,
            prev_hash: r.get(7)?,
            hash: r.get(8)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// SQLite locking is unreliable on network filesystems, and a synchronised folder would give two
/// hosts their own "winner". Both are refused before anything is opened.
fn refuse_shared_location(dir: &Path) -> HubResult<()> {
    if let Some(synced) = dir.ancestors().find(|a| a.join(".stfolder").exists()) {
        return Err(HubError::Store(format!(
            "{} is inside the synchronised folder {}; the ledger must be a local file",
            dir.display(),
            synced.display()
        )));
    }
    if let Some(kind) = network_filesystem(dir) {
        return Err(HubError::Store(format!(
            "{} is on a {kind} filesystem; the ledger must be a local file",
            dir.display()
        )));
    }
    Ok(())
}

fn network_filesystem(dir: &Path) -> Option<&'static str> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statfs` writes only into the zeroed structure passed to it, and `c_path` is a
    // NUL-terminated string that outlives the call.
    let magic = unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        if libc::statfs(c_path.as_ptr(), &mut buf) != 0 {
            return None;
        }
        // The field type differs between targets; the magic numbers fit 32 bits.
        (buf.f_type as u64) & 0xffff_ffff
    };
    match magic {
        0x6969 => Some("NFS"),
        0x517b | 0xff53_4d42 | 0xfe53_4d42 => Some("SMB"),
        0x00c3_6400 => Some("Ceph"),
        _ => None,
    }
}

fn private_file(path: &Path) -> HubResult<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| HubError::Store(format!("cannot create {}: {e}", dir.display())))?;
    let dir = dir
        .canonicalize()
        .map_err(|e| HubError::Store(format!("cannot resolve {}: {e}", dir.display())))?;
    refuse_shared_location(&dir)?;
    if !path.exists() {
        // Concurrent creators are fine: `create` does not truncate.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| HubError::Store(format!("cannot create {}: {e}", path.display())))?;
    }
    // A link must not lead the file into a shared location either.
    let file = path
        .canonicalize()
        .map_err(|e| HubError::Store(format!("cannot resolve {}: {e}", path.display())))?;
    refuse_shared_location(file.parent().unwrap_or(&dir))
}

/// Switching a new file to WAL can report "busy" without honouring the busy timeout.
fn retry_busy<T>(mut f: impl FnMut() -> rusqlite::Result<T>) -> HubResult<T> {
    let start = Instant::now();
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) && start.elapsed() < BUSY_TIMEOUT =>
            {
                std::thread::park_timeout(Duration::from_millis(10));
            }
            Err(e) => return Err(e.into()),
        }
    }
}

impl Store {
    pub fn open(path: &Path) -> HubResult<Self> {
        Self::open_with(path, Faults::default())
    }

    pub fn open_with(path: &Path, faults: Faults) -> HubResult<Self> {
        private_file(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String = retry_busy(|| conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)))?;
        if !mode.eq_ignore_ascii_case("wal") {
            retry_busy(|| conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(())))?;
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        let mut store = Store { conn, faults };
        store.prepare_schema()?;
        Ok(store)
    }

    fn prepare_schema(&mut self) -> HubResult<()> {
        let version: i64 =
            retry_busy(|| self.conn.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
        if version > SCHEMA_VERSION {
            return Err(HubError::Store(format!(
                "ledger schema {version} is newer than this engine ({SCHEMA_VERSION}); update stenio"
            )));
        }
        if version < SCHEMA_VERSION {
            let unique = !self.faults.drop_unique_claim;
            self.write(|tx| {
                tx.execute_batch(SCHEMA)?;
                if unique {
                    tx.execute_batch(UNIQUE_CLAIM)?;
                }
                tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// One `BEGIN IMMEDIATE` transaction: committed when `f` succeeds, rolled back otherwise.
    pub fn write<T>(&mut self, f: impl FnOnce(&Transaction<'_>) -> HubResult<T>) -> HubResult<T> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Writes a consistent copy of the live database to `target`, which must not exist.
    pub fn snapshot(&mut self, target: &Path) -> HubResult<()> {
        let target = target
            .to_str()
            .ok_or_else(|| HubError::Usage("the backup path is not UTF-8".to_string()))?;
        retry_busy(|| self.conn.execute("VACUUM INTO ?1", [target]))?;
        Ok(())
    }

    /// Leaves a copy as one self-contained file (no write-ahead log beside it).
    pub fn seal(&mut self) -> HubResult<()> {
        retry_busy(|| {
            self.conn
                .query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))
        })?;
        Ok(())
    }

    /// A consistent read snapshot.
    pub fn read<T>(&mut self, f: impl FnOnce(&Connection) -> HubResult<T>) -> HubResult<T> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        f(&tx)
    }
}
