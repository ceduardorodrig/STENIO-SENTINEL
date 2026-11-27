//! Read-only index of the registered queues, for callers that must find rows or lock queue
//! directories (the shared work ledger) without auditing them.

use std::path::{Path, PathBuf};

/// One queue present under an audited root.
#[derive(Clone, Debug)]
pub struct QueueFiles {
    /// Id prefix without the dash, e.g. `GB`.
    pub prefix: String,
    pub dir: PathBuf,
}

impl QueueFiles {
    pub fn active(&self) -> PathBuf {
        self.dir.join(super::BACKLOG_REL)
    }

    pub fn archive(&self) -> PathBuf {
        self.dir.join(super::ARCHIVE_REL)
    }
}

/// Prefixes (without the dash) of every queue declared in the registry.
pub fn declared_prefixes() -> Vec<String> {
    super::registry()
        .into_iter()
        .map(|q| q.prefix.trim_end_matches('-').to_uppercase())
        .collect()
}

/// The declared queues that exist under `root`.
pub fn present_queues(root: &Path) -> Vec<QueueFiles> {
    super::registry()
        .into_iter()
        .filter_map(|q| {
            let dir = super::resolve_queue_dir(root, &q)?;
            dir.join(super::BACKLOG_REL).is_file().then(|| QueueFiles {
                prefix: q.prefix.trim_end_matches('-').to_uppercase(),
                dir,
            })
        })
        .collect()
}

/// The table line of `id` in a queue file (the row whose first cell is the id).
pub fn row_line<'a>(text: &'a str, id: &str) -> Option<&'a str> {
    let (prefix, _) = id.split_once('-')?;
    let prefix = format!("{prefix}-");
    text.lines().find(|line| {
        super::split_row(line)
            .first()
            .and_then(|cell| super::extract_id(cell, &prefix))
            .is_some_and(|found| found == id)
    })
}
