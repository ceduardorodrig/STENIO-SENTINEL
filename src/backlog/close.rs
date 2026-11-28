//! `stenio backlog close`: moves rows from the active queue to the archive (backlog-method.md
//! section 4, rule 3) and removes their ids from every document's `pending:` list in the same
//! operation (GB-252).
//!
//! The command is all-or-nothing: every id is validated and every file is computed in memory
//! before the first write. The archive is written before the active queue, so an interrupted run
//! leaves a duplicated id (which `DOC-BACKLOG-DRIFT` reports) and never a lost row. Each write is
//! refused when the file changed after it was read.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;

use super::integrity::cells;
use super::{
    ARCHIVE_REL, BACKLOG_REL, CLOSED_STATES, Queue, audit_queue, extract_id, normalize_header,
    registry, remove_pending, resolve_queue_dir,
};
use crate::opportunity::guarded_write;

/// One row to close.
#[derive(Clone, Debug)]
pub struct CloseItem {
    pub id: String,
    /// `resolved` or `discarded`.
    pub state: String,
    /// How it was resolved (or why it was discarded).
    pub note: String,
}

/// A computed file change.
#[derive(Clone, Debug)]
pub struct Change {
    pub path: PathBuf,
    pub before: String,
    pub after: String,
}

/// What [`plan`] computed.
#[derive(Debug)]
pub struct Plan {
    /// Writes in the order they must happen: archives, active queues, documents.
    pub changes: Vec<Change>,
    /// The archive row of every closed id.
    pub rows: Vec<(String, String)>,
    /// Things a human still has to look at.
    pub warnings: Vec<String>,
    queues: Vec<(Queue, PathBuf)>,
}

/// A header-led id table: header names and the line index of its last row.
struct IdTable {
    header: Vec<String>,
    last: usize,
}

/// The last table of `lines` whose header starts with `ID`.
fn id_table(lines: &[String]) -> Option<IdTable> {
    let mut found = None;
    let mut i = 0;
    while i < lines.len() {
        let c = cells(&lines[i]);
        let is_header = lines[i].trim_start().starts_with('|')
            && c.first().is_some_and(|f| normalize_header(f) == "id");
        if !is_header {
            i += 1;
            continue;
        }
        let mut last = i;
        while last + 1 < lines.len() && lines[last + 1].trim_start().starts_with('|') {
            last += 1;
        }
        found = Some(IdTable {
            header: c.iter().map(|h| normalize_header(h)).collect(),
            last,
        });
        i = last + 1;
    }
    found
}

/// Line indexes of the rows whose first cell is exactly `id`.
fn rows_of(lines: &[String], id: &str, prefix: &str) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim_start().starts_with('|'))
        .filter(|(_, l)| {
            cells(l)
                .first()
                .and_then(|c| extract_id(c, prefix))
                .is_some_and(|f| f == id)
        })
        .map(|(i, _)| i)
        .collect()
}

fn clean_note(note: &str) -> String {
    note.replace('|', "/")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_string()
}

/// Builds the archive row from the active row, column by column, following the archive header.
fn archive_row(
    archive_header: &[String],
    active_header: &[String],
    active: &[String],
    item: &CloseItem,
    date: &str,
) -> String {
    let from = |names: &[&str]| -> Option<String> {
        active_header
            .iter()
            .position(|h| names.contains(&h.as_str()))
            .and_then(|i| active.get(i))
            .cloned()
    };
    let note = clean_note(&item.note);
    let origin = from(&["origin", "origem"]).unwrap_or_default();
    let out: Vec<String> = archive_header
        .iter()
        .map(|h| match h.as_str() {
            "id" => from(&["id"]).unwrap_or_default(),
            "item" => {
                let mut text = from(&["item"]).unwrap_or_default();
                for open in ["Status: open.", "Status: in progress.", "Status: blocked."] {
                    text = text.replace(open, "Status: closed.");
                }
                if let Some(rec) = from(&["recurrence", "recorrência", "recorrencia"]) {
                    if rec.chars().any(|c| c.is_ascii_digit()) {
                        text = format!("{text} Recurrence: {rec}.");
                    }
                }
                format!("{text} Closed {date} ({}): {note}.", item.state)
            }
            "ref" => from(&["ref"]).unwrap_or_default(),
            "sev" | "severity" | "severidade" => {
                from(&["sev", "severity", "severidade"]).unwrap_or_default()
            }
            "state" | "estado" => item.state.clone(),
            "closed" | "fechado" => date.to_string(),
            "origin / closed" => format!("{origin}; closed {date}"),
            "recurred-by" | "recurred by" | "recorrido por" => "—".to_string(),
            other => from(&[other]).unwrap_or_else(|| "—".to_string()),
        })
        .collect();
    format!("| {} |", out.join(" | "))
}

/// Markdown documents under `root`, skipping Syncthing history.
fn documents(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = crate::baseline::build_file_walker(root)
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .filter(|p| {
            let s = p.to_string_lossy();
            !s.contains("/.stversions/") && !s.contains("/.smart-env/")
        })
        .collect();
    out.sort();
    out
}

/// Computes every change needed to close `items` under `root`; writes nothing.
pub fn plan(root: &Path, items: &[CloseItem], date: &str) -> Result<Plan, String> {
    if items.is_empty() {
        return Err("no id to close".to_string());
    }
    if chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_err() {
        return Err(format!("--date '{date}' is not YYYY-MM-DD"));
    }
    let mut seen = BTreeSet::new();
    // queue prefix -> (queue, dir, active before, active lines, archive before, archive lines)
    type Files = (Queue, PathBuf, String, Vec<String>, String, Vec<String>);
    let mut files: BTreeMap<String, Files> = BTreeMap::new();
    let mut rows = Vec::new();
    let mut warnings = Vec::new();

    for item in items {
        let id = item.id.trim().to_uppercase();
        if !seen.insert(id.clone()) {
            return Err(format!("{id} is listed twice"));
        }
        if !CLOSED_STATES.contains(&item.state.as_str()) {
            return Err(format!(
                "{id}: state '{}' is not 'resolved' or 'discarded'",
                item.state
            ));
        }
        if clean_note(&item.note).is_empty() {
            return Err(format!("{id}: a closing note is mandatory"));
        }
        let q = registry()
            .into_iter()
            .find(|q| extract_id(&id, &q.prefix).is_some())
            .ok_or_else(|| format!("{id}: no queue has this prefix (backlog-queues.toml)"))?;
        if !files.contains_key(&q.prefix) {
            let dir = resolve_queue_dir(root, &q).ok_or_else(|| {
                format!("{id}: queue {} not found under {}", q.name, root.display())
            })?;
            let read = |name: &str| {
                let p = dir.join(name);
                fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
            };
            let active = read(BACKLOG_REL)?;
            let archive = read(ARCHIVE_REL)?;
            let al = active.split('\n').map(str::to_string).collect();
            let hl = archive.split('\n').map(str::to_string).collect();
            files.insert(q.prefix.clone(), (q.clone(), dir, active, al, archive, hl));
        }
        let Some((_, _, _, active, _, archive)) = files.get_mut(&q.prefix) else {
            return Err(format!("{id}: queue not loaded"));
        };

        let archived = rows_of(archive, &id, &q.prefix);
        if let Some(i) = archived.first() {
            return Err(format!(
                "{id} is already in {ARCHIVE_REL} (line {}); nothing written",
                i + 1
            ));
        }
        let found = rows_of(active, &id, &q.prefix);
        let at = match found.as_slice() {
            [one] => *one,
            [] => return Err(format!("{id} is not in {BACKLOG_REL}; nothing written")),
            many => {
                let lines: Vec<String> = many.iter().map(|i| (i + 1).to_string()).collect();
                return Err(format!(
                    "{id} identifies {} rows of {BACKLOG_REL} (lines {}): renumber first; nothing written",
                    many.len(),
                    lines.join(", ")
                ));
            }
        };
        // The header that governs this row is the nearest one above it.
        let active_header: Vec<String> = active[..at]
            .iter()
            .rev()
            .map(|l| cells(l))
            .find(|c| c.first().is_some_and(|f| normalize_header(f) == "id"))
            .map(|c| c.iter().map(|h| normalize_header(h)).collect())
            .ok_or_else(|| format!("{id}: no table header above the row; nothing written"))?;
        let row = cells(&active[at]);
        if row.len() != active_header.len() {
            return Err(format!(
                "{id}: line {} has {} cells, the header has {} (an unescaped '|'?); fix the row first; nothing written",
                at + 1,
                row.len(),
                active_header.len()
            ));
        }
        let table = id_table(archive)
            .ok_or_else(|| format!("{id}: {ARCHIVE_REL} has no '| ID |' table; nothing written"))?;
        let new_row = archive_row(&table.header, &active_header, &row, item, date);
        archive.insert(table.last + 1, new_row.clone());
        active.remove(at);
        let rec = active_header
            .iter()
            .position(|h| h.starts_with("recurr") || h.starts_with("recorr"))
            .and_then(|i| row.get(i))
            .filter(|c| c.chars().any(|c| c.is_ascii_digit()));
        if let Some(rec) = rec {
            warnings.push(format!(
                "{id} recurred from {rec}: check the 'Recurred-by' cell of that archived row"
            ));
        }
        rows.push((id, new_row));
    }

    let ids: Vec<String> = rows.iter().map(|(i, _)| i.clone()).collect();
    let mut archives = Vec::new();
    let mut actives = Vec::new();
    let mut docs = Vec::new();
    let mut handled = BTreeSet::new();
    let mut queues = Vec::new();
    for (q, dir, active_before, active, archive_before, archive) in files.into_values() {
        let apath = dir.join(BACKLOG_REL);
        let hpath = dir.join(ARCHIVE_REL);
        // The queue files may carry their own `pending:` frontmatter: edit it in the same buffer.
        let unlink = |text: String| remove_pending(&text, &ids).unwrap_or(text);
        archives.push(Change {
            path: hpath.clone(),
            before: archive_before,
            after: unlink(archive.join("\n")),
        });
        actives.push(Change {
            path: apath.clone(),
            before: active_before,
            after: unlink(active.join("\n")),
        });
        handled.insert(apath);
        handled.insert(hpath);
        queues.push((q, dir));
    }
    let mut candidates = documents(root);
    for (_, dir) in &queues {
        candidates.extend(documents(dir));
    }
    candidates.sort();
    candidates.dedup();
    for path in candidates {
        if handled.contains(&path) {
            continue;
        }
        let Ok(before) = fs::read_to_string(&path) else {
            continue;
        };
        match remove_pending(&before, &ids) {
            Some(after) if after != before => docs.push(Change {
                path,
                before,
                after,
            }),
            Some(_) => {}
            None => warnings.push(format!(
                "{}: block-style `pending:` list, remove the closed ids by hand",
                path.display()
            )),
        }
    }
    let mut changes = archives;
    changes.extend(actives);
    changes.extend(docs);
    Ok(Plan {
        changes,
        rows,
        warnings,
        queues,
    })
}

/// Writes the plan; on a failure the files already written are restored.
pub fn apply(plan: &Plan) -> Result<(), String> {
    for c in &plan.changes {
        let now = fs::read_to_string(&c.path)
            .map_err(|e| format!("cannot re-read {}: {e}", c.path.display()))?;
        if now != c.before {
            return Err(format!(
                "{} changed while the move was prepared; nothing written, retry",
                c.path.display()
            ));
        }
    }
    for (n, c) in plan.changes.iter().enumerate() {
        if c.before == c.after {
            continue;
        }
        if let Err(e) = guarded_write(&c.path, &c.before, &c.after) {
            let mut left = Vec::new();
            for done in plan.changes[..n].iter().rev() {
                if guarded_write(&done.path, &done.after, &done.before).is_err() {
                    left.push(done.path.display().to_string());
                }
            }
            return Err(if left.is_empty() {
                format!("{e}; earlier writes were restored")
            } else {
                format!("{e}; could NOT restore: {}", left.join(", "))
            });
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(
    name = "stenio backlog close",
    about = "Move rows from backlog.md to backlog-archive.md and drop their ids from every `pending:` list",
    after_help = "Batch file: one row per line, TAB separated: ID<TAB>note  or  ID<TAB>state<TAB>note.\nLines starting with '#' are ignored. All ids are validated before the first write."
)]
struct CloseArgs {
    /// Ids that share --state and --note, e.g. GB-008 GB-138
    ids: Vec<String>,
    #[arg(long, default_value = "resolved", help = "resolved or discarded")]
    state: String,
    #[arg(
        long,
        help = "How it was resolved (with proof) or why it was discarded"
    )]
    note: Option<String>,
    #[arg(long, help = "Batch file with one id per line (see below)")]
    file: Option<PathBuf>,
    #[arg(long, help = "Closing date YYYY-MM-DD (default: today)")]
    date: Option<String>,
    #[arg(
        long,
        help = "Vault or repository root (default: the vault found from the cwd)"
    )]
    path: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
    #[arg(
        long,
        help = "Ledger worker id (or $STENIO_HUB_WORKER): needed while that worker holds a backlog:<prefix>:write claim"
    )]
    worker: Option<String>,
}

/// Parses the batch file format of `--file`.
pub fn parse_batch(text: &str, default_state: &str) -> Result<Vec<CloseItem>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').map(str::trim).collect();
        let (id, state, note) = match parts.as_slice() {
            [id, note] => (*id, default_state, *note),
            [id, state, note] => (*id, *state, *note),
            _ => {
                return Err(format!(
                    "batch line {}: expected ID<TAB>note or ID<TAB>state<TAB>note",
                    n + 1
                ));
            }
        };
        out.push(CloseItem {
            id: id.to_string(),
            state: state.to_string(),
            note: note.to_string(),
        });
    }
    Ok(out)
}

fn collect_items(a: &CloseArgs) -> Result<Vec<CloseItem>, String> {
    let mut items = Vec::new();
    if let Some(file) = &a.file {
        let text =
            fs::read_to_string(file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        items.extend(parse_batch(&text, &a.state)?);
    }
    if !a.ids.is_empty() {
        let note = a
            .note
            .clone()
            .ok_or_else(|| "--note is mandatory with ids on the command line".to_string())?;
        items.extend(a.ids.iter().map(|id| CloseItem {
            id: id.clone(),
            state: a.state.clone(),
            note: note.clone(),
        }));
    }
    Ok(items)
}

/// Entry point of `stenio backlog close`. Exit codes: 0 done, 1 refused, 2 usage, 3 ledger unavailable.
pub fn run_cli(argv: &[String]) -> i32 {
    let a = match CloseArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => return crate::util::usage_exit(&e),
    };
    let root = crate::opportunity::vault_root(a.path.as_deref());
    let date = a
        .date
        .clone()
        .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d").to_string());
    let items = match collect_items(&a) {
        Ok(items) => items,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut prefixes: Vec<String> = items
        .iter()
        .filter_map(|i| i.id.split_once('-'))
        .map(|(prefix, _)| prefix.trim().to_uppercase())
        .collect();
    prefixes.sort();
    prefixes.dedup();
    // GB-354: a recorded proof that the tree has left behind does not close a row.
    let ids: Vec<String> = items.iter().map(|i| i.id.clone()).collect();
    if let Err(e) = crate::hub::receipt::refuse_invalid(&ids) {
        eprintln!("{e}");
        return e.exit_code();
    }
    // Planned and applied under one lock, so no other writer changes a file in between.
    let written =
        crate::hub::guard::guarded(&root, &prefixes, a.worker.as_deref(), a.dry_run, || {
            let p = plan(&root, &items, &date)?;
            if !a.dry_run {
                apply(&p)?;
            }
            let changed = crate::hub::guard::Written {
                rows: p.rows.iter().map(|(id, _)| id.clone()).collect(),
                files: p
                    .changes
                    .iter()
                    .filter(|c| c.before != c.after)
                    .map(|c| c.path.clone())
                    .collect(),
            };
            Ok((p, changed))
        });
    let p = match written {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", crate::hub::guard::failure_text(&e));
            return e.exit_code();
        }
    };
    let verb = if a.dry_run { "would close" } else { "closed" };
    for (id, row) in &p.rows {
        println!("{verb} {id}");
        if a.dry_run {
            println!("  {row}");
        }
    }
    for c in p.changes.iter().filter(|c| c.before != c.after) {
        let how = if a.dry_run { "would write" } else { "wrote" };
        println!("{how} {}", c.path.display());
    }
    for w in &p.warnings {
        println!("warning: {w}");
    }
    if !a.dry_run {
        let mut open = 0usize;
        for (q, dir) in &p.queues {
            let report = audit_queue(&root, dir, q);
            for v in report
                .violations
                .iter()
                .filter(|v| p.rows.iter().any(|(id, _)| v.snippet == *id))
            {
                open += 1;
                println!(
                    "audit: [{}] {}:{} {}",
                    v.rule_id, v.file_path, v.line_number, v.message
                );
            }
        }
        println!(
            "{} row(s) moved; {open} audit finding(s) on them",
            p.rows.len()
        );
    }
    0
}
