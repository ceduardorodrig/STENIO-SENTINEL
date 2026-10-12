//! Backlog traceability audit — "every pending item has a single, traceable source".
//!
//! Mnemocine keeps the **active queue** of pending work in `mnemocine/backlog.md` and the
//! **history** of closed items in `mnemocine/backlog-archive.md`. The technical detail stays
//! in the area document, which declares its own *active* items in the frontmatter field
//! `pending: [HB-xxx]`. The index and the documents must agree — that contract is what
//! stops the index from rotting into a second, disconnected list. See
//! `mnemocine/guides/backlog-routine.md` for the weekly cadence.
//!
//! The split keeps the queue lean: only `open` / `in progress` / `blocked` live in the
//! index; a closed item moves to the archive (with its closing date) and its id leaves the
//! document's `pending:` list. A problem that comes back opens a **new** item linked to the
//! archived one through the `Recurrence` / `Recurred-by` pair — a verifiable, bidirectional
//! recurrence edge, so "this is the same problem again" is a fact, not a memory.
//!
//! Emitted rules:
//!   * `DOC-BACKLOG-DRIFT`          — the two sides disagree: a `Ref` points to a missing
//!     document, an *active* item's document does not declare it, a document declares an id
//!     the active queue does not contain, or it declares an *archived* id.
//!   * `HOMELAB-BACKLOG-MALFORMED`  — a row is not well-formed (missing `Ref`, an unknown
//!     severity, an invalid state) or a table has no recognizable header.
//!   * `HOMELAB-BACKLOG-LIFECYCLE`  — a closed item (`resolved` / `discarded`) records no
//!     closing date.
//!   * `HOMELAB-BACKLOG-STATE`      — an id lives in both files at once, or an item's state
//!     does not match its file (a closed state in the queue, an active state in the archive).
//!   * `DOC-BACKLOG-RECURRENCE`     — a `Recurrence` link and its `Recurred-by` twin do not
//!     agree: a recurring item must point at an *archived* item, and that archived item must
//!     point back at the open one.
//!
//! Severity is adaptive: a drift on a 🔴 (critical) item is an **Error** and blocks the gate;
//! every other finding stays a **Warning** (visible, never silenced). Columns are resolved
//! from the table header, so the layout can grow (e.g. `Recurrence`) without touching the
//! engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use colored::Colorize;

use crate::engine::Violation;
use crate::rule::Severity;

#[allow(dead_code)]
pub struct BacklogReport {
    pub total_items: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

/// Active queue, relative to the mnemocine tree root.
const BACKLOG_REL: &str = "backlog.md";
/// History of closed items, relative to the mnemocine tree root.
const ARCHIVE_REL: &str = "backlog-archive.md";

/// States accepted by the governance table in the backlog header.
const VALID_STATES: [&str; 5] = ["open", "in progress", "resolved", "discarded", "blocked"];
/// States that mean "still in the active queue".
const ACTIVE_STATES: [&str; 3] = ["open", "in progress", "blocked"];
/// States that mean "belongs in the archive".
const CLOSED_STATES: [&str; 2] = ["resolved", "discarded"];

/// Canonical row layout, echoed in the malformed-row suggestion.
const ACTIVE_LAYOUT: &str = "| ID | Item | Ref | Sev | State | Origin | Recurrence |";
const ARCHIVE_LAYOUT: &str = "| ID | Item | Ref | Sev | State | Closed | Recurred-by |";

/// Column layout resolved from the table header (name → position).
#[derive(Clone)]
struct Columns {
    id: usize,
    item: Option<usize>,
    reference: usize,
    severity: usize,
    state: usize,
    recurrence: Option<usize>,
    recurred_by: Option<usize>,
}

/// A parsed backlog row.
struct Item {
    id: String,
    reference: Option<String>,
    severity: Severity,
    severity_known: bool,
    state: String,
    recurrence: Vec<String>,
    recurred_by: Vec<String>,
    line: usize,
}

/// One parsed Markdown table (header-driven).
struct Table {
    columns: Option<Columns>,
    items: Vec<Item>,
    /// Rows carrying an `HB-` id that could not be parsed (no header / short row).
    orphans: Vec<(usize, String)>,
}

impl Table {
    fn empty() -> Self {
        Table {
            columns: None,
            items: Vec::new(),
            orphans: Vec::new(),
        }
    }
}

/// Cross-checks the active queue and the archive against the `pending:` frontmatter of every
/// note, in both directions. A scope without a mnemocine tree (or without an adopted index)
/// yields nothing — the rule is inert until it has data.
pub fn audit_backlog(repo_root: &Path) -> BacklogReport {
    let Some(mnemocine_dir) = resolve_mnemocine(repo_root) else {
        return silent();
    };

    let active_path = mnemocine_dir.join(BACKLOG_REL);
    let Ok(active_content) = fs::read_to_string(&active_path) else {
        // The index is optional until adopted: nothing to cross-check yet.
        return silent();
    };
    let active_display = display_path(&active_path, repo_root);

    let archive_path = mnemocine_dir.join(ARCHIVE_REL);
    let archive_content = fs::read_to_string(&archive_path).ok();
    let archive_display = display_path(&archive_path, repo_root);

    let active = parse_table(&active_content);
    let archive = match archive_content.as_deref() {
        Some(content) => parse_table(content),
        None => Table::empty(),
    };

    let active_ids: BTreeSet<&str> = active.items.iter().map(|item| item.id.as_str()).collect();
    let archive_ids: BTreeSet<&str> = archive.items.iter().map(|item| item.id.as_str()).collect();
    let active_by_id: BTreeMap<&str, &Item> = active
        .items
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect();
    let archive_by_id: BTreeMap<&str, &Item> = archive
        .items
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect();

    let mut violations = Vec::new();

    // ── R0. The tables themselves: an id row with no usable header ───────────
    violations.extend(report_orphans(&active_display, &active));
    violations.extend(report_orphans(&archive_display, &archive));

    // ── R1..R3. The active queue ─────────────────────────────────────────────
    for item in &active.items {
        violations.extend(check_row(
            &active_display,
            &active_content,
            item,
            ACTIVE_LAYOUT,
        ));
        if CLOSED_STATES.contains(&item.state.as_str()) {
            violations.push(state_violation(
                &active_display,
                item,
                format!(
                    "Backlog item {} is '{}' but lives in the active queue ({}).",
                    item.id, item.state, BACKLOG_REL
                ),
                format!(
                    "Move the row to {} and drop its id from the document's `pending:` list.",
                    ARCHIVE_REL
                ),
            ));
        }
        violations.extend(check_forward(
            repo_root,
            &mnemocine_dir,
            &active_display,
            item,
            true,
        ));

        // R5a. A recurring item must point at an archived item that points back.
        for target in &item.recurrence {
            match archive_by_id.get(target.as_str()) {
                None => violations.push(recurrence_violation(
                    &active_display,
                    item,
                    format!(
                        "Backlog item {} declares 'Recurrence: {}', but {} is not in {}.",
                        item.id, target, target, ARCHIVE_REL
                    ),
                    format!(
                        "Point the Recurrence at an archived item, or drop it if {} is not a recurrence.",
                        target
                    ),
                )),
                Some(archived) => {
                    if !archived.recurred_by.iter().any(|id| id == &item.id) {
                        violations.push(recurrence_violation(
                            &active_display,
                            item,
                            format!(
                                "Backlog item {} recurs from {}, but {} does not carry 'Recurred-by: {}'.",
                                item.id, target, target, item.id
                            ),
                            format!("Add 'Recurred-by: {}' to the {} row.", item.id, target),
                        ));
                    }
                }
            }
        }
    }

    // ── The archive (history) ────────────────────────────────────────────────
    for item in &archive.items {
        let archive_text = archive_content.as_deref().unwrap_or_default();
        violations.extend(check_row(
            &archive_display,
            archive_text,
            item,
            ARCHIVE_LAYOUT,
        ));
        if ACTIVE_STATES.contains(&item.state.as_str()) {
            violations.push(state_violation(
                &archive_display,
                item,
                format!(
                    "Archived item {} is '{}' (an active state).",
                    item.id, item.state
                ),
                format!(
                    "Move the row back to {} while the item is still open.",
                    BACKLOG_REL
                ),
            ));
        }
        // The Ref stays informational here — but it must still resolve.
        violations.extend(check_forward(
            repo_root,
            &mnemocine_dir,
            &archive_display,
            item,
            false,
        ));

        // R5b. A `Recurred-by` target must be an active item that points back.
        for target in &item.recurred_by {
            match active_by_id.get(target.as_str()) {
                None => violations.push(recurrence_violation(
                    &archive_display,
                    item,
                    format!(
                        "Archived item {} declares 'Recurred-by: {}', but {} is not in the active queue.",
                        item.id, target, target
                    ),
                    format!("Point Recurred-by at an open item, or drop it if {} never recurred.", item.id),
                )),
                Some(open) => {
                    if !open.recurrence.iter().any(|id| id == &item.id) {
                        violations.push(recurrence_violation(
                            &archive_display,
                            item,
                            format!(
                                "Archived item {} was recurred by {}, but {} does not declare 'Recurrence: {}'.",
                                item.id, target, target, item.id
                            ),
                            format!("Add 'Recurrence: {}' to the {} row.", item.id, target),
                        ));
                    }
                }
            }
        }
    }

    // ── R4. An id must live in exactly one of the two files ──────────────────
    for id in active_ids.intersection(&archive_ids) {
        if let Some(item) = active_by_id.get(id) {
            violations.push(state_violation(
                &active_display,
                item,
                format!(
                    "Backlog item {} appears in both {} and {}.",
                    id, BACKLOG_REL, ARCHIVE_REL
                ),
                format!(
                    "Keep {} in exactly one file — the queue while open, the archive once closed.",
                    id
                ),
            ));
        }
    }

    // ── R6. Reverse direction: a document may only declare *active* ids ──────
    for path in crate::baseline::build_file_walker(&mnemocine_dir) {
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains("/.stversions/") || path_str.contains("/.smart-env/") {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Ok(doc) = fs::read_to_string(&path) else {
            continue;
        };
        for id in parse_pending(&doc) {
            if active_ids.contains(id.as_str()) {
                continue;
            }
            let (message, suggestion) = if archive_ids.contains(id.as_str()) {
                (
                    format!(
                        "Document declares 'pending: [{}]', but {} is archived — the active queue no longer lists it.",
                        id, id
                    ),
                    format!(
                        "Remove {} from this document's `pending:` list (the archive keeps the history).",
                        id
                    ),
                )
            } else {
                (
                    format!(
                        "Document declares 'pending: [{}]', but {} is not an item in the backlog.",
                        id, id
                    ),
                    format!(
                        "Open {} in {} or remove the stale declaration.",
                        id, BACKLOG_REL
                    ),
                )
            };
            violations.push(Violation {
                rule_id: "DOC-BACKLOG-DRIFT".to_string(),
                rule_name: "Backlog Traceability Drift".to_string(),
                severity: Severity::Warning,
                file_path: display_path(&path, repo_root),
                line_number: 1,
                snippet: id.clone(),
                message,
                suggestion: Some(suggestion),
            });
        }
    }

    let mut messages = Vec::new();
    if violations.is_empty() {
        messages.push(format!(
            "✅ {} active backlog item(s) traced bidirectionally to their documents ({} archived).",
            active.items.len(),
            archive.items.len()
        ));
    } else {
        messages.push(format!(
            "⚠️ {} backlog issue(s) across {} active item(s).",
            violations.len(),
            active.items.len()
        ));
    }

    BacklogReport {
        total_items: active.items.len(),
        messages,
        violations,
    }
}

fn silent() -> BacklogReport {
    BacklogReport {
        total_items: 0,
        messages: Vec::new(),
        violations: Vec::new(),
    }
}

/// Flags `HB-` rows that could not be parsed because the table header is missing or the row
/// is short — so a broken table never degrades into a silent "zero items" pass.
fn report_orphans(display: &str, table: &Table) -> Vec<Violation> {
    let reason = if table.columns.is_none() {
        "the table header is missing or unrecognized"
    } else {
        "the row is shorter than the header"
    };
    table
        .orphans
        .iter()
        .map(|(line, id)| Violation {
            rule_id: "HOMELAB-BACKLOG-MALFORMED".to_string(),
            rule_name: "Malformed Backlog Item".to_string(),
            severity: Severity::Warning,
            file_path: display.to_string(),
            line_number: *line,
            snippet: id.clone(),
            message: format!("Backlog item {} could not be parsed: {}.", id, reason),
            suggestion: Some(format!(
                "Restore the table header ('{}' or '{}') and keep every row aligned to it.",
                ACTIVE_LAYOUT, ARCHIVE_LAYOUT
            )),
        })
        .collect()
}

/// R1/R2 — structural integrity (malformed row) and lifecycle (closing date).
fn check_row(display: &str, content: &str, item: &Item, layout: &str) -> Vec<Violation> {
    let mut found = Vec::new();
    let state_ok = VALID_STATES.contains(&item.state.as_str());
    if item.reference.is_none() || !item.severity_known || !state_ok {
        let mut missing = Vec::new();
        if item.reference.is_none() {
            missing.push("Ref");
        }
        if !item.severity_known {
            missing.push("Severity");
        }
        if !state_ok {
            missing.push("State");
        }
        found.push(Violation {
            rule_id: "HOMELAB-BACKLOG-MALFORMED".to_string(),
            rule_name: "Malformed Backlog Item".to_string(),
            severity: Severity::Warning,
            file_path: display.to_string(),
            line_number: item.line,
            snippet: item.id.clone(),
            message: format!(
                "Backlog item {} is incomplete or invalid (missing {}).",
                item.id,
                missing.join(", ")
            ),
            suggestion: Some(format!(
                "Use the row layout '{}' with a resolvable Ref, a 🔴/🟡/🔵/💡 severity and a valid state.",
                layout
            )),
        });
    }

    if CLOSED_STATES.contains(&item.state.as_str()) && !has_iso_date(row_at(content, item.line)) {
        found.push(Violation {
            rule_id: "HOMELAB-BACKLOG-LIFECYCLE".to_string(),
            rule_name: "Backlog Item Missing Closing Date".to_string(),
            severity: Severity::Warning,
            file_path: display.to_string(),
            line_number: item.line,
            snippet: item.id.clone(),
            message: format!(
                "Backlog item {} is closed ('{}') but records no closing date (YYYY-MM-DD).",
                item.id, item.state
            ),
            suggestion: Some(
                "Record the resolution date (e.g. '2026-10-12 — fixed by #123') in the row."
                    .to_string(),
            ),
        });
    }
    found
}

/// R3 — forward direction: the `Ref` resolves, and (for an active item) the document
/// declares the item in its `pending:` frontmatter.
fn check_forward(
    repo_root: &Path,
    mnemocine_dir: &Path,
    index_display: &str,
    item: &Item,
    require_pending: bool,
) -> Vec<Violation> {
    let mut found = Vec::new();
    let Some(reference) = &item.reference else {
        return found;
    };
    let target = mnemocine_dir.join(reference.trim_start_matches("./"));
    if !target.is_file() {
        found.push(Violation {
            rule_id: "DOC-BACKLOG-DRIFT".to_string(),
            rule_name: "Backlog Traceability Drift".to_string(),
            severity: item.severity,
            file_path: index_display.to_string(),
            line_number: item.line,
            snippet: item.id.clone(),
            message: format!(
                "Backlog item {} points to '{}', which does not exist.",
                item.id, reference
            ),
            suggestion: Some(
                "Fix the Ref to an existing document under mnemocine/, or remove the item."
                    .to_string(),
            ),
        });
        return found;
    }
    if !require_pending {
        return found;
    }
    let Ok(doc) = fs::read_to_string(&target) else {
        return found;
    };
    let declares_item = parse_pending(&doc)
        .iter()
        .any(|declared| declared == &item.id);
    if !declares_item {
        found.push(Violation {
            rule_id: "DOC-BACKLOG-DRIFT".to_string(),
            rule_name: "Backlog Traceability Drift".to_string(),
            severity: item.severity,
            file_path: display_path(&target, repo_root),
            line_number: 1,
            snippet: item.id.clone(),
            message: format!(
                "Backlog item {} references this document, but its frontmatter does not declare 'pending: [{}]'.",
                item.id, item.id
            ),
            suggestion: Some(format!(
                "Add 'pending: [{}]' to the frontmatter of this document.",
                item.id
            )),
        });
    }
    found
}

fn state_violation(display: &str, item: &Item, message: String, suggestion: String) -> Violation {
    Violation {
        rule_id: "HOMELAB-BACKLOG-STATE".to_string(),
        rule_name: "Backlog Item State Mismatch".to_string(),
        severity: Severity::Warning,
        file_path: display.to_string(),
        line_number: item.line,
        snippet: item.id.clone(),
        message,
        suggestion: Some(suggestion),
    }
}

fn recurrence_violation(
    display: &str,
    item: &Item,
    message: String,
    suggestion: String,
) -> Violation {
    Violation {
        rule_id: "DOC-BACKLOG-RECURRENCE".to_string(),
        rule_name: "Backlog Recurrence Link Drift".to_string(),
        severity: item.severity,
        file_path: display.to_string(),
        line_number: item.line,
        snippet: item.id.clone(),
        message,
        suggestion: Some(suggestion),
    }
}

fn row_at(content: &str, line: usize) -> &str {
    content.lines().nth(line.saturating_sub(1)).unwrap_or("")
}

/// Splits a Markdown table row into its trimmed cells (`| a | b |` → `["a", "b"]`).
fn split_row(line: &str) -> Vec<String> {
    let mut cells: Vec<String> = line
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect();
    if cells.first().map_or(false, |cell| cell.is_empty()) {
        cells.remove(0);
    }
    if cells.last().map_or(false, |cell| cell.is_empty()) {
        cells.pop();
    }
    cells
}

/// Normalizes a header cell for comparison (`**Ref**` → `ref`).
fn normalize_header(cell: &str) -> String {
    cell.trim()
        .trim_matches(|c: char| c == '*' || c == '`' || c.is_whitespace())
        .to_lowercase()
}

/// Position of the first header cell matching any of `names`.
fn header_index(cells: &[String], names: &[&str]) -> Option<usize> {
    cells.iter().position(|cell| {
        let key = normalize_header(cell);
        names.iter().any(|name| key == *name)
    })
}

/// Resolves the column layout from a header row; `None` when a mandatory column is absent.
fn resolve_columns(header: &[String]) -> Option<Columns> {
    Some(Columns {
        id: header_index(header, &["id"])?,
        item: header_index(header, &["item"]),
        reference: header_index(header, &["ref"])?,
        severity: header_index(header, &["sev", "severity"])?,
        state: header_index(header, &["state"])?,
        recurrence: header_index(header, &["recurrence"]),
        recurred_by: header_index(header, &["recurred-by", "recurred by"]),
    })
}

/// Extracts `HB-123` from a (possibly bolded) ID cell, tolerating surrounding `**`.
fn extract_id(cell: &str) -> Option<String> {
    let cleaned = cell.trim_matches(|c: char| c == '*' || c.is_whitespace());
    let digits = cleaned.strip_prefix("HB-")?;
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        Some(cleaned.to_string())
    } else {
        None
    }
}

/// Extracts every `HB-123` token from a cell (`↻ HB-007` → `["HB-007"]`).
fn extract_ids(cell: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let bytes = cell.as_bytes();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        if &bytes[i..i + 3] == b"HB-" {
            let start = i + 3;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Some(digits) = cell.get(start..end) {
                    ids.push(format!("HB-{digits}"));
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    ids
}

/// Extracts the target of a Markdown link cell (`[text](target)`).
fn extract_link(cell: &str) -> Option<String> {
    let open = cell.find("](")?;
    let rest = &cell[open + 2..];
    let close = rest.find(')')?;
    let target = rest[..close].split('#').next().unwrap_or("").trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

/// Maps the severity emoji to a rule severity; `false` when unrecognized.
fn parse_severity(cell: &str) -> (Severity, bool) {
    if cell.contains('🔴') {
        (Severity::Error, true)
    } else if cell.contains('🟡') || cell.contains('🔵') || cell.contains('💡') {
        (Severity::Warning, true)
    } else {
        (Severity::Warning, false)
    }
}

/// Parses a backlog table (header-driven): the column layout is resolved from the header row,
/// so the layout can grow (e.g. `Recurrence`) without an engine change.
fn parse_table(content: &str) -> Table {
    let lines: Vec<&str> = content.lines().collect();
    let header = lines.iter().enumerate().find_map(|(idx, line)| {
        let cells = split_row(line);
        let is_header = cells
            .first()
            .map(|cell| normalize_header(cell) == "id")
            .unwrap_or(false);
        if is_header { Some((idx, cells)) } else { None }
    });

    let Some((header_idx, header_cells)) = header else {
        return Table {
            columns: None,
            items: Vec::new(),
            orphans: collect_orphans(&lines),
        };
    };
    let Some(columns) = resolve_columns(&header_cells) else {
        return Table {
            columns: None,
            items: Vec::new(),
            orphans: collect_orphans(&lines),
        };
    };

    let mut items = Vec::new();
    let mut orphans = Vec::new();
    for (idx, line) in lines.iter().enumerate().skip(header_idx + 1) {
        let cells = split_row(line);
        let Some(id) = cells.get(columns.id).and_then(|cell| extract_id(cell)) else {
            if let Some(id) = cells.first().and_then(|cell| extract_id(cell)) {
                orphans.push((idx + 1, id));
            }
            continue;
        };
        let (severity, severity_known) = cells
            .get(columns.severity)
            .map(|cell| parse_severity(cell))
            .unwrap_or((Severity::Warning, false));
        items.push(Item {
            id,
            reference: cells
                .get(columns.reference)
                .and_then(|cell| extract_link(cell)),
            severity,
            severity_known,
            state: cells
                .get(columns.state)
                .map(|cell| cell.to_lowercase())
                .unwrap_or_default(),
            recurrence: column_ids(&cells, columns.recurrence),
            recurred_by: column_ids(&cells, columns.recurred_by),
            line: idx + 1,
        });
    }

    Table {
        columns: Some(columns),
        items,
        orphans,
    }
}

/// Reads the `HB-` tokens of an optional link column.
fn column_ids(cells: &[String], column: Option<usize>) -> Vec<String> {
    column
        .and_then(|idx| cells.get(idx))
        .map(|cell| extract_ids(cell))
        .unwrap_or_default()
}

/// Rows carrying an `HB-` id in their first cell (candidates for a header-less table).
fn collect_orphans(lines: &[&str]) -> Vec<(usize, String)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let cells = split_row(line);
            let id = cells.first().and_then(|cell| extract_id(cell))?;
            Some((idx + 1, id))
        })
        .collect()
}

/// Reads the `pending: [HB-xxx, ...]` list from a document's frontmatter only.
fn parse_pending(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let Some(rest) = content.strip_prefix("---") else {
        return ids;
    };
    let Some(end) = rest.find("\n---") else {
        return ids;
    };
    for line in rest[..end].lines() {
        let Some(value) = line.trim().strip_prefix("pending:") else {
            continue;
        };
        for token in value.split(|c: char| c == '[' || c == ']' || c == ',') {
            let candidate = token.trim();
            if extract_id(candidate).is_some() {
                ids.push(candidate.to_string());
            }
        }
    }
    ids
}

/// Cheap ISO-8601 (`YYYY-MM-DD`) detector over a raw row.
fn has_iso_date(row: &str) -> bool {
    let bytes = row.as_bytes();
    bytes.windows(10).any(|w| {
        w[0].is_ascii_digit()
            && w[1].is_ascii_digit()
            && w[2].is_ascii_digit()
            && w[3].is_ascii_digit()
            && w[4] == b'-'
            && w[5].is_ascii_digit()
            && w[6].is_ascii_digit()
            && w[7] == b'-'
            && w[8].is_ascii_digit()
            && w[9].is_ascii_digit()
    })
}

fn resolve_mnemocine(repo_root: &Path) -> Option<PathBuf> {
    if repo_root.join("mnemocine").is_dir() {
        Some(repo_root.join("mnemocine"))
    } else if repo_root.ends_with("mnemocine") {
        Some(repo_root.to_path_buf())
    } else {
        None
    }
}

fn display_path(path: &Path, repo_root: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

// ── CLI mode: `stenio --backlog [--search <term>]` ──────────────────────────

/// Prints the active queue (and the archive size). With a search term, it greps **both**
/// files, so a problem that already happened shows up — the dynamic half of the recurrence
/// contract (`Recurrence` ↔ `Recurred-by` is the verifiable half).
pub fn run_backlog_report(repo_root: &Path, search: Option<&str>) {
    crate::baseline::print_banner("StenioSentinel — Backlog: Active Queue & History");

    let Some(mnemocine_dir) = resolve_mnemocine(repo_root) else {
        println!("   {}", "No mnemocine/ tree under this path.".yellow());
        return;
    };

    let active_content = fs::read_to_string(mnemocine_dir.join(BACKLOG_REL)).unwrap_or_default();
    let archive_content = fs::read_to_string(mnemocine_dir.join(ARCHIVE_REL)).unwrap_or_default();

    if let Some(term) = search {
        print_backlog_search(&active_content, &archive_content, term);
        return;
    }

    let active = parse_table(&active_content);
    let archive = parse_table(&archive_content);
    println!(
        "   {} {}",
        "Active queue:".white().bold(),
        format!("{} item(s)", active.items.len()).dimmed()
    );
    print_queue(&active, &active_content);
    println!();
    println!(
        "   {} {}",
        "Archive:".white().bold(),
        format!("{} item(s)", archive.items.len()).dimmed()
    );
    println!();
    println!(
        "   {}",
        "Tip: --backlog --search <term> greps the queue and the archive (find recurrences)."
            .dimmed()
    );
}

/// Lists the parsed rows with their severity marker, one-line summary and state.
fn print_queue(table: &Table, content: &str) {
    if table.items.is_empty() {
        println!("     {}", "(empty — nothing pending)".dimmed());
        return;
    }
    for item in &table.items {
        let cells = split_row(row_at(content, item.line));
        let cell = |column: Option<usize>| {
            column
                .and_then(|idx| cells.get(idx))
                .cloned()
                .unwrap_or_default()
        };
        let marker = cell(table.columns.as_ref().map(|columns| columns.severity));
        let summary = cell(table.columns.as_ref().and_then(|columns| columns.item));
        println!(
            "     {} {}  {}  {}",
            marker,
            item.id.bold(),
            summary.dimmed(),
            format!("[{}]", item.state).cyan()
        );
    }
}

/// Greps both tables for a term, tagging each hit with its file — a hit in both files is a
/// recurrence.
fn print_backlog_search(active: &str, archive: &str, term: &str) {
    let needle = term.to_lowercase();
    let mut hits = 0usize;
    for (label, content) in [("active", active), ("archived", archive)] {
        for line in content.lines() {
            let is_item = split_row(line)
                .first()
                .and_then(|cell| extract_id(cell))
                .is_some();
            if is_item && line.to_lowercase().contains(&needle) {
                hits += 1;
                println!("   {} {}", format!("[{label}]").cyan(), line.trim());
            }
        }
    }
    println!();
    if hits == 0 {
        println!(
            "   {}",
            format!("No backlog row matches '{term}'.").dimmed()
        );
    } else {
        println!(
            "   {}",
            format!(
                "{hits} match(es). A hit in both files is a recurrence — open a new item with 'Recurrence: <archived id>'."
            )
            .dimmed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_item_rows_and_ignores_header() {
        let content = "| ID | Item | Ref | Sev | State | Origin |\n\
                       |---|---|---|---|---|---|\n\
                       | **HB-001** | disk | [`servers/a.md`](servers/a.md) | 🔴 | open | 2026-10-08 |";
        let table = parse_table(content);
        assert_eq!(table.items.len(), 1);
        assert_eq!(table.items[0].id, "HB-001");
        assert_eq!(table.items[0].reference.as_deref(), Some("servers/a.md"));
        assert_eq!(table.items[0].severity, Severity::Error);
        assert_eq!(table.items[0].state, "open");
        assert!(table.orphans.is_empty());
    }

    #[test]
    fn resolves_columns_by_header_name_not_position() {
        // The Recurrence column is optional; a missing header column is not a failure.
        let content = "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
                       |---|---|---|---|---|---|---|\n\
                       | **HB-019** | flapping | [`servers/a.md`](servers/a.md) | 🔵 | open | 2026-10-12 | ↻ HB-007 |";
        let table = parse_table(content);
        assert_eq!(table.items[0].recurrence, vec!["HB-007".to_string()]);
        assert!(table.items[0].recurred_by.is_empty());
    }

    #[test]
    fn extracts_recurred_by_from_archive_rows() {
        let content = "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n\
                       |---|---|---|---|---|---|---|\n\
                       | **HB-007** | eno1 drops | [`servers/a.md`](servers/a.md) | 🔵 | resolved | 2026-10-12 | HB-019 |";
        let table = parse_table(content);
        assert_eq!(table.items[0].recurred_by, vec!["HB-019".to_string()]);
    }

    #[test]
    fn headerless_table_reports_orphans_not_silence() {
        let content =
            "| **HB-001** | disk | [`servers/a.md`](servers/a.md) | 🔴 | open | 2026-10-08 |";
        let table = parse_table(content);
        assert!(table.items.is_empty());
        assert_eq!(table.orphans.len(), 1);
    }

    #[test]
    fn critical_severity_is_blocking_and_others_are_not() {
        assert_eq!(parse_severity("🔴"), (Severity::Error, true));
        assert_eq!(parse_severity("🟡"), (Severity::Warning, true));
        assert_eq!(parse_severity("n/a"), (Severity::Warning, false));
    }

    #[test]
    fn reads_pending_from_frontmatter_only() {
        let doc =
            "---\ntags: [homelab]\npending: [HB-001, HB-009]\n---\n\n# Body\npending: [HB-999]\n";
        assert_eq!(
            parse_pending(doc),
            vec!["HB-001".to_string(), "HB-009".to_string()]
        );
    }

    #[test]
    fn lifecycle_date_is_detected() {
        assert!(has_iso_date(
            "| **HB-003** | x | y | 🔵 | resolved | 2026-10-12 — done |"
        ));
        assert!(!has_iso_date(
            "| **HB-003** | x | y | 🔵 | resolved | later |"
        ));
    }

    #[test]
    fn malformed_id_is_rejected() {
        assert_eq!(extract_id("**HB-12**"), Some("HB-12".to_string()));
        assert_eq!(extract_id("ID"), None);
        assert_eq!(extract_id("**HB-abc**"), None);
    }
}
