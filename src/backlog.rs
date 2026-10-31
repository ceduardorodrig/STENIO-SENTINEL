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

/// A backlog queue, declared in the embedded registry (`backlog-queues.toml`). All queues share
/// one lifecycle model; `linked` decides whether items are also traced both ways to the
/// documents they reference (`pending:` frontmatter). The homelab queue is linked; the product
/// queues (Hub, Miracena) keep their detail in the repository's own docs and are checked for
/// structure, lifecycle, state, recurrence and `Ref` resolution only.
#[derive(Clone, Debug, serde::Deserialize)]
struct Queue {
    name: String,
    prefix: String,
    dir: String,
    #[serde(default)]
    requires: Option<String>,
    #[serde(default)]
    linked: bool,
    #[serde(default)]
    self_if_named: bool,
}

#[derive(serde::Deserialize)]
struct Registry {
    queue: Vec<Queue>,
}

/// The registry is compiled into the binary: the set of queues is versioned and reproducible
/// with the engine.
const REGISTRY_TOML: &str = include_str!("../backlog-queues.toml");

/// Template of a new queue (`stenio --backlog-new`); `{{NAME}}` and `{{PREFIX}}` are substituted.
const TEMPLATE_QUEUE: &str = include_str!("../templates/backlog.md.tpl");
const TEMPLATE_ARCHIVE: &str = include_str!("../templates/backlog-archive.md.tpl");

fn registry() -> Vec<Queue> {
    toml::from_str::<Registry>(REGISTRY_TOML)
        .map(|r| r.queue)
        .unwrap_or_default()
}

/// Directory of a queue under `repo_root`, if the audited path contains it.
fn resolve_queue_dir(repo_root: &Path, q: &Queue) -> Option<PathBuf> {
    if let Some(req) = &q.requires {
        if !repo_root.join(req).is_dir() {
            return None;
        }
    }
    let dir = repo_root.join(&q.dir);
    if dir.is_dir() {
        Some(dir)
    } else if q.self_if_named && repo_root.ends_with(&q.dir) {
        Some(repo_root.to_path_buf())
    } else {
        None
    }
}

/// Audits every registered queue whose `linked` flag equals `linked`, found under `repo_root`.
fn audit_registered(repo_root: &Path, linked: bool) -> BacklogReport {
    let mut report = silent();
    for q in registry().into_iter().filter(|q| q.linked == linked) {
        let Some(dir) = resolve_queue_dir(repo_root, &q) else {
            continue;
        };
        let part = audit_queue(repo_root, &dir, &q);
        report.total_items += part.total_items;
        report.messages.extend(part.messages);
        report.violations.extend(part.violations);
    }
    report
}

/// Audits the *linked* queues (the homelab one), traced bidirectionally to their documents. A
/// scope without such a tree or without an adopted index yields nothing — the rule is inert
/// until it has data.
pub fn audit_backlog(repo_root: &Path) -> BacklogReport {
    audit_registered(repo_root, true)
}

/// Audits the *product* queues (Hub, Miracena, ...): structure, lifecycle, state, recurrence and
/// `Ref` resolution. They keep their detail in the repository's own docs, so no `pending:`
/// declaration is required.
pub fn audit_product_queues(repo_root: &Path) -> BacklogReport {
    audit_registered(repo_root, false)
}

/// Cross-checks one queue and its archive. For a linked queue the check also runs against the
/// `pending:` frontmatter of every note, in both directions.
fn audit_queue(repo_root: &Path, base_dir: &Path, q: &Queue) -> BacklogReport {
    let active_path = base_dir.join(BACKLOG_REL);
    let Ok(active_content) = fs::read_to_string(&active_path) else {
        // The index is optional until adopted: nothing to cross-check yet.
        return silent();
    };
    let active_display = display_path(&active_path, repo_root);

    let archive_path = base_dir.join(ARCHIVE_REL);
    let archive_content = fs::read_to_string(&archive_path).ok();
    let archive_display = display_path(&archive_path, repo_root);

    let active = parse_table(&active_content, &q.prefix);
    let archive = match archive_content.as_deref() {
        Some(content) => parse_table(content, &q.prefix),
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
            &q.prefix,
            repo_root,
            base_dir,
            &active_display,
            item,
            q.linked,
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
            &q.prefix,
            repo_root,
            base_dir,
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
    // Only linked queues declare `pending:` in documents; the product queues skip this walk.
    let documents: Vec<PathBuf> = if q.linked {
        crate::baseline::build_file_walker(base_dir).collect()
    } else {
        Vec::new()
    };
    for path in documents {
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
        for id in parse_pending(&doc, &q.prefix) {
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
        let how = if q.linked {
            "traced bidirectionally to their documents"
        } else {
            "well-formed"
        };
        messages.push(format!(
            "✅ {} active {}* backlog item(s) {} ({} archived).",
            active.items.len(),
            q.prefix,
            how,
            archive.items.len()
        ));
    } else {
        messages.push(format!(
            "⚠️ {} backlog issue(s) across {} active {}* item(s).",
            violations.len(),
            active.items.len(),
            q.prefix
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
    prefix: &str,
    repo_root: &Path,
    base_dir: &Path,
    index_display: &str,
    item: &Item,
    require_pending: bool,
) -> Vec<Violation> {
    let mut found = Vec::new();
    let Some(reference) = &item.reference else {
        return found;
    };
    let target = base_dir.join(reference.trim_start_matches("./"));
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
                "Fix the Ref to an existing document, or remove the item."
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
    let declares_item = parse_pending(&doc, prefix)
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
        severity: header_index(header, &["sev", "severity", "severidade"])?,
        state: header_index(header, &["state", "estado"])?,
        recurrence: header_index(header, &["recurrence", "recorrência", "recorrencia"]),
        recurred_by: header_index(header, &["recurred-by", "recurred by", "recorrido por"]),
    })
}

/// Extracts `HB-123` from a (possibly bolded) ID cell, tolerating surrounding `**`.
fn extract_id(cell: &str, prefix: &str) -> Option<String> {
    let cleaned = cell.trim_matches(|c: char| c == '*' || c.is_whitespace());
    let digits = cleaned.strip_prefix(prefix)?;
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        Some(cleaned.to_string())
    } else {
        None
    }
}

/// Extracts every `HB-123` token from a cell (`↻ HB-007` → `["HB-007"]`).
fn extract_ids(cell: &str, prefix: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let needle = prefix.as_bytes();
    let bytes = cell.as_bytes();
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let start = i + needle.len();
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                if let Some(digits) = cell.get(start..end) {
                    ids.push(format!("{prefix}{digits}"));
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
    } else if ['🟠', '🟡', '🟢', '🔵', '💡'].iter().any(|glyph| cell.contains(*glyph)) {
        (Severity::Warning, true)
    } else {
        (Severity::Warning, false)
    }
}

/// Canonical state of a table cell. Accepts the English words (homelab) and the status glyphs
/// of the Hub documentation standard (⏳ open, 🏗 in progress, ⏸ blocked, ✅ resolved,
/// ✗ discarded), so every queue shares one lifecycle model.
fn normalize_state(cell: &str) -> String {
    for (glyph, state) in [
        ('⏳', "open"),
        ('🏗', "in progress"),
        ('⏸', "blocked"),
        ('✅', "resolved"),
        ('✗', "discarded"),
    ] {
        if cell.contains(glyph) {
            return state.to_string();
        }
    }
    cell.to_lowercase()
}

/// Parses a backlog table (header-driven): the column layout is resolved from the header row,
/// so the layout can grow (e.g. `Recurrence`) without an engine change.
fn parse_table(content: &str, prefix: &str) -> Table {
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
            orphans: collect_orphans(&lines, prefix),
        };
    };
    let Some(columns) = resolve_columns(&header_cells) else {
        return Table {
            columns: None,
            items: Vec::new(),
            orphans: collect_orphans(&lines, prefix),
        };
    };

    let mut items = Vec::new();
    let mut orphans = Vec::new();
    for (idx, line) in lines.iter().enumerate().skip(header_idx + 1) {
        let cells = split_row(line);
        let Some(id) = cells.get(columns.id).and_then(|cell| extract_id(cell, prefix)) else {
            if let Some(id) = cells.first().and_then(|cell| extract_id(cell, prefix)) {
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
                .map(|cell| normalize_state(cell))
                .unwrap_or_default(),
            recurrence: column_ids(&cells, columns.recurrence, prefix),
            recurred_by: column_ids(&cells, columns.recurred_by, prefix),
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
fn column_ids(cells: &[String], column: Option<usize>, prefix: &str) -> Vec<String> {
    column
        .and_then(|idx| cells.get(idx))
        .map(|cell| extract_ids(cell, prefix))
        .unwrap_or_default()
}

/// Rows carrying an `HB-` id in their first cell (candidates for a header-less table).
fn collect_orphans(lines: &[&str], prefix: &str) -> Vec<(usize, String)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let cells = split_row(line);
            let id = cells.first().and_then(|cell| extract_id(cell, prefix))?;
            Some((idx + 1, id))
        })
        .collect()
}

/// Reads the `pending: [HB-xxx, ...]` list from a document's frontmatter only.
fn parse_pending(content: &str, prefix: &str) -> Vec<String> {
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
            if extract_id(candidate, prefix).is_some() {
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

fn display_path(path: &Path, repo_root: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

// ── CLI mode: `stenio --backlog [--search <term>]` ──────────────────────────

/// Prints every registered queue found under the path (active items and archive size). With a
/// search term, it greps **both** files of each queue, so a problem that already happened shows
/// up — the dynamic half of the recurrence contract (`Recurrence` ↔ `Recurred-by` is the
/// verifiable half).
pub fn run_backlog_report(repo_root: &Path, search: Option<&str>) {
    crate::baseline::print_banner("StenioSentinel — Backlog: Active Queues & History");

    let found: Vec<(Queue, PathBuf)> = registry()
        .into_iter()
        .filter_map(|q| resolve_queue_dir(repo_root, &q).map(|dir| (q, dir)))
        .filter(|(_, dir)| dir.join(BACKLOG_REL).is_file())
        .collect();
    if found.is_empty() {
        println!(
            "   {}",
            "No backlog queue under this path (see backlog-queues.toml).".yellow()
        );
        return;
    }

    for (q, dir) in &found {
        let active_content = fs::read_to_string(dir.join(BACKLOG_REL)).unwrap_or_default();
        let archive_content = fs::read_to_string(dir.join(ARCHIVE_REL)).unwrap_or_default();

        if let Some(term) = search {
            println!("   {}", format!("[{} {}]", q.name, q.prefix).white().bold());
            print_backlog_search(&active_content, &archive_content, term, &q.prefix);
            continue;
        }

        let active = parse_table(&active_content, &q.prefix);
        let archive = parse_table(&archive_content, &q.prefix);
        println!(
            "   {} {}",
            format!("{} ({}) — active queue:", q.name, q.prefix).white().bold(),
            format!("{} item(s), {} archived", active.items.len(), archive.items.len()).dimmed()
        );
        print_queue(&active, &active_content);
        println!();
    }
    if search.is_none() {
        println!(
            "   {}",
            "Tip: --backlog --search <term> greps every queue and its archive (find recurrences)."
                .dimmed()
        );
    }
}

/// `stenio --backlog-new <PREFIX> --path <dir>`: scaffolds a new queue (`backlog.md` +
/// `backlog-archive.md`) from the embedded templates and prints the registry entry to add.
/// Never overwrites an existing file. Returns `Err` with a human-readable reason on refusal.
pub fn scaffold_queue(prefix: &str, dir: &Path, name: Option<&str>) -> Result<Vec<PathBuf>, String> {
    let valid = prefix.len() >= 3
        && prefix.len() <= 5
        && prefix.ends_with('-')
        && prefix[..prefix.len() - 1].chars().all(|c| c.is_ascii_uppercase());
    if !valid {
        return Err(format!(
            "invalid prefix '{prefix}': use 2-4 capital letters and a dash (e.g. TB-)"
        ));
    }
    if registry().iter().any(|q| q.prefix == prefix) {
        return Err(format!("prefix '{prefix}' is already in the registry"));
    }
    let label = name.map(str::to_string).unwrap_or_else(|| {
        dir.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Project")
            .to_string()
    });
    fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut written = Vec::new();
    for (file, template) in [(BACKLOG_REL, TEMPLATE_QUEUE), (ARCHIVE_REL, TEMPLATE_ARCHIVE)] {
        let target = dir.join(file);
        if target.exists() {
            return Err(format!("{} already exists; refusing to overwrite", target.display()));
        }
        let body = template.replace("{{NAME}}", &label).replace("{{PREFIX}}", prefix);
        fs::write(&target, body).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        written.push(target);
    }
    Ok(written)
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
fn print_backlog_search(active: &str, archive: &str, term: &str, prefix: &str) {
    let needle = term.to_lowercase();
    let mut hits = 0usize;
    for (label, content) in [("active", active), ("archived", archive)] {
        for line in content.lines() {
            let is_item = split_row(line)
                .first()
                .and_then(|cell| extract_id(cell, prefix))
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
        let table = parse_table(content, "HB-");
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
        let table = parse_table(content, "HB-");
        assert_eq!(table.items[0].recurrence, vec!["HB-007".to_string()]);
        assert!(table.items[0].recurred_by.is_empty());
    }

    #[test]
    fn extracts_recurred_by_from_archive_rows() {
        let content = "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n\
                       |---|---|---|---|---|---|---|\n\
                       | **HB-007** | eno1 drops | [`servers/a.md`](servers/a.md) | 🔵 | resolved | 2026-10-12 | HB-019 |";
        let table = parse_table(content, "HB-");
        assert_eq!(table.items[0].recurred_by, vec!["HB-019".to_string()]);
    }

    #[test]
    fn headerless_table_reports_orphans_not_silence() {
        let content =
            "| **HB-001** | disk | [`servers/a.md`](servers/a.md) | 🔴 | open | 2026-10-08 |";
        let table = parse_table(content, "HB-");
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
            parse_pending(doc, "HB-"),
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
        assert_eq!(extract_id("**HB-12**", "HB-"), Some("HB-12".to_string()));
        assert_eq!(extract_id("ID", "HB-"), None);
        assert_eq!(extract_id("**HB-abc**", "HB-"), None);
    }

    #[test]
    fn prefix_is_configurable_and_isolated() {
        assert_eq!(extract_id("**SB-012**", "SB-"), Some("SB-012".to_string()));
        assert_eq!(extract_id("**SB-012**", "HB-"), None);
        assert_eq!(extract_ids("↻ SB-003 and HB-001", "SB-"), vec!["SB-003".to_string()]);
    }

    #[test]
    fn status_glyphs_map_to_canonical_states() {
        assert_eq!(normalize_state("⏳"), "open");
        assert_eq!(normalize_state("🏗"), "in progress");
        assert_eq!(normalize_state("⏸"), "blocked");
        assert_eq!(normalize_state("✅"), "resolved");
        assert_eq!(normalize_state("✗"), "discarded");
        assert_eq!(normalize_state("Open"), "open");
    }

    #[test]
    fn hub_severity_glyphs_are_recognized() {
        assert_eq!(parse_severity("🟠"), (Severity::Warning, true));
        assert_eq!(parse_severity("🟢"), (Severity::Warning, true));
        assert_eq!(parse_severity("🔴"), (Severity::Error, true));
    }

    #[test]
    fn portuguese_headers_resolve_to_the_same_columns() {
        let content = "| ID | Item | Ref | Severidade | Estado | Origem | Recorrência |\n\
                       |---|---|---|---|---|---|---|\n\
                       | **SB-001** | x | [a](a.md) | 🟠 | ⏳ | 2026-10-30 | ↻ SB-000 |";
        let table = parse_table(content, "SB-");
        assert_eq!(table.items.len(), 1);
        assert_eq!(table.items[0].state, "open");
        assert_eq!(table.items[0].recurrence, vec!["SB-000".to_string()]);
    }

    /// A product queue (Hub-style) is audited for structure and lifecycle but is not required
    /// to be declared in a document's `pending:` frontmatter.
    #[test]
    fn product_queue_needs_no_pending_declaration() {
        let root = std::env::temp_dir().join(format!("stenio-backlog-test-{}", std::process::id()));
        let docs = root.join("docs");
        let created = fs::create_dir_all(root.join("app")).is_ok() && fs::create_dir_all(&docs).is_ok();
        assert!(created);
        let wrote = fs::write(docs.join("area.md"), "# area\n").is_ok()
            && fs::write(
                docs.join("backlog.md"),
                "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
                 |---|---|---|---|---|---|---|\n\
                 | **SB-001** | x | [area](area.md) | 🟠 | ⏳ | 2026-10-30 | — |\n",
            )
            .is_ok()
            && fs::write(
                docs.join("backlog-archive.md"),
                "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n|---|---|---|---|---|---|---|\n",
            )
            .is_ok();
        assert!(wrote);

        let report = audit_product_queues(&root);
        let _ = fs::remove_dir_all(&root);

        assert_eq!(report.total_items, 1);
        assert!(report.violations.is_empty(), "unexpected: {}", report.violations.len());
    }

    #[test]
    fn embedded_registry_parses_with_unique_prefixes() {
        let queues = registry();
        assert!(queues.len() >= 3, "registry must declare the HB/SB/MB queues");
        let mut prefixes: Vec<&str> = queues.iter().map(|q| q.prefix.as_str()).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), queues.len(), "queue prefixes must be unique");
        assert!(queues.iter().all(|q| q.prefix.ends_with('-') && !q.dir.is_empty()));
        // Only the homelab queue is traced to documents.
        assert!(queues.iter().filter(|q| q.linked).all(|q| q.prefix == "HB-"));
    }

    #[test]
    fn scaffold_rejects_bad_or_taken_prefixes() {
        let dir = std::env::temp_dir().join(format!("stenio-scaffold-bad-{}", std::process::id()));
        assert!(scaffold_queue("tb-", &dir, None).is_err());
        assert!(scaffold_queue("TB", &dir, None).is_err());
        assert!(scaffold_queue("TOOLONG-", &dir, None).is_err());
        assert!(scaffold_queue("HB-", &dir, None).is_err(), "HB- is already registered");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A freshly scaffolded queue must audit clean once it is registered, and a second scaffold
    /// into the same directory must refuse to overwrite.
    #[test]
    fn scaffolded_queue_audits_clean_and_is_not_overwritten() {
        let root = std::env::temp_dir().join(format!("stenio-scaffold-ok-{}", std::process::id()));
        let dir = root.join("tasks");
        let written = scaffold_queue("ZZ-", &dir, Some("Tasks"));
        assert!(written.is_ok());
        assert!(scaffold_queue("ZY-", &dir, None).is_err(), "must not overwrite");

        let active = fs::read_to_string(dir.join(BACKLOG_REL)).unwrap_or_default();
        assert!(active.contains("# Tasks Backlog") && active.contains("ZZ-nnn"));
        let queue = Queue {
            name: "tasks".to_string(),
            prefix: "ZZ-".to_string(),
            dir: "tasks".to_string(),
            requires: None,
            linked: false,
            self_if_named: false,
        };
        let report = audit_queue(&root, &dir, &queue);
        let _ = fs::remove_dir_all(&root);
        assert!(report.violations.is_empty(), "unexpected: {}", report.violations.len());
    }
}
