//! Backlog traceability audit — "every pending item has a single, traceable source".
//!
//! Mnemocine keeps the *index* of pending work in `mnemocine/backlog.md`; the
//! technical detail stays in the area document, which declares its own items in
//! the frontmatter field `pending: [HB-xxx]`. Both sides must agree — that
//! contract is what stops the index from rotting into a second, disconnected
//! list. See `mnemocine/guides/backlog-routine.md` for the weekly cadence.
//!
//! Emitted rules:
//!   * `DOC-BACKLOG-DRIFT`          — the two sides disagree: a `Ref` points to a
//!     missing document, a referenced document does not declare the item, or a
//!     document declares an ID the index does not contain.
//!   * `HOMELAB-BACKLOG-MALFORMED`  — a row is not well-formed (missing `Ref`, an
//!     unknown severity or an invalid state).
//!   * `HOMELAB-BACKLOG-LIFECYCLE`  — a `resolved` item carries no closing date.
//!
//! Severity is adaptive: a drift on a 🔴 (critical) item is an **Error** and
//! blocks the gate; every other finding stays a **Warning** (visible, never
//! silenced). The state/severity vocabulary is read from the rows themselves,
//! so evolving the governance header does not require touching the engine.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

#[allow(dead_code)]
pub struct BacklogReport {
    pub total_items: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

/// Index file, relative to the mnemocine tree root.
const BACKLOG_REL: &str = "backlog.md";

/// States accepted by the governance table in the backlog header.
const VALID_STATES: [&str; 5] = ["open", "in progress", "resolved", "discarded", "blocked"];

/// A parsed backlog row.
struct Item {
    id: String,
    reference: Option<String>,
    severity: Severity,
    severity_known: bool,
    state: String,
    line: usize,
}

/// Cross-checks `mnemocine/backlog.md` against the `pending:` frontmatter of
/// every note, in both directions. A scope without a mnemocine tree (or without
/// an adopted index) yields nothing — the rule is inert until it has data.
pub fn audit_backlog(repo_root: &Path) -> BacklogReport {
    let Some(mnemocine_dir) = resolve_mnemocine(repo_root) else {
        return silent();
    };

    let backlog_path = mnemocine_dir.join(BACKLOG_REL);
    let Ok(content) = fs::read_to_string(&backlog_path) else {
        // The index is optional until adopted: nothing to cross-check yet.
        return silent();
    };

    let backlog_display = display_path(&backlog_path, repo_root);
    let items = parse_items(&content);
    let declared: BTreeSet<&str> = items.iter().map(|i| i.id.as_str()).collect();
    let mut violations = Vec::new();

    for item in &items {
        // ── R1. Structural integrity of the row ─────────────────────────────
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
            violations.push(Violation {
                rule_id: "HOMELAB-BACKLOG-MALFORMED".to_string(),
                rule_name: "Malformed Backlog Item".to_string(),
                severity: Severity::Warning,
                file_path: backlog_display.clone(),
                line_number: item.line,
                snippet: item.id.clone(),
                message: format!(
                    "Backlog item {} is incomplete or invalid (missing {}).",
                    item.id,
                    missing.join(", ")
                ),
                suggestion: Some(
                    "Use the row layout '| ID | Item | Ref | Sev | State | Origin |' with a resolvable Ref, a 🔴/🟡/🔵/💡 severity and a valid state.".to_string(),
                ),
            });
        }

        // ── R2. Lifecycle: a `resolved` item carries its closing date ────────
        if item.state == "resolved" {
            let row = content
                .lines()
                .nth(item.line.saturating_sub(1))
                .unwrap_or("");
            if !has_iso_date(row) {
                violations.push(Violation {
                    rule_id: "HOMELAB-BACKLOG-LIFECYCLE".to_string(),
                    rule_name: "Backlog Item Missing Closing Date".to_string(),
                    severity: Severity::Warning,
                    file_path: backlog_display.clone(),
                    line_number: item.line,
                    snippet: item.id.clone(),
                    message: format!(
                        "Backlog item {} is marked 'resolved' but records no closing date (YYYY-MM-DD).",
                        item.id
                    ),
                    suggestion: Some(
                        "Record the resolution date (e.g. '2026-10-12 — fixed by #123') in the row."
                            .to_string(),
                    ),
                });
            }
        }

        // ── R3. Forward direction: the Ref exists and declares the item ──────
        let Some(reference) = &item.reference else {
            continue;
        };
        let target = mnemocine_dir.join(reference.trim_start_matches("./"));
        if !target.is_file() {
            violations.push(Violation {
                rule_id: "DOC-BACKLOG-DRIFT".to_string(),
                rule_name: "Backlog Traceability Drift".to_string(),
                severity: item.severity,
                file_path: backlog_display.clone(),
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
        } else if let Ok(doc) = fs::read_to_string(&target) {
            let declares_item = parse_pending(&doc)
                .iter()
                .any(|declared_id| declared_id == &item.id);
            if !declares_item {
                violations.push(Violation {
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
        }
    }

    // ── R4. Reverse direction: a document declares an ID the index lacks ─────
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
            if declared.contains(id.as_str()) {
                continue;
            }
            violations.push(Violation {
                rule_id: "DOC-BACKLOG-DRIFT".to_string(),
                rule_name: "Backlog Traceability Drift".to_string(),
                severity: Severity::Warning,
                file_path: display_path(&path, repo_root),
                line_number: 1,
                snippet: id.clone(),
                message: format!(
                    "Document declares 'pending: [{}]', but {} is not an item in the backlog.",
                    id, id
                ),
                suggestion: Some(format!(
                    "Open {} in mnemocine/backlog.md, or remove the stale declaration.",
                    id
                )),
            });
        }
    }

    let mut messages = Vec::new();
    if violations.is_empty() {
        messages.push(format!(
            "✅ {} backlog item(s) traced bidirectionally to their documents.",
            items.len()
        ));
    } else {
        messages.push(format!(
            "⚠️ {} backlog traceability issue(s) across {} item(s).",
            violations.len(),
            items.len()
        ));
    }

    BacklogReport {
        total_items: items.len(),
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

/// Parses the item rows of the backlog table, ignoring the header and separator.
fn parse_items(content: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let cells = split_row(line);
        if cells.len() < 5 {
            continue;
        }
        let Some(id) = extract_id(&cells[0]) else {
            continue;
        };
        let (severity, severity_known) = parse_severity(&cells[3]);
        items.push(Item {
            id,
            reference: extract_link(&cells[2]),
            severity,
            severity_known,
            state: cells[4].to_lowercase(),
            line: idx + 1,
        });
    }
    items
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_item_rows_and_ignores_header() {
        let content = "| ID | Item | Ref | Sev | State | Origin |\n\
                       |---|---|---|---|---|---|\n\
                       | **HB-001** | disk | [`servers/a.md`](servers/a.md) | 🔴 | open | 2026-10-08 |";
        let items = parse_items(content);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "HB-001");
        assert_eq!(items[0].reference.as_deref(), Some("servers/a.md"));
        assert_eq!(items[0].severity, Severity::Error);
        assert_eq!(items[0].state, "open");
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
