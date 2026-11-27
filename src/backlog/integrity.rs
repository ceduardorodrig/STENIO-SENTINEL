//! Identity and shape checks of the queue files themselves. Every finding here is about the
//! tables as data: a row the reader and the engine would resolve differently, an id that names
//! two things, or a reference that points at nothing.
//!
//! Emitted rules:
//!   * `BACKLOG-TABLE-INTEGRITY`      — a blank or non-row line detaches rows from the header, or
//!     a row has a different cell count than the header (GB-152).
//!   * `DOC-BACKLOG-DRIFT`            — one id in two rows across the queue and its archive
//!     (GB-300).
//!   * `DOC-BACKLOG-FOREIGN-ROW`      — a row carries the prefix of another queue (GB-251).
//!   * `BACKLOG-ID-CONTIGUOUS`        — an id far above the contiguous series (GB-215).
//!   * `BACKLOG-DUPLICATE-DEFECT`     — two open rows describe the same defect (GB-199).
//!   * `BACKLOG-DEDUP-FOLD-LOSSLESS`  — a row archived as a duplicate carries a measurement the
//!     surviving row lacks (GB-209).
//!   * `BACKLOG-CROSS-REF`            — an item cites an id of another queue that exists in
//!     neither of its files (GB-008).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::{ARCHIVE_REL, BACKLOG_REL, Queue, normalize_header, registry, resolve_queue_dir};
use crate::engine::Violation;
use crate::rule::Severity;

pub const TABLE_ID: &str = "BACKLOG-TABLE-INTEGRITY";
pub const DRIFT_ID: &str = "DOC-BACKLOG-DRIFT";
pub const FOREIGN_ID: &str = "DOC-BACKLOG-FOREIGN-ROW";
pub const CONTIGUOUS_ID: &str = "BACKLOG-ID-CONTIGUOUS";
pub const DUPLICATE_ID: &str = "BACKLOG-DUPLICATE-DEFECT";
pub const FOLD_ID: &str = "BACKLOG-DEDUP-FOLD-LOSSLESS";
pub const CROSS_ID: &str = "BACKLOG-CROSS-REF";

/// An id this far above its predecessor is outside the series, not a skipped number.
const OUTLIER_GAP: u32 = 50;

/// One queue file: display path and content.
#[derive(Clone, Copy)]
pub struct File<'a> {
    pub display: &'a str,
    pub content: &'a str,
}

/// Cells of a Markdown table row. A `\|` is content, not a separator.
pub fn cells(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut escaped = false;
    for ch in line.trim().chars() {
        if ch == '|' && !escaped {
            out.push(String::new());
        } else if let Some(last) = out.last_mut() {
            last.push(ch);
        }
        escaped = ch == '\\' && !escaped;
    }
    let mut out: Vec<String> = out.into_iter().map(|c| c.trim().to_string()).collect();
    if out.first().is_some_and(String::is_empty) {
        out.remove(0);
    }
    if out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out
}

/// `(prefix with dash, number)` of an id cell such as `**GB-008**`.
fn id_of(cell: &str) -> Option<(String, u32)> {
    let cleaned = cell.trim_matches(|c: char| c == '*' || c.is_whitespace());
    let (prefix, digits) = cleaned.split_once('-')?;
    let shaped = (2..=4).contains(&prefix.len())
        && prefix.chars().all(|c| c.is_ascii_uppercase())
        && !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit());
    if !shaped {
        return None;
    }
    Some((format!("{prefix}-"), digits.parse().ok()?))
}

/// A table row whose first cell is an id.
struct Row {
    id: String,
    prefix: String,
    number: u32,
    line: usize,
    cells: Vec<String>,
}

fn id_rows(content: &str) -> Vec<Row> {
    let mut fenced = false;
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        if fenced || !line.trim_start().starts_with('|') {
            continue;
        }
        let c = cells(line);
        if let Some((prefix, number)) = c.first().and_then(|f| id_of(f)) {
            let id = c[0].trim_matches(|ch| ch == '*' || ch == ' ').to_string();
            out.push(Row {
                id,
                prefix,
                number,
                line: i + 1,
                cells: c,
            });
        }
    }
    out
}

/// Numbers of the id cells (never of ids quoted in prose) that carry `prefix`.
pub fn id_numbers(content: &str, prefix: &str) -> Vec<u32> {
    id_rows(content)
        .into_iter()
        .filter(|r| r.prefix.trim_end_matches('-') == prefix.trim_end_matches('-'))
        .map(|r| r.number)
        .collect()
}

/// The first number outside the contiguous series, when there is one.
pub fn first_outlier(numbers: &BTreeSet<u32>) -> Option<(u32, u32)> {
    let mut previous: Option<u32> = None;
    for &n in numbers {
        if let Some(p) = previous {
            if n - p > OUTLIER_GAP {
                return Some((p, n));
            }
        }
        previous = Some(n);
    }
    None
}

fn violation(
    rule: &str,
    name: &str,
    severity: Severity,
    file: &str,
    line: usize,
    id: &str,
    message: String,
    suggestion: &str,
) -> Violation {
    Violation {
        rule_id: rule.to_string(),
        rule_name: name.to_string(),
        severity,
        file_path: file.to_string(),
        line_number: line,
        snippet: id.to_string(),
        message,
        suggestion: Some(suggestion.to_string()),
    }
}

// ── GB-152 ──────────────────────────────────────────────────────────────────

/// Rows detached from their header and rows with the wrong cell count.
pub fn table_integrity(file: File<'_>, severity: Severity) -> Vec<Violation> {
    let mut found = Vec::new();
    let finding = |line, id: &str, message, suggestion| {
        violation(
            TABLE_ID,
            "Backlog Table Integrity",
            severity,
            file.display,
            line,
            id,
            message,
            suggestion,
        )
    };
    let mut fenced = false;
    // Width of the id table the current block belongs to.
    let mut width: Option<usize> = None;
    let mut in_block = false;
    // Line that ended the last id table, and whether this detached block was already reported.
    let mut broke_at: Option<usize> = None;
    let mut reported = false;
    let lines: Vec<&str> = file.content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        if fenced || !line.trim_start().starts_with('|') {
            if in_block && (width.is_some() || reported) {
                broke_at = Some(i + 1);
            }
            in_block = false;
            width = None;
            reported = false;
            continue;
        }
        let c = cells(line);
        let first = c.first().cloned().unwrap_or_default();
        if !in_block {
            in_block = true;
            if normalize_header(&first) == "id" {
                width = Some(c.len());
                broke_at = None;
                continue;
            }
        } else if normalize_header(&first) == "id" {
            width = Some(c.len());
            continue;
        }
        let Some((_, _)) = id_of(&first) else {
            continue;
        };
        let id = first.trim_matches(|ch| ch == '*' || ch == ' ');
        match width {
            Some(w) if w != c.len() => found.push(finding(
                i + 1,
                id,
                format!(
                    "Row {id} ({}:{}) has {} cells; the header has {w}.",
                    file.display,
                    i + 1,
                    c.len()
                ),
                "Give the row exactly one cell per header column; write a literal pipe as '\\|'.",
            )),
            Some(_) => {}
            None if !reported => {
                reported = true;
                let detached = lines[i..]
                    .iter()
                    .take_while(|l| l.trim_start().starts_with('|'))
                    .count();
                let cause = broke_at.map_or_else(
                    || "no table header precedes them".to_string(),
                    |n| format!("the table is interrupted at line {n} (blank or non-row line)"),
                );
                found.push(finding(
                i + 1,
                id,
                    format!(
                        "{detached} row(s) from {id} ({}:{}) are detached from the header: {cause}.",
                        file.display,
                        i + 1
                    ),
                    "Delete the interrupting line so every row stays in the table under its header.",
                ));
            }
            None => {}
        }
    }
    found
}

/// `stenio --path <queue>.md`: the integrity check of one queue file. Empty for any other file.
pub fn audit_file(path: &Path) -> Vec<Violation> {
    let name = path.file_name().and_then(|n| n.to_str());
    let severity = match name {
        Some(BACKLOG_REL) => Severity::Error,
        Some(ARCHIVE_REL) => Severity::Warning,
        _ => return Vec::new(),
    };
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let display = path.to_string_lossy();
    table_integrity(
        File {
            display: &display,
            content: &content,
        },
        severity,
    )
}

// ── GB-300 ──────────────────────────────────────────────────────────────────

/// One id in two rows, whichever of the two files holds them.
pub fn duplicate_ids(prefix: &str, active: File<'_>, archive: File<'_>) -> Vec<Violation> {
    let mut seen: BTreeMap<u32, Vec<(String, usize, String)>> = BTreeMap::new();
    for file in [active, archive] {
        for r in id_rows(file.content) {
            if r.prefix == prefix {
                seen.entry(r.number)
                    .or_default()
                    .push((file.display.to_string(), r.line, r.id));
            }
        }
    }
    seen.into_values()
        .filter(|places| places.len() > 1)
        .map(|places| {
            let at: Vec<String> = places.iter().map(|(f, l, _)| format!("{f}:{l}")).collect();
            let (file, line, id) = places[0].clone();
            violation(
                DRIFT_ID,
                "Backlog Traceability Drift",
                Severity::Error,
                &file,
                line,
                &id,
                format!(
                    "Backlog id {id} names {} rows: {}.",
                    places.len(),
                    at.join(" and ")
                ),
                "Keep one row per id: renumber the newer one (`stenio backlog --next-id`) or delete the copy.",
            )
        })
        .collect()
}

// ── GB-251 ──────────────────────────────────────────────────────────────────

/// Rows whose prefix belongs to another queue.
pub fn foreign_rows(prefix: &str, file: File<'_>) -> Vec<Violation> {
    id_rows(file.content)
        .into_iter()
        .filter(|r| r.prefix != prefix)
        .map(|r| {
            let owner = registry()
                .into_iter()
                .find(|q| q.prefix == r.prefix)
                .map_or_else(
                    || "no registered queue".to_string(),
                    |q| format!("the {} queue ({}/)", q.name, q.dir),
                );
            violation(
                FOREIGN_ID,
                "Foreign Backlog Row",
                Severity::Warning,
                file.display,
                r.line,
                &r.id,
                format!(
                    "Row {} sits in a {prefix} queue file; it belongs to {owner}.",
                    r.id
                ),
                "Move the row to the queue of its prefix and re-check its relative links.",
            )
        })
        .collect()
}

// ── GB-215 ──────────────────────────────────────────────────────────────────

/// Rows whose id jumps far above the series of the queue.
pub fn contiguity(prefix: &str, active: File<'_>, archive: File<'_>) -> Vec<Violation> {
    let rows: Vec<(String, Row)> = [active, archive]
        .into_iter()
        .flat_map(|f| {
            id_rows(f.content)
                .into_iter()
                .map(move |r| (f.display.to_string(), r))
        })
        .filter(|(_, r)| r.prefix == prefix)
        .collect();
    let numbers: BTreeSet<u32> = rows.iter().map(|(_, r)| r.number).collect();
    let Some((top, first)) = first_outlier(&numbers) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter(|(_, r)| r.number >= first)
        .map(|(file, r)| {
            violation(
                CONTIGUOUS_ID,
                "Backlog Id Out Of Series",
                Severity::Error,
                &file,
                r.line,
                &r.id,
                format!(
                    "Queue {prefix}: {} is out of series (the series ends at {prefix}{top:03}; first free id {prefix}{:03}).",
                    r.id,
                    top + 1
                ),
                "Renumber the row with `stenio backlog --next-id`.",
            )
        })
        .collect()
}

// ── GB-199 ──────────────────────────────────────────────────────────────────

/// `RULE-ID` of a `**Stenio: RULE-ID.**` item, lower-cased.
fn slug(item: &str) -> Option<String> {
    let rest = item.strip_prefix("**Stenio:")?.trim_start();
    let title = rest.split("**").next().unwrap_or(rest);
    let title = title.trim().trim_end_matches('.').to_lowercase();
    (!title.is_empty()).then_some(title)
}

/// True when `short` is `long` cut at a `-` boundary (`arch-no-python` / `arch-no-python-scope`).
fn slug_extends(short: &str, long: &str) -> bool {
    short.contains('-')
        && !short.contains(' ')
        && long
            .strip_prefix(short)
            .is_some_and(|rest| rest.starts_with('-'))
}

/// Compiled once: the pair comparison below would otherwise rebuild them thousands of times.
static FILE_LINE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"[\w./-]+\.(?:rs|py|md|toml|ya?ml|json|sh|tsx?|jsx?|vue|lua|conf|css|html|sql|hujson|service|timer):\d+").ok()
});

static DECLARED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[.;:,(—–]\**\s*|\b(?:this|it)(?:\s+(?:row|item))?(?:\s+is\s+an?)?\s+|\b(?:closed|discarded|archived)\s+as\s+(?:an?\s+)?)\**duplicat(?:es|e\s+of|ed\s+of|e:)\s+\**([A-Z]{2,4}-\d+)",
    )
    .ok()
});

fn file_lines(text: &str) -> BTreeSet<String> {
    FILE_LINE
        .as_ref()
        .map(|re| re.find_iter(text).map(|m| m.as_str().to_string()).collect())
        .unwrap_or_default()
}

/// The part of an item where the defect is described: `Evidence:` up to `Desired behaviour:`,
/// or the whole item for rows without that layout.
fn evidence(item: &str) -> &str {
    let rest = item.split_once("Evidence:").map_or(item, |(_, r)| r);
    rest.split("Desired behaviour:").next().unwrap_or(rest)
}

/// Ids the text declares itself (or the other row) to be a duplicate of. Only a declaration
/// counts (at the start of a clause, "this row is a duplicate of", "closed as duplicate of"); a
/// row that merely talks about duplicates, as a rule description does, declares nothing.
fn declared_duplicates(text: &str) -> Vec<String> {
    DECLARED
        .as_ref()
        .map(|re| {
            re.captures_iter(text)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn mentions_related(item: &str, id: &str) -> bool {
    item.split("Related:").skip(1).any(|t| {
        t.split("Origin:")
            .next()
            .unwrap_or(t)
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .any(|w| w == id)
    })
}

/// Pairs of open rows that describe the same defect.
pub fn duplicate_defects(prefix: &str, active: File<'_>) -> Vec<Violation> {
    let rows: Vec<Row> = id_rows(active.content)
        .into_iter()
        .filter(|r| r.prefix == prefix && r.cells.len() > 2)
        .collect();
    // Per row, computed once: slug, declared duplicates and defect sites.
    let facts: Vec<(Option<String>, Vec<String>, BTreeSet<String>)> = rows
        .iter()
        .map(|r| {
            let text = evidence(&r.cells[1]);
            let mut sites = file_lines(text);
            if let Some(reference) = r.cells.get(2) {
                sites.extend(file_lines(reference));
            }
            (slug(&r.cells[1]), declared_duplicates(text), sites)
        })
        .collect();
    let mut found = Vec::new();
    let mut report = |severity, row: &Row, message: String| {
        found.push(violation(
            DUPLICATE_ID,
            "Duplicate Backlog Defect",
            severity,
            active.display,
            row.line,
            &row.id,
            message,
            "Keep one row (the older id), fold the other's evidence into it and archive the duplicate; or record `Related: <id>` when both are real.",
        ));
    };
    for (i, a) in rows.iter().enumerate() {
        for (j, b) in rows.iter().enumerate().skip(i + 1) {
            let (ia, ib) = (&a.cells[1], &b.cells[1]);
            let (sa, sb) = (&facts[i].0, &facts[j].0);
            let pair = format!("{} (line {}) and {} (line {})", a.id, a.line, b.id, b.line);
            if let (Some(x), Some(y)) = (sa, sb) {
                if x == y {
                    report(
                        Severity::Error,
                        b,
                        format!("Open rows {pair} carry the same slug '{x}'."),
                    );
                    continue;
                }
            }
            if facts[i].1.contains(&b.id) || facts[j].1.contains(&a.id) {
                report(
                    Severity::Error,
                    b,
                    format!("Open rows {pair}: one cites the other as its duplicate."),
                );
                continue;
            }
            if mentions_related(ia, &b.id) || mentions_related(ib, &a.id) {
                continue;
            }
            if let (Some(x), Some(y)) = (sa, sb) {
                if slug_extends(x, y) || slug_extends(y, x) {
                    report(
                        Severity::Warning,
                        b,
                        format!("Open rows {pair} have overlapping slugs '{x}' and '{y}'."),
                    );
                    continue;
                }
            }
            if let Some(shared) = facts[i].2.intersection(&facts[j].2).next() {
                report(
                    Severity::Warning,
                    b,
                    format!("Open rows {pair} cite the same defect site '{shared}'."),
                );
            }
        }
    }
    found
}

// ── GB-209 ──────────────────────────────────────────────────────────────────

/// Measurements a fold must not lose: commit shas, `rc=` values, `file:line` and counts.
fn measurements(text: &str) -> BTreeSet<String> {
    let mut out = file_lines(text);
    let patterns = [r"\brc=\d+", r"\b[0-9a-f]{7,40}\b"];
    for (i, p) in patterns.iter().enumerate() {
        let Ok(re) = Regex::new(p) else { continue };
        for m in re.find_iter(text) {
            let t = m.as_str();
            let sha_shaped =
                t.chars().any(|c| c.is_ascii_digit()) && t.chars().any(|c| c.is_ascii_alphabetic());
            if i == 0 || sha_shaped {
                out.insert(t.to_string());
            }
        }
    }
    // A count is a free-standing integer of three digits or more; dates, versions, ids, line
    // numbers and years are not counts.
    for word in text.split(|c: char| c.is_whitespace() || "()[]{},;\"'`*".contains(c)) {
        let word = word.trim_end_matches(['.', ':', '!', '?']);
        let year = word.len() == 4 && (word.starts_with("19") || word.starts_with("20"));
        if word.len() >= 3 && !year && word.chars().all(|c| c.is_ascii_digit()) {
            out.insert(word.to_string());
        }
    }
    out
}

fn contains_token(haystack: &str, token: &str) -> bool {
    haystack.match_indices(token).any(|(i, _)| {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + token.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_alphanumeric())
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

/// Archived duplicates whose measurements are missing from the open surviving row.
pub fn fold_lossless(prefix: &str, active: File<'_>, archive: File<'_>) -> Vec<Violation> {
    let survivors: BTreeMap<String, String> = id_rows(active.content)
        .into_iter()
        .map(|r| (r.id.clone(), r.cells.join(" ")))
        .collect();
    let mut found = Vec::new();
    for r in id_rows(archive.content) {
        if r.prefix != prefix || r.cells.len() < 2 {
            continue;
        }
        let item = &r.cells[1];
        for survivor in declared_duplicates(item) {
            let Some(kept) = survivors.get(&survivor) else {
                continue;
            };
            let missing: Vec<String> = measurements(item)
                .into_iter()
                .filter(|t| !contains_token(kept, t))
                .collect();
            if !missing.is_empty() {
                found.push(violation(
                    FOLD_ID,
                    "Lossy Duplicate Fold",
                    Severity::Error,
                    archive.display,
                    r.line,
                    &r.id,
                    format!(
                        "{} was archived as a duplicate of {survivor}, but {survivor} lacks: {}.",
                        r.id,
                        missing.join(", ")
                    ),
                    "Copy the missing measurement(s) into the surviving row.",
                ));
            }
        }
    }
    found
}

// ── GB-008 ──────────────────────────────────────────────────────────────────

/// Ids of other queues cited by this queue's items that exist in neither of that queue's files.
/// A queue absent from the audited tree is not checked, and an archived id is a valid target.
pub(super) fn cross_refs(repo_root: &Path, q: &Queue, files: &[File<'_>]) -> Vec<Violation> {
    let mut found = Vec::new();
    for other in registry().into_iter().filter(|o| o.prefix != q.prefix) {
        let Some(dir) = resolve_queue_dir(repo_root, &other) else {
            continue;
        };
        let Ok(active) = fs::read_to_string(dir.join(BACKLOG_REL)) else {
            continue;
        };
        let archive = fs::read_to_string(dir.join(ARCHIVE_REL)).unwrap_or_default();
        let known: BTreeSet<u32> = id_numbers(&active, &other.prefix)
            .into_iter()
            .chain(id_numbers(&archive, &other.prefix))
            .collect();
        let Ok(re) = Regex::new(&format!(r"\b{}(\d{{3,}})\b", regex::escape(&other.prefix))) else {
            continue;
        };
        let mut reported = BTreeSet::new();
        for file in files {
            for r in id_rows(file.content) {
                let Some(item) = r.cells.get(1) else { continue };
                for c in re.captures_iter(item) {
                    let missing = c[1].parse::<u32>().is_ok_and(|n| !known.contains(&n));
                    let target = c[0].to_string();
                    if missing && reported.insert(target.clone()) {
                        found.push(violation(
                            CROSS_ID,
                            "Broken Cross-Queue Reference",
                            Severity::Warning,
                            file.display,
                            r.line,
                            &r.id,
                            format!(
                                "{} cites {target}, which is in neither the {} queue nor its archive.",
                                r.id, other.name
                            ),
                            "Fix the id, or restore the missing row in that queue's archive.",
                        ));
                    }
                }
            }
        }
    }
    found
}

/// Every check of this module for one queue.
pub(super) fn audit(
    repo_root: &Path,
    q: &Queue,
    active: File<'_>,
    archive: File<'_>,
) -> Vec<Violation> {
    let mut found = table_integrity(active, Severity::Error);
    found.extend(table_integrity(archive, Severity::Warning));
    found.extend(duplicate_ids(&q.prefix, active, archive));
    found.extend(foreign_rows(&q.prefix, active));
    found.extend(foreign_rows(&q.prefix, archive));
    found.extend(contiguity(&q.prefix, active, archive));
    found.extend(duplicate_defects(&q.prefix, active));
    found.extend(fold_lossless(&q.prefix, active, archive));
    found.extend(cross_refs(repo_root, q, &[active, archive]));
    found
}
