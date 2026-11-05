//! Stenio opportunities (backlog-method.md section 9): `STENIO-ITEM-FORMAT` and
//! `stenio opportunity add`, the one command every agent uses to log a missing rule.
//!
//! The command allocates the next `GB-` id, refuses a title that is already open, and inserts one
//! correctly formatted row after the last `GB-` row of `governance/backlog.md` (read, insert one
//! line, guarded write; refused when the file changed in between; no `.bak`), adds the id to the
//! `pending:` list of the referenced document and runs the backlog audit.

use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

use crate::backlog;
use crate::engine::Violation;
use crate::rule::Severity;

pub const FORMAT_RULE_ID: &str = "STENIO-ITEM-FORMAT";
const FIELDS: [&str; 5] = [
    "Evidence:",
    "Desired behaviour:",
    "Acceptance:",
    "Origin:",
    "Status:",
];
const BACKLOG_REL: &str = "governance/backlog.md";
const DEFAULT_REF: &str = "governance/stenio-troubleshooting.md";
const DEFAULT_VAULT: &str = "/mnt/NVME_PCI/agentic-ai";

/// `STENIO-ITEM-FORMAT`: a row titled `Stenio: ...` must carry the five mandatory fields.
pub fn check_format(display: &str, row: &str, id: &str, line: usize) -> Vec<Violation> {
    let title = row
        .split('|')
        .nth(2)
        .unwrap_or("")
        .trim()
        .trim_start_matches('*')
        .trim_start();
    if !title.starts_with("Stenio:") {
        return Vec::new();
    }
    let missing: Vec<&str> = FIELDS
        .iter()
        .copied()
        .filter(|f| !row.contains(f))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }
    vec![Violation {
        rule_id: FORMAT_RULE_ID.to_string(),
        rule_name: "Stenio Backlog Item Format".to_string(),
        severity: Severity::Error,
        file_path: display.to_string(),
        line_number: line,
        snippet: id.to_string(),
        message: format!("Stenio item {id} lacks the field(s): {}.", missing.join(" ")),
        suggestion: Some(
            "Use `stenio opportunity add` or add Evidence:, Desired behaviour:, Acceptance:, Origin: and Status: to the row (backlog-method.md section 9).".to_string(),
        ),
    }]
}

#[derive(Parser, Debug)]
#[command(
    name = "stenio opportunity add",
    about = "Log a Stenio opportunity as a formatted GB backlog row"
)]
struct AddArgs {
    #[arg(long, help = "RULE-ID or subcommand (the `Stenio: ` prefix is added)")]
    title: String,
    #[arg(long)]
    evidence: String,
    #[arg(long)]
    desired: String,
    #[arg(long)]
    acceptance: String,
    #[arg(long, default_value = "unspecified agent")]
    origin: String,
    #[arg(long, default_value = "🟡")]
    priority: String,
    #[arg(long = "ref", default_value = DEFAULT_REF, help = "Vault-relative document that gets `pending: [id]`")]
    doc: String,
    #[arg(
        long,
        help = "Vault root (default: the vault found from the cwd, else the standard one)"
    )]
    path: Option<PathBuf>,
    #[arg(long)]
    dry_run: bool,
}

/// Input of [`add`], independent from the clap surface so tests can drive the writer.
#[derive(Clone, Debug)]
pub struct AddRequest {
    pub title: String,
    pub evidence: String,
    pub desired: String,
    pub acceptance: String,
    pub origin: String,
    pub priority: String,
    /// Vault-relative document that receives `pending: [id]`.
    pub doc: String,
}

/// State of the `pending:` link after [`add`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pending {
    Added,
    AlreadyPresent,
    /// The document is missing, has no frontmatter or uses a block list.
    Manual,
}

/// What [`add`] wrote (or would write, under `dry_run`).
#[derive(Clone, Debug)]
pub struct Added {
    pub id: String,
    pub row: String,
    pub pending: Pending,
}

fn clean(s: &str) -> String {
    s.replace(['|', '\n', '\r'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_string()
}

pub(crate) fn vault_root(given: Option<&Path>) -> PathBuf {
    if let Some(p) = given {
        return p.to_path_buf();
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    cwd.ancestors()
        .find(|a| a.join(BACKLOG_REL).is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT))
}

fn build_row(id: &str, a: &AddRequest) -> String {
    let title = clean(&a.title);
    let title = title
        .strip_prefix("Stenio:")
        .map_or(title.clone(), |t| t.trim().to_string());
    let origin = clean(&a.origin);
    let name = a.doc.rsplit('/').next().unwrap_or(&a.doc);
    format!(
        "| **{id}** | **Stenio: {title}.** Evidence: {}. Desired behaviour: {}. Acceptance: {}. Origin: {origin}. Status: open. | [`{name}`]({name}) | {} | open | {origin} | — |",
        clean(&a.evidence),
        clean(&a.desired),
        clean(&a.acceptance),
        clean(&a.priority),
    )
}

/// Inserts `row` after the last `GB-` table row; None when there is no such row.
fn insert_row(content: &str, row: &str) -> Option<String> {
    let lines: Vec<&str> = content.split('\n').collect();
    let last = lines
        .iter()
        .rposition(|l| l.starts_with("| **GB-") || l.starts_with("| GB-"))?;
    let mut out: Vec<&str> = lines[..=last].to_vec();
    out.push(row);
    out.extend_from_slice(&lines[last + 1..]);
    Some(out.join("\n"))
}

/// Title of a `GB` row: the text between `**Stenio: ` and the closing `.**`.
fn row_title(row: &str) -> Option<&str> {
    let cell = row.split('|').nth(2)?.trim();
    let rest = cell.strip_prefix("**Stenio:")?.trim_start();
    Some(rest.split(".**").next().unwrap_or(rest).trim())
}

/// Comparison key: the `Stenio:` prefix and the trailing period are formatting, not identity.
fn title_key(title: &str) -> String {
    clean(title)
        .strip_prefix("Stenio:")
        .map_or_else(|| clean(title), |t| t.trim().to_string())
        .to_lowercase()
}

/// Id of the active row already carrying this title. The archive is not consulted on purpose:
/// an archived problem that comes back is a *new* item linked with `Recurrence:` (§4).
fn find_duplicate(content: &str, title: &str) -> Option<String> {
    let wanted = title_key(title);
    content.lines().find_map(|line| {
        if !line.starts_with("| **GB-") {
            return None;
        }
        if title_key(row_title(line)?) != wanted {
            return None;
        }
        line.split('|')
            .nth(1)
            .map(|c| c.trim().trim_matches('*').to_string())
    })
}

fn validate(req: &AddRequest) -> Result<(), String> {
    for (name, v) in [
        ("title", &req.title),
        ("evidence", &req.evidence),
        ("desired", &req.desired),
        ("acceptance", &req.acceptance),
    ] {
        if clean(v).is_empty() {
            return Err(format!("--{name} must not be empty"));
        }
    }
    Ok(())
}

/// The single writer behind `stenio opportunity add`: allocates the next `GB-` id with the same
/// allocator as `--next-id`, refuses a title already open, inserts one row after the last `GB-`
/// row (read → insert → guarded write, so the rest of the file is byte-identical) and links the
/// id into the `pending:` frontmatter of `req.doc`.
pub fn add(root: &Path, req: &AddRequest, dry_run: bool) -> Result<Added, String> {
    validate(req)?;
    let id = backlog::next_id(root, "GB")?;
    let bpath = root.join(BACKLOG_REL);
    let original =
        fs::read_to_string(&bpath).map_err(|e| format!("cannot read {}: {e}", bpath.display()))?;
    if let Some(existing) = find_duplicate(&original, &req.title) {
        return Err(format!(
            "duplicate: {existing} already has the title \"{}\"; nothing written",
            clean(&req.title)
        ));
    }
    let row = build_row(&id, req);
    if dry_run {
        return Ok(Added {
            id,
            row,
            pending: Pending::Manual,
        });
    }
    let new = insert_row(&original, &row)
        .ok_or_else(|| format!("no GB row found in {}; nothing written", bpath.display()))?;
    guarded_write(&bpath, &original, &new)?;

    let dpath = root.join(&req.doc);
    let pending = match fs::read_to_string(&dpath)
        .ok()
        .and_then(|d| backlog::add_pending(&d, &id).map(|n| (d, n)))
    {
        Some((d, n)) if d == n => Pending::AlreadyPresent,
        Some((d, n)) => match guarded_write(&dpath, &d, &n) {
            Ok(()) => Pending::Added,
            Err(_) => Pending::Manual,
        },
        None => Pending::Manual,
    };
    Ok(Added { id, row, pending })
}

/// Writes `new` over `path` only when the file still equals `original`, through a sibling temp
/// file and a rename. No `.bak`: the other backlog writers keep none, and the vault is
/// Syncthing-synced, where a per-run backup would replicate itself to every device.
fn guarded_write(path: &Path, original: &str, new: &str) -> Result<(), String> {
    let now =
        fs::read_to_string(path).map_err(|e| format!("cannot re-read {}: {e}", path.display()))?;
    if now != original {
        return Err(format!(
            "{} changed while the row was prepared; nothing written, retry",
            path.display()
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("backlog.md");
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".{name}.tmp"));
    fs::write(&tmp, new).map_err(|e| format!("cannot write: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace: {e}"))?;
    Ok(())
}

impl AddArgs {
    fn request(&self) -> AddRequest {
        AddRequest {
            title: self.title.clone(),
            evidence: self.evidence.clone(),
            desired: self.desired.clone(),
            acceptance: self.acceptance.clone(),
            origin: self.origin.clone(),
            priority: self.priority.clone(),
            doc: self.doc.clone(),
        }
    }
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match AddArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            // `--help`/`--version` are a successful cycle, not a usage error.
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
                _ => 2,
            };
        }
    };
    let root = vault_root(a.path.as_deref());
    let req = a.request();
    let done = match add(&root, &req, a.dry_run) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if a.dry_run {
        println!("{}\n{}", done.id, done.row);
        return 0;
    }
    let bpath = root.join(BACKLOG_REL);
    println!("row written to {}", bpath.display());
    match done.pending {
        Pending::Added => println!("pending: [{}] added to {}", done.id, req.doc),
        Pending::AlreadyPresent => println!("pending: {} already in {}", done.id, req.doc),
        Pending::Manual => eprintln!(
            "manual: add {} to the pending: list of {}",
            done.id, req.doc
        ),
    }
    let audit = backlog::audit_backlog(&root);
    let mine: Vec<_> = audit
        .violations
        .iter()
        .filter(|v| v.snippet == done.id)
        .collect();
    println!("{}", done.id);
    println!(
        "audit: {} violation(s) in the GB/HB queues, {} about {}",
        audit.violations.len(),
        mine.len(),
        done.id
    );
    for v in &mine {
        println!("  {} {}", v.rule_id, v.message);
    }
    i32::from(mine.iter().any(|v| v.severity == Severity::Error))
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let args = |t: &str| AddRequest {
        title: t.into(),
        evidence: "seen.".into(),
        desired: "do it".into(),
        acceptance: "fixture".into(),
        origin: "Claude, Code".into(),
        priority: "🟠".into(),
        doc: DEFAULT_REF.into(),
    };
    let row = build_row("GB-099", &args("Stenio: X-RULE"));
    let broken = row.replace("Acceptance:", "Accept:");
    let table = "| ID |\n| **GB-001** | a |\n| **GB-002** | b |\n\ntext\n";
    vec![
        (
            "item format accepts a built row".to_string(),
            check_format("b.md", &row, "GB-099", 3).is_empty() && !row.contains("Stenio: Stenio:"),
        ),
        (
            "item format rejects a missing field".to_string(),
            check_format("b.md", &broken, "GB-099", 3).len() == 1
                && check_format("b.md", "| **GB-1** | **Other.** | x |", "GB-1", 1).is_empty(),
        ),
        (
            "opportunity row inserted after last GB row".to_string(),
            insert_row(table, "| NEW |").as_deref()
                == Some("| ID |\n| **GB-001** | a |\n| **GB-002** | b |\n| NEW |\n\ntext\n")
                && insert_row("no rows", "x").is_none(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEQ: AtomicUsize = AtomicUsize::new(0);

    /// A throwaway vault tree; the directory is removed when the guard drops.
    struct Vault(PathBuf);

    impl Drop for Vault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const BACKLOG: &str = "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
|---|---|---|---|---|---|---|\n\
| **GB-002** | **Stenio: OLD-RULE.** Evidence: x. Desired behaviour: y. Acceptance: z. Origin: a. Status: open. | [`area.md`](area.md) | 🟡 | open | a | — |\n\
| **GB-009** | plain item | [`area.md`](area.md) | 🟠 | open | a | — |\n\
\nFooter kept.\n";

    fn vault(label: &str) -> Vault {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "stenio-opportunity-{}-{label}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        assert!(fs::create_dir_all(root.join("governance")).is_ok());
        Vault(root)
    }

    fn seed(v: &Vault, archive: &str) -> bool {
        fs::write(v.0.join("governance/backlog.md"), BACKLOG).is_ok()
            && fs::write(v.0.join("governance/backlog-archive.md"), archive).is_ok()
            && fs::write(
                v.0.join("governance/area.md"),
                "---\ntags: [gov]\npending: [GB-002]\n---\n# Area\n",
            )
            .is_ok()
    }

    fn request(title: &str) -> AddRequest {
        AddRequest {
            title: title.to_string(),
            evidence: "seen".to_string(),
            desired: "do it".to_string(),
            acceptance: "fixture".to_string(),
            origin: "test, harness".to_string(),
            priority: "🟡".to_string(),
            doc: "governance/area.md".to_string(),
        }
    }

    #[test]
    fn add_allocates_after_the_archive_and_preserves_the_file() {
        let v = vault("insert");
        assert!(seed(&v, "| **GB-040** | archived |\n"));
        let Ok(done) = add(&v.0, &request("NEW-RULE"), false) else {
            panic!("add failed");
        };
        assert_eq!(done.id, "GB-041");
        assert_eq!(done.pending, Pending::Added);
        let after = fs::read_to_string(v.0.join("governance/backlog.md")).unwrap_or_default();
        assert_eq!(after.lines().count(), BACKLOG.lines().count() + 1);
        assert_eq!(after.replacen(&format!("{}\n", done.row), "", 1), BACKLOG);
        assert!(after.contains("**Stenio: NEW-RULE.** Evidence: seen"));
        let doc = fs::read_to_string(v.0.join("governance/area.md")).unwrap_or_default();
        assert!(doc.contains("pending: [GB-002, GB-041]"));
        assert!(
            !fs::read_dir(v.0.join("governance"))
                .map(|d| d
                    .flatten()
                    .any(|e| e.file_name().to_string_lossy().contains(".bak")))
                .unwrap_or(true),
            "the writer must not leave a .bak in the synced vault"
        );
    }

    #[test]
    fn add_refuses_a_title_already_open() {
        let v = vault("dup");
        assert!(seed(&v, "| **GB-040** | archived |\n"));
        let Err(err) = add(&v.0, &request("Stenio: old-rule"), false) else {
            panic!("duplicate title accepted");
        };
        assert!(err.contains("duplicate") && err.contains("GB-002"), "{err}");
        let after = fs::read_to_string(v.0.join("governance/backlog.md")).unwrap_or_default();
        assert_eq!(after, BACKLOG);
    }

    #[test]
    fn dry_run_reports_the_row_and_writes_nothing() {
        let v = vault("dry");
        assert!(seed(&v, "| **GB-040** | archived |\n"));
        let before_backlog = fs::read(v.0.join("governance/backlog.md")).unwrap_or_default();
        let before_doc = fs::read(v.0.join("governance/area.md")).unwrap_or_default();
        let before_entries = fs::read_dir(v.0.join("governance"))
            .map(|d| d.count())
            .unwrap_or(0);
        let Ok(done) = add(&v.0, &request("DRY-RULE"), true) else {
            panic!("dry run failed");
        };
        assert_eq!(done.id, "GB-041");
        assert!(done.row.contains("**Stenio: DRY-RULE.**"));
        assert_eq!(
            fs::read(v.0.join("governance/backlog.md")).unwrap_or_default(),
            before_backlog
        );
        assert_eq!(
            fs::read(v.0.join("governance/area.md")).unwrap_or_default(),
            before_doc
        );
        assert_eq!(
            fs::read_dir(v.0.join("governance"))
                .map(|d| d.count())
                .unwrap_or(0),
            before_entries,
            "dry run must not create a backup or temp file"
        );
    }

    #[test]
    fn add_refuses_a_backlog_without_gb_rows() {
        let v = vault("empty");
        assert!(fs::create_dir_all(v.0.join("governance")).is_ok());
        assert!(
            fs::write(
                v.0.join("governance/backlog.md"),
                "| ID | Item |\n|---|---|\n"
            )
            .is_ok()
        );
        let Err(err) = add(&v.0, &request("NO-ROW"), false) else {
            panic!("write without a GB row accepted");
        };
        assert!(err.contains("no GB row"), "{err}");
    }
}
