//! Stenio opportunities (backlog-method.md section 9): `STENIO-ITEM-FORMAT` and
//! `stenio opportunity add`, the one command every agent uses to log a missing rule.
//!
//! The command allocates the next `GB-` id, inserts one correctly formatted row after the last
//! `GB-` row of `governance/backlog.md` (read, insert one line, write; refused when the file
//! changed in between; a `.bak-<timestamp>` copy is kept and the previous one deleted), adds the
//! id to the `pending:` list of the referenced document and runs the backlog audit.

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

fn clean(s: &str) -> String {
    s.replace(['|', '\n', '\r'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_string()
}

fn vault_root(given: Option<&Path>) -> PathBuf {
    if let Some(p) = given {
        return p.to_path_buf();
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    cwd.ancestors()
        .find(|a| a.join(BACKLOG_REL).is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT))
}

fn build_row(id: &str, a: &AddArgs) -> String {
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

fn timestamp() -> String {
    chrono::Local::now().format("%Y%m%dT%H%M%S").to_string()
}

/// Writes `new` over `path` only when the file still equals `original`; keeps one `.bak-*`.
fn guarded_write(path: &Path, original: &str, new: &str, backup: bool) -> Result<PathBuf, String> {
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
    let bak = dir.join(format!("{name}.bak-{}", timestamp()));
    if backup {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                if e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{name}.bak-"))
                {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        fs::write(&bak, original).map_err(|e| format!("cannot write backup: {e}"))?;
    }
    let tmp = dir.join(format!(".{name}.tmp"));
    fs::write(&tmp, new).map_err(|e| format!("cannot write: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot replace: {e}"))?;
    Ok(bak)
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match AddArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    for (name, v) in [
        ("title", &a.title),
        ("evidence", &a.evidence),
        ("desired", &a.desired),
        ("acceptance", &a.acceptance),
    ] {
        if clean(v).is_empty() {
            eprintln!("--{name} must not be empty");
            return 2;
        }
    }
    let root = vault_root(a.path.as_deref());
    let id = match backlog::next_id(&root, "GB") {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let row = build_row(&id, &a);
    if a.dry_run {
        println!("{id}\n{row}");
        return 0;
    }
    let bpath = root.join(BACKLOG_REL);
    let original = match fs::read_to_string(&bpath) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {e}", bpath.display());
            return 1;
        }
    };
    let Some(new) = insert_row(&original, &row) else {
        eprintln!("no GB row found in {}; nothing written", bpath.display());
        return 1;
    };
    match guarded_write(&bpath, &original, &new, true) {
        Ok(bak) => println!(
            "row written to {} (backup {})",
            bpath.display(),
            bak.display()
        ),
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    }
    let dpath = root.join(&a.doc);
    match fs::read_to_string(&dpath)
        .ok()
        .and_then(|d| backlog::add_pending(&d, &id).map(|n| (d, n)))
    {
        Some((d, n)) if d == n => println!("pending: {id} already in {}", a.doc),
        Some((d, n)) => match guarded_write(&dpath, &d, &n, false) {
            Ok(_) => println!("pending: [{id}] added to {}", a.doc),
            Err(e) => eprintln!("manual: add {id} to pending: of {} ({e})", a.doc),
        },
        None => eprintln!("manual: add {id} to the pending: list of {}", a.doc),
    }
    let audit = backlog::audit_backlog(&root);
    let mine: Vec<_> = audit
        .violations
        .iter()
        .filter(|v| v.snippet == id)
        .collect();
    println!("{id}");
    println!(
        "audit: {} violation(s) in the GB/HB queues, {} about {id}",
        audit.violations.len(),
        mine.len()
    );
    for v in &mine {
        println!("  {} {}", v.rule_id, v.message);
    }
    i32::from(mine.iter().any(|v| v.severity == Severity::Error))
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let args = |t: &str| AddArgs {
        title: t.into(),
        evidence: "seen.".into(),
        desired: "do it".into(),
        acceptance: "fixture".into(),
        origin: "Claude, Code".into(),
        priority: "🟠".into(),
        doc: DEFAULT_REF.into(),
        path: None,
        dry_run: true,
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
