//! `stenio secret-dumps --root DIR` (GB-226): secrets written to scratch space. A file named after
//! a secret key (`e_POSTGRES_PASSWORD.txt`) or carrying a credential fails the check. The report has
//! Without `--root` the agent harness scratch roots are scanned (GB-189: environment snapshots
//! serialised by the harness). The report has
//! paths, line numbers and key names; never a value. To compare two env files use
//! `stenio secrets-drift` (names only on the right-hand side), never per-key dump files.

use clap::Parser;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

const MAX_BYTES: u64 = 4 * 1_048_576;
const NAME_MARKS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTHKEY",
    "DATABASE_URL",
    "SMTP_PASS",
];
const DUMP_EXTENSIONS: &[&str] = &[
    "", "txt", "env", "val", "value", "secret", "key", "tmp", "out",
];

#[derive(Parser, Debug)]
#[command(about = "Fail when scratch directories hold secrets (paths and key names only)")]
struct Args {
    #[arg(
        long,
        help = "Directory to scan (repeatable); default: the harness scratch roots under $HOME"
    )]
    root: Vec<PathBuf>,
    #[arg(
        long,
        help = "Path prefix that is allowed to hold secrets (repeatable)"
    )]
    allow: Vec<PathBuf>,
}

/// A dump named after a key: an upper-case secret key name and a data extension.
fn named_like_a_key(path: &Path) -> bool {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    DUMP_EXTENSIONS.contains(&ext) && NAME_MARKS.iter().any(|m| stem.contains(m))
}

/// `(files read, findings)` for every file under `roots`.
fn scan(roots: &[PathBuf], allow: &[PathBuf]) -> (usize, Vec<String>) {
    let mut seen = 0usize;
    let mut out = Vec::new();
    for root in roots {
        let mut walker = WalkBuilder::new(root);
        walker.standard_filters(false);
        for entry in walker.build().flatten() {
            let path = entry.path();
            let regular = entry.file_type().is_some_and(|t| t.is_file());
            if !regular
                || allow.iter().any(|a| path.starts_with(a))
                || path.components().any(|c| c.as_os_str() == ".git")
            {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.len() == 0 || meta.len() > MAX_BYTES {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            seen += 1;
            if crate::guardian::has_sops_dotenv_markers(&content) {
                continue;
            }
            let shown = path.display();
            if named_like_a_key(path) {
                out.push(format!(
                    "FAIL SEC-SECRET-WRITTEN-TO-DISK {shown}: file named after a secret key"
                ));
            }
            for v in crate::infra::plaintext_secret_violations("scratch", &content, false) {
                let key = content
                    .lines()
                    .nth(v.line_number.saturating_sub(1))
                    .and_then(super::store::assignment)
                    .map_or("token shape", |(k, _)| k);
                out.push(format!(
                    "FAIL SEC-SECRET-WRITTEN-TO-DISK {shown}:{} {key}",
                    v.line_number
                ));
            }
        }
    }
    out.sort();
    (seen, out)
}

/// Where agent harnesses write snapshots, transcripts and scratch files.
const HARNESS_ROOTS: &[&str] = &[".hermes/cache", ".hermes/tmp", ".hermes/logs"];

fn harness_roots(home: &Path) -> Vec<PathBuf> {
    HARNESS_ROOTS
        .iter()
        .map(|r| home.join(r))
        .filter(|p| p.is_dir())
        .collect()
}

pub fn run_cli(argv: &[String]) -> i32 {
    let args = match Args::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let mut roots = args.root;
    if roots.is_empty()
        && let Some(home) = std::env::var_os("HOME")
    {
        roots = harness_roots(Path::new(&home));
    }
    if roots.is_empty() || roots.iter().any(|r| !r.is_dir()) {
        eprintln!("stenio: secret-dumps found no directory to scan (check --root)");
        return 2;
    }
    let (seen, findings) = scan(&roots, &args.allow);
    for l in &findings {
        println!("{l}");
    }
    let verdict = if findings.is_empty() { "PASS" } else { "FAIL" };
    println!(
        "stenio: {verdict} secret-dumps files={seen} fails={}",
        findings.len()
    );
    i32::from(!findings.is_empty())
}

/// A random-looking fake credential for fixtures.
pub(crate) const FAKE_VALUE: &str = "Qv7mZp2Lx9Rt4Kd8Wn3Bs6Hy";

pub fn self_test_cases() -> Vec<(String, bool)> {
    let run = |tag: &str, files: &[(&str, &str)]| {
        let d = super::fixture(tag, files);
        let (_, f) = scan(std::slice::from_ref(&d), &[]);
        let allowed = scan(std::slice::from_ref(&d), std::slice::from_ref(&d)).1;
        let _ = std::fs::remove_dir_all(&d);
        (f.join("\n"), allowed.len())
    };
    let named = run("dp1", &[("scratch/e_POSTGRES_PASSWORD.txt", "anything\n")]);
    let body = format!("A=1\nDB_PASSWORD={FAKE_VALUE}\n");
    let content = run("dp2", &[("notes.log", &body)]);
    let clean = run(
        "dp3",
        &[
            ("names.txt", "POSTGRES_PASSWORD\nSECRET_KEY\n"),
            ("token_count.rs", "fn x() {}\n"),
            ("e.env", "DB_PASSWORD=${DB_PASSWORD}\n"),
        ],
    );
    let snap =
        format!("export PATH=\"/usr/bin\"\ndeclare -x OPENCODE_GO_API_KEY=\"{FAKE_VALUE}\"\n");
    let home = super::fixture("dp4", &[(".hermes/cache/scratch/hermes-snap-ab.sh", &snap)]);
    let leaked = scan(&harness_roots(&home), &[]).1.join("\n");
    let _ = std::fs::write(
        home.join(".hermes/cache/scratch/hermes-snap-ab.sh"),
        "declare -x OPENCODE_GO_API_KEY=\"[REDACTED]\"\n",
    );
    let redacted = scan(&harness_roots(&home), &[]).1;
    let _ = std::fs::remove_dir_all(&home);
    vec![
        (
            "harness snapshot: mutation, exported sentinel fails with file and line".to_string(),
            leaked.contains("hermes-snap-ab.sh:2 OPENCODE_GO_API_KEY")
                && !leaked.contains(FAKE_VALUE),
        ),
        (
            "harness snapshot: redaction marker passes".to_string(),
            redacted.is_empty(),
        ),
        (
            "secret dumps: mutation, key-named file fails naming it".to_string(),
            named
                .0
                .contains("e_POSTGRES_PASSWORD.txt: file named after"),
        ),
        (
            "secret dumps: mutation, content hit names line and key, not value".to_string(),
            content.0.contains("notes.log:2 DB_PASSWORD") && !content.0.contains(FAKE_VALUE),
        ),
        (
            "secret dumps: names-only comparison stays green".to_string(),
            clean.0.is_empty(),
        ),
        (
            "secret dumps: allowed prefix is skipped".to_string(),
            named.1 == 0,
        ),
    ]
}
