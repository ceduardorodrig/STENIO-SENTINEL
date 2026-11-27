//! `OPS-STATIC-PARITY` build age (GB-238): a local bundle older than its own sources proves
//! nothing when compared with production.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{case, opt, unreadable, verdict, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "OPS-STATIC-PARITY-BUILD-AGE";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Local Frontend Build Predates Its Sources",
    severity: "WARNING",
    tag: "infra",
    summary: "Next to OPS-STATIC-PARITY (and as `stenio hostops build-age --dir app/frontend-v2`): fails when dist/index.html is older than the newest file under src/ that git does not ignore, naming both times.",
    rationale: "GB-238: production served the bundle of 2026-10-31 02:50 while the local dist (10-31 14:28) already predated a src commit of 11-06; name comparison alone would have blessed deploying the old build.",
    bad_example: "dist/index.html 10-31, src/App.tsx 11-06",
    good_example: "npm run build after the last source change",
    remediation: "Rebuild before comparing or deploying.",
};

fn utc(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t)
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

/// The finding text when the build is older than a source file.
pub fn stale(fe_dir: &Path) -> Option<String> {
    let dist = std::fs::metadata(fe_dir.join("dist/index.html"))
        .and_then(|m| m.modified())
        .ok()?;
    let newest = ignore::WalkBuilder::new(fe_dir.join("src"))
        .require_git(false)
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.into_path())))
        .max()?;
    (newest.0 > dist).then(|| {
        format!(
            "local build is stale: dist/index.html built {}, newest source {} modified {}",
            utc(dist),
            newest.1.display(),
            utc(newest.0)
        )
    })
}

/// Violation for the infrastructure audit.
pub fn stale_build_violation(fe_dir: &Path) -> Option<Violation> {
    stale(fe_dir).map(|m| {
        violation(
            RULE_ID,
            Severity::Warning,
            &fe_dir.join("dist/index.html").to_string_lossy(),
            1,
            "dist/index.html",
            m,
            "Run the frontend build before comparing with or deploying to production.",
        )
    })
}

pub fn run_cli(args: &[String]) -> i32 {
    let dir = opt(args, "--dir").unwrap_or_else(|| "app/frontend-v2".to_string());
    let dir = Path::new(&dir);
    if !dir.join("dist/index.html").is_file() || !dir.join("src").is_dir() {
        return unreadable(RULE_ID, "needs dist/index.html and src/ under --dir");
    }
    let found: Vec<String> = stale(dir).into_iter().collect();
    verdict(RULE_ID, &dir.to_string_lossy(), 1, &found)
}

/// Temporary tree with the given source and build ages (seconds after the epoch).
fn tree(tag: &str, source: u64, build: u64) -> Option<bool> {
    let root = crate::frappe::write_fixture(
        tag,
        &[
            ("src/app.ts".to_string(), "x\n".to_string()),
            ("dist/index.html".to_string(), "x\n".to_string()),
        ],
    )?;
    for (file, secs) in [("src/app.ts", source), ("dist/index.html", build)] {
        std::fs::File::options()
            .write(true)
            .open(root.join(file))
            .and_then(|f| f.set_modified(UNIX_EPOCH + Duration::from_secs(secs)))
            .ok()?;
    }
    let found = stale(&root).is_some();
    let _ = std::fs::remove_dir_all(&root);
    Some(found)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    vec![
        case(
            "build-age: source newer than dist fires",
            tree("buildage-old", 2_000, 1_000) == Some(true),
        ),
        case(
            "build-age: fresh build is clean",
            tree("buildage-new", 1_000, 2_000) == Some(false),
        ),
    ]
}
