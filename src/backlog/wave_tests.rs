//! Mutation proofs: every check is silent on the clean fixture and fires on the broken copy.

use std::fs;
use std::path::{Path, PathBuf};

use super::close::{CloseItem, apply, parse_batch, plan};
use super::integrity;
use super::{audit_backlog, audit_product_queues, fix_drift, next_id_in, remove_pending};
use crate::engine::Violation;
use crate::rule::Severity;

const HEAD: &str =
    "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n|---|---|---|---|---|---|---|\n";
const AHEAD: &str =
    "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n|---|---|---|---|---|---|---|\n";

fn row(id: &str, item: &str, sev: &str) -> String {
    format!("| **{id}** | {item} | [d](doc.md) | {sev} | open | 2026-11-01 | — |\n")
}

fn done(id: &str, item: &str, sev: &str) -> String {
    format!("| **{id}** | {item} | [d](doc.md) | {sev} | resolved | 2026-11-02 | — |\n")
}

/// A vault with a governance and a miracena queue.
struct Vault(PathBuf);

impl Vault {
    fn new(name: &str, active: &str, archive: &str, pending: &str) -> Vault {
        let root = std::env::temp_dir().join(format!("stenio-bl-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let v = Vault(root);
        v.queue(active);
        v.archive(archive);
        v.write(
            "governance/doc.md",
            &format!("---\ntags: [a]\npending: [{pending}]\n---\nbody\n"),
        );
        let mb = format!("{HEAD}{}", row("MB-004", "m", "🟡"));
        v.write("clients/miracena/backlog.md", &mb);
        v.write("clients/miracena/backlog-archive.md", AHEAD);
        v.write("clients/miracena/doc.md", "body\n");
        v
    }

    fn write(&self, rel: &str, text: &str) {
        let p = self.0.join(rel);
        if let Some(parent) = p.parent() {
            assert!(fs::create_dir_all(parent).is_ok());
        }
        assert!(fs::write(p, text).is_ok());
    }

    fn queue(&self, rows: &str) {
        self.write("governance/backlog.md", &format!("{HEAD}{rows}"));
    }

    fn archive(&self, rows: &str) {
        self.write("governance/backlog-archive.md", &format!("{AHEAD}{rows}"));
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.0.join(rel)).unwrap_or_default()
    }

    fn findings(&self) -> Vec<Violation> {
        let mut v = audit_backlog(&self.0).violations;
        v.extend(audit_product_queues(&self.0).violations);
        v
    }

    fn of(&self, rule: &str) -> Vec<Violation> {
        self.findings()
            .into_iter()
            .filter(|v| v.rule_id == rule)
            .collect()
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn messages(found: &[Violation]) -> String {
    found
        .iter()
        .map(|f| f.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn clean_fixture_is_silent() {
    let v = Vault::new(
        "clean",
        &row("GB-002", "waits for MB-004", "🟡"),
        &done("GB-001", "x", "🟡"),
        "GB-002",
    );
    let found = v.findings();
    assert!(found.is_empty(), "{}", messages(&found));
}

#[test]
fn gb008_cross_ref_fires_once_per_missing_id_and_accepts_archived() {
    let active = row("GB-002", "waits for MB-999 and MB-999", "🟡")
        + &row("GB-003", "MB-999 again, MB-004 fine", "🟡");
    let v = Vault::new(
        "cross",
        &active,
        &done("GB-001", "x", "🟡"),
        "GB-002, GB-003",
    );
    let found = v.of(integrity::CROSS_ID);
    assert_eq!(found.len(), 1, "{}", messages(&found));
    assert!(found[0].message.contains("MB-999"));
    // The same id archived is a legal target.
    let archived = format!("{AHEAD}{}", done("MB-999", "gone", "🟡"));
    v.write("clients/miracena/backlog-archive.md", &archived);
    assert!(v.of(integrity::CROSS_ID).is_empty());
    // Inert when the other queue is not in the tree.
    v.write("clients/miracena/backlog-archive.md", AHEAD);
    assert!(fs::remove_file(v.root().join("clients/miracena/backlog.md")).is_ok());
    assert!(v.of(integrity::CROSS_ID).is_empty());
}

#[test]
fn gb138_directory_ref_resolves_and_a_missing_one_names_the_path() {
    let dir_row = "| **GB-002** | x | [p/](patrimonio/) | 🟡 | open | 2026-11-01 | — |\n";
    let v = Vault::new("dir", dir_row, "", "");
    v.write("governance/patrimonio/a.md", "a\n");
    let found = v.of(integrity::DRIFT_ID);
    assert!(!messages(&found).contains("does not exist"));
    assert!(fs::remove_dir_all(v.root().join("governance/patrimonio")).is_ok());
    let found = v.of(integrity::DRIFT_ID);
    assert!(messages(&found).contains("tried 'governance/patrimonio"));
}

#[test]
fn gb152_blank_line_and_cell_count_fire() {
    let good = row("GB-001", "a", "🟡") + &row("GB-002", "b \\| c", "🟡");
    let v = Vault::new("table", &good, "", "GB-001, GB-002");
    assert!(v.of(integrity::TABLE_ID).is_empty());
    v.queue(&(row("GB-001", "a", "🟡") + "\n" + &row("GB-002", "b", "🟡")));
    let found = v.of(integrity::TABLE_ID);
    assert_eq!(found.len(), 1);
    assert!(
        found[0].message.contains("interrupted at line 4"),
        "{}",
        found[0].message
    );
    assert_eq!(found[0].line_number, 5);
    assert_eq!(found[0].severity, Severity::Error);
    // `--path <queue>.md` sees it too, and only on queue files.
    let one = integrity::audit_file(&v.root().join("governance/backlog.md"));
    assert_eq!(one.len(), 1);
    assert!(integrity::audit_file(&v.root().join("governance/doc.md")).is_empty());
    // A second detached block names its own interrupting line.
    let twice = row("GB-001", "a", "🟡") + "\n" + &row("GB-002", "b", "🟡");
    v.queue(&(twice + "\n" + &row("GB-003", "c", "🟡")));
    let found = v.of(integrity::TABLE_ID);
    assert_eq!(found.len(), 2);
    assert!(found[1].message.contains("interrupted at line 6"));
    for bad in [
        "| **GB-001** | a | [d](doc.md) | 🟡 | open | x |\n",
        "| **GB-001** | a | b | [d](doc.md) | 🟡 | open | x | — |\n",
    ] {
        v.queue(bad);
        let found = v.of(integrity::TABLE_ID);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("the header has 7"));
    }
}

#[test]
fn gb300_duplicate_id_names_both_lines() {
    let twice = row("GB-001", "a", "🟡") + &row("GB-001", "b", "🟡");
    let v = Vault::new("dupid", &twice, "", "GB-001");
    let found = v.of(integrity::DRIFT_ID);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, Severity::Error);
    assert!(
        found[0]
            .message
            .contains("backlog.md:3 and governance/backlog.md:4"),
        "{}",
        found[0].message
    );
    // Across the queue and its archive.
    v.queue(&row("GB-001", "a", "🟡"));
    assert!(v.of(integrity::DRIFT_ID).is_empty());
    v.archive(&done("GB-001", "a", "🟡"));
    assert!(messages(&v.of(integrity::DRIFT_ID)).contains("backlog-archive.md:3"));
}

#[test]
fn gb251_foreign_row_fires_and_names_its_queue() {
    let v = Vault::new("foreign", &row("GB-002", "a", "🟡"), "", "GB-002");
    assert!(v.of(integrity::FOREIGN_ID).is_empty());
    v.archive(&done("MB-046", "m", "🟡"));
    let found = v.of(integrity::FOREIGN_ID);
    assert_eq!(found.len(), 1);
    assert!(found[0].message.contains("MB-046") && found[0].message.contains("miracena"));
}

#[test]
fn gb215_outlier_fails_and_next_id_ignores_prose() {
    let series: String = (1..=9)
        .map(|n| row(&format!("GB-00{n}"), "x", "🟡"))
        .collect();
    let outlier = series.clone() + &row("GB-900", "cites GB-901", "🟡");
    let v = Vault::new("series", &series, "", "");
    assert!(v.of(integrity::CONTIGUOUS_ID).is_empty());
    v.queue(&outlier);
    let found = v.of(integrity::CONTIGUOUS_ID);
    assert_eq!(found.len(), 1);
    assert!(found[0].message.contains("first free id GB-010"));
    assert_eq!(next_id_in("GB", &[&outlier]), "GB-010");
    let quoted = series + &row("GB-010", "the acceptance cites GB-900", "🟡");
    assert_eq!(next_id_in("GB", &[&quoted]), "GB-011");
}

#[test]
fn gb199_duplicate_defects() {
    let a = row("GB-001", "**Stenio: ARCH-NO-PYTHON.** Evidence: one.", "🟡");
    let other = row("GB-002", "**Stenio: OTHER-RULE.** Evidence: three.", "🟡");
    let v = Vault::new("defect", &(a.clone() + &other), "", "GB-001, GB-002");
    assert!(v.of(integrity::DUPLICATE_ID).is_empty());
    let check = |first: &str, item: &str, severity: Severity| {
        v.queue(&format!("{first}{}", row("GB-002", item, "🟡")));
        let found = v.of(integrity::DUPLICATE_ID);
        assert_eq!(found.len(), 1, "{item}");
        assert_eq!(found[0].severity, severity, "{item}");
        assert!(found[0].message.contains("GB-001") && found[0].message.contains("GB-002"));
    };
    check(
        &a,
        "**Stenio: ARCH-NO-PYTHON-SCOPE.** Evidence: two.",
        Severity::Warning,
    );
    check(
        &a,
        "**Stenio: ARCH-NO-PYTHON.** Evidence: two.",
        Severity::Error,
    );
    check(
        &a,
        "**Stenio: X-Y.** Evidence: this is a duplicate of GB-001.",
        Severity::Error,
    );
    // A row that only describes duplicate handling declares nothing.
    let talk = "Evidence: an archive row that says duplicate of GB-001 is not checked.";
    v.queue(&format!("{a}{}", row("GB-002", talk, "🟡")));
    assert!(v.of(integrity::DUPLICATE_ID).is_empty());
    let site = row("GB-001", "Evidence: seen at src/a.rs:10.", "🟡");
    check(&site, "Evidence: also src/a.rs:10.", Severity::Warning);
    let acknowledged = "**Stenio: ARCH-NO-PYTHON-SCOPE.** Related: GB-001 (overlap acknowledged).";
    v.queue(&format!("{a}{}", row("GB-002", acknowledged, "🟡")));
    assert!(v.of(integrity::DUPLICATE_ID).is_empty());
}

#[test]
fn gb209_lossy_fold_fires_until_the_token_is_copied() {
    let item = "duplicate of GB-001: commit 910a8e8, rc=0, 505 hits, 2026-11-06";
    let v = Vault::new(
        "fold",
        &row("GB-001", "rc=0 and 505 hits", "🟡"),
        &done("GB-002", item, "🟡"),
        "GB-001",
    );
    let found = v.of(integrity::FOLD_ID);
    assert_eq!(found.len(), 1);
    assert!(
        found[0].message.contains("GB-001 lacks: 910a8e8."),
        "{}",
        found[0].message
    );
    v.queue(&row("GB-001", "910a8e8, rc=0, 505 hits", "🟡"));
    assert!(v.of(integrity::FOLD_ID).is_empty());
}

#[test]
fn gb252_stale_pending_is_an_error_for_urgent_items_and_fix_removes_it() {
    for (sev, expected) in [
        ("🔴", Severity::Error),
        ("🟠", Severity::Error),
        ("🟡", Severity::Warning),
    ] {
        let v = Vault::new(
            "stale",
            &row("GB-002", "a", "🟡"),
            &done("GB-001", "x", sev),
            "GB-001, GB-002",
        );
        let found = v.of(integrity::DRIFT_ID);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, expected, "{sev}");
        assert_eq!(fix_drift(v.root()).0, 1);
        assert!(v.read("governance/doc.md").contains("pending: [GB-002]"));
        assert!(v.findings().is_empty());
    }
}

#[test]
fn remove_pending_touches_only_the_frontmatter_list() {
    let ids = vec!["GB-001".to_string()];
    let doc = "---\npending: [GB-001, GB-0010, GB-002]\nk: v\n---\npending: [GB-001]\n";
    assert_eq!(
        remove_pending(doc, &ids).as_deref(),
        Some("---\npending: [GB-0010, GB-002]\nk: v\n---\npending: [GB-001]\n")
    );
    assert_eq!(
        remove_pending("---\npending: [GB-001]\n---\n", &ids).as_deref(),
        Some("---\npending: []\n---\n")
    );
    assert_eq!(
        remove_pending("---\npending:\n  - GB-001\n---\n", &ids),
        None
    );
}

fn close(id: &str, note: &str) -> CloseItem {
    CloseItem {
        id: id.to_string(),
        state: "resolved".to_string(),
        note: note.to_string(),
    }
}

#[test]
fn close_moves_rows_and_unlinks_documents_in_one_step() {
    let active = row("GB-002", "keep", "🟡")
        + &row("GB-003", "**Stenio: R.** Status: open.", "🔴")
        + &row("GB-004", "four", "🟠");
    let v = Vault::new(
        "close",
        &active,
        &done("GB-001", "x", "🟡"),
        "GB-002, GB-003, GB-004",
    );
    v.write(
        "clients/miracena/doc.md",
        "---\npending: [MB-004, GB-003]\n---\n",
    );
    let items = [close("GB-003", "shipped | #12."), close("GB-004", "done")];
    let Ok(p) = plan(v.root(), &items, "2026-11-26") else {
        panic!("plan refused");
    };
    assert!(
        v.read("governance/backlog.md").contains("GB-003"),
        "plan writes nothing"
    );
    assert!(apply(&p).is_ok());
    let kept = format!("{HEAD}{}", row("GB-002", "keep", "🟡"));
    assert_eq!(v.read("governance/backlog.md"), kept);
    let archive = v.read("governance/backlog-archive.md");
    assert!(
        archive.ends_with(
            "| **GB-004** | four Closed 2026-11-26 (resolved): done. | [d](doc.md) | 🟠 | resolved | 2026-11-26 | — |\n"
        ),
        "{archive}"
    );
    assert!(archive.contains("Status: closed. Closed 2026-11-26 (resolved):"));
    assert!(archive.contains("shipped / #12."));
    assert!(v.read("governance/doc.md").contains("pending: [GB-002]"));
    let other = v.read("clients/miracena/doc.md");
    assert!(other.contains("pending: [MB-004]"));
    let found = v.findings();
    assert!(found.is_empty(), "{}", messages(&found));
}

#[test]
fn close_refuses_the_whole_batch_on_any_bad_id() {
    let active = row("GB-002", "a", "🟡")
        + &row("GB-003", "b", "🟡")
        + &row("GB-003", "c", "🟡")
        + "| **GB-005** | a | b | [d](doc.md) | 🟡 | open | x | — |\n";
    let v = Vault::new("refuse", &active, &done("GB-001", "x", "🟡"), "GB-002");
    let snapshot = || {
        (
            v.read("governance/backlog.md"),
            v.read("governance/backlog-archive.md"),
        )
    };
    let before = snapshot();
    for (bad, why) in [
        ("GB-001", "already in"),
        ("GB-009", "is not in"),
        ("GB-003", "identifies 2 rows"),
        ("GB-005", "cells"),
        ("XX-001", "no queue"),
        ("GB-002", "listed twice"),
    ] {
        let items = [close("GB-002", "n"), close(bad, "n")];
        let err = plan(v.root(), &items, "2026-11-26").err();
        assert!(
            err.as_deref().is_some_and(|e| e.contains(why)),
            "{bad}: {err:?}"
        );
    }
    assert!(plan(v.root(), &[close("GB-002", " ")], "2026-11-26").is_err());
    assert!(plan(v.root(), &[close("GB-002", "n")], "26/11").is_err());
    assert_eq!(before, snapshot());
}

#[test]
fn close_aborts_when_a_file_changed_and_fills_a_combined_column() {
    let v = Vault::new("race", &row("GB-002", "a", "🟡"), "", "GB-002");
    v.write(
        "governance/backlog-archive.md",
        "| ID | Item | Ref | Sev | State | Origin / Closed | Recurred-by |\n|---|---|---|---|---|---|---|\n\nfooter\n",
    );
    let Ok(p) = plan(v.root(), &[close("GB-002", "n")], "2026-11-26") else {
        panic!("plan refused");
    };
    v.write("governance/doc.md", "edited meanwhile\n");
    assert!(apply(&p).is_err());
    assert!(v.read("governance/backlog.md").contains("GB-002"));
    v.write("governance/doc.md", "---\npending: [GB-002]\n---\n");
    let Ok(p) = plan(v.root(), &[close("GB-002", "n")], "2026-11-26") else {
        panic!("plan refused");
    };
    assert!(apply(&p).is_ok());
    let archive = v.read("governance/backlog-archive.md");
    assert!(
        archive.contains(
            "|---|\n| **GB-002** | a Closed 2026-11-26 (resolved): n. | [d](doc.md) | 🟡 | resolved | 2026-11-01; closed 2026-11-26 | — |\n\nfooter\n"
        ),
        "{archive}"
    );
}

#[test]
fn batch_file_format() {
    let text = "# c\nGB-001\tdone\nGB-002\tdiscarded\twhy\n";
    let Ok(items) = parse_batch(text, "resolved") else {
        panic!("batch refused");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].state, "resolved");
    assert_eq!(items[1].state, "discarded");
    assert!(parse_batch("GB-001 done\n", "resolved").is_err());
}
