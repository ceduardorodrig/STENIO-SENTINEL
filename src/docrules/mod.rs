//! `DOC-*` rules over documents, one file per rule.
//!
//! Every rule gates itself on what it can see (a vault root, a declared marker, a tagged
//! application), so the audit runs on any `--path` and stays silent where it has nothing to
//! judge. `RULES` is the single registration point: the audit, `--self-test` and `--explain`
//! all iterate it.

use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

/// One document rule: its id, the audit, its mutation proof and its `--explain` entry.
pub struct DocRule {
    pub id: &'static str,
    pub check: fn(&Ctx, &mut Vec<Violation>),
    pub self_test: fn() -> Vec<(String, bool)>,
    pub explain: RuleExplanation,
}

mod adr_roadmap;
mod bind_claim;
mod contract_parity;
mod count_drift;
mod incident;
mod inline_style;
mod live_claim;
mod quote_source;
mod raci;
mod route_drift;
mod rule_count;
mod sources;

#[rustfmt::skip]
pub static RULES: &[&DocRule] = &[
    &incident::RULE,
    &rule_count::RULE,
    &inline_style::RULE,
    &contract_parity::RULE,
    &live_claim::RULE,
    &bind_claim::RULE,
    &raci::RULE,
    &quote_source::RULE,
    &count_drift::RULE,
    &route_drift::RULE,
    &adr_roadmap::RULE,
];

/// What the rules may look at.
pub struct Ctx {
    /// The path given with `--path` (a directory or a single file).
    pub target: PathBuf,
    /// Nearest ancestor of the target holding `governance/agent-global-rules.md`.
    pub vault: Option<PathBuf>,
    /// The mirror of the live host configuration (`/mnt/BACKUP/configs-homelab`).
    pub mirror: Option<PathBuf>,
    /// The directory holding the repository checkouts the vault documents describe.
    pub repos: Option<PathBuf>,
    /// Checkout of the Miracena application, source of panel labels and permissions.
    pub panel_app: Option<PathBuf>,
    /// Active `--tag`, lowercased.
    pub tag: Option<String>,
}

impl Ctx {
    pub fn new(target: &Path, tag: Option<&str>) -> Self {
        let target = target
            .canonicalize()
            .unwrap_or_else(|_| target.to_path_buf());
        let vault = target
            .ancestors()
            .find(|a| a.join("governance/agent-global-rules.md").is_file())
            .map(Path::to_path_buf);
        let existing = |p: &str| Some(PathBuf::from(p)).filter(|p| p.is_dir());
        Ctx {
            target,
            vault,
            mirror: existing("/mnt/BACKUP/configs-homelab"),
            repos: existing("/mnt/NVME_PCI/homelab"),
            panel_app: existing("/mnt/NVME_PCI/homelab/miracena/miracena"),
            tag: tag.map(str::to_lowercase),
        }
    }

    /// A context confined to a fixture tree: no host paths leak into a self-test.
    pub fn fixture(target: &Path) -> Self {
        let mut ctx = Ctx::new(target, None);
        ctx.mirror = Some(ctx.target.join("mirror")).filter(|p| p.is_dir());
        ctx.repos = Some(ctx.target.join("repos")).filter(|p| p.is_dir());
        ctx.panel_app = Some(ctx.target.join("app")).filter(|p| p.is_dir());
        ctx
    }

    /// The directory findings are printed relative to.
    pub fn root(&self) -> &Path {
        if self.target.is_file() {
            self.vault
                .as_deref()
                .or_else(|| self.target.parent())
                .unwrap_or(&self.target)
        } else {
            &self.target
        }
    }

    pub fn display(&self, path: &Path) -> String {
        path.strip_prefix(self.root())
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    }

    /// Files under the target with one of `extensions`, archives and scratch trees excluded.
    pub fn files(&self, extensions: &[&str]) -> Vec<PathBuf> {
        let wanted = |p: &Path| {
            p.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| extensions.contains(&e))
        };
        if self.target.is_file() {
            return Some(self.target.clone())
                .filter(|p| wanted(p))
                .into_iter()
                .collect();
        }
        let mut walker = WalkBuilder::new(&self.target);
        walker.hidden(true).git_ignore(true).parents(false);
        let mut out: Vec<PathBuf> = walker
            .build()
            .flatten()
            .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
            .map(ignore::DirEntry::into_path)
            .filter(|p| wanted(p) && !excluded(p, &self.target))
            .collect();
        out.sort();
        out
    }

    /// Markdown documents with their content. Backlogs are queues that quote defects verbatim,
    /// so no rule judges them.
    pub fn docs(&self) -> Vec<(PathBuf, String)> {
        self.files(&["md"])
            .into_iter()
            .filter(|p| {
                !matches!(
                    p.file_name().and_then(|n| n.to_str()),
                    Some("backlog.md" | "backlog-archive.md")
                )
            })
            .filter_map(|p| fs::read_to_string(&p).ok().map(|c| (p, c)))
            .collect()
    }
}

const EXCLUDED_DIRS: &[&str] = &[
    ".stversions",
    ".smart-env",
    "node_modules",
    "target",
    "archive",
    "external",
    "templates",
    "temp",
    "personal",
    "openwiki",
    "vendor",
];

fn excluded(path: &Path, root: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.parent().is_some_and(|dir| {
        dir.components().any(|c| {
            c.as_os_str()
                .to_str()
                .is_some_and(|s| EXCLUDED_DIRS.contains(&s))
        })
    })
}

/// Builds a finding.
pub fn finding(
    explain: &RuleExplanation,
    severity: Severity,
    file: String,
    line: usize,
    snippet: &str,
    message: String,
) -> Violation {
    Violation {
        rule_id: explain.id.to_string(),
        rule_name: explain.name.to_string(),
        severity,
        file_path: file,
        line_number: line,
        snippet: snippet.trim().chars().take(160).collect(),
        message,
        suggestion: Some(explain.remediation.to_string()),
    }
}

/// `(index, line)` of the prose: YAML frontmatter and fenced code blocks are skipped.
pub fn prose_lines(content: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut fence = false;
    let mut frontmatter = content.starts_with("---\n");
    for (idx, line) in content.lines().enumerate() {
        if frontmatter {
            frontmatter = idx == 0 || line.trim_end() != "---";
            continue;
        }
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
            continue;
        }
        if !fence {
            out.push((idx, line));
        }
    }
    out
}

/// The YAML frontmatter of a document, if it has one.
pub fn frontmatter(content: &str) -> Option<serde_yaml::Value> {
    let rest = content.strip_prefix("---\n")?;
    let end = rest.find("\n---")?;
    serde_yaml::from_str(&rest[..end]).ok()
}

/// Runs the rules over `target`. `only` restricts the audit to one rule id.
pub fn audit(target: &Path, tag: Option<&str>, only: Option<&str>) -> Vec<Violation> {
    run(&Ctx::new(target, tag), only)
}

pub fn run(ctx: &Ctx, only: Option<&str>) -> Vec<Violation> {
    let mut out = Vec::new();
    for rule in RULES {
        if only.is_none_or(|o| o.eq_ignore_ascii_case(rule.id)) {
            (rule.check)(ctx, &mut out);
        }
    }
    out
}

/// The tags of the custom rules the repository's `steniocheck.toml` declares.
pub fn custom_tags(root: &Path) -> Vec<String> {
    crate::config::SteniocheckConfig::load_from_dir(root)
        .custom_rules
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.tag)
        .collect()
}

/// True when `--tag`/`--only` ask for something these rules answer.
pub fn applies(target: &Path, tag: Option<&str>, only: Option<&str>) -> bool {
    let tag_ok = tag.is_none_or(|t| {
        t.eq_ignore_ascii_case("doc")
            || custom_tags(target)
                .iter()
                .any(|c| c.eq_ignore_ascii_case(t))
    });
    tag_ok && only.is_none_or(|o| RULES.iter().any(|r| r.id.eq_ignore_ascii_case(o)))
}

/// Writes a fixture tree, runs one rule over it and removes the tree.
pub fn probe(rule: &DocRule, name: &str, files: &[(&str, &str)]) -> Option<Vec<Violation>> {
    probe_with(rule, name, files, None)
}

pub fn probe_with(
    rule: &DocRule,
    name: &str,
    files: &[(&str, &str)],
    tag: Option<&str>,
) -> Option<Vec<Violation>> {
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect();
    let tag_name = format!("docrules-{}-{name}", rule.id);
    let root = crate::frappe::write_fixture(&tag_name, &owned)?;
    let mut ctx = Ctx::fixture(&root);
    ctx.tag = tag.map(str::to_string);
    let mut found = Vec::new();
    (rule.check)(&ctx, &mut found);
    let _ = fs::remove_dir_all(&root);
    Some(found)
}

/// One mutation proof: the good tree is silent and the broken copy fires `expected` times.
pub fn red_green(
    rule: &DocRule,
    name: &str,
    good: &[(&str, &str)],
    bad: &[(&str, &str)],
    expected: usize,
) -> (String, bool) {
    let silent = probe(rule, &format!("{name}-good"), good).is_some_and(|v| v.is_empty());
    let fires = probe(rule, &format!("{name}-bad"), bad).is_some_and(|v| v.len() == expected);
    (format!("{} {name}", rule.id), silent && fires)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    RULES.iter().flat_map(|r| (r.self_test)()).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_document_rule_is_red_on_its_broken_fixture_and_green_on_the_good_one() {
        let failed: Vec<String> = super::self_test_cases()
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(name, _)| name)
            .collect();
        assert!(failed.is_empty(), "failed cases: {failed:?}");
    }
}
