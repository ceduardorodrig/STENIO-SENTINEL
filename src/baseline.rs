use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

#[derive(Debug, Default, Clone)]
pub struct Whitelist {
    /// The scanned tree the keys are relative to.
    root: PathBuf,
    /// Exact paths relative to `root`.
    exempt: HashSet<String>,
}

pub const STALE_ID: &str = "SCAN-EXEMPTION-STALE";

impl Whitelist {
    /// The registry of a tree; absent means no exemption. A file that cannot be read, is not a
    /// JSON object or holds an empty key is an error: it must never exempt more than it names.
    pub fn load_from_file(path: &Path, root: &Path) -> Result<Self, String> {
        let fail = |cause: String| format!("exemption registry {}: {cause}", path.display());
        let mut list = Self {
            root: root.to_path_buf(),
            exempt: HashSet::new(),
        };
        if fs::symlink_metadata(path).is_err() {
            return Ok(list);
        }
        let content = fs::read_to_string(path).map_err(|e| fail(e.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| fail(e.to_string()))?;
        let object = value
            .as_object()
            .ok_or_else(|| fail("not a JSON object of file paths".to_string()))?;
        for key in object.keys() {
            let name = key.trim().trim_start_matches("./");
            if name.is_empty() {
                return Err(fail("empty file path".to_string()));
            }
            list.exempt.insert(name.to_string());
        }
        Ok(list)
    }

    /// Entries that name no file of the tree exempt nothing and are reported.
    pub fn stale_findings(&self) -> Vec<Violation> {
        let mut missing: Vec<&String> = self
            .exempt
            .iter()
            .filter(|name| !self.root.join(name).is_file())
            .collect();
        missing.sort();
        missing
            .into_iter()
            .map(|name| Violation {
                rule_id: STALE_ID.to_string(),
                rule_name: "Stale Exemption".to_string(),
                severity: Severity::Warning,
                file_path: ".steniocheck-whitelist-registry.json".to_string(),
                line_number: 1,
                snippet: name.clone(),
                message: format!("the exemption of `{name}` names no file: it does nothing"),
                suggestion: Some("Delete the entry.".to_string()),
            })
            .collect()
    }

    fn names(&self, file_path: &str) -> bool {
        let path = Path::new(file_path);
        let relative = path.strip_prefix(&self.root).unwrap_or(path);
        let relative = relative.to_string_lossy();
        self.exempt.contains(relative.trim_start_matches("./"))
    }

    pub fn is_ignored(&self, file_path: &str, rule_id: &str, line_content: &str) -> bool {
        // Inviolable Canonical Rules: NEVER suppressed via inline comments,
        // neither by AI agents nor by humans. Tampering attempts are rejected.
        let is_inviolable = rule_id.starts_with("SEC-")
            || rule_id.starts_with("AGENT-")
            || rule_id.starts_with("ARCH-")
            || rule_id.starts_with("RUST-")
            || rule_id.starts_with("CONF-")
            || rule_id == "TEST-NO-SILENT-SKIP";

        if is_inviolable {
            return false;
        }

        // 1. Support for inline comment with specific rule: # stenio-ignore: RULE_ID
        // SECURITY NOTE: 'stenio-ignore: all' is strictly FORBIDDEN and has no effect.
        if line_content.contains("# stenio-ignore") || line_content.contains("// stenio-ignore") {
            // Strict prohibition of global 'all' bypass
            if line_content.contains("stenio-ignore: all")
                || line_content.contains("stenio-ignore:all")
            {
                return false;
            }
            if line_content.contains(rule_id) {
                return true;
            }
        }

        // 2. nosemgrep: compatible with semgrep CLI (specific non-critical rules only)
        if line_content.contains("# nosemgrep") || line_content.contains("// nosemgrep") {
            if let Some(after) = line_content.split("nosemgrep").nth(1) {
                let trimmed_after = after.trim();
                if trimmed_after.is_empty() || !trimmed_after.starts_with(':') {
                    // Generic nosemgrep is prohibited to prevent blind suppression by AI agents
                    return false;
                }
                // nosemgrep: RULE_ID — ignores only if rule_id matches
                if trimmed_after.contains(rule_id) {
                    return true;
                }
                return false;
            }
            return false;
        }

        // 3. Check file whitelist (.steniocheck-whitelist-registry.json)
        self.names(file_path)
    }
}

pub fn print_banner(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!("{}", title.cyan().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
}

pub fn print_banner_with_badge(title: &str, badge: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!("{} {}", title.cyan().bold(), badge.yellow());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
}

pub fn print_banner_green(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!("{}", title.green().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .green()
            .bold()
    );
}

pub fn print_banner_red(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .red()
            .bold()
    );
    println!("{}", title.red().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .red()
            .bold()
    );
}

pub fn parse_tags_file(tags_file: &Path) -> HashSet<String> {
    let mut valid_tags = HashSet::new();
    if tags_file.is_file() {
        if let Ok(content) = fs::read_to_string(tags_file) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("- `#") || trimmed.starts_with("- `") {
                    if let Some(first_tick) = trimmed.find('`') {
                        if let Some(second_tick) = trimmed[first_tick + 1..].find('`') {
                            let tag_clean = trimmed[first_tick + 1..first_tick + 1 + second_tick]
                                .trim_start_matches('#')
                                .trim();
                            if !tag_clean.is_empty() {
                                valid_tags.insert(tag_clean.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    valid_tags
}

pub fn is_common_ignored_path(path_str: &str) -> bool {
    path_str.contains("/target/")
        || path_str.contains("/node_modules/")
        || path_str.contains("/.venv/")
        || path_str.contains("/.git/")
        || path_str.contains("/dist/")
        || path_str.contains("/.obsidian/")
        || path_str.contains("/dependencies/")
        || path_str.contains("/archive/")
        || path_str.contains("/cold-storage/")
}

pub fn build_file_walker(root: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    let mut walker = ignore::WalkBuilder::new(root);
    walker.hidden(true).git_ignore(true);
    walker.build().flatten().filter_map(|entry| {
        if entry.file_type().map_or(false, |ft| ft.is_file()) {
            Some(entry.into_path())
        } else {
            None
        }
    })
}

pub fn create_standard_walker(root: &Path) -> ignore::WalkBuilder {
    let mut walker = ignore::WalkBuilder::new(root);
    walker
        .hidden(true)
        .parents(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true);
    walker
}
