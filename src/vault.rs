use ignore::WalkBuilder;
use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct VaultReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_vault(vault_root: &Path) -> VaultReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();

    // 1. Load universal tag taxonomy from governance/_tags.md
    let tags_file = vault_root.join("governance").join("_tags.md");
    let valid_tags = crate::baseline::parse_tags_file(&tags_file);

    let mut scanned_count = 0;
    for path in crate::baseline::build_file_walker(vault_root) {
        let path_str = path.to_string_lossy().to_string();

        if path_str.contains("/.stversions/")
            || path_str.contains("/.smart-env/")
            || path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/mnemocine/")
            || path_str.contains("/sumaenimahub/")
            || path_str.contains("/docs/external/")
            || path_str.contains("/openwiki/")
        {
            continue;
        }

        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "md" {
            continue;
        }

        scanned_count += 1;
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };

        // Validation 1: YAML Frontmatter in Obsidian vault notes
        if !content.starts_with("---") {
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if ![
                "README.md",
                "CONTRIBUTORS.md",
                "LICENSE.md",
                "CONTRIBUTING.md",
                "CLAUDE.md",
                "OSS-ACKNOWLEDGMENTS.md",
                "AGENTS.md",
            ]
            .contains(&file_name)
            {
                violations.push(Violation {
                    rule_id: "VAULT-FRONTMATTER".to_string(),
                    rule_name: "Mandatory YAML Frontmatter".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: content.lines().next().unwrap_or("").to_string(),
                    message: "Vault notes must contain YAML frontmatter with tags from governance/_tags.md".to_string(),
                    suggestion: Some("Add '---\\ntags: [meta, ...]\\n---' to the note header.".to_string()),
                });
            }
        } else {
            // Validation 2: Valid Tags Audit against canonical taxonomy
            if let Some(frontmatter_end) = content[3..].find("---") {
                let fm = &content[3..3 + frontmatter_end];
                if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(fm) {
                    if let Some(tags_val) = yaml.get("tags").and_then(|t| t.as_sequence()) {
                        for t in tags_val {
                            if let Some(tag_str) = t.as_str() {
                                let clean = tag_str.trim_start_matches('#');
                                if !valid_tags.is_empty() && !valid_tags.contains(clean) {
                                    violations.push(Violation {
                                        rule_id: "VAULT-TAG-TAXONOMY".to_string(),
                                        rule_name: "Tag Outside Official Taxonomy".to_string(),
                                        severity: Severity::Warning,
                                        file_path: path_str.clone(),
                                        line_number: 2,
                                        snippet: format!("tag: {}", clean),
                                        message: format!("Tag '{}' is not cataloged in governance/_tags.md.", clean),
                                        suggestion: Some("Use only approved tags in governance/_tags.md or formally add it there.".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Validation 3: Broken Relative Markdown Links Audit
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("](")
                && !line.contains("http://")
                && !line.contains("https://")
                && !line.contains("mailto:")
            {
                let mut start_search = 0;
                while let Some(open) = line[start_search..].find("](") {
                    let actual_open = start_search + open + 2;
                    if let Some(close) = line[actual_open..].find(')') {
                        let link_target = &line[actual_open..actual_open + close]
                            .split('#')
                            .next()
                            .unwrap_or("")
                            .trim();
                        if !link_target.is_empty()
                            && (link_target.ends_with(".md")
                                || link_target.ends_with(".png")
                                || link_target.ends_with(".jpg"))
                        {
                            let target_path = if link_target.starts_with('/') {
                                vault_root.join(&link_target[1..])
                            } else {
                                path.parent().unwrap_or(vault_root).join(link_target)
                            };

                            if !target_path.exists() {
                                violations.push(Violation {
                                    rule_id: "VAULT-BROKEN-LINK".to_string(),
                                    rule_name: "Broken Link in Markdown".to_string(),
                                    severity: Severity::Warning,
                                    file_path: path_str.clone(),
                                    line_number: line_idx + 1,
                                    snippet: format!("[...](<{}>)", link_target),
                                    message: format!("Link points to non-existent file: '{}'", link_target),
                                    suggestion: Some("Update relative path or remove reference to deleted/moved file.".to_string()),
                                });
                            }
                        }
                        start_search = actual_open + close + 1;
                    } else {
                        break;
                    }
                }
            }
        }

        // Validation 3b: Cleartext secrets (SEC-SECRETS) in notes and configs.
        // Syncthing mirrors vault to phones and houses the encrypted store.
        violations.extend(crate::guardian::scan_content_for_secrets(&path, &content));
    }

    // Validation 4: Strict Directory Naming in projects/ (YYMMDD-contractor-name)
    let projects_dir = vault_root.join("projects");
    if projects_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&projects_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                    let dir_name = entry.file_name().to_string_lossy().to_string();
                    if dir_name == "cold-storage" {
                        continue;
                    }
                    let is_valid_project_name = dir_name.len() >= 8
                        && dir_name[0..6].chars().all(|c| c.is_ascii_digit())
                        && dir_name.chars().nth(6) == Some('-')
                        && dir_name
                            .chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');

                    if !is_valid_project_name && !dir_name.starts_with('.') {
                        violations.push(Violation {
                            rule_id: "PROJECT-NAMING-CONVENTION".to_string(),
                            rule_name: "Canonical Project Naming Convention (YYMMDD-...)".to_string(),
                            severity: Severity::Warning,
                            file_path: format!("projects/{}", dir_name),
                            line_number: 1,
                            snippet: dir_name.clone(),
                            message: format!("Project directory 'projects/{}' deviates from canonical YYMMDD-contractor-name format.", dir_name),
                            suggestion: Some("Rename to YYMMDD-contractor-name format in lowercase with hyphens.".to_string()),
                        });
                    }

                    // Validation 5: Inactivity Alert > 30 Days (PROJECT-AUTO-COLD-STORAGE)
                    // Calculates latest modification recursively across all project files
                    let mut latest_mod_time = entry.metadata().ok().and_then(|m| m.modified().ok());
                    let project_walker = WalkBuilder::new(entry.path())
                        .hidden(true)
                        .parents(false)
                        .git_ignore(true)
                        .build();

                    for sub_entry in project_walker.flatten() {
                        if let Ok(sub_meta) = sub_entry.metadata() {
                            if let Ok(sub_mtime) = sub_meta.modified() {
                                if latest_mod_time.map_or(true, |cur| sub_mtime > cur) {
                                    latest_mod_time = Some(sub_mtime);
                                }
                            }
                        }
                    }

                    if let Some(mod_time) = latest_mod_time {
                        if let Ok(elapsed) = mod_time.elapsed() {
                            let days = elapsed.as_secs() / (3600 * 24);
                            if days > 30 {
                                violations.push(Violation {
                                    rule_id: "PROJECT-AUTO-COLD-STORAGE".to_string(),
                                    rule_name: "Project Inactive for More Than 30 Days".to_string(),
                                    severity: Severity::Warning,
                                    file_path: format!("projects/{}", dir_name),
                                    line_number: 1,
                                    snippet: format!("Inactive for {} days", days),
                                    message: format!("Project 'projects/{}' has had no modifications for over {} days.", dir_name, days),
                                    suggestion: Some("Archive to projects/cold-storage/ according to governance/cold-storage.md and run stenio --scope all to validate integrity.".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} Obsidian vault notes audited and intact.",
            scanned_count
        ));
    } else {
        messages.push(format!(
            "ℹ️ {} taxonomy, metadata, or link deviation(s) detected in vault.",
            violations.len()
        ));
    }

    VaultReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
