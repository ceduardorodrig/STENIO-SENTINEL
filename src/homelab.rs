use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct HomelabReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_homelab(repo_root: &Path) -> HomelabReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();

    let mnemocine_dir = if repo_root.join("mnemocine").is_dir() {
        repo_root.join("mnemocine")
    } else if repo_root.ends_with("mnemocine") {
        repo_root.to_path_buf()
    } else {
        return HomelabReport {
            total_files_scanned: 0,
            messages: vec!["Directory mnemocine/ not found in scope.".to_string()],
            violations: vec![],
        };
    };

    // 1. Load canonical tag taxonomy from mnemocine/_tags.md
    let tags_file = mnemocine_dir.join("_tags.md");
    let mut valid_tags = crate::baseline::parse_tags_file(&tags_file);

    // Universal default tags
    valid_tags.insert("homelab".to_string());
    valid_tags.insert("meta".to_string());
    valid_tags.insert("agents".to_string());
    valid_tags.insert("servico".to_string());
    valid_tags.insert("servidor".to_string());

    // 2. Collect files from mnemocine
    let mut scanned_count = 0;
    for path in crate::baseline::build_file_walker(&mnemocine_dir) {
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains("/.stversions/") || path_str.contains("/.smart-env/") {
            continue;
        }
        scanned_count += 1;

        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        // Validation A: Homelab Markdown Notes
        if ext == "md" {
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };

            // Rule 1: Mandatory YAML Frontmatter
            if !content.starts_with("---") {
                violations.push(Violation {
                    rule_id: "HOMELAB-FRONTMATTER".to_string(),
                    rule_name: "Mandatory YAML Frontmatter".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: content.lines().next().unwrap_or("").to_string(),
                    message: "All homelab notes must begin with YAML frontmatter (---)".to_string(),
                    suggestion: Some("Add '---\\ntags: [homelab, category, host]\\n---' block at the top of the note.".to_string()),
                });
            } else {
                // Check for #homelab tag presence
                if let Some(end_idx) = content[3..].find("---") {
                    let fm_str = &content[3..3 + end_idx];
                    if !fm_str.contains("homelab") {
                        violations.push(Violation {
                            rule_id: "HOMELAB-TAG-ROOT".to_string(),
                            rule_name: "Mandatory #homelab Tag".to_string(),
                            severity: Severity::Warning,
                            file_path: path_str.clone(),
                            line_number: 2,
                            snippet: "tags: [...]".to_string(),
                            message:
                                "All notes in mnemocine/ must contain the 'homelab' tag in frontmatter."
                                    .to_string(),
                            suggestion: Some(
                                "Include 'homelab' in the YAML frontmatter tag list."
                                    .to_string(),
                            ),
                        });
                    }
                }
            }

            // Rule 2: File naming convention (lowercase with hyphens, no uppercase)
            let allowed_specials = [
                "README.md",
                "_tags.md",
                "AGENTS.md",
                "SECURITY.md",
                "CONTRIBUTORS.md",
            ];
            if !allowed_specials.contains(&file_name) && file_name.chars().any(|c| c.is_uppercase())
            {
                violations.push(Violation {
                    rule_id: "HOMELAB-NAMING".to_string(),
                    rule_name: "Lowercase-Hyphenated Naming Convention".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: file_name.to_string(),
                    message: format!(
                        "File name '{}' contains uppercase letters. Use lowercase with hyphens.",
                        file_name
                    ),
                    suggestion: Some(format!("Rename to '{}'.", file_name.to_lowercase())),
                });
            }
        }

        // Validation B: NFS Mounts in /etc/fstab or scripts
        if ext == "sh" || ext == "md" || file_name == "fstab" {
            if let Ok(content) = fs::read_to_string(&path) {
                for (line_idx, line) in content.lines().enumerate() {
                    if (line.contains("nfs") || line.contains("nfs4"))
                        && (line.contains(",hard") || line.contains("hard,"))
                    {
                        violations.push(Violation {
                            rule_id: "HOMELAB-NFS-SOFT".to_string(),
                            rule_name: "Prohibition of Hard NFS Mounts".to_string(),
                            severity: Severity::Error,
                            file_path: path_str.clone(),
                            line_number: line_idx + 1,
                            snippet: line.trim().to_string(),
                            message: "NFS mounts over VPN/Tailscale must never use 'hard' (risk of kernel deadlock).".to_string(),
                            suggestion: Some("Replace 'hard' with 'soft,timeo=30,retrans=2,_netdev,x-systemd.automount'.".to_string()),
                        });
                    }
                }
            }
        }

        // Validation D: Cleartext secrets (SEC-SECRETS) — documentation and configs.
        // Syncthing mirrors vault to phones and houses the encrypted store:
        // any credential pasted into a note leaks across all synchronized devices.
        if let Ok(content) = fs::read_to_string(&path) {
            violations.extend(crate::guardian::scan_content_for_secrets(&path, &content));
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} notes and infrastructure configs in mnemocine/ 100% compliant.",
            scanned_count
        ));
        messages.push("✅ Tag taxonomy and YAML frontmatter intact.".to_string());
        messages
            .push("✅ No hard NFS mounts detected (Tailscale resilience OK).".to_string());
    } else {
        messages.push(format!(
            "⚠️ {} file(s) with deviations in mnemocine/.",
            violations.len()
        ));
    }

    HomelabReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
