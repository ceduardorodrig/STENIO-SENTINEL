use ignore::WalkBuilder;
use std::collections::HashSet;
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

    // 1. Carregar taxonomia universal de tags de governance/_tags.md
    let tags_file = vault_root.join("governance").join("_tags.md");
    let mut valid_tags = HashSet::new();
    if tags_file.is_file() {
        if let Ok(content) = fs::read_to_string(&tags_file) {
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

    let mut walker = WalkBuilder::new(vault_root);
    walker.hidden(true).git_ignore(true);

    let mut scanned_count = 0;
    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
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

        // Validação 1: Frontmatter YAML nas notas do vault Obsidian
        if !content.starts_with("---") {
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !["README.md", "CONTRIBUTORS.md", "LICENSE.md", "CONTRIBUTING.md", "CLAUDE.md", "OSS-ACKNOWLEDGMENTS.md", "AGENTS.md"].contains(&file_name) {
                violations.push(Violation {
                    rule_id: "VAULT-FRONTMATTER".to_string(),
                    rule_name: "Frontmatter YAML Obrigatório".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: content.lines().next().unwrap_or("").to_string(),
                    message: "Notas do vault devem conter frontmatter YAML com tags de governance/_tags.md".to_string(),
                    suggestion: Some("Adicione '---\\ntags: [meta, ...]\\n---' no cabeçalho da nota.".to_string()),
                });
            }
        } else {
            // Validação 2: Auditoria de Tags válidas contra a taxonomia canônica
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
                                        rule_name: "Tag Fora da Taxonomia Oficial".to_string(),
                                        severity: Severity::Warning,
                                        file_path: path_str.clone(),
                                        line_number: 2,
                                        snippet: format!("tag: {}", clean),
                                        message: format!("Tag '{}' não está catalogada em governance/_tags.md.", clean),
                                        suggestion: Some("Utilize apenas tags aprovadas em governance/_tags.md ou adicione-a formalmente lá.".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Validação 3: Auditoria de Links Markdown Relativos Quebrados
        for (line_idx, line) in content.lines().enumerate() {
            if line.contains("](") && !line.contains("http://") && !line.contains("https://") && !line.contains("mailto:") {
                let mut start_search = 0;
                while let Some(open) = line[start_search..].find("](") {
                    let actual_open = start_search + open + 2;
                    if let Some(close) = line[actual_open..].find(')') {
                        let link_target = &line[actual_open..actual_open + close].split('#').next().unwrap_or("").trim();
                        if !link_target.is_empty() && (link_target.ends_with(".md") || link_target.ends_with(".png") || link_target.ends_with(".jpg")) {
                            let target_path = if link_target.starts_with('/') {
                                vault_root.join(&link_target[1..])
                            } else {
                                path.parent().unwrap_or(vault_root).join(link_target)
                            };

                            if !target_path.exists() {
                                violations.push(Violation {
                                    rule_id: "VAULT-BROKEN-LINK".to_string(),
                                    rule_name: "Link Quebrado no Markdown".to_string(),
                                    severity: Severity::Warning,
                                    file_path: path_str.clone(),
                                    line_number: line_idx + 1,
                                    snippet: format!("[...](<{}>)", link_target),
                                    message: format!("Link aponta para arquivo inexistente: '{}'", link_target),
                                    suggestion: Some("Atualize o caminho relativo ou remova a referência ao arquivo deletado/movido.".to_string()),
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
    }

    // Validação 4: Nomenclatura Estrita de Pastas em projects/ (AAMMDD-nome-contratante)
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
                        && dir_name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');

                    if !is_valid_project_name && !dir_name.starts_with('.') {
                        violations.push(Violation {
                            rule_id: "PROJECT-NAMING-CONVENTION".to_string(),
                            rule_name: "Nomenclatura Canônica de Projetos (AAMMDD-...)".to_string(),
                            severity: Severity::Warning,
                            file_path: format!("projects/{}", dir_name),
                            line_number: 1,
                            snippet: dir_name.clone(),
                            message: format!("Pasta de projeto 'projects/{}' desvia do padrão canônico AAMMDD-nome-contratante.", dir_name),
                            suggestion: Some("Renomeie para o formato AAMMDD-nome-contratante em lowercase e com hífens.".to_string()),
                        });
                    }

                    // Validação 5: Alerta de Inatividade > 30 Dias (PROJECT-AUTO-COLD-STORAGE)
                    // Calcula a modificação mais recente recursivamente em todos os arquivos do projeto
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
                                    rule_name: "Projeto Inativo há mais de 30 dias".to_string(),
                                    severity: Severity::Warning,
                                    file_path: format!("projects/{}", dir_name),
                                    line_number: 1,
                                    snippet: format!("Inativo há {} dias", days),
                                    message: format!("O projeto 'projects/{}' não tem modificações há mais de {} dias.", dir_name, days),
                                    suggestion: Some("Arquive para projects/cold-storage/ conforme governance/cold-storage.md e execute stenio --scope all para validar integridade.".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!("✅ {} notas do vault Obsidian auditadas e íntegras.", scanned_count));
    } else {
        messages.push(format!("ℹ️ {} desvio(s) de taxonomia, metadados ou links detectados no vault.", violations.len()));
    }

    VaultReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
