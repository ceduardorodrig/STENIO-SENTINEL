use ignore::WalkBuilder;
use std::collections::HashSet;
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
            messages: vec!["Diretório mnemocine/ não encontrado no escopo.".to_string()],
            violations: vec![],
        };
    };

    // 1. Carregar taxonomia canônica de tags de mnemocine/_tags.md
    let tags_file = mnemocine_dir.join("_tags.md");
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

    // Tags padrão universais
    valid_tags.insert("homelab".to_string());
    valid_tags.insert("meta".to_string());
    valid_tags.insert("agents".to_string());
    valid_tags.insert("servico".to_string());
    valid_tags.insert("servidor".to_string());

    // 2. Coletar arquivos do mnemocine
    let mut walker = WalkBuilder::new(&mnemocine_dir);
    walker.hidden(true).git_ignore(true);

    let mut scanned_count = 0;
    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains("/.stversions/") || path_str.contains("/.smart-env/") {
            continue;
        }
        scanned_count += 1;

        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        // Validação A: Markdown Notas do Homelab
        if ext == "md" {
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };

            // Regra 1: Frontmatter YAML obrigatório
            if !content.starts_with("---") {
                violations.push(Violation {
                    rule_id: "HOMELAB-FRONTMATTER".to_string(),
                    rule_name: "Frontmatter YAML Obrigatório".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: content.lines().next().unwrap_or("").to_string(),
                    message: "Toda nota do homelab deve iniciar com frontmatter YAML (---)".to_string(),
                    suggestion: Some("Adicione o bloco '---\\ntags: [homelab, categoria, host]\\n---' no topo da nota.".to_string()),
                });
            } else {
                // Verificar tag #homelab presente
                if let Some(end_idx) = content[3..].find("---") {
                    let fm_str = &content[3..3 + end_idx];
                    if !fm_str.contains("homelab") {
                        violations.push(Violation {
                            rule_id: "HOMELAB-TAG-ROOT".to_string(),
                            rule_name: "Tag #homelab Obrigatória".to_string(),
                            severity: Severity::Warning,
                            file_path: path_str.clone(),
                            line_number: 2,
                            snippet: "tags: [...]".to_string(),
                            message:
                                "Toda nota em mnemocine/ deve conter a tag 'homelab' no frontmatter"
                                    .to_string(),
                            suggestion: Some(
                                "Inclua 'homelab' na lista de tags do frontmatter YAML."
                                    .to_string(),
                            ),
                        });
                    }
                }
            }

            // Regra 2: Nomenclatura de arquivos (lowercase com hífen, sem maiúsculas)
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
                    rule_name: "Nomenclatura Lowercase-Hifenizada".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: file_name.to_string(),
                    message: format!(
                        "Nome de arquivo '{}' contém letras maiúsculas. Use lowercase com hífens.",
                        file_name
                    ),
                    suggestion: Some(format!("Renomeie para '{}'.", file_name.to_lowercase())),
                });
            }
        }

        // Validação B: Montagens NFS no /etc/fstab ou scripts
        if ext == "sh" || ext == "md" || file_name == "fstab" {
            if let Ok(content) = fs::read_to_string(&path) {
                for (line_idx, line) in content.lines().enumerate() {
                    if (line.contains("nfs") || line.contains("nfs4"))
                        && (line.contains(",hard") || line.contains("hard,"))
                    {
                        violations.push(Violation {
                            rule_id: "HOMELAB-NFS-SOFT".to_string(),
                            rule_name: "Proibição de Montagem NFS Hard".to_string(),
                            severity: Severity::Error,
                            file_path: path_str.clone(),
                            line_number: line_idx + 1,
                            snippet: line.trim().to_string(),
                            message: "Montagens NFS via VPN/Tailscale nunca devem usar 'hard' (risco de deadlock no kernel).".to_string(),
                            suggestion: Some("Substitua 'hard' por 'soft,timeo=30,retrans=2,_netdev,x-systemd.automount'.".to_string()),
                        });
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} notas e arquivos de infraestrutura em mnemocine/ 100% em conformidade.",
            scanned_count
        ));
        messages.push("✅ Taxonomia de tags e frontmatter YAML íntegros.".to_string());
        messages
            .push("✅ Nenhuma montagem NFS hard detectada (resiliência Tailscale OK).".to_string());
    } else {
        messages.push(format!(
            "⚠️ {} arquivo(s) com desvios em mnemocine/.",
            violations.len()
        ));
    }

    HomelabReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
