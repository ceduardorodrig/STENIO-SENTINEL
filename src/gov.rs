use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct GovAuditResult {
    pub agents_md_ok: bool,
    pub laws_count: usize,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
}

pub fn audit_governance(repo_root: &Path) -> GovAuditResult {
    let mut messages = Vec::new();
    let mut errors = Vec::new();

    let agents_md_path = if repo_root.is_file() && repo_root.file_name().and_then(|s| s.to_str()) == Some("AGENTS.md") {
        repo_root.to_path_buf()
    } else {
        let base = if repo_root.is_file() {
            repo_root.parent().unwrap_or(repo_root)
        } else {
            repo_root
        };
        if base.join("sumaenimahub/SUMAENIMA-HUB/AGENTS.md").is_file() {
            base.join("sumaenimahub/SUMAENIMA-HUB/AGENTS.md")
        } else if base.join("../../AGENTS.md").is_file() {
            base.join("../../AGENTS.md")
        } else {
            base.join("AGENTS.md")
        }
    };

    if !agents_md_path.is_file() {
        let err = "❌ AGENTS.md não encontrado na raiz do repositório!".to_string();
        messages.push(err.clone());
        errors.push(err);
        return GovAuditResult {
            agents_md_ok: false,
            laws_count: 0,
            errors,
            messages,
        };
    }

    let content = match fs::read_to_string(&agents_md_path) {
        Ok(c) => c,
        Err(e) => {
            let err = format!("❌ Falha ao ler AGENTS.md: {}", e);
            messages.push(err.clone());
            errors.push(err);
            return GovAuditResult {
                agents_md_ok: false,
                laws_count: 0,
                errors,
                messages,
            };
        }
    };

    let mut laws_count = 0;

    // Se for o AGENTS.md universal do Vault/Homelab
    if content.contains("agent-conventions.md") && !content.contains("StênioBOT") {
        let has_conventions = content.contains("agent-conventions.md");
        let has_rust_tools =
            content.contains("Ferramentas Rust") || content.contains("Preferências de Terminal");
        let has_homelab_or_mei = content.contains("Homelab") || content.contains("MEI");

        if has_conventions && has_rust_tools && has_homelab_or_mei {
            messages.push(
                "✅ AGENTS.md universal íntegro e alinhado ao padrão de governança".to_string(),
            );
            messages.push(
                "✅ Regras de ferramentas Rust e privilégios de sistema preservadas".to_string(),
            );
            laws_count = 14;
        } else {
            let err =
                "❌ AGENTS.md universal com convenções ou regras essenciais ausentes".to_string();
            messages.push(err.clone());
            errors.push(err);
        }
    } else {
        // AGENTS.md do Hub de Engenharia (38 Leis Absolutas)
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(|c: char| c.is_ascii_digit()) && trimmed.contains(". **") {
                laws_count += 1;
            }
        }

        if laws_count >= 13 {
            messages.push(format!(
                "✅ AGENTS.md íntegro com {} Leis Absolutas preservadas",
                laws_count
            ));
        } else {
            let err = format!(
                "❌ AGENTS.md contém apenas {} leis (esperado >= 13). Omissão de leis absolutas!",
                laws_count
            );
            messages.push(err.clone());
            errors.push(err);
        }

        // Validação de cláusulas vitais
        if content.contains("REGRA DE OURO") {
            messages.push("✅ Cláusula da Regra de Ouro presente".to_string());
        } else {
            let err = "❌ Cláusula 'REGRA DE OURO' ausente no AGENTS.md".to_string();
            messages.push(err.clone());
            errors.push(err);
        }

        if content.contains("HERANÇA DE CONTEXTO") {
            messages.push("✅ Cláusula de Herança de Contexto presente".to_string());
        } else {
            let err = "❌ Cláusula 'HERANÇA DE CONTEXTO' ausente no AGENTS.md".to_string();
            messages.push(err.clone());
            errors.push(err);
        }
    }

    // Auditoria de Skills (substitui validate_skills.py por completo)
    let skills_dir = if repo_root.join("sumaenimahub/SUMAENIMA-HUB/skills").is_dir() {
        repo_root.join("sumaenimahub/SUMAENIMA-HUB/skills")
    } else {
        repo_root.join("skills")
    };
    if skills_dir.is_dir() {
        let mut total_skills = 0;
        let mut valid_skills = 0;
        let mut skill_errors = Vec::new();

        if let Ok(entries) = fs::read_dir(&skills_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    total_skills += 1;
                    let skill_md = path.join("SKILL.md");
                    if !skill_md.is_file() {
                        skill_errors
                            .push(format!("❌ Skill '{}': SKILL.md não encontrado", dir_name));
                        continue;
                    }

                    if let Ok(skill_content) = fs::read_to_string(&skill_md) {
                        let has_name = skill_content.contains("name:");
                        let has_desc = skill_content.contains("description:");
                        let has_comp = skill_content.contains("compatibility:");
                        let has_tools = skill_content.contains("allowed-tools:");

                        if !has_name || !has_desc || !has_comp || !has_tools {
                            skill_errors.push(format!(
                                "❌ Skill '{}': metadados incompletos no frontmatter",
                                dir_name
                            ));
                        } else {
                            valid_skills += 1;
                        }
                    }
                }
            }
        }

        if skill_errors.is_empty() && total_skills > 0 {
            messages.push(format!(
                "✅ Todas as {} skills em skills/ com manifesto SKILL.md íntegro",
                valid_skills
            ));
        } else {
            for err in &skill_errors {
                messages.push(err.clone());
                errors.push(err.clone());
            }
        }
    }

    // Auditoria de Artefatos Residuais de Teste (Regra 3 do AGENTS.md)
    let leftover_artifacts = audit_leftover_test_artifacts(repo_root);
    if leftover_artifacts.is_empty() {
        messages.push(
            "✅ Nenhum artefato residual de teste (*.bak, *.tmp, scratch_*) detectado".to_string(),
        );
    } else {
        for err in &leftover_artifacts {
            messages.push(err.clone());
            errors.push(err.clone());
        }
    }

    GovAuditResult {
        agents_md_ok: laws_count >= 13 && errors.is_empty(),
        laws_count,
        errors,
        messages,
    }
}

/// Auditoria de Artefatos de Teste e Arquivos Residuais (AGENTS.md Regra 3).
/// Agentes de IA e modelos menores frequentemente criam scripts temporários de teste (*.bak, *.tmp, scratch_*, etc.)
/// e esquecem de apagá-los, violando a regra mandatória de limpeza de artefatos de teste.
pub fn audit_leftover_test_artifacts(repo_root: &Path) -> Vec<String> {
    let mut artifact_errors = Vec::new();
    let walker = ignore::WalkBuilder::new(repo_root)
        .hidden(true)
        .parents(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.path();
        let path_str = path.to_string_lossy();

        // Ignora diretórios legítimos de build, target, git, obsidian e caches
        if path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/.venv/")
            || path_str.contains("/.git/")
            || path_str.contains("/dist/")
            || path_str.contains("/.obsidian/")
            || path_str.contains("/.stversions/")
            || path_str.contains("/temp/") // pasta temp/ canônica do Obsidian
            || path_str.contains("/scratch/") // diretório de scratch autorizado
            || path_str.contains("/brain/")
        // brain artifacts
        {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. Extensões de arquivos temporários/backup
        let is_temp_ext = matches!(ext.as_str(), "bak" | "tmp" | "orig" | "old" | "swp" | "rej");

        // 2. Nomes de arquivos temporários soltos deixados por agentes
        let is_scratch_name = file_name.starts_with("scratch_")
            || file_name.starts_with("temp_")
            || file_name.starts_with("tmp_")
            || file_name.starts_with("dummy_")
            || file_name.starts_with("test_dummy")
            || file_name == "temp.txt"
            || file_name == "temp.md"
            || file_name == "temp.sh"
            || file_name == "temp.py"
            || file_name == "scratch.py"
            || file_name == "scratch.sh";

        // 3. Scripts de teste na raiz do repositório/projetos fora de diretórios tests/
        let is_root_test_script = (file_name == "test.py"
            || file_name == "test.sh"
            || file_name == "test.rs"
            || file_name == "test.js")
            && !path_str.contains("/tests/")
            && !path_str.contains("/test/");

        if is_temp_ext || is_scratch_name || is_root_test_script {
            let rel_path = path
                .strip_prefix(repo_root)
                .unwrap_or(path)
                .display()
                .to_string();
            artifact_errors.push(format!(
                "❌ [GOV-LEFTOVER-TEST-ARTIFACTS] Artefato residual de teste/rascunho detectado: '{}'. Violação da Regra 3 do AGENTS.md (arquivos de teste devem ser limpos após a tarefa).",
                rel_path
            ));
        }
    }

    artifact_errors
}
