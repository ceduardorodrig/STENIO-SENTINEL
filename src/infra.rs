use ignore::WalkBuilder;
use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct InfraReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_infrastructure(root: &Path) -> InfraReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();
    let mut scanned_count = 0;

    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(true);

    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
        let path_str = path.to_string_lossy().to_string();

        if path_str.contains("/.git/")
            || path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/.venv/")
            || path_str.contains("/.stversions/")
        {
            continue;
        }

        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        // ── 1. Guarda Profunda de Segredos SOPS / Age (SEC-SOPS-UNENCRYPTED) ────
        // Cobre 100% dos arquivos de texto e configuração de infraestrutura
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let is_text_or_config = matches!(
            ext,
            "yml" | "yaml" | "env" | "json" | "sh" | "conf" | "service" | "md"
        );

        if is_text_or_config {
            if let Ok(content) = fs::read_to_string(&path) {
                // Arquivo com extensão .enc.* DEVE conter armadura SOPS ou Age
                let is_sops_encrypted = content.contains("sops:") && content.contains("mac:");
                let is_age_armored = content.contains("-----BEGIN AGE ENCRYPTED FILE-----");

                if file_name.contains(".enc.") && !is_sops_encrypted && !is_age_armored {
                    violations.push(Violation {
                        rule_id: "SEC-SOPS-UNENCRYPTED".to_string(),
                        rule_name: "Arquivo .enc Sem Criptografia SOPS/Age".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: content.lines().next().unwrap_or("").to_string(),
                        message: "Arquivo com extensão .enc não possui cabeçalho criptografado do SOPS ou Age.".to_string(),
                        suggestion: Some("Criptografe com: sops --encrypt --age <KEY> arquivo > arquivo.enc.yaml".to_string()),
                    });
                }

                // Detecta chaves privadas desprotegidas em texto claro
                if content.contains("-----BEGIN")
                    && content.contains("PRIVATE KEY-----")
                    && !is_age_armored
                {
                    violations.push(Violation {
                        rule_id: "SEC-PRIVATE-KEY-CLEARTEXT".to_string(),
                        rule_name: "Chave Privada em Texto Claro Detectada".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: format!("{}-BEGIN PRIVATE KEY-{}", "----", "----"),
                        message: "Chave privada SSH/TLS desprotegida encontrada no repositório.".to_string(),
                        suggestion: Some("Mova para ~/.ssh/ ou armazene criptografado com sops/age em mnemocine/secrets.enc.env.".to_string()),
                    });
                }

                // Detecta tokens e senhas literais em texto plano (fora de templates/exemplos)
                if !path_str.contains(".template")
                    && !path_str.contains(".example")
                    && !path_str.contains("templates/")
                {
                    for (line_idx, line) in content.lines().enumerate() {
                        let trimmed = line.trim();
                        // Ignora comentários e linhas vazias
                        if trimmed.starts_with('#') || trimmed.starts_with("//") {
                            continue;
                        }

                        let is_leak = (trimmed.starts_with("ghp_")
                            || trimmed.starts_with("github_pat_"))
                            || ((trimmed.starts_with("PASSWORD=")
                                || trimmed.starts_with("API_KEY=")
                                || trimmed.starts_with("SECRET="))
                                && !trimmed.ends_with("=\"\"")
                                && !trimmed.ends_with("=")
                                && !trimmed.contains("ENC[AES256_GCM")
                                && !trimmed.contains("${")
                                && !trimmed.contains("$("));

                        if is_leak && !is_sops_encrypted && !is_age_armored {
                            violations.push(Violation {
                                rule_id: "SEC-PLAINTEXT-SECRET".to_string(),
                                rule_name: "Segredo em Texto Claro Detectado".to_string(),
                                severity: Severity::Error,
                                file_path: path_str.clone(),
                                line_number: line_idx + 1,
                                snippet: format!("{:.30}...", trimmed),
                                message: "Credencial ou token em texto claro encontrado em arquivo de infraestrutura.".to_string(),
                                suggestion: Some("Substitua o valor por variável de ambiente ou criptografe via sops/age.".to_string()),
                            });
                            break; // 1 aviso por arquivo
                        }
                    }
                }
            }
        }

        // ── 2. Validação Estática de Docker Compose (INFRA-COMPOSE) ───────────
        let is_compose = file_name == "compose.yml"
            || file_name == "compose.yaml"
            || file_name == "docker-compose.yml"
            || file_name == "docker-compose.yaml";

        if is_compose {
            scanned_count += 1;
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };

            // Validação de sintaxe YAML
            match serde_yaml::from_str::<serde_yaml::Value>(&content) {
                Ok(yaml_val) => {
                    // Checagens estruturais de compose
                    if let Some(services) = yaml_val.get("services").and_then(|s| s.as_mapping()) {
                        for (svc_key, svc_val) in services {
                            let svc_name = svc_key.as_str().unwrap_or("unknown");

                            // Checagem de política de restart
                            let has_restart = svc_val.get("restart").is_some()
                                || svc_val
                                    .get("deploy")
                                    .and_then(|d| d.get("restart_policy"))
                                    .is_some();
                            if !has_restart {
                                violations.push(Violation {
                                    rule_id: "INFRA-COMPOSE-RESTART".to_string(),
                                    rule_name: "Política de Restart Ausente no Serviço".to_string(),
                                    severity: Severity::Warning,
                                    file_path: path_str.clone(),
                                    line_number: 1,
                                    snippet: format!("{}:", svc_name),
                                    message: format!("Serviço '{}' não define 'restart: unless-stopped' ou 'restart: always'.", svc_name),
                                    suggestion: Some("Adicione 'restart: unless-stopped' ao serviço no compose.yml.".to_string()),
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    violations.push(Violation {
                        rule_id: "INFRA-COMPOSE-SYNTAX".to_string(),
                        rule_name: "Erro de Sintaxe em Docker Compose".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: e.to_string(),
                        message: format!("Sintaxe inválida no arquivo compose: {}", e),
                        suggestion: Some(
                            "Corrija a formatação YAML do arquivo compose.yml.".to_string(),
                        ),
                    });
                }
            }
        }

        // ── 3. Validação Estática de Systemd Units (INFRA-SYSTEMD-SYNTAX) ─────
        if file_name.ends_with(".service") || file_name.ends_with(".timer") {
            scanned_count += 1;
            if let Ok(content) = fs::read_to_string(&path) {
                let has_unit = content.contains("[Unit]");
                let has_service_or_timer =
                    content.contains("[Service]") || content.contains("[Timer]");
                let has_install = content.contains("[Install]");

                if !has_unit || !has_service_or_timer || !has_install {
                    violations.push(Violation {
                        rule_id: "INFRA-SYSTEMD-SYNTAX".to_string(),
                        rule_name: "Estrutura Incompleta de Systemd Unit".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: "".to_string(),
                        message: "Arquivo unit do systemd deve conter seções [Unit], [Service]/[Timer] e [Install].".to_string(),
                        suggestion: Some("Adicione as seções obrigatórias padrão do systemd.".to_string()),
                    });
                }
            }
        }

        // ── 4. Práticas Estritas de Scripts Bash (INFRA-BASH-STRICT) ───────────
        if file_name.ends_with(".sh") {
            scanned_count += 1;
            if let Ok(content) = fs::read_to_string(&path) {
                if !content.contains("set -euo pipefail") && !content.contains("set -e") {
                    violations.push(Violation {
                        rule_id: "INFRA-BASH-STRICT".to_string(),
                        rule_name: "Script Bash Sem Modo Estrito (set -euo pipefail)".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: content.lines().next().unwrap_or("").to_string(),
                        message: "Scripts de automação no Homelab devem conter 'set -euo pipefail' para falhar rapidamente em caso de erro.".to_string(),
                        suggestion: Some("Adicione 'set -euo pipefail' logo abaixo da shebang (#/bin/bash).".to_string()),
                    });
                }
            }
        }

        // ── 5. Detecção de Débito Técnico: Python Fora do Hub (ARCH-LEGACY-PYTHON)
        if file_name.ends_with(".py") {
            scanned_count += 1;
            violations.push(Violation {
                rule_id: "ARCH-LEGACY-PYTHON".to_string(),
                rule_name: "Script Python Legado Detectado".to_string(),
                severity: Severity::Warning,
                file_path: path_str.clone(),
                line_number: 1,
                snippet: format!("Arquivo: {}", file_name),
                message: "Script Python legado encontrado no workspace. Avaliar migração para Rust nativo ou congelamento.".to_string(),
                suggestion: Some("Reescreva o script em Rust ou documente a exceção com metadados.".to_string()),
            });
        }

        // ── 6. Auditoria de Permissões POSIX em Segredos (SEC-PERM-LEAK) ──────
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file_name == "secrets.env"
                || file_name == "keys.txt"
                || file_name.contains("id_ed25519")
                || file_name.contains("id_rsa")
            {
                if let Ok(meta) = fs::metadata(&path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode > 0o600 {
                        violations.push(Violation {
                            rule_id: "SEC-PERM-LEAK".to_string(),
                            rule_name: "Permissões POSIX Inseguras em Arquivo de Segredo".to_string(),
                            severity: Severity::Error,
                            file_path: path_str.clone(),
                            line_number: 1,
                            snippet: format!("Permissão atual: 0{:o}", mode),
                            message: format!("Arquivo sensível '{}' possui permissão 0{:o} (deve ser 0600 ou 0400).", file_name, mode),
                            suggestion: Some("Corrija imediatamente executando: chmod 0600 <arquivo>.".to_string()),
                        });
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} arquivos de infraestrutura (Compose/Systemd/SOPS) auditados e conformes.",
            scanned_count
        ));
    } else {
        messages.push(format!(
            "ℹ️ {} desvio(s) de infraestrutura detectados.",
            violations.len()
        ));
    }

    InfraReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
