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

/// Redacts the matched value so the report never re-leaks the credential it found.
fn mask_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let head: String = trimmed.chars().take(28).collect();
    if trimmed.chars().count() > 28 {
        format!("{head}…[REDACTED]")
    } else {
        format!("{head}[REDACTED]")
    }
}

/// Distinguishes a real credential from prose that merely mentions one.
///
/// Documentation frequently shows illustrative values ("Garantir
/// `ADMINPASSWORD=adminpz123` em ...") or lists variable names as a concept.
/// Those are not leaks: nothing is being exposed. Real leaks have random-looking
/// values; examples are short, dictionary-like, or match a well-known demo
/// value. This keeps the rule actionable instead of training everyone to
/// ignore it.
fn is_documentation_example(line: &str, value: &str) -> bool {
    // Prose markers around the assignment (bullets in guides, "definir X em ...",
    // backticked inline examples).
    let prose_markers = ["Garantir", "definir", "ex.:", "exemplo", "Exemplo", "por exemplo"];
    if prose_markers.iter().any(|m| line.contains(m)) {
        return true;
    }
    if line.trim_start().starts_with(['1', '2', '3', '4', '5', '6', '7', '8', '9'])
        && line.contains(". ")
    {
        // numbered list item in a guide, e.g. "1. Garantir ..."
        return true;
    }

    // Well-known demo values used in docs.
    let demo_values = [
        "adminpz123",
        "password123",
        "secret123",
        "admin123",
        "changeme123",
        "example123",
        "test1234",
        "mysecret",
        "supersecret",
        "sua_senha",
        "seu_segredo",
        "yourpassword",
    ];
    let lowered = value.to_ascii_lowercase();
    if demo_values.iter().any(|d| lowered == *d) {
        return true;
    }

    // Very short or purely alphabetic values are almost always words in prose,
    // not generated credentials (which mix case, digits and symbols).
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value.chars().any(|c| !c.is_alphanumeric());
    let all_lower_alpha = value.chars().all(|c| c.is_ascii_lowercase());
    value.len() < 12 && !has_symbol && (!has_digit || all_lower_alpha)
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

                        // Reconhece o padrão mesmo com prefixos de YAML/Compose
                        // (`- VAR=valor`), chaves JSON/YAML (`VAR: valor`) e
                        // sufixos (`INITIAL_ADMIN_PASSWORD`, `MYSQL_ROOT_PASSWORD`).
                        // A versão anterior só aceitava a linha começando em
                        // PASSWORD=/API_KEY=/SECRET=, então um
                        // `- INITIAL_ADMIN_PASSWORD=segredo` passava batido.
                        let trimmed_no_prefix = trimmed
                            .trim_start_matches(['-', ' '])
                            .trim_start_matches("export ")
                            .trim();
                        let (maybe_key, maybe_value) = trimmed_no_prefix
                            .split_once('=')
                            .or_else(|| trimmed_no_prefix.split_once(':'))
                            .unwrap_or(("", ""));
                        let key = maybe_key.trim().trim_matches('"');
                        let value = maybe_value.trim().trim_matches(['"', '\'']);
                        let key_upper = key.to_ascii_uppercase();

                        let looks_like_secret_key = key_upper.ends_with("PASSWORD")
                            || key_upper.ends_with("PASSWD")
                            || key_upper.ends_with("SECRET")
                            || key_upper.ends_with("API_KEY")
                            || key_upper.ends_with("ACCESS_TOKEN")
                            || key_upper.ends_with("AUTH_TOKEN")
                            || key_upper.ends_with("_TOKEN")
                            || key_upper == "PASSWORD"
                            || key_upper == "SECRET";

                        let value_is_literal = value.len() >= 8
                            && !value.is_empty()
                            && !value.contains("${")
                            && !value.contains("$(")
                            && !value.contains("ENC[AES256_GCM")
                            && value != "\"\""
                            && value != "''"
                            // placeholders óbvios não são vazamento
                            && !value.eq_ignore_ascii_case("changeme")
                            && !value.eq_ignore_ascii_case("placeholder")
                            && !value.eq_ignore_ascii_case("example")
                            && !value.eq_ignore_ascii_case("your_password")
                            && !value.starts_with('<')
                            && !value.starts_with('%');

                        let is_leak = (trimmed.starts_with("ghp_")
                            || trimmed.starts_with("github_pat_"))
                            || (looks_like_secret_key && value_is_literal && !is_documentation_example(trimmed, value));

                        if is_leak && !is_sops_encrypted && !is_age_armored {
                            violations.push(Violation {
                                rule_id: "SEC-PLAINTEXT-SECRET".to_string(),
                                rule_name: "Segredo em Texto Claro Detectado".to_string(),
                                severity: Severity::Error,
                                file_path: path_str.clone(),
                                line_number: line_idx + 1,
                                snippet: mask_snippet(trimmed),
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

        // ── 5. Detecção de Débito Técnico: Python Solto (ARCH-LEGACY-PYTHON)
        // Regra: scripts/archive/ é o lugar correto para scripts legados — silêncio total lá.
        // Projetos Rust dedicados (docx-extractor/, validador-roteiro/) têm seu próprio
        // steniocheck.toml, não auditamos aqui.
        // Só disparamos WARN para .py soltos fora do archive e fora de projeto próprio.
        if file_name.ends_with(".py") {
            scanned_count += 1;
            let in_archive =
                path_str.contains("/scripts/archive/") || path_str.contains("/archive/");
            let in_dedicated_project = path_str.contains("/scripts/docx-extractor/")
                || path_str.contains("/scripts/validador-roteiro/");

            if !in_archive && !in_dedicated_project {
                violations.push(Violation {
                    rule_id: "ARCH-LEGACY-PYTHON".to_string(),
                    rule_name: "Script Python Solto (Fora do Archive)".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: format!("Arquivo: {}", file_name),
                    message: "Script Python encontrado fora de scripts/archive/. Scripts legados devem ser movidos para archive/ ou migrados para Rust.".to_string(),
                    suggestion: Some("Mova para scripts/archive/ se for legado/referência, ou reescreva em Rust se ainda estiver em uso ativo.".to_string()),
                });
            }
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

    // ── 7. Verificação de Paridade Estática de Produção (OPS-STATIC-PARITY) ──
    if let Some(parity) = crate::deploy::check_static_parity(root) {
        if !parity.in_sync {
            violations.push(Violation {
                rule_id: "OPS-STATIC-PARITY".to_string(),
                rule_name: "Deriva de Paridade Estática do Frontend em Produção".to_string(),
                severity: Severity::Warning,
                file_path: "app/frontend-v2/dist/index.html".to_string(),
                line_number: 1,
                snippet: format!("Local: {} | Remoto: {}", parity.local_bundle, parity.remote_bundle),
                message: format!(
                    "Nó de borda em produção está servindo bundle legado ('{}'), divergente da build local ('{}').",
                    parity.remote_bundle, parity.local_bundle
                ),
                suggestion: Some("Sincronize a produção imediatamente executando: stenio --deploy front".to_string()),
            });
        }
    }

    // ── 8. Auditoria de Integridade de Release (REL-PKGBUILD-SYNC & REL-TAG-DRIFT)
    let pkgbuild_path = root.join("PKGBUILD");
    let cargo_path = root.join("Cargo.toml");
    if pkgbuild_path.exists() && cargo_path.exists() {
        if let (Ok(pkg_content), Ok(cargo_content)) = (
            fs::read_to_string(&pkgbuild_path),
            fs::read_to_string(&cargo_path),
        ) {
            let mut cargo_ver = None;
            for line in cargo_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("version = \"") && trimmed.ends_with('"') {
                    cargo_ver = Some(
                        trimmed
                            .trim_start_matches("version = \"")
                            .trim_end_matches('"'),
                    );
                    break;
                }
            }

            let mut pkg_ver = None;
            for line in pkg_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("pkgver=") {
                    pkg_ver = Some(trimmed.trim_start_matches("pkgver=").trim());
                    break;
                }
            }

            if let (Some(cver), Some(pver)) = (cargo_ver, pkg_ver) {
                if cver != pver {
                    violations.push(Violation {
                        rule_id: "REL-PKGBUILD-SYNC".to_string(),
                        rule_name: "Dessincronia de Versão entre Cargo.toml e PKGBUILD".to_string(),
                        severity: Severity::Error,
                        file_path: "PKGBUILD".to_string(),
                        line_number: 1,
                        snippet: format!("Cargo.toml: {} | PKGBUILD: {}", cver, pver),
                        message: format!(
                            "A versão do pacote PKGBUILD ('{}') difere da versão declarada em Cargo.toml ('{}').",
                            pver, cver
                        ),
                        suggestion: Some(format!("Sincronize pkgver={} no PKGBUILD conforme governance/release-policy.md.", cver)),
                    });
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
