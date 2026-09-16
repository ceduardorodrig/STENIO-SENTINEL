use crate::config::SteniocheckConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub tag: String,
    pub severity: Severity,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub file_extensions: Vec<String>,
    pub must_match: bool,
    pub suggestion: Option<String>,
    pub fix_replacement: Option<String>,
}

impl Rule {
    pub fn new(
        id: &str,
        tag: &str,
        severity: Severity,
        name: &str,
        description: &str,
        pattern: &str,
        file_extensions: &[&str],
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tag: tag.to_string(),
            severity,
            name: name.to_string(),
            description: description.to_string(),
            pattern: pattern.to_string(),
            file_extensions: file_extensions.iter().map(|s| s.to_string()).collect(),
            must_match: false,
            suggestion: suggestion.map(|s| s.to_string()),
            fix_replacement: None,
        }
    }

    pub fn with_fix(mut self, fix: &str) -> Self {
        self.fix_replacement = Some(fix.to_string());
        self
    }
}

pub fn get_rules_from_config(config: &SteniocheckConfig) -> Vec<Rule> {
    let mut rules = Vec::new();

    // ── 0. Soberania Rust: Proibição Total de Arquivos Python ──────────────
    rules.push(Rule::new(
        "ARCH-NO-PYTHON",
        "arch",
        Severity::Error,
        "Arquivo Python Proibido",
        "O repositório migrou 100% para Rust nativo (ADR-036). Nenhum arquivo .py deve ser criado ou mantido.",
        r".+",
        &["py"],
        Some("Remova o arquivo .py e reescreva a funcionalidade em Rust nativo dentro de app/server/src/."),
    ));

    // ── 1. Banimento Dinâmico de Pacotes Python (de steniocheck.toml) ────────
    let banned_pkgs = config
        .security
        .as_ref()
        .and_then(|s| s.banned_python_packages.clone())
        .unwrap_or_else(|| vec!["torch".to_string(), "ctranslate2".to_string()]);

    for pkg in banned_pkgs {
        let pattern = format!(r"(?m)^\s*(import\s+{}\b|from\s+{}\b)", pkg, pkg);
        rules.push(Rule::new(
            &format!("SEC-BAN-{}", pkg.to_uppercase()),
            "sec",
            Severity::Error,
            &format!("Banimento de {}", pkg),
            &format!("O uso de '{}' é proibido após a migração para Rust.", pkg),
            &pattern,
            &["py"],
            Some(&format!("Elimine a dependência '{}' e utilize a engine Rust em app/server.", pkg)),
        ));
    }

    // ── 2. Banimento Dinâmico de Módulos Legados Descomissionados ───────────
    let banned_mods = config
        .architecture
        .as_ref()
        .and_then(|a| a.banned_modules.clone())
        .unwrap_or_else(|| {
            vec![
                "core.canvas".to_string(),
                "core.ocr_engine".to_string(),
                "worker_vision".to_string(),
                "run_vision".to_string(),
                "run_datavis".to_string(),
                "worker_datavis".to_string(),
                "core.whisper_pytorch".to_string(),
            ]
        });

    let mod_joined = banned_mods
        .iter()
        .map(|m| regex::escape(m))
        .collect::<Vec<_>>()
        .join("|");
    let mod_pattern = format!(r"(?m)^\s*(from|import)\s+({})\b", mod_joined);

    rules.push(Rule::new(
        "ARCH-BANNED-MODULES",
        "arch",
        Severity::Error,
        "Import de Módulos Descomissionados",
        "Não importar módulos de visão, OCR, canvas, datavis ou whisper_pytorch legados.",
        &mod_pattern,
        &["py"],
        Some("Remova o import do módulo legado descomissionado."),
    ));

    // ── 3. Proibição de Sudo Puro (AGENTS.md Regra 10) ──────────────────────
    // Padrão cobre QUALQUER comando executado via sudo, sem lista branca.
    // O fix substitui apenas "sudo " por "pkexec ", preservando o comando e args intactos.
    rules.push(Rule::new(
        "SEC-SUDO",
        "sec",
        Severity::Error,
        "Proibição de sudo puro",
        "Regra 10 do AGENTS.md: Use pkexec em vez de sudo em scripts sem TTY.",
        r"(?m)\bsudo\s+",
        &["sh", "bash"],
        Some("Substitua 'sudo <comando>' por 'pkexec <comando>' ou execute dentro de container com privilégios configurados."),
    ).with_fix("pkexec "));

    // ── 4. Scanner Universal de Credenciais & Segredos ──────────────────────
    rules.push(Rule::new(
        "SEC-SECRETS",
        "sec",
        Severity::Error,
        "Segredos Hardcoded",
        "Tokens de API ou chaves privadas não devem constar em claro no código.",
        r#"(ghp_[A-Za-z0-9]{36}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----|sk-[A-Za-z0-9]{48})|(?i)(api_key|secret_key)\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]"#,
        &["py", "rs", "ts", "tsx", "js", "sh"],
        Some("Remova o token em claro e injete via variável de ambiente (.env) ou segredo no cofre do sistema."),
    ));

    // ── 5. Segurança SQL ───────────────────────────────────────────────────
    rules.push(Rule::new(
        "SEC-SQL",
        "sec",
        Severity::Warning,
        "Interpolação de SQL Insegura",
        "Use queries parametrizadas em vez de formatar strings diretamente no SQL.",
        r#"f["'].*?(SELECT\s+|INSERT\s+INTO\s+|UPDATE\s+\w+\s+SET\s+|DELETE\s+FROM\s+).*?\{"#,
        &["py"],
        Some("Utilize parâmetros bind ($1, $2) do SQLx / queries preparadas em vez de interpolação de strings."),
    ));

    // ── 6. Error Handling sem Bare Except ───────────────────────────────────
    rules.push(Rule::new(
        "SEC-EXCEPT",
        "sec",
        Severity::Warning,
        "Bare Except Proibido",
        "Blocos except devem capturar tipos específicos de Exception (evite 'except:').",
        r"(?m)^\s*except\s*:",
        &["py"],
        Some("Especifique a classe de erro (ex: except Exception as err: ou tipo específico)."),
    ));

    // ── 7. Frontend: Zustand Selector Stability (sem loop infinito) ────────
    rules.push(Rule::new(
        "FRONT-ZUSTAND",
        "frontend",
        Severity::Warning,
        "Zustand Seletor Instável",
        "Objetos retornados por seletores Zustand causam re-renderizações infinitas sem useShallow.",
        r"use[A-Za-z0-9]+Store\s*\(\s*\([^)]*\)\s*=>\s*\{",
        &["ts", "tsx"],
        Some("Envolva a função do seletor em useShallow(state => ({ ... })) importado de 'zustand/react/shallow'."),
    ));

    // ── 8. Frontend: Pureza de Logs de Produção ────────────────────────────
    rules.push(Rule::new(
        "FRONT-LOGS",
        "frontend",
        Severity::Warning,
        "Logs Residuais no Frontend",
        "Remova logs de depuração console.log/console.debug antes de enviar para produção.",
        r"(?m)^\s*console\.(log|debug)\(",
        &["ts", "tsx"],
        Some("Remova o console.log/debug ou envolva-o em uma checagem de ambiente de desenvolvimento."),
    ));

    // ── 9. Infra: Nginx WebSocket Buffering ────────────────────────────────
    rules.push(Rule::new(
        "INFRA-WS-BUFFERING",
        "infra",
        Severity::Warning,
        "Nginx WebSocket Buffering",
        "Locations de WebSocket no Nginx devem definir 'proxy_buffering off' para streaming em tempo real.",
        r"proxy_pass\s+http://[^;]+;\s*#\s*ws",
        &["conf", "j2"],
        Some("Adicione 'proxy_buffering off;' e 'proxy_cache off;' na configuração do proxy WebSocket."),
    ));

    // ── 10. Arquitetura: Preferência por Ferramentas Rust ──────────────────
    rules.push(Rule::new(
        "ARCH-RUST-TOOLS",
        "arch",
        Severity::Warning,
        "Uso de Ferramentas GNU Legadas",
        "Regra de Terminal do AGENTS.md: Preferir alternativas Rust (eza, bat, rg, fd, dust).",
        r"(?m)^\s*(grep\s+-r|find\s+\.\s+-name|du\s+-sh)\b",
        &["sh"],
        Some("Substitua comandos GNU pelas alternativas Rust: grep -> rg, find -> fd, du -> dust, ls -> eza."),
    ));

    // ── 11. Rust: Proibição de Thread Sleep em Runtime Assíncrono ──────────
    rules.push(Rule::new(
        "RUST-ASYNC-SLEEP",
        "rust",
        Severity::Error,
        "std::thread::sleep em Código Assíncrono",
        "Em código assíncrono Tokio, use tokio::time::sleep para evitar bloquear a thread do runtime.",
        r"\bstd::thread::sleep\(",
        &["rs"],
        Some("Substitua 'std::thread::sleep(dur);' por 'tokio::time::sleep(dur).await;'."),
    ));

    // ── 12. Rust: Logging Estruturado em Servidor Web ──────────────────────
    rules.push(Rule::new(
        "RUST-STRUCTURED-LOGGING",
        "rust",
        Severity::Warning,
        "Uso de println! no Servidor",
        "Em servidores web Axum, utilize macros do crate tracing (info!, warn!, error!, debug!) em vez de println!.",
        r"(?m)^\s*(println!|eprintln!)\(",
        &["rs"],
        Some("Substitua println!/eprintln! por tracing::info!, tracing::warn! ou tracing::error!."),
    ));

    // ── 13. Soberania Rust: Proibição de Chamadas a Ferramentas GNU em Código .rs ──
    // Garante que o próprio código Rust não invoque binários GNU via Command::new().
    // O Stênio é o guardião; ele não pode violar as regras que impõe.
    rules.push(Rule::new(
        "ARCH-RUST-CMD-LEGACY",
        "arch",
        Severity::Warning,
        "Ferramenta GNU Legada Invocada em Código Rust",
        "Command::new() com ferramentas GNU viola AGENTS.md. Use equivalentes Rust: xh (curl), walkdir (find), regex (grep), statvfs/nix (df).",
        r#"Command::new\("(df|curl|find|grep|ls|cat|sed|du|awk|ps|top)"\)"#,
        &["rs"],
        Some("Substitua pela alternativa Rust nativa: curl→xh, df→/proc/statvfs ou nix crate, find→walkdir, grep→regex."),
    ));

    // ── 14. Regras Customizadas e Aprendidas Dinamicamente (steniocheck.toml) ──

    if let Some(custom_rules) = &config.custom_rules {
        for cr in custom_rules {
            let sev = match cr.severity.as_deref().map(|s| s.to_lowercase()).as_deref() {
                Some("warning") | Some("warn") => Severity::Warning,
                _ => Severity::Error,
            };
            let rule = Rule {
                id: cr.id.clone(),
                tag: cr.tag.clone().unwrap_or_else(|| "custom".to_string()),
                severity: sev,
                name: cr.name.clone(),
                description: cr.description.clone(),
                pattern: cr.pattern.clone(),
                file_extensions: cr.extensions.clone(),
                must_match: cr.must_match.unwrap_or(false),
                suggestion: cr.suggestion.clone(),
                fix_replacement: cr.fix_replacement.clone(),
            };
            rules.push(rule);
        }
    }

    rules
}
