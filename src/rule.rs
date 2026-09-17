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

    #[allow(dead_code)]
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
            Some(&format!(
                "Elimine a dependência '{}' e utilize a engine Rust em app/server.",
                pkg
            )),
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

    // ── 3. Uso de Sudo e Privilégios de Sistema (AGENTS.md Regra 10) ────────
    // Em automações profissionais, o usuário deve possuir regra NOPASSWD no sudoers
    // ou as credenciais devem ser injetadas via .env/SOPS.
    // 'pkexec' é apenas mecanismo gráfico opcional do KDE no psicopompo; em scripts de servidor
    // ou tarefas repetidas deve ser evitado para não cansar o operador com diálogos de senha.
    rules.push(Rule::new(
        "SEC-SUDO",
        "sec",
        Severity::Warning,
        "Atenção ao Uso de Sudo em Scripts",
        "Regra 10 do AGENTS.md: Automações devem utilizar sudoers (NOPASSWD) ou .env/SOPS. Evite senhas interativas ou forçar pkexec em servidores headless.",
        r"(?m)\bsudo\s+",
        &["sh", "bash"],
        Some("Configure regra NOPASSWD no sudoers para o usuário da máquina ou injete credenciais via .env/SOPS."),
    ));

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

    // ── 14. Soberania Rust: Proibição de unwrap()/expect() em Produção ─────
    rules.push(Rule::new(
        "RUST-NO-UNWRAP",
        "rust",
        Severity::Warning,
        "Uso de unwrap() ou expect() em Código de Produção",
        "Chamadas a .unwrap() ou .expect() podem causar panics em runtime. Trate erros com '?', match, ou métodos com fallback.",
        r"\.(unwrap|expect)\(",
        &["rs"],
        Some("Substitua .unwrap()/.expect() por '?' (operador try), pattern matching com 'match'/'if let', ou métodos seguros como .unwrap_or_default() / .ok_or(...)."),
    ));

    // ── 15. Anti-Preguiça: Proibição de Stubs e Placeholders de IA ─────────
    rules.push(Rule::new(
        "AGENT-NO-LAZY-STUB",
        "gov",
        Severity::Error,
        "Placeholder ou Stub Preguiçoso de IA",
        "Modelos de IA não devem deixar código incompleto com stubs, 'todo!()', 'unimplemented!()' ou '// rest of code'.",
        r#"(?i)(//\s*(\.\.\.|rest of (the )?code|existing code|code remains|TODO:?\s*implement|add logic here)|\b(todo!|unimplemented!)\(|\bthrow new Error\(["'](Not implemented|TODO)["']\))"#,
        &["rs", "ts", "tsx", "js", "py", "sh"],
        Some("Implemente o código completo da funcionalidade. É expressamente proibido usar stubs, 'todo!()' ou placeholders em entregas."),
    ));

    // ── 15.1 Anti-Bypass: Proibição de Diretivas de Supressão e Ignorância ─
    rules.push(Rule::new(
        "AGENT-NO-SUPPRESSION-DIRECTIVES",
        "gov",
        Severity::Error,
        "Diretiva de Supressão ou Bypass Proibida",
        "Proíbe o uso de @ts-ignore, @ts-nocheck, eslint-disable, type: ignore ou stenio-ignore: all para mascarar erros.",
        r#"(?m)(//\s*@ts-(ignore|nocheck)|/\*\s*eslint-disable|#\s*type:\s*ignore|//\s*stenio-ignore:\s*all)"#,
        &["ts", "tsx", "js", "rs", "py", "sh"],
        Some("Corrija a tipagem ou a conformidade real do código. É proibido mascarar erros com diretivas de supressão."),
    ));

    // ── 15.2 Anti-Tampering: Proibição de Adulteração de Hooks e Verificadores ─
    rules.push(Rule::new(
        "AGENT-NO-TAMPERING-VERIFIER",
        "gov",
        Severity::Error,
        "Tentativa de Adulteração de Verificador ou Hook",
        "Proíbe desativar pre-commit hooks, comentar chamadas ao stenio ou adulterar configurações de auditoria.",
        r#"(?m)(stenio\s+.*--no-verify|git\s+commit\s+.*--no-verify|\.git/hooks/.*exit\s+0|rm\s+-f\s+\.git/hooks)"#,
        &["sh", "bash", "ts", "tsx", "js", "rs"],
        Some("Nunca ignore nem desative hooks de validação (--no-verify). O Stênio é o árbitro canônico de entrega."),
    ));

    // ── 15.3 Integridade de Build: Proibição de Enfraquecimento de Modo Estrito ─
    rules.push(Rule::new(
        "CONF-NO-WEAKEN-STRICT",
        "gov",
        Severity::Error,
        "Enfraquecimento de Modo Estrito no Compilador",
        "Proíbe desativar o modo estrito ('\"strict\": false') em tsconfig.json ou desabilitar verificações de segurança.",
        r#""strict"\s*:\s*false|"noImplicitAny"\s*:\s*false"#,
        &["json"],
        Some("Mantenha '\"strict\": true' no compilador TypeScript para garantir segurança de tipos."),
    ));

    // ── 16. Integridade de Testes: Proibição de Desativação Silenciosa de Testes ──
    rules.push(Rule::new(
        "TEST-NO-SILENT-SKIP",
        "test",
        Severity::Error,
        "Teste Desativado ou Asserção Comentada",
        "Proíbe o uso de #[ignore], test.skip ou asserções comentadas para mascarar falhas em testes.",
        r#"(?m)(^\s*#\[ignore\]|^\s*//\s*(assert!|assert_eq!|assert_ne!|expect\()|\b(it|test|describe)\.skip\(|\b(xit|xtest)\(|@pytest\.mark\.skip)"#,
        &["rs", "ts", "tsx", "js", "py"],
        Some("Não desative testes nem comente asserções para fazer os testes passarem. Identifique e corrija a causa raiz no código."),
    ));

    // ── 17. Confiabilidade: Proibição de Tratamento de Erro Vazio (Catch Vazio) ──
    rules.push(Rule::new(
        "CODE-NO-EMPTY-CATCH",
        "gov",
        Severity::Warning,
        "Tratamento de Erro Silenciado (Catch Vazio)",
        "Blocos catch/except vazios engolem erros silenciosamente sem registrar log.",
        r#"(?m)(catch\s*(\([^\)]*\))?\s*\{\s*\}|^\s*except(\s+\w+)?:\s*pass\s*$)"#,
        &["ts", "tsx", "js", "py"],
        Some("Registre o erro nos logs (tracing, logger, console.error) ou propague a falha com '?'. Nunca engula erros."),
    ));

    // ── 18. Backend: Proibição de Operações de E/S Síncronas em Tokio ──────
    rules.push(Rule::new(
        "BACKEND-BLOCKING-IO",
        "rust",
        Severity::Error,
        "E/S Bloqueante (std::fs) em Runtime Assíncrono",
        "O uso de std::fs em handlers assíncronos bloqueia as threads do pool Tokio. Utilize tokio::fs.",
        r"\bstd::fs::(read|write|read_to_string|remove_file|copy|rename|create_dir)\(",
        &["rs"],
        Some("Substitua 'std::fs::*' por 'tokio::fs::*' com '.await' ou 'tokio::task::spawn_blocking'."),
    ));

    // ── 19. Backend: Proibição de Panics e Asserts em Servidor Web ─────────
    rules.push(Rule::new(
        "BACKEND-NO-PANIC",
        "rust",
        Severity::Warning,
        "Panic ou Assert em Código de Servidor",
        "Chamadas a panic!() ou assert!() derrubam o processo do servidor web. Trate erros graciosamente retornando Result.",
        r"(?m)^\s*(panic!|assert!|assert_eq!|assert_ne!)\(",
        &["rs"],
        Some("Retorne um erro HTTP estruturado (ex: Err(AppError::BadRequest(...))) em vez de causar panic no servidor."),
    ));

    // ── 20. Arquitetura: Princípio DRY (Don't Repeat Yourself) Obrigatório ─
    rules.push(Rule::new(
        "ARCH-DRY-DUPLICATION",
        "arch",
        Severity::Warning,
        "Duplicação de Código (Princípio DRY)",
        "Proíbe blocos de código substantivos duplicados (>6 linhas idênticas). Extraia a lógica em funções compartilhadas ou hooks.",
        r"(?m)^.*stenio-dry-marker.*$",
        &["rs", "ts", "tsx", "py", "js"],
        Some("Extraia a lógica duplicada para um hook customizado ('features/<dominio>/hooks/'), componente atômico ou função utilitária."),
    ));

    // ── 21. Frontend & GPU: Zero-Repaint em Animações e Hovers 3D ──────────
    rules.push(Rule::new(
        "PERF-GPU-ZERO-REPAINT",
        "frontend",
        Severity::Warning,
        "Transição de Paint em Container 3D/Hover",
        "Transições em 'box-shadow', 'backdrop-filter' ou 'background-color' forçam repaint de GPU a cada frame.",
        r"(?m)(transition:.*(box-shadow|backdrop-filter)|magic-card-tilt-container.*transition-(colors|all))",
        &["css", "tsx"],
        Some("Anime a opacidade (0 -> 1) de um pseudo-elemento ::after isolado no Compositor da GPU em vez de transicionar sombra ou fundo."),
    ));

    // ── 22. Frontend & GPU: Proibição de Layout Thrashing em Eventos ────────
    rules.push(Rule::new(
        "PERF-NO-LAYOUT-THRASH",
        "frontend",
        Severity::Warning,
        "Layout Thrashing em Event Handlers",
        "Leituras síncronas de geometria (getBoundingClientRect / offset*) em handlers de mouse disparam reflow forçado a 1000Hz.",
        r"\.getBoundingClientRect\(\)",
        &["ts", "tsx"],
        Some("Faça cache do rect em um useRef no onMouseEnter ou bufferize coordenadas e processe no tick do requestAnimationFrame."),
    ));

    // ── 23. Frontend & GPU: Contenção de Grade Arandu (.card-cell) ─────────
    rules.push(Rule::new(
        "PERF-GPU-CONTAINMENT",
        "frontend",
        Severity::Warning,
        "Grade de Cards sem Contenção CSS",
        "Grades densas de cards com hover/tilt 3D exigem contenção CSS (.card-cell) para não invalidar o layout de cards vizinhos.",
        r"<MagicCard",
        &["tsx"],
        Some("Envolva cada MagicCard em um container <div className=\"card-cell\"><MagicCard ... /></div>."),
    ));

    // ── 24. Frontend & GPU: will-change Restrito a Estados Interativos ──────
    rules.push(Rule::new(
        "PERF-GPU-WILL-CHANGE",
        "frontend",
        Severity::Warning,
        "will-change Estático em Repouso",
        "'will-change' aplicado estaticamente consome texturas de GPU em repouso. Mantenha restrito a seletores :hover.",
        r"will-change:\s*(transform|opacity)",
        &["css"],
        Some("Aplique 'will-change: transform' estritamente sob seletores de interação (:hover, .is-hovered) e remova em repouso."),
    ));

    // ── 25. Frontend: Desacoplamento de Chamadas de Rede em Páginas ─────────
    rules.push(Rule::new(
        "FRONT-MODULAR-HOOKS",
        "frontend",
        Severity::Warning,
        "Chamada de Rede Direta na Camada de Página",
        "Páginas são orquestradores puros (<400 linhas). Chamadas de API diretas violam o desacoplamento arquitetural.",
        r"(fetch\(|axios\.|new WebSocket\()",
        &["tsx"],
        Some("Extraia a chamada de API e a lógica de mutação para um Custom Hook em 'src/features/<dominio>/hooks/'."),
    ));

    // ── 26. Frontend: Proibição de Erros Silenciados sem Feedback Visual ───
    rules.push(Rule::new(
        "FRONT-FEEDBACK-ON-ERROR",
        "frontend",
        Severity::Warning,
        "Erro em UI sem Feedback Visual",
        "Blocos catch que apenas emitem console.error deixam o usuário sem resposta visual se a ação falhar.",
        r"console\.(error|warn)\(",
        &["tsx", "ts"],
        Some("Adicione notificação com toast.error('Mensagem') ou atualize o estado de erro do componente."),
    ));

    // ── 27. Frontend: Proibição de URLs Hardcoded de Localhost ─────────────
    rules.push(Rule::new(
        "FRONT-NO-HARDCODED-HOST",
        "frontend",
        Severity::Error,
        "URL de Localhost Hardcoded no Frontend",
        "URLs absolutas de localhost quebram em produção atrás do proxy Nginx.",
        r"(?m)^.*stenio-frontend-marker.*$",
        &["tsx", "ts", "js"],
        Some("Utilize caminho relativo (/api/...) ou carregue a URL via 'import.meta.env.VITE_API_URL'."),
    ));

    // ── 28. Banco de Dados: Idempotência Mandatória em Migrações SQL ───────
    rules.push(Rule::new(
        "DB-IDEMPOTENT-MIGRATION",
        "db",
        Severity::Error,
        "Migração SQL Não-Idempotente",
        "Comandos DDL em migrations/ devem usar IF NOT EXISTS ou IF EXISTS para permitir re-execução segura.",
        r"(?m)^.*stenio-migration-marker.*$",
        &["sql"],
        Some("Adicione 'IF NOT EXISTS' em CREATE ou 'IF EXISTS' em DROP para garantir idempotência."),
    ));

    // ── 29. Infraestrutura: Conformidade com Topologia Canônica da Malha ───
    rules.push(Rule::new(
        "INFRA-TOPOLOGY-COMPLIANCE",
        "infra",
        Severity::Error,
        "Alvo de Deploy Fora da Topologia Ativa",
        "Scripts de deploy e stacks do Hub só podem apontar para nós ativos da topologia (kavure, ybyra, psicopompo).",
        r"(?m)^.*stenio-topology-marker.*$",
        &["sh", "ini", "yml", "yaml"],
        Some("Aponte o serviço para os nós canônicos da topologia (kavure para backend/docker, ybyra para borda frontend)."),
    ));

    // ── 30. Rust: Proibição de Canais Assíncronos sem Limite (Unbounded MPSC) ─
    rules.push(Rule::new(
        "RUST-NO-UNBOUNDED-CHANNEL",
        "rust",
        Severity::Error,
        "Canal Assíncrono sem Limite (Unbounded MPSC)",
        "Canais 'unbounded_channel()' não aplicam backpressure e causam exaustão de memória (OOM). Use canais com capacidade finita 'channel(N)'.",
        r"\b(tokio::sync::mpsc::|mpsc::)unbounded_channel\(",
        &["rs"],
        Some("Substitua 'mpsc::unbounded_channel()' por 'mpsc::channel(buffer_size)' definindo uma capacidade explícita de backpressure."),
    ));

    // ── 31. Rust: Proibição de Process Command Síncrono em Runtime Tokio ───
    rules.push(Rule::new(
        "RUST-ASYNC-BLOCKING-CMD",
        "rust",
        Severity::Error,
        "Comando de Processo Síncrono em Runtime Assíncrono",
        "std::process::Command::new() bloqueia a thread de execução do Tokio. Em código assíncrono, use tokio::process::Command.",
        r"\bstd::process::Command::new\(",
        &["rs"],
        Some("Substitua 'std::process::Command::new' por 'tokio::process::Command::new' e use '.await', ou envolva em 'tokio::task::spawn_blocking'."),
    ));

    // ── 32. Rust: Proibição de std::sync::Mutex Retido em Contexto Tokio ──
    rules.push(Rule::new(
        "RUST-NO-SYNC-MUTEX-AWAIT",
        "rust",
        Severity::Warning,
        "Uso de std::sync::Mutex em Contexto Assíncrono",
        "Reter um lock de std::sync::Mutex através de pontos .await causa deadlocks e viola Send. Use tokio::sync::Mutex ou solte o guard antes do await.",
        r"\bstd::sync::Mutex\b",
        &["rs"],
        Some("Substitua 'std::sync::Mutex' por 'tokio::sync::Mutex', ou garanta que o guard síncrono seja descartado com drop(guard) antes de qualquer .await."),
    ));

    // ── 33. Rust: Convenção Idiomática de Arc::clone(&ptr) ─────────────────
    rules.push(Rule::new(
        "RUST-IDIOMATIC-ARC-CLONE",
        "rust",
        Severity::Warning,
        "Clonagem Não-Idiomática de Arc",
        "Convenção RFC 258 / Clippy: prefira 'Arc::clone(&ptr)' a 'ptr.clone()' para explicitar que se trata de duplicação de ponteiro atômico, não deep copy.",
        r"\b[A-Za-z0-9_]+_arc\.clone\(\)|\b(arc_|shared_)[A-Za-z0-9_]*\.clone\(\)",
        &["rs"],
        Some("Substitua 'ptr.clone()' por 'Arc::clone(&ptr)' para manter o código Rust idiomático e claro."),
    ));

    // ── 34. Rust: Preferência por Slices (&str / &[T]) em Parâmetros ───────
    rules.push(Rule::new(
        "RUST-IDIOMATIC-SLICES",
        "rust",
        Severity::Warning,
        "Assinatura Não-Idiomática com &String ou &Vec<T>",
        "Assinaturas de funções não devem receber referências a coleções concretas (&String ou &Vec<T>). Use fatias (slices) '&str' e '&[T]'.",
        r"\bfn\s+[a-z0-9_]+\s*(?:<[^>]+>)?\s*\([^)]*:\s*&(?:mut\s+)?(String\b|Vec<)",
        &["rs"],
        Some("Substitua o parâmetro '&String' por '&str' e '&Vec<T>' por '&[T]' para permitir que qualquer fatia ou literal seja passado sem alocações."),
    ));

    // ── 35. Rust: Tratamento Obrigatório de Erros em tokio::spawn ──────────
    rules.push(Rule::new(
        "RUST-SPAWN-ERROR-HANDLING",
        "rust",
        Severity::Warning,
        "tokio::spawn Órfão sem Rastreamento de Erro ou Tracing",
        "Tarefas assíncronas disparadas via 'tokio::spawn' sem tratamento de JoinHandle ou instrumentação tracing engolem panics e erros silenciosamente.",
        r"(?m)^\s*tokio::spawn\s*\(\s*async\s+move\s*\{",
        &["rs"],
        Some("Armazene o JoinHandle (let handle = tokio::spawn(...)) ou instrumente a task com '.instrument(tracing::info_span!(...))' para observabilidade em caso de panic."),
    ));

    // ── 30. Regras Customizadas e Aprendidas Dinamicamente (steniocheck.toml) ──

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
