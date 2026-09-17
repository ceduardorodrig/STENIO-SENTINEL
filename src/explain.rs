use colored::*;

#[derive(Debug, Clone)]
pub struct RuleExplanation {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: &'static str,
    pub tag: &'static str,
    pub summary: &'static str,
    pub rationale: &'static str,
    pub bad_example: &'static str,
    pub good_example: &'static str,
    pub remediation: &'static str,
}

pub static EXPLANATIONS: &[RuleExplanation] = &[
    RuleExplanation {
        id: "SEC-SUDO",
        name: "Atenção ao Uso de Sudo e Privilégios de Sistema",
        severity: "WARN",
        tag: "sec",
        summary: "Orienta o uso profissional de privilégios de sistema via sudoers (NOPASSWD) ou .env/SOPS em vez de senhas interativas ou pkexec.",
        rationale: "Em arquiteturas heterogêneas (servidores headless como ybyra/ybytu/kuaray/kavure e containers), 'pkexec' não existe ou falha. No desktop psicopompo (KDE), forçar 'pkexec' exibe diálogos gráficos repetidos que cansam o usuário. A abordagem profissional universal consiste em: 1) Configurar regra 'NOPASSWD: ALL' no sudoers para tarefas administrativas; 2) Injetar credenciais sensíveis via variáveis de ambiente (.env) ou cofre criptográfico SOPS/Age; 3) 'pkexec' fica restrito apenas a intervenções manuais interativas com prompt no desktop.",
        bad_example: "# Senha em texto puro ou pipe inseguro:\necho 'minhasenha' | sudo -S systemctl restart nginx\n# Ou forçar pkexec em servidores sem interface gráfica:\npkexec systemctl restart nginx",
        good_example: "# 1. Host configurado com sudoers NOPASSWD (ex: /etc/sudoers.d/99-edu-homelab):\nsudo systemctl restart nginx\n\n# 2. Leitura profissional de segredos via .env ou SOPS/Age:\nDATABASE_URL=$(sops -d --extract '[\"DATABASE_URL\"]' secrets.enc.env)",
        remediation: "Configure o usuário no sudoers com NOPASSWD ou carregue credenciais via .env/SOPS. Não force pkexec em scripts de automação nem injete senhas via pipe.",
    },
    RuleExplanation {
        id: "RUST-NO-UNWRAP",
        name: "Uso de unwrap() ou expect() em Código de Produção",
        severity: "WARN",
        tag: "rust",
        summary: "Proíbe o uso de .unwrap() e .expect() em código Rust de produção.",
        rationale: "Modelos menores e desenvolvedores apressados frequentemente usam .unwrap() para contornar erros do compilador. Em servidores concorrentes (Axum/Tokio), um .unwrap() em valor None/Err causa panic imediato da thread ou do processo, derrubando o serviço para todos os usuários.",
        bad_example: "let user = find_user(id).unwrap();\nlet config = parse_config().expect(\"Falha no config\");",
        good_example: "let user = find_user(id).ok_or_else(|| AppError::NotFound)?;\nlet config = parse_config().unwrap_or_default();\n// Ou com pattern matching:\nlet user = match find_user(id) {\n    Some(u) => u,\n    None => return Err(AppError::NotFound),\n};",
        remediation: "Substitua por '?' (operador try), pattern matching com 'match'/'if let', ou métodos seguros com fallback (.unwrap_or_default(), .unwrap_or_else()).",
    },
    RuleExplanation {
        id: "ARCH-NO-PYTHON",
        name: "Arquivo Python Proibido",
        severity: "ERROR",
        tag: "arch",
        summary: "Proíbe arquivos .py no repositório Sumænimá (ADR-036).",
        rationale: "O ecossistema Sumænimá Hub migrou 100% para Rust nativo compilado (Axum, Tokio, SQLx, GGML Q8_0). Manter ou reintroduzir scripts Python cria duplicidade de pilha, reintroduz dependências lentas (PyTorch, CTranslate2) e quebra a arquitetura unificada de binário único.",
        bad_example: "app/server/run_transcription.py\nscripts/worker.py",
        good_example: "app/server/src/transcription.rs\napp/server/src/bin/worker.rs",
        remediation: "Reescreva a funcionalidade em Rust nativo dentro de app/server/src/ ou utilize os binários existentes.",
    },
    RuleExplanation {
        id: "ARCH-RUST-TOOLS",
        name: "Uso de Ferramentas GNU Legadas em Scripts Shell",
        severity: "WARN",
        tag: "arch",
        summary: "Exige ferramentas modernas escritas em Rust em vez de utilitários GNU legados.",
        rationale: "Conforme a tabela mandatória de preferências de terminal do AGENTS.md, utilitários Rust são ordens de magnitude mais rápidos, possuem sintaxe ergonômica e respeitam .gitignore automaticamente.",
        bad_example: "grep -r \"foo\" .\nfind . -name \"*.rs\"\ndu -sh *\ncat file.txt",
        good_example: "rg \"foo\"\nfd -e rs\ndust\nbat --paging=never file.txt",
        remediation: "Troque grep→rg, find→fd, du→dust, cat→bat, ls→eza, sed→sd, curl→xh.",
    },
    RuleExplanation {
        id: "ARCH-RUST-CMD-LEGACY",
        name: "Ferramenta GNU Invocada em Código Rust",
        severity: "WARN",
        tag: "arch",
        summary: "Proíbe Command::new() chamando ferramentas GNU legadas.",
        rationale: "O próprio código Rust não deve depender de subprocessos GNU (curl, grep, find, df). Invocar subprocessos externos causa overhead de fork/exec, depende de ferramentas externas instaladas no host e viola a soberania da biblioteca padrão e crates Rust.",
        bad_example: "Command::new(\"curl\").args([\"-s\", url]).output()\nCommand::new(\"grep\").args([\"-r\", pat]).output()",
        good_example: "let resp = reqwest::get(url).await?;\n// Ou usando a crate regex:\nlet re = Regex::new(pat)?;",
        remediation: "Substitua a chamada por uma crate Rust nativa (reqwest/xh para HTTP, regex para busca, walkdir para arquivos, statvfs/nix para espaço em disco).",
    },
    RuleExplanation {
        id: "RUST-ASYNC-SLEEP",
        name: "std::thread::sleep em Runtime Tokio Assíncrono",
        severity: "ERROR",
        tag: "rust",
        summary: "Proíbe std::thread::sleep dentro de funções async/Tokio.",
        rationale: "std::thread::sleep bloqueia a thread do sistema operacional inteira, impedindo o Tokio de executar outras centenas de tarefas agendadas na mesma thread de trabalho. Isso causa latência extrema e travamento total do servidor.",
        bad_example: "async fn handle_request() {\n    std::thread::sleep(Duration::from_millis(500));\n}",
        good_example: "async fn handle_request() {\n    tokio::time::sleep(Duration::from_millis(500)).await;\n}",
        remediation: "Substitua std::thread::sleep por tokio::time::sleep(duration).await.",
    },
    RuleExplanation {
        id: "RUST-STRUCTURED-LOGGING",
        name: "Uso de println!/eprintln! em Servidor Web",
        severity: "WARN",
        tag: "rust",
        summary: "Proíbe println! em rotas e serviços Axum/Tokio.",
        rationale: "println! em stdout perde metadados essenciais (timestamps, span contexts, trace IDs, níveis de log, destino de arquivo). Deve-se usar a macro de tracing apropriada para observabilidade em produção.",
        bad_example: "println!(\"Requisição recebida para {}\", id);",
        good_example: "tracing::info!(user_id = %id, \"Requisição processada com sucesso\");",
        remediation: "Substitua por tracing::info!, tracing::warn!, tracing::error! ou tracing::debug!.",
    },
    RuleExplanation {
        id: "SEC-SECRETS",
        name: "Segredos Hardcoded em Código",
        severity: "ERROR",
        tag: "sec",
        summary: "Detecta chaves privadas, tokens GitHub (ghp_), OpenAI (sk-) ou senhas em texto puro.",
        rationale: "Credenciais versionadas no Git vazam permanentemente no histórico, expondo infraestrutura pessoal e de clientes a ataques automatizados na internet.",
        bad_example: "let api_key = \"sk-1234567890abcdef1234567890abcdef12345678\";\nconst GITHUB_TOKEN = \"ghp_abcdef1234567890abcdef123456789012\";",
        good_example: "let api_key = std::env::var(\"OPENAI_API_KEY\")?;\n// Ou injetado via cofre SOPS/Age em secrets.env",
        remediation: "Remova a credencial imediatamente, revogue-a no provedor e carregue via variável de ambiente ou SOPS/Age.",
    },
    RuleExplanation {
        id: "SEC-SQL",
        name: "Interpolação de Strings em Queries SQL",
        severity: "WARN",
        tag: "sec",
        summary: "Detecta strings formatadas diretamente dentro de declarações SQL.",
        rationale: "A interpolação direta de parâmetros em strings SQL abre brechas para SQL Injection, permitindo extração e destruição de dados.",
        bad_example: "let query = format!(\"SELECT * FROM users WHERE id = {}\", user_id);",
        good_example: "sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id).fetch_one(&pool).await?;",
        remediation: "Utilize bind parameters ($1, $2, ?) nas queries preparadas do SQLx.",
    },
    RuleExplanation {
        id: "SEC-EXCEPT",
        name: "Bare Except Proibido",
        severity: "WARN",
        tag: "sec",
        summary: "Proíbe blocos 'except:' desprovidos de tipo de exceção.",
        rationale: "Captura indiscriminada 'except:' intercepta KeyboardInterrupt, SystemExit e exceções de memória, tornando impossível interromper scripts ou depurar falhas reais.",
        bad_example: "try:\n    do_something()\nexcept:\n    pass",
        good_example: "try:\n    do_something()\nexcept SpecificError as err:\n    logger.error(\"Erro: %s\", err)",
        remediation: "Especifique a classe de exceção concreta (ex: except Exception as err: ou tipo específico).",
    },
    RuleExplanation {
        id: "FRONT-ZUSTAND",
        name: "Zustand Seletor Instável",
        severity: "WARN",
        tag: "frontend",
        summary: "Detecta criação de novos objetos em seletores de lojas Zustand sem useShallow.",
        rationale: "Quando um seletor Zustand retorna um objeto literal `{ a, b }`, uma nova referência de memória é alocada a cada ciclo, disparando re-renderizações infinitas e congelando o navegador do usuário.",
        bad_example: "const { activeId, status } = useSessionStore(state => ({ activeId: state.id, status: state.status }));",
        good_example: "import { useShallow } from 'zustand/react/shallow';\nconst { activeId, status } = useSessionStore(\n    useShallow(state => ({ activeId: state.id, status: state.status }))\n);",
        remediation: "Envolva o seletor em useShallow(...) da biblioteca 'zustand/react/shallow'.",
    },
    RuleExplanation {
        id: "FRONT-LOGS",
        name: "Logs de Depuração no Frontend",
        severity: "WARN",
        tag: "frontend",
        summary: "Detecta console.log e console.debug em componentes React/TypeScript.",
        rationale: "Logs de depuração em produção poluem o console do usuário, podem vazar dados confidenciais e degradam a performance de renderização.",
        bad_example: "console.log(\"Dados recebidos:\", data);\nconsole.debug(\"Render count\", count);",
        good_example: "// Remova o log ou proteja com flag de desenvolvimento:\nif (process.env.NODE_ENV === 'development') {\n    console.info(\"Dados:\", data);\n}",
        remediation: "Remova a linha ou utilize 'stenio --fix' para remover logs desnecessários.",
    },
    RuleExplanation {
        id: "GOV-LEFTOVER-TEST-ARTIFACTS",
        name: "Limpeza Obrigatória de Artefatos de Teste / Scratch Residual",
        severity: "ERROR",
        tag: "gov",
        summary: "Detecta arquivos de teste, backup ou rascunho deixados para trás por agentes de IA.",
        rationale: "Regra 3 do AGENTS.md: 'Arquivos/pastas criados apenas para teste/validação DEVEM ser removidos ao final da tarefa, nunca deixados no sistema ou na pasta'. Modelos de IA frequentemente criam 'test.py', 'temp.txt', '*.bak' ou 'scratch_*' e esquecem de apagá-los, poluindo a sincronização do Syncthing e o repositório.",
        bad_example: "test.py na raiz do vault\nscripts/temp_output.txt\napp/server/test_debug.rs\nproject/document.md.bak",
        good_example: "Crie arquivos temporários exclusivamente no diretório de scratch persistente do agente (<appDataDir>/brain/<id>/scratch/) ou remova-os imediatamente com std::fs::remove_file antes de finalizar.",
        remediation: "Exclua imediatamente o arquivo temporário ou mova-o para o diretório de scratch autorizado.",
    },
    RuleExplanation {
        id: "VAULT-FRONTMATTER",
        name: "Frontmatter YAML Obrigatório em Notas do Vault",
        severity: "ERROR",
        tag: "vault",
        summary: "Exige frontmatter YAML inicial com tags em todas as notas Markdown do vault.",
        rationale: "O Obsidian e os scripts de indexação do ecossistema dependem do bloco YAML inicial ('---\\ntags: [...]\\n---') para catalogação, busca semântica e governança de documentos.",
        bad_example: "# Minha Nota\nTexto da nota sem metadados.",
        good_example: "---\ntags: [projeto, sumaanima]\n---\n\n# Minha Nota\nTexto da nota com metadados.",
        remediation: "Adicione o cabeçalho YAML delimitado por '---' contendo a chave 'tags:' no topo exato do arquivo.",
    },
    RuleExplanation {
        id: "VAULT-TAG-TAXONOMY",
        name: "Conformidade com Taxonomia de Tags",
        severity: "ERROR",
        tag: "vault",
        summary: "Exige que todas as tags utilizadas pertençam à taxonomia canônica em governance/_tags.md.",
        rationale: "A proliferação de tags arbitrárias fragmenta a navegação e o grafo do Obsidian. Toda tag deve ser previamente aprovada e documentada na taxonomia oficial.",
        bad_example: "tags: [minha-tag-inventada, teste123]",
        good_example: "tags: [projeto, infra, homelab, meta, reuniões]",
        remediation: "Consulte 'governance/_tags.md' e utilize exclusivamente as tags canônicas catalogadas.",
    },
    RuleExplanation {
        id: "HOMELAB-NAMING",
        name: "Nomenclatura Homelab (Minúsculas e Hífens)",
        severity: "ERROR",
        tag: "homelab",
        summary: "Exige que arquivos na pasta mnemocine/ utilizem apenas letras minúsculas, números e hífens.",
        rationale: "Padrão canônico de documentação do homelab Mnemocine. Arquivos em MAIÚSCULAS ou com espaços causam inconsistências em sistemas de arquivos case-sensitive/insensitive via Syncthing.",
        bad_example: "mnemocine/OSS-ACKNOWLEDGMENTS.md\nmnemocine/Guia Servidor.md",
        good_example: "mnemocine/oss-acknowledgments.md\nmnemocine/guia-servidor.md",
        remediation: "Renomeie o arquivo para usar somente caracteres minúsculos separados por hífen.",
    },
    RuleExplanation {
        id: "HOMELAB-NFS-SOFT",
        name: "Montagem NFS Suave Obrigatória",
        severity: "ERROR",
        tag: "homelab",
        summary: "Proíbe montagens NFS com opção 'hard' em sistemas de rede sem timeout.",
        rationale: "Montagens NFS 'hard' fazem o kernel do Linux congelar indefinidamente processos de E/S se o servidor NAS reiniciar ou a rede cair, exigindo hard reboot do psicopompo.",
        bad_example: "192.168.1.100:/export /mnt/nfs nfs defaults,hard 0 0",
        good_example: "192.168.1.100:/export /mnt/nfs nfs defaults,soft,timeo=50,retrans=2 0 0",
        remediation: "Substitua 'hard' por 'soft,timeo=50,retrans=2' nas opções de montagem em /etc/fstab ou systemd mounts.",
    },
    RuleExplanation {
        id: "INFRA-BASH-STRICT",
        name: "Modo Estrito em Scripts Bash",
        severity: "ERROR",
        tag: "infra",
        summary: "Exige 'set -euo pipefail' nos primeiros comandos de scripts shell.",
        rationale: "Scripts shell que continuam executando após erros silenciosos ou com variáveis não inicializadas causam corrupção de dados e comportamento imprevisível em infraestrutura.",
        bad_example: "#!/usr/bin/env bash\ncp /src /dest\nrm -rf /tmp/files",
        good_example: "#!/usr/bin/env bash\nset -euo pipefail\ncp /src /dest\nrm -rf /tmp/files",
        remediation: "Adicione 'set -euo pipefail' logo abaixo da shebang '#!/usr/bin/env bash'.",
    },
    RuleExplanation {
        id: "AGENT-NO-LAZY-STUB",
        name: "Proibição de Stubs e Placeholders Preguiçosos de IA",
        severity: "ERROR",
        tag: "gov",
        summary: "Detecta e proíbe placeholders incompletos como '// rest of code', 'todo!()', 'unimplemented!()' ou '/* TODO */'.",
        rationale: "Modelos menores (7B/14B) e agentes apressados frequentemente sofrem de 'output truncation' ou 'preguiça', truncando o código com comentários de resumo para economizar esforço. Isso quebra builds, corrompe o comportamento esperado e força o usuário a terminar a tarefa manualmente.",
        bad_example: "// rest of the code remains the same...\nfn compute_matrix() {\n    todo!(\"implement later\");\n}\nthrow new Error(\"Not implemented\");",
        good_example: "fn compute_matrix() -> Matrix {\n    let data = calculate_initial_values();\n    Matrix::from_data(data)\n}",
        remediation: "Implemente a funcionalidade de ponta a ponta sem recorrer a stubs ou comentários de corte.",
    },
    RuleExplanation {
        id: "TEST-NO-SILENT-SKIP",
        name: "Proibição de Desativação Silenciosa de Testes",
        severity: "ERROR",
        tag: "test",
        summary: "Proíbe comentar asserções, usar #[ignore] ou test.skip para 'consertar' testes que falharam.",
        rationale: "Quando confrontados com testes em falha, modelos preguiçosos frequentemente tentam trapacear desativando o teste ou comentando a linha do assert. Isso cria falsa sensação de sucesso no CI enquanto a regressão permanece em produção.",
        bad_example: "// assert_eq!(result, 42); // comentado para passar\n#[test]\n#[ignore]\nfn test_payment() { ... }\ntest.skip(\"should authenticate\", () => { ... });",
        good_example: "#[test]\nfn test_payment() {\n    let result = process_payment(amount);\n    assert_eq!(result, PaymentStatus::Success);\n}",
        remediation: "Não comente nem ignore testes. Descubra por que a asserção falhou e corrija o código real de negócio.",
    },
    RuleExplanation {
        id: "CODE-NO-EMPTY-CATCH",
        name: "Proibição de Catch/Except Vazio",
        severity: "WARN",
        tag: "gov",
        summary: "Proíbe blocos try/catch ou try/except que engolem erros silenciosamente sem registrar log.",
        rationale: "Capturar erros sem fazer nada cria 'falhas zumbis' onde a aplicação continua em estado corrompido sem deixar rastro de log ou notificação nos servidores.",
        bad_example: "try {\n    saveData();\n} catch (e) {}\n\ntry:\n    connect_nas()\nexcept:\n    pass",
        good_example: "try {\n    saveData();\n} catch (e) {\n    console.error(\"Falha ao salvar dados:\", e);\n    throw e;\n}\n\ntry:\n    connect_nas()\nexcept Exception as err:\n    logger.error(\"Erro ao conectar no NAS: %s\", err)\n    raise",
        remediation: "Trate a falha, registre log com tracing/console.error ou propague a exceção com '?' ou 'throw/raise'.",
    },
];

pub fn get_explanation(rule_id: &str) -> Option<&'static RuleExplanation> {
    EXPLANATIONS
        .iter()
        .find(|e| e.id.eq_ignore_ascii_case(rule_id))
}

pub fn format_explanation_cli(exp: &RuleExplanation) -> String {
    let sev_badge = if exp.severity == "ERROR" {
        "CRITICAL ERROR".red().bold()
    } else {
        "WARNING".yellow().bold()
    };

    let mut s = String::new();
    s.push_str(&format!(
        "\n{}\n",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    ));
    s.push_str(&format!(
        "🛡️  StenioSentinel Rule Reference: [{}] {}\n",
        exp.id.green().bold(),
        exp.name.white().bold()
    ));
    s.push_str(&format!(
        "   Severidade: {} | Tag: {}\n",
        sev_badge,
        exp.tag.magenta()
    ));
    s.push_str(&format!(
        "{}\n\n",
        "──────────────────────────────────────────────────────────────────────────────".cyan()
    ));

    s.push_str(&format!("📋 {}\n   {}\n\n", "SUMÁRIO:".bold(), exp.summary));
    s.push_str(&format!(
        "💡 {}\n   {}\n\n",
        "POR QUE ESTA REGRA EXISTE? (RATIONALE):".bold(),
        exp.rationale
    ));

    s.push_str(&format!(
        "❌ {}\n",
        "EXEMPLO DE CÓDIGO INCORRETO (VIOLAÇÃO):".red().bold()
    ));
    for line in exp.bad_example.lines() {
        s.push_str(&format!("   {}\n", line.red()));
    }
    s.push('\n');

    s.push_str(&format!(
        "✅ {}\n",
        "EXEMPLO DE CÓDIGO CORRETO (CONFORME):".green().bold()
    ));
    for line in exp.good_example.lines() {
        s.push_str(&format!("   {}\n", line.green()));
    }
    s.push('\n');

    s.push_str(&format!(
        "🔧 {}\n   {}\n\n",
        "COMO CORRIGIR / REMEDIAÇÃO:".cyan().bold(),
        exp.remediation
    ));

    s.push_str(&format!(
        "{}\n",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    ));

    s
}

pub fn format_explanation_plain(exp: &RuleExplanation) -> String {
    format!(
        "RULE: [{}] {} (Severidade: {}, Tag: {})\n\n\
        SUMÁRIO:\n{}\n\n\
        RATIONALE:\n{}\n\n\
        EXEMPLO INCORRETO (VIOLAÇÃO):\n{}\n\n\
        EXEMPLO CORRETO (CONFORME):\n{}\n\n\
        REMEDIAÇÃO:\n{}",
        exp.id,
        exp.name,
        exp.severity,
        exp.tag,
        exp.summary,
        exp.rationale,
        exp.bad_example,
        exp.good_example,
        exp.remediation
    )
}

pub fn list_all_explanations() -> String {
    let mut s = String::new();
    s.push_str("\nRegras Documentadas no StenioSentinel Reference:\n\n");
    for exp in EXPLANATIONS {
        s.push_str(&format!(
            "  • {:<26} [{:<5}] {:<7} - {}\n",
            exp.id, exp.tag, exp.severity, exp.name
        ));
    }
    s.push_str("\nUse 'stenio --explain <RULE_ID>' para ver detalhes, código incorreto e código correto.\n");
    s
}
