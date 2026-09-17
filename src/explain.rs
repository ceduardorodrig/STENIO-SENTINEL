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
        severity: "ERROR",
        tag: "rust",
        summary: "Proíbe expressamente o uso de .unwrap() e .expect() em código Rust de produção.",
        rationale: "Modelos menores e desenvolvedores apressados frequentemente usam .unwrap() ou tentam burlar trocando por .expect() para contornar erros do compilador. Em servidores concorrentes (Axum/Tokio), tanto .unwrap() quanto .expect() causam panic imediato da thread ou do processo, derrubando o serviço para todos os usuários.",
        bad_example: "let user = find_user(id).unwrap();\nlet config = parse_config().expect(\"Falha no config\"); // PROIBIDO: expect causa panic!",
        good_example: "let user = find_user(id).ok_or_else(|| AppError::NotFound)?;\nlet config = parse_config().unwrap_or_default();\n// Ou com pattern matching:\nlet user = match find_user(id) {\n    Some(u) => u,\n    None => return Err(AppError::NotFound),\n};",
        remediation: "Substitua por '?' (operador try), pattern matching com 'match'/'if let', ou métodos seguros com fallback (.unwrap_or_default(), .unwrap_or_else()). É proibido trocar unwrap por expect.",
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
        id: "AGENT-NO-SUPPRESSION-DIRECTIVES",
        name: "Proibição de Diretivas de Supressão e Bypass de Qualidade",
        severity: "ERROR",
        tag: "gov",
        summary: "Proíbe @ts-ignore, @ts-nocheck, eslint-disable, type: ignore ou stenio-ignore: all.",
        rationale: "Quando confrontadas com erros estritos do compilador TypeScript ou regras de arquitetura, LLMs burras ou preguiçosas tentam calar o linter inserindo diretivas de supressão no código em vez de consertar os tipos ou respeitar os contratos de API. Isso degrada a tipagem de todo o projeto e esconde bugs em runtime.",
        bad_example: "// @ts-ignore\nconst data = response.data;\n\n// stenio-ignore: all\nlet unsafe = dangerous();",
        good_example: "interface CardResponse { data: Card[] }\nconst data: Card[] = (response as CardResponse).data;",
        remediation: "Defina os tipos corretos em TypeScript ou corrija o código para satisfazer os contratos do sistema sem recorrer a diretivas de supressão.",
    },
    RuleExplanation {
        id: "AGENT-NO-TAMPERING-VERIFIER",
        name: "Proibição de Adulteração de Verificadores e Hooks",
        severity: "ERROR",
        tag: "gov",
        summary: "Proíbe git commit --no-verify, desativação de pre-commit hooks ou sabotagem de checagens.",
        rationale: "Quando confrontados com problemas complexos de código, agentes desonestos ou preguiçosos tentam 'Goodhart's Law / Reward Hacking': em vez de resolver a causa raiz do bug, tentam desativar o verificador rodando git commit com '--no-verify' ou apagando os scripts de auditoria.",
        bad_example: "git commit -m 'fix' --no-verify\nrm -f .git/hooks/pre-commit",
        good_example: "stenio --gate\ngit commit -m 'fix: implement proper solution'",
        remediation: "Nunca use '--no-verify'. O StênioSentinel é o árbitro canônico inviolável. Se não conseguir resolver a causa raiz, escale para o usuário com explicação detalhada.",
    },
    RuleExplanation {
        id: "CONF-NO-WEAKEN-STRICT",
        name: "Proibição de Enfraquecimento de Modo Estrito no Compilador",
        severity: "ERROR",
        tag: "gov",
        summary: "Proíbe desativar 'strict: false' ou 'noImplicitAny: false' em tsconfig.json.",
        rationale: "Quando uma LLM não consegue resolver erros estritos de tipagem em TypeScript, uma trapaça comum é editar o arquivo tsconfig para desligar o modo estrito ('strict: false'). Isso remove a segurança de tipos do projeto inteiro para disfarçar a incapacidade do modelo de escrever tipos corretos.",
        bad_example: "{\n  \"compilerOptions\": {\n    \"strict\": false\n  }\n}",
        good_example: "{\n  \"compilerOptions\": {\n    \"strict\": true\n  }\n}",
        remediation: "Mantenha '\"strict\": true' e corrija as anotações e interfaces de tipos no código fonte.",
    },
    RuleExplanation {
        id: "ARCH-SCOPE-ISOLATION",
        name: "Violação de Isolamento de Escopo Monorepo",
        severity: "ERROR",
        tag: "arch",
        summary: "Proíbe misturar alterações em código da aplicação (Sumaenima) com alterações no motor do Stênio no mesmo commit/tarefa.",
        rationale: "O monorepo abriga tanto a aplicação de negócios (sumaenimahub/) quanto o árbitro de governança (governance/stenio/). Permitir que um único diff ou commit modifique ambos abre brechas para que um agente adultere as regras de validação para forçar a aprovação de um código de aplicação defeituoso. O princípio de separação de responsabilidades e mitigação de Goodhart's Law exige que melhorias no Stênio e desenvolvimento de produto sejam sempre conduzidos em commits/tarefas estritamente isolados.",
        bad_example: "git diff HEAD --name-only\nsumaenimahub/SUMAENIMA-HUB/app/frontend-v2/src/App.tsx\ngovernance/stenio/src/engine.rs",
        good_example: "# Tarefa A (Aplicação):\ngit commit -m 'feat: add audio waveform visualizer' sumaenimahub/\n\n# Tarefa B (Governança):\ngit commit -m 'feat: add new lint rule' governance/stenio/",
        remediation: "Isole as responsabilidades: desfaça as alterações no motor de governança (governance/stenio) se o objetivo for o app, ou divida o trabalho em dois commits/PRs independentes.",
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
    RuleExplanation {
        id: "FRONT-TOKEN-PALETTE",
        name: "Proibição de Cinzas Genéricos do Tailwind",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe classes como bg-gray-*, bg-zinc-*, bg-slate-* nos componentes React do Sumænimá Hub.",
        rationale: "O Sumænimá Hub possui DNA visual unificado (Material You + Zinc Deep Dark + Glassmorphism). O uso de cinzas arbitrários quebra a identidade da marca e o tema dinâmico.",
        bad_example: "<div className=\"bg-gray-800 text-gray-200 border border-gray-700\">...</div>",
        good_example: "<div className=\"bg-surface-900 text-on-surface border border-outline sm-glass\">...</div>",
        remediation: "Utilize os tokens canônicos: bg-surface-950 (fundo), bg-surface-900 (cards), bg-surface-800 (hover), text-on-surface (#e4e4e7), border-outline, ou a classe .sm-glass.",
    },
    RuleExplanation {
        id: "FRONT-NO-ANY",
        name: "Proibição de 'any' em TypeScript",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe tipagem 'any' ('as any', ': any') em arquivos .ts e .tsx do frontend.",
        rationale: "O uso de 'any' desativa a verificação estática do TypeScript, mascarando dessincronizações entre o frontend e as rotas Axum do backend.",
        bad_example: "const handleData = (payload: any) => {\n    const user = payload as any;\n};",
        good_example: "import type { UserProfile } from '@/types/user';\nconst handleData = (payload: UserProfile) => {\n    // Tipagem estrita e segura\n};",
        remediation: "Importe o tipo de src/types/ ou execute 'stenio --typegen' para gerar os bindings atualizados a partir dos structs Rust do backend.",
    },
    RuleExplanation {
        id: "FRONT-A11Y-BUTTON",
        name: "Acessibilidade de Botões Interativos (aria-label)",
        severity: "WARN",
        tag: "frontend",
        summary: "Exige aria-label ou title em botões que contêm apenas ícones gráficos.",
        rationale: "Botões sem texto legível são invisíveis para usuários que utilizam tecnologias assistivas (leitores de tela), violando as diretrizes WCAG 2.1 AA.",
        bad_example: "<button onClick={onDelete}>\n    <TrashIcon className=\"w-4 h-4\" />\n</button>",
        good_example: "<button onClick={onDelete} aria-label=\"Excluir item\">\n    <TrashIcon className=\"w-4 h-4\" />\n</button>",
        remediation: "Adicione a propriedade aria-label=\"...\" ou title=\"...\" explicando a ação do botão.",
    },
    RuleExplanation {
        id: "FRONT-AUDIO-WASM",
        name: "Soberania AudioWorklet + WebAssembly",
        severity: "ERROR",
        tag: "frontend",
        summary: "Proíbe createScriptProcessor obsoleto em captura e processamento de áudio.",
        rationale: "createScriptProcessor executa na thread principal da UI, causando travamentos na tela durante a fala. O ecossistema Sumænimá processa áudio via AudioWorkletNode acoplado ao wasm-audio-dsp compilado em Rust.",
        bad_example: "const processor = audioCtx.createScriptProcessor(4096, 1, 1);",
        good_example: "const worklet = new AudioWorkletNode(audioCtx, 'audio-recorder-processor');",
        remediation: "Utilize AudioWorkletNode e o motor WebAssembly em wasm-audio.",
    },
    RuleExplanation {
        id: "FRONT-COMPONENT-BUDGET",
        name: "Componente Monolítico (>400 Linhas)",
        severity: "WARN",
        tag: "frontend",
        summary: "Alerta componentes React .tsx com mais de 400 linhas de código.",
        rationale: "Componentes gigantescos dificultam a manutenção e levam modelos de IA a truncar código com placeholders preguiçosos. O design atômico exige divisão em submódulos atômicos.",
        bad_example: "Arquivo CockpitView.tsx com 950 linhas contendo 8 sub-painéis e modais internos.",
        good_example: "CockpitView.tsx contendo apenas orquestração de sub-componentes: <CockpitHeader />, <CockpitTimeline />, <CockpitAudioControls />.",
        remediation: "Fatie o componente em submódulos menores dentro de src/components/.",
    },
    RuleExplanation {
        id: "BACKEND-BLOCKING-IO",
        name: "E/S Bloqueante (std::fs) em Runtime Tokio",
        severity: "ERROR",
        tag: "rust",
        summary: "Proíbe operações síncronas std::fs em handlers assíncronos do backend Axum.",
        rationale: "std::fs bloqueia a thread do sistema operacional e esgota o pool de workers do Tokio. Toda E/S de arquivos no servidor deve ser assíncrona com tokio::fs.",
        bad_example: "async fn save_file(data: &[u8]) {\n    std::fs::write(\"path\", data).unwrap();\n}",
        good_example: "async fn save_file(data: &[u8]) -> Result<()> {\n    tokio::fs::write(\"path\", data).await?;\n    Ok(())\n}",
        remediation: "Substitua std::fs por tokio::fs e use .await, ou tokio::task::spawn_blocking para chamadas síncronas pesadas.",
    },
    RuleExplanation {
        id: "BACKEND-NO-PANIC",
        name: "Proibição de Panic ou Assert em Servidor Web",
        severity: "WARN",
        tag: "rust",
        summary: "Proíbe panic!() ou assert!() em código do servidor web fora de suítes de teste.",
        rationale: "panic! aborta a thread de atendimento e pode derrubar conexões de múltiplos usuários simultâneos. Erros devem ser mapeados em AppError ou StatusCode HTTP.",
        bad_example: "if user.is_none() {\n    panic!(\"Usuário não encontrado!\");\n}",
        good_example: "let user = user.ok_or_else(|| (StatusCode::NOT_FOUND, \"Usuário não encontrado\"))?;",
        remediation: "Retorne Result<..., AppError> com o código de status HTTP correspondente em vez de causar panic.",
    },
    RuleExplanation {
        id: "ARCH-DRY-DUPLICATION",
        name: "Princípio DRY (Don't Repeat Yourself) Obrigatório",
        severity: "WARN",
        tag: "arch",
        summary: "Detecta e proíbe blocos idênticos de código duplicados entre arquivos ou funções.",
        rationale: "Modelos de IA menores frequentemente copiam e colam trechos inteiros de lógica (filtros, paginação, mapeamento de dados, layout de cards) em múltiplos arquivos. Isso infla a base de código, gera inconsistências visuais e cria débito técnico massivo. Toda lógica comum deve ser abstraída.",
        bad_example: "// Copiado em ComponentA.tsx e ComponentB.tsx:\nconst filtered = items.filter(i => i.name.toLowerCase().includes(q.toLowerCase()));\nconst sorted = filtered.sort((a, b) => a.order - b.order);\nconst paginated = sorted.slice(page * 20, (page + 1) * 20);",
        good_example: "// Abstraído em features/common/hooks/useFilteredCollection.ts:\nconst { items: paginated } = useFilteredCollection(rawItems, { query: q, page, pageSize: 20 });",
        remediation: "Extraia o bloco duplicado para um custom hook ('features/<dominio>/hooks/'), componente atômico reutilizável ou função utilitária compartilhada.",
    },
    RuleExplanation {
        id: "PERF-GPU-ZERO-REPAINT",
        name: "Zero-Repaint em Animações e Hovers de GPU",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe transicionar propriedades de Paint (box-shadow, backdrop-filter, bg-color) em containers 3D/hover.",
        rationale: "Em navegadores Chromium/WebKit, transicionar sombras pesadas ou filtros gaussianos força a GPU a rasterizar e repintar toda a camada a cada frame (caindo para 15-30 FPS em grids densas). Transicionar a opacidade de pseudo-elementos isolados opera puramente no Compositor da GPU (0ms CPU/GPU paint, cravando 60/120 FPS contínuos).",
        bad_example: "/* Força repaints de paint contínuos na GPU */\n.magic-card-tilt-container {\n    transition: box-shadow 0.3s ease, background-color 0.3s ease;\n}\n.magic-card-tilt-container:hover {\n    box-shadow: 0 0 24px rgba(234, 179, 8, 0.4);\n}",
        good_example: "/* Compositor puro: Zero Repaint */\n.magic-card-tilt-container::after {\n    content: '';\n    position: absolute;\n    inset: 0;\n    box-shadow: var(--hover-glow);\n    opacity: 0;\n    transition: opacity 0.25s ease;\n    pointer-events: none;\n    transform: translateZ(0);\n}\n.magic-card-tilt-container:hover::after {\n    opacity: 1;\n}",
        remediation: "Transicione exclusivamente 'opacity' ou 'transform' via pseudo-elemento ::after com transform: translateZ(0).",
    },
    RuleExplanation {
        id: "PERF-NO-LAYOUT-THRASH",
        name: "Proibição de Layout Thrashing em Event Handlers",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe chamadas síncronas de geometria (getBoundingClientRect / offset*) em listeners de mouse/scroll sem cache.",
        rationale: "Mouses gamers modernos operam em frequências de 500Hz a 1000Hz. Disparar getBoundingClientRect() diretamente no listener de mousemove força o motor do navegador a sincronizar estilo e geometria centenas de vezes por segundo, travando a thread principal de renderização.",
        bad_example: "const handleMouseMove = (e: React.MouseEvent) => {\n    // Força reflow a cada 1ms!\n    const rect = e.currentTarget.getBoundingClientRect();\n    const x = e.clientX - rect.left;\n    setPos({ x });\n};",
        good_example: "// Faz cache de rect na entrada do hover ou consome coordenadas no tick de rAF:\nconst handleMouseMove = (e: React.MouseEvent) => {\n    if (!boundsRef.current) {\n        boundsRef.current = el.getBoundingClientRect();\n    }\n    mousePosRef.current = { x: e.clientX, y: e.clientY };\n    startAnimationLoop();\n};",
        remediation: "Faça cache de dimensões em useRef no onMouseEnter ou armazene coordenadas em buffer consumido exclusivamente em requestAnimationFrame.",
    },
    RuleExplanation {
        id: "PERF-GPU-CONTAINMENT",
        name: "Contenção de Grade Arandu (.card-cell)",
        severity: "WARN",
        tag: "frontend",
        summary: "Exige wrapper com contenção CSS (.card-cell) ao renderizar cartas em loops de catálogo ou binder.",
        rationale: "Grades densas com 60 a 100+ cartas interativas necessitam de contenção CSS isolada. Sem ela, inclinar uma única carta em 3D ou ativar seu brilho invalida e repinta todas as 99 cartas adjacentes da página.",
        bad_example: "<div className=\"grid grid-cols-4 gap-4\">\n    {cards.map(c => <MagicCard key={c.id} card={c} />)}\n</div>",
        good_example: "<div className=\"grid grid-cols-4 gap-4\">\n    {cards.map(c => (\n        <div key={c.id} className=\"card-cell\">\n            <MagicCard card={c} />\n        </div>\n    ))}\n</div>",
        remediation: "Envolva o MagicCard em um elemento com a classe '.card-cell' ou 'contain: content'.",
    },
    RuleExplanation {
        id: "PERF-GPU-WILL-CHANGE",
        name: "will-change Restrito a Estados Ativos",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe will-change estático em dezenas de elementos em repouso.",
        rationale: "'will-change: transform' instrui a GPU a alocar um buffer de textura dedicado para a camada. Se aplicado indiscriminadamente a 100 cartas paradas na tela, consome centenas de megabytes de VRAM e satura o compositor gráfico sem qualquer benefício de performance.",
        bad_example: ".magic-card {\n    will-change: transform;\n}",
        good_example: ".magic-card:hover {\n    will-change: transform;\n}",
        remediation: "Aplique will-change estritamente em pseudo-classes interativas (:hover, :focus) ou classes ativas (.is-hovered).",
    },
    RuleExplanation {
        id: "FRONT-MODULAR-HOOKS",
        name: "Desacoplamento de Chamadas de Rede em Páginas",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe chamadas diretas de rede (fetch, axios, ws) no topo de páginas (src/pages/*.tsx).",
        rationale: "Páginas devem ser orquestradores limpos com menos de 400 linhas. Misturar chamadas de API, mutações e estados locais torna o código frágil e impossibilita o reuso de lógica em outras abas ou componentes.",
        bad_example: "// Em src/pages/AranduPage.tsx:\nuseEffect(() => {\n    fetch('/api/v1/cards').then(r => r.json()).then(setCards);\n}, []);",
        good_example: "// Em src/pages/AranduPage.tsx:\nconst { cards, isLoading } = useAranduCards();",
        remediation: "Extraia a chamada de API e os estados de loading/error para um custom hook em 'src/features/<dominio>/hooks/'.",
    },
    RuleExplanation {
        id: "FRONT-FEEDBACK-ON-ERROR",
        name: "Feedback Visual Obrigatório em Falhas de UI",
        severity: "WARN",
        tag: "frontend",
        summary: "Proíbe blocos catch de UI que apenas disparam console.error sem avisar o usuário.",
        rationale: "Quando uma ação do usuário falha silenciosamente, o botão trava em spinner ou a tela parece morta. Toda mutação de UI deve disparar um toast de erro ou atualizar um estado visual de falha.",
        bad_example: "try {\n    await saveCard(card);\n} catch (err) {\n    console.error(err);\n}",
        good_example: "try {\n    await saveCard(card);\n} catch (err) {\n    toast.error('Não foi possível salvar a carta.');\n    setError(err.message);\n}",
        remediation: "Adicione 'toast.error(...)' ou atualize o estado de erro do componente para dar feedback imediato.",
    },
    RuleExplanation {
        id: "FRONT-NO-HARDCODED-HOST",
        name: "Proibição de Localhost Hardcoded no Frontend",
        severity: "ERROR",
        tag: "frontend",
        summary: "Proíbe URLs absolutas 'http://localhost' ou 'http://127.0.0.1' no código React.",
        rationale: "URLs absolutas de localhost quebram quando a aplicação roda em produção atrás de Nginx ou em outros dispositivos na rede local, gerando erros fatais de CORS e conexão recusada.",
        bad_example: "const API_URL = 'http://localhost:8000/api/v1/cards';",
        good_example: "const API_URL = import.meta.env.VITE_API_URL || '/api/v1/cards';",
        remediation: "Utilize rotas relativas (/api/...) ou obtenha o endpoint via variável de ambiente VITE_API_URL.",
    },
    RuleExplanation {
        id: "DB-IDEMPOTENT-MIGRATION",
        name: "Idempotência Mandatória em Migrações SQL",
        severity: "ERROR",
        tag: "db",
        summary: "Proíbe comandos DDL (CREATE/DROP TABLE e INDEX) sem cláusula IF NOT EXISTS ou IF EXISTS.",
        rationale: "Migrações SQLx devem ser estritamente idempotentes. Se um deploy falhar no meio ou precisar re-executar, declarações DDL sem guardas geram falha catastrófica de 'relation already exists'.",
        bad_example: "CREATE TABLE users (id UUID PRIMARY KEY);\nDROP INDEX idx_users_email;",
        good_example: "CREATE TABLE IF NOT EXISTS users (id UUID PRIMARY KEY);\nDROP INDEX IF EXISTS idx_users_email;",
        remediation: "Adicione 'IF NOT EXISTS' em CREATE TABLE/INDEX e 'IF EXISTS' em DROP TABLE/INDEX.",
    },
    RuleExplanation {
        id: "INFRA-TOPOLOGY-COMPLIANCE",
        name: "Conformidade com a Topologia Canônica da Malha",
        severity: "ERROR",
        tag: "infra",
        summary: "Garante que deploys e serviços apontem apenas para nós autorizados da topologia homelab.",
        rationale: "Nós legados ou desativados não devem receber workloads. Todo target de deploy deve estar registrado em 'steniocheck.toml [topology.authorized_hub_nodes]'.",
        bad_example: "deploy_target=\"kuaray\" # nó desativado",
        good_example: "deploy_target=\"kavure\" # nó canônico ativo",
        remediation: "Atualize o script para apontar para um dos nós canônicos: kavure (backend/GPU), ybyra (frontend), psicopompo (workstation).",
    },
    RuleExplanation {
        id: "RUST-NO-UNBOUNDED-CHANNEL",
        name: "Proibição de Canais Tokio sem Limite (Unbounded Channel)",
        severity: "ERROR",
        tag: "rust",
        summary: "Proíbe o uso de 'tokio::sync::mpsc::unbounded_channel()' em código assíncrono.",
        rationale: "Canais sem limite não oferecem backpressure. Se a taxa de produção de mensagens exceder a capacidade de consumo, a fila cresce infinitamente até o kernel derrubar o processo por OOM (Out Of Memory).",
        bad_example: "let (tx, rx) = tokio::sync::mpsc::unbounded_channel();",
        good_example: "let (tx, rx) = tokio::sync::mpsc::channel(64); // Capacidade finita com backpressure",
        remediation: "Substitua por 'mpsc::channel(buffer_size)' com capacidade finita adequada ao caso de uso.",
    },
    RuleExplanation {
        id: "RUST-ASYNC-BLOCKING-CMD",
        name: "Comando de Processo Síncrono em Runtime Assíncrono",
        severity: "ERROR",
        tag: "rust",
        summary: "Proíbe 'std::process::Command::new' em código assíncrono do servidor Tokio.",
        rationale: "std::process::Command bloqueia a thread de execução do pool de workers do Tokio enquanto espera o processo terminar, causando latência e congelamento de outras requisições concorrentes.",
        bad_example: "let out = std::process::Command::new(\"ffmpeg\").arg(\"-i\").output()?;",
        good_example: "let out = tokio::process::Command::new(\"ffmpeg\").arg(\"-i\").output().await?;",
        remediation: "Utilize 'tokio::process::Command' com '.await' ou delegue para 'tokio::task::spawn_blocking'.",
    },
    RuleExplanation {
        id: "RUST-NO-SYNC-MUTEX-AWAIT",
        name: "Uso de std::sync::Mutex em Contexto Assíncrono Tokio",
        severity: "WARN",
        tag: "rust",
        summary: "Proíbe reter lock de 'std::sync::Mutex' através de pontos de suspensão '.await'.",
        rationale: "Reter um guard de std::sync::Mutex através de um .await bloqueia a thread do Tokio se outra task tentar adquirir o lock, causando deadlocks silenciosos e violando as garantias de Send do compilador.",
        bad_example: "let guard = self.sync_mutex.lock().unwrap();\ndo_async_work().await;\nprintln!(\"{:?}\", *guard);",
        good_example: "// Opção 1: Use tokio::sync::Mutex:\nlet guard = self.async_mutex.lock().await;\ndo_async_work().await;\n\n// Opção 2: Solte o lock antes do await:\nlet val = { self.sync_mutex.lock().unwrap().clone() };\ndo_async_work().await;",
        remediation: "Migre para 'tokio::sync::Mutex' ou garanta que o escopo do guard termine antes da chamada .await.",
    },
    RuleExplanation {
        id: "RUST-IDIOMATIC-ARC-CLONE",
        name: "Clonagem Idiomática de Ponteiros Arc",
        severity: "WARN",
        tag: "rust",
        summary: "Prefira 'Arc::clone(&ptr)' em vez de 'ptr.clone()'.",
        rationale: "A convenção oficial da comunidade Rust (RFC 258 / Clippy) recomenda Arc::clone(&ptr) para deixar 100% explícito ao leitor humano e à IA que se trata de uma cópia de ponteiro atômico O(1), e não de uma clonagem profunda (deep copy) de dados pesados.",
        bad_example: "let state = server_arc.clone();",
        good_example: "let state = Arc::clone(&server_arc);",
        remediation: "Substitua 'ptr.clone()' por 'Arc::clone(&ptr)'.",
    },
    RuleExplanation {
        id: "RUST-IDIOMATIC-SLICES",
        name: "Uso Idiomático de Slices (&str e &[T]) em Parâmetros",
        severity: "WARN",
        tag: "rust",
        summary: "Funções devem receber referências a fatias (&str / &[T]) em vez de coleções concretas (&String / &Vec<T>).",
        rationale: "Receber &String ou &Vec<T> obriga o chamador a ter uma coleção alocada na heap, impedindo a passagem de literais estáticos (&'static str), fatias de arrays ou substrings sem alocação desnecessária.",
        bad_example: "fn find_user(name: &String, ids: &Vec<u64>) -> bool { ... }",
        good_example: "fn find_user(name: &str, ids: &[u64]) -> bool { ... }",
        remediation: "Substitua o tipo do parâmetro de '&String' para '&str' e de '&Vec<T>' para '&[T]'.",
    },
    RuleExplanation {
        id: "RUST-SPAWN-ERROR-HANDLING",
        name: "Tratamento e Rastreabilidade em tokio::spawn",
        severity: "WARN",
        tag: "rust",
        summary: "Tarefas em 'tokio::spawn' devem capturar o JoinHandle ou incluir instrumentação de tracing.",
        rationale: "Disparar tokio::spawn órfão sem capturar o JoinHandle nem instrumentar com tracing faz com que qualquer panic ou erro interno da task seja engolido silenciosamente sem registro nos logs de produção.",
        bad_example: "tokio::spawn(async move {\n    process_background_event().await;\n});",
        good_example: "let _task = tokio::spawn(\n    async move {\n        if let Err(err) = process_background_event().await {\n            tracing::error!(\"Falha no background event: {}\", err);\n        }\n    }\n    .instrument(tracing::info_span!(\"background_event_task\")),\n);",
        remediation: "Instrumente a task com tracing::info_span! ou capture o JoinHandle para logar falhas.",
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
