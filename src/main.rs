use anyhow::Result;
use clap::Parser;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

mod baseline;
mod config;
mod context;
mod cv;
mod doc;
mod engine;
mod explain;
mod frontend;
mod gov;
mod gpu;
mod guardian;
mod health;
mod homelab;
mod infra;
mod learner;
mod mcp;
mod mesh;
mod migrations;
mod rule;
mod typegen;
mod vault;
mod watch;

use guardian::audit_stenio_integrity;

use baseline::Whitelist;
use config::SteniocheckConfig;
use cv::audit_curriculum_vitae;
use doc::audit_documentation;
use engine::Engine;
use gov::audit_governance;
use gpu::audit_gpu_subsystem;
use homelab::audit_homelab;
use infra::audit_infrastructure;
use migrations::audit_migrations;
use rule::{get_rules_from_config, Rule, Severity};
use vault::audit_vault;

#[derive(Parser, Debug)]
#[command(
    name = "stenio",
    author = "Sumænimá Platform",
    version = "3.0.0",
    about = "StenioSentinel — Universal Governance & Homelab Engine in Rust"
)]
struct Args {
    #[arg(
        short = 's',
        long,
        help = "Escopo de auditoria: hub, homelab, vault, cv, all [default: all]"
    )]
    scope: Option<String>,

    #[arg(
        short,
        long,
        help = "Filtrar regras por tag (ex: sec, arch, frontend, infra, gov, gpu, doc, db, custom)"
    )]
    tag: Option<String>,

    #[arg(
        short,
        long,
        help = "Modo rápido: escaneia apenas arquivos modificados no Git"
    )]
    fast: bool,

    #[arg(long, help = "Caminho raiz do escaneamento", default_value = ".")]
    path: PathBuf,

    #[arg(long, help = "Emitir saída em formato JSON")]
    json: bool,

    #[arg(long, help = "Formatar erros para anotações do GitHub Actions")]
    github_format: bool,

    #[arg(long, help = "Falhar imediatamente com exit code 1 se houver erros")]
    strict: bool,

    #[arg(
        long,
        help = "Aprender nova regra dinamicamente e persistir em steniocheck.toml (JSON)"
    )]
    learn: Option<String>,

    #[arg(long, help = "Listar todas as regras e autômatos ativos")]
    list: bool,

    #[arg(
        long,
        help = "Executar apenas uma regra específica (ex: --only FRONT-HEX)"
    )]
    only: Option<String>,

    #[arg(
        long,
        help = "Executar bateria de auto-testes sintéticos das regras do motor"
    )]
    self_test: bool,

    #[arg(
        long,
        help = "Executar raio-X completo de infraestrutura, disco, RAM, GPU e serviços"
    )]
    health: bool,

    #[arg(
        long,
        help = "Audita a malha Tailscale de todos os nós do Homelab via Tokio"
    )]
    mesh: bool,

    #[arg(
        long,
        help = "Gera automaticamente tipos TypeScript a partir dos structs Rust"
    )]
    typegen: bool,

    #[arg(
        long,
        help = "Gera contexto canônico de alta densidade para LLMs em Markdown"
    )]
    context: bool,

    #[arg(
        long,
        help = "Aplica correções automáticas (auto-fix) em violações passíveis de reparo"
    )]
    fix: bool,

    #[arg(
        long,
        help = "Audita a integridade criptográfica e mecanismos anti-tampering do próprio Stênio"
    )]
    guardian: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "",
        help = "Scan cirúrgico apenas nos arquivos alterados no Git (ex: --diff, --diff HEAD~1, --diff - para stdin)"
    )]
    diff: Option<String>,

    #[arg(
        long,
        help = "Gerenciar git hook pre-commit: 'install' para instalar no repositório, ou 'check' para executar validação"
    )]
    pre_commit: Option<String>,

    #[arg(
        long,
        help = "Saída ultra-compacta de uma linha por violação (otimizada para agentes de IA e LLMs)"
    )]
    compact: bool,

    #[arg(
        long,
        help = "Modo Daemon Watchdog: monitora o sistema de arquivos via inotify e audita instantaneamente (<5ms) qualquer arquivo salvo"
    )]
    watch: bool,

    #[arg(
        long,
        alias = "mcp-server",
        help = "Modo Servidor MCP: executa como servidor Model Context Protocol (stdio/JSON-RPC 2.0) para OpenCode, Claude Code, Antigravity, Cursor"
    )]
    mcp: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "all",
        help = "Exibe documentação técnica detalhada, exemplos incorretos/corretos e remediação de regras (ex: --explain SEC-SUDO, --explain RUST-NO-UNWRAP)"
    )]
    explain: Option<String>,
}

fn install_pre_commit_hook(start_dir: &Path) -> Result<()> {
    let canonical = if let Ok(c) = fs::canonicalize(start_dir) {
        c
    } else {
        start_dir.to_path_buf()
    };
    let mut current = canonical.as_path();
    loop {
        let git_dir = current.join(".git");
        if git_dir.is_dir() {
            let hooks_dir = git_dir.join("hooks");
            fs::create_dir_all(&hooks_dir)?;
            let hook_file = hooks_dir.join("pre-commit");
            let hook_script = r#"#!/usr/bin/env bash
# StenioSentinel Universal Pre-Commit Hook (v3.1)
# Auto-instalado pelo StenioSentinel
set -euo pipefail

if command -v stenio >/dev/null 2>&1; then
    echo "🛡️  [StenioSentinel] Auditando arquivos em staging..."
    exec stenio --diff staged --strict
else
    echo "⚠️  [StenioSentinel] Binário 'stenio' não encontrado no PATH. Pulando verificação."
fi
"#;
            fs::write(&hook_file, hook_script)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&hook_file) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(&hook_file, perms);
                }
            }
            println!(
                "{} Hook pre-commit instalado com sucesso em: {}",
                "✨".green().bold(),
                hook_file.display().to_string().cyan().bold()
            );
            return Ok(());
        }
        match current.parent() {
            Some(p) => current = p,
            None => break,
        }
    }
    anyhow::bail!(
        "Nenhum repositório Git (.git) encontrado a partir de {:?}",
        start_dir
    );
}

fn run_self_tests(rules: &[Rule]) -> Result<()> {
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "StênioKernel — Bateria de Auto-Testes Sintéticos (Self-Test)"
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );

    let mut passed = 0;
    let mut total = 0;

    macro_rules! check_case {
        ($name:expr, $pattern_id:expr, $sample:expr, $expected_match:expr) => {
            total += 1;
            let rule_opt = rules.iter().find(|r| r.id == $pattern_id);
            if let Some(rule) = rule_opt {
                let re = regex::Regex::new(&rule.pattern)?;
                let is_m = re.is_match($sample);
                if is_m == $expected_match {
                    passed += 1;
                    println!("   ✅ Teste {:<22} [{}] - OK", $name, $pattern_id.cyan());
                } else {
                    println!(
                        "   ❌ Teste {:<22} [{}] - FALHA (esperado match={})",
                        $name,
                        $pattern_id.red(),
                        $expected_match
                    );
                }
            } else {
                println!("   ⚠️ Regra {} não encontrada", $pattern_id.yellow());
            }
        };
    }

    check_case!("Python Banido", "ARCH-NO-PYTHON", "print('hello')", true);
    check_case!(
        "Thread Sleep Tokio",
        "RUST-ASYNC-SLEEP",
        "std::thread::sleep(Duration::from_millis(100));",
        true
    ); // stenio-ignore: RUST-ASYNC-SLEEP
    check_case!(
        "Tokio Sleep Válido",
        "RUST-ASYNC-SLEEP",
        "tokio::time::sleep(Duration::from_millis(100)).await;",
        false
    );
    check_case!(
        "Segredo Hardcoded",
        "SEC-SECRETS",
        "api_key = \"ghp_123456789012345678901234567890123456\"",
        true
    ); // stenio-ignore: SEC-SECRETS
    check_case!(
        "Sudo Desprotegido",
        "SEC-SUDO",
        "sudo systemctl restart nginx",
        true
    );
    check_case!(
        "Sudo curl Desprotegido",
        "SEC-SUDO",
        "sudo curl https://example.com",
        true
    ); // Novo: captura qualquer comando
    check_case!(
        "Sudo useradd Desprotegido",
        "SEC-SUDO",
        "sudo useradd -m user",
        true
    ); // Novo: era ponto cego
    check_case!(
        "Pkexec Válido",
        "SEC-SUDO",
        "pkexec systemctl restart nginx",
        false
    );
    check_case!(
        "Bare Except Proibido",
        "SEC-EXCEPT",
        "except:\n    pass",
        true
    );
    check_case!(
        "Except Tipado",
        "SEC-EXCEPT",
        "except ValueError:\n    pass",
        false
    );
    check_case!(
        "GNU Tools em Shell",
        "ARCH-RUST-TOOLS",
        "grep -r pattern .",
        true
    ); // Novo: AGENTS.md regra de terminal
    check_case!(
        "Rust Tools Válido",
        "ARCH-RUST-TOOLS",
        "rg 'pattern' .",
        false
    ); // Novo: rg não dispara
    check_case!(
        "Curl em Rust Proibido",
        "ARCH-RUST-CMD-LEGACY",
        r#"Command::new("curl")"#,
        true
    ); // Novo: regra ARCH-RUST-CMD-LEGACY
    check_case!(
        "XH em Rust OK",
        "ARCH-RUST-CMD-LEGACY",
        r#"Command::new("xh")"#,
        false
    ); // Novo: xh não dispara
    check_case!(
        "Console.log Proibido",
        "FRONT-LOGS",
        "  console.log('debug info')",
        true
    ); // Novo: FRONT-LOGS
    check_case!(
        "Unwrap Proibido",
        "RUST-NO-UNWRAP",
        "let val = opt.unwrap();",
        true
    );
    check_case!(
        "Expect Proibido",
        "RUST-NO-UNWRAP",
        r#"let val = opt.expect("erro");"#,
        true
    );
    check_case!(
        "Match Válido",
        "RUST-NO-UNWRAP",
        "let val = match opt { Some(v) => v, None => return };",
        false
    );

    // Teste sintético de Auto-Fix para SEC-SUDO (regex expandido: captura qualquer comando)
    total += 1;
    let sudo_rule = rules.iter().find(|r| r.id == "SEC-SUDO");
    if let Some(rule) = sudo_rule {
        if let Some(ref fix) = rule.fix_replacement {
            let re = regex::Regex::new(&rule.pattern)?;
            let sample = "sudo systemctl restart nginx";
            let fixed = re.replace_all(sample, fix.as_str());
            if fixed == "pkexec systemctl restart nginx" {
                passed += 1;
                println!(
                    "   ✅ Teste {:<22} [{}] - OK",
                    "Auto-Fix SEC-SUDO",
                    "SEC-SUDO".cyan()
                );
            } else {
                println!("   ❌ Teste Auto-Fix gerou resultado inesperado: {}", fixed);
            }
        }
    }

    // Teste Auto-Fix para comando não listado anteriormente (sudo curl — era ponto cego)
    total += 1;
    let sudo_rule2 = rules.iter().find(|r| r.id == "SEC-SUDO");
    if let Some(rule) = sudo_rule2 {
        if let Some(ref fix) = rule.fix_replacement {
            let re = regex::Regex::new(&rule.pattern)?;
            let sample = "sudo curl https://example.com";
            let fixed = re.replace_all(sample, fix.as_str());
            if fixed == "pkexec curl https://example.com" {
                passed += 1;
                println!(
                    "   ✅ Teste {:<22} [{}] - OK",
                    "Auto-Fix sudo curl",
                    "SEC-SUDO".cyan()
                );
            } else {
                println!("   ❌ Teste Auto-Fix (sudo curl) gerou: {}", fixed);
            }
        }
    }

    println!();
    if passed == total {
        println!(
            "{}",
            format!(
                "✨ Auto-teste aprovado com sucesso! ({}/{} suítes sintéticas válidas)",
                passed, total
            )
            .green()
            .bold()
        );
    } else {
        println!(
            "{}",
            format!("❌ Falha em auto-testes ({}/{} passaram)", passed, total)
                .red()
                .bold()
        );
        std::process::exit(1);
    }
    println!();
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // ── Modo Explicação de Regras (--explain [RULE_ID]) ─────────────────────
    if let Some(ref rule_target) = args.explain {
        if rule_target == "all" || rule_target.is_empty() {
            println!("{}", explain::list_all_explanations());
        } else if let Some(exp) = explain::get_explanation(rule_target) {
            println!("{}", explain::format_explanation_cli(exp));
        } else {
            eprintln!(
                "{} Nenhuma explicação encontrada para a regra '{}'.",
                "⚠️".yellow(),
                rule_target
            );
            println!("{}", explain::list_all_explanations());
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Modo Aprendizado: Aprender nova regra e persistir no steniocheck.toml ──
    if let Some(ref payload) = args.learn {
        learner::handle_learn(&args.path, payload)?;
        return Ok(());
    }

    // ── Modo Raio-X de Infraestrutura (--health) ───────────────────────────
    if args.health {
        health::run_system_health()?;
        return Ok(());
    }

    // ── Modo Malha Tailscale Homelab (--mesh) ──────────────────────────────
    if args.mesh {
        let rt = tokio::runtime::Runtime::new()?;
        let start = std::time::Instant::now();
        let results = rt.block_on(mesh::audit_tailscale_mesh());
        mesh::print_mesh_report(&results, start.elapsed());
        return Ok(());
    }

    // ── Modo Typegen Automático Rust → TypeScript (--typegen) ──────────────
    if args.typegen {
        let target_dir = if args.path.join("app/frontend-v2").is_dir() {
            args.path.clone()
        } else if PathBuf::from("/mnt/NVME_PCI/sumaenimahub/SUMAENIMA-HUB").is_dir() {
            PathBuf::from("/mnt/NVME_PCI/sumaenimahub/SUMAENIMA-HUB")
        } else {
            args.path.clone()
        };
        typegen::generate_typescript_bindings(&target_dir)?;
        return Ok(());
    }

    // ── Modo Knowledge Context Engine para LLMs (--context) ────────────────
    if args.context {
        context::generate_llm_context(&args.path);
        return Ok(());
    }

    // ── Modo Pre-Commit Hook (--pre-commit install / check) ────────────────
    if let Some(ref action) = args.pre_commit {
        match action.as_str() {
            "install" => {
                install_pre_commit_hook(&args.path)?;
                return Ok(());
            }
            "check" => {
                // Continua a execução no modo diff com target staged
            }
            other => {
                eprintln!(
                    "Ação desconhecida para --pre-commit: '{}'. Use 'install' ou 'check'.",
                    other
                );
                std::process::exit(1);
            }
        }
    }

    // ── Modo Guardian Anti-Tampering & Auto-Preservação (--guardian) ────────
    if args.guardian {
        let stenio_src = PathBuf::from("/mnt/NVME_PCI/agentic-ai/governance/stenio");
        let rep = audit_stenio_integrity(&stenio_src);
        println!();
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "StenioSentinel — Guardian: Autoproteção Criptográfica & Anti-Tampering"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        for m in &rep.messages {
            println!("   {}", m);
        }
        if !rep.tamper_alerts.is_empty() {
            println!();
            for a in &rep.tamper_alerts {
                println!("   {}", a.red().bold());
            }
        }
        println!();
        return Ok(());
    }

    let whitelist_path = args.path.join(".steniocheck-whitelist-registry.json");
    let whitelist = Whitelist::load_from_file(&whitelist_path);

    // Carrega configuração canônica steniocheck.toml
    let steniocheck_cfg = SteniocheckConfig::load_from_dir(&args.path);
    let rules = get_rules_from_config(&steniocheck_cfg);

    // ── Modo MCP Server (Protocolo JSON-RPC 2.0 stdio para OpenCode, Antigravity, Claude) ──
    if args.mcp {
        mcp::run_mcp_server(&args.path, rules, whitelist)?;
        return Ok(());
    }

    // ── Modo Watchdog em Tempo Real (--watch com inotify) ─────────────────
    if args.watch {
        let engine = Engine::new(rules, whitelist)?;
        let tag_lower = args.tag.as_ref().map(|s| s.to_lowercase());
        let only_rule = args.only.as_deref();
        watch::start_watch_mode(&args.path, &engine, tag_lower.as_deref(), only_rule)?;
        return Ok(());
    }

    // ── Modo Listagem (--list) ─────────────────────────────────────────────
    if args.list {
        println!();
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "StênioKernel — Catálogo de Regras Ativas & Autômatos"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "══════════════════════════════════════════════════════════════════════════════"
                .cyan()
                .bold()
        );
        println!(
            "{:<26} {:<10} {:<8} {:<14} {}",
            "ID DA REGRA".bold(),
            "TAG".bold(),
            "SEV".bold(),
            "EXTENSÕES".bold(),
            "NOME".bold()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        );

        for r in &rules {
            let sev_str = match r.severity {
                Severity::Error => "ERROR".red().bold(),
                Severity::Warning => "WARN ".yellow().bold(),
            };
            let exts = r.file_extensions.join(", ");
            println!(
                "{:<26} {:<10} {:<8} {:<14} {}",
                r.id.cyan().bold(),
                r.tag.yellow(),
                sev_str,
                format!("[{}]", exts).dimmed(),
                r.name
            );
        }
        println!();
        println!("Total de regras ativas: {}", rules.len().to_string().bold());
        println!();
        return Ok(());
    }

    // ── Modo Auto-Teste (--self-test) ──────────────────────────────────────
    if args.self_test {
        run_self_tests(&rules)?;
        return Ok(());
    }

    let tag_lower = args.tag.as_deref().map(|s| s.to_lowercase());
    let only_rule = args.only.as_deref();
    let scope = if let Some(s) = args.scope.as_deref() {
        s.to_lowercase()
    } else {
        let p_canon = args
            .path
            .canonicalize()
            .unwrap_or_else(|_| args.path.clone());
        let p_str = p_canon.to_string_lossy();
        if p_str.contains("sumaenimahub")
            || (args.path.join("app").is_dir() && args.path.join("migrations").is_dir())
        {
            "hub".to_string()
        } else if p_str.ends_with("mnemocine") {
            "homelab".to_string()
        } else if p_str.contains("curriculum-vitae") {
            "cv".to_string()
        } else if args.path.join("mnemocine").is_dir() && args.path.join("governance").is_dir() {
            "all".to_string()
        } else {
            "all".to_string()
        }
    };

    let is_hub_active = scope == "all" || scope == "hub";
    let is_homelab_active = scope == "all" || scope == "homelab" || scope == "mnemocine";
    let is_vault_active = scope == "all" || scope == "vault" || scope == "docs";
    let is_cv_active = scope == "all" || scope == "cv";

    let should_audit_gpu = is_hub_active
        && (tag_lower.as_deref() == Some("gpu") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("GPU-BLOAT-OR-MODEL"))
                .unwrap_or(false));
    let should_audit_gov = is_hub_active
        && (tag_lower.as_deref() == Some("gov") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("GOV-AGENT-LAWS"))
                .unwrap_or(false));
    let should_audit_doc = (is_hub_active || is_homelab_active || is_vault_active)
        && (tag_lower.as_deref() == Some("doc") || tag_lower.is_none())
        && (only_rule.is_none() || only_rule.map(|s| s.starts_with("DOC-")).unwrap_or(false));
    let should_audit_mig = is_hub_active
        && (tag_lower.as_deref() == Some("db")
            || tag_lower.as_deref() == Some("migrations")
            || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("DB-MIGRATION-INTEGRITY"))
                .unwrap_or(false));

    let scan_target = if scope == "homelab" || scope == "mnemocine" {
        if args.path.join("mnemocine").is_dir() {
            args.path.join("mnemocine")
        } else {
            args.path.clone()
        }
    } else if scope == "hub" {
        if args.path.join("sumaenimahub/SUMAENIMA-HUB").is_dir() {
            args.path.join("sumaenimahub/SUMAENIMA-HUB")
        } else {
            args.path.clone()
        }
    } else if scope == "cv" {
        if args.path.join("curriculum-vitae").is_dir() {
            args.path.join("curriculum-vitae")
        } else {
            args.path.clone()
        }
    } else {
        args.path.clone()
    };

    let diff_target: Option<&str> = if args.pre_commit.as_deref() == Some("check") {
        Some("staged")
    } else {
        args.diff.as_deref()
    };

    let engine = Engine::new(rules, whitelist)?;

    // Executa em paralelo o escaneamento do repositório e os subsistemas auxiliares
    let (
        (scan_res, (gov_res, doc_res)),
        ((gpu_res, mig_res), (((homelab_res, infra_res), vault_res), cv_res)),
    ) = rayon::join(
        || {
            rayon::join(
                || {
                    engine.scan_directory(
                        &scan_target,
                        tag_lower.as_deref(),
                        only_rule,
                        args.fast,
                        diff_target,
                        args.fix,
                    )
                },
                || {
                    let g = if should_audit_gov {
                        Some(audit_governance(&args.path))
                    } else {
                        None
                    };
                    let d = if should_audit_doc {
                        Some(audit_documentation(&args.path))
                    } else {
                        None
                    };
                    (g, d)
                },
            )
        },
        || {
            rayon::join(
                || {
                    let gp = if should_audit_gpu {
                        Some(audit_gpu_subsystem())
                    } else {
                        None
                    };
                    let m = if should_audit_mig {
                        Some(audit_migrations(&args.path))
                    } else {
                        None
                    };
                    (gp, m)
                },
                || {
                    rayon::join(
                        || {
                            let (h, inf) = if is_homelab_active {
                                (
                                    Some(audit_homelab(&args.path)),
                                    Some(audit_infrastructure(&args.path)),
                                )
                            } else {
                                (None, None)
                            };
                            let v = if is_vault_active {
                                Some(audit_vault(&args.path))
                            } else {
                                None
                            };
                            ((h, inf), v)
                        },
                        || {
                            if is_cv_active {
                                Some(audit_curriculum_vitae(&args.path))
                            } else {
                                None
                            }
                        },
                    )
                },
            )
        },
    );

    let mut report = scan_res?;

    // ── Subsistema de Governança (AGENTS.md & skills) ──────────────────────
    let mut gov_messages = Vec::new();
    if let Some(gov) = gov_res {
        gov_messages = gov.messages;
        if !gov.errors.is_empty() {
            report.error_count += gov.errors.len();
            report.total_violations += gov.errors.len();
            for err in gov.errors {
                report.violations.push(engine::Violation {
                    rule_id: "GOV-AGENT-LAWS".to_string(),
                    rule_name: "Governança & Leis do Agente".to_string(),
                    severity: Severity::Error,
                    file_path: "AGENTS.md".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: err,
                    suggestion: Some(
                        "Mantenha as 38 Leis Absolutas e a Regra de Ouro no AGENTS.md.".to_string(),
                    ),
                });
            }
        }
    }

    // ── Subsistema de Documentação (docs/ & ADRs) ───────────────────────────
    let mut doc_messages = Vec::new();
    if let Some(doc) = doc_res {
        doc_messages = doc.messages;
        for v in doc.violations {
            if v.severity == Severity::Error {
                report.error_count += 1;
            } else {
                report.warning_count += 1;
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Subsistema GPU & Modelos (RTX / NVMe) ──────────────────────────────
    let mut gpu_messages = Vec::new();
    if let Some(gpu) = gpu_res {
        gpu_messages = gpu.messages;
        if !gpu.errors.is_empty() {
            report.error_count += gpu.errors.len();
            report.total_violations += gpu.errors.len();
            for gpu_err in gpu.errors {
                report.violations.push(engine::Violation {
                    rule_id: "GPU-BLOAT-OR-MODEL".to_string(),
                    rule_name: "Integridade de GPU & Modelos".to_string(),
                    severity: Severity::Error,
                    file_path: "llm_model_cache".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: gpu_err,
                    suggestion: Some("Verifique o arquivo GGML em /mnt/NVME_PCI/sumaenimahub/llm_model_cache/whisper-ggml/.".to_string()),
                });
            }
        }
    }

    // ── Subsistema de Banco de Dados & Migrações (migrations/) ───────────────
    let mut mig_messages = Vec::new();
    if let Some(mig) = mig_res {
        mig_messages = mig.messages;
    }

    // ── Subsistema Homelab (mnemocine/) ────────────────────────────────────
    let mut homelab_messages = Vec::new();
    if let Some(hl) = homelab_res {
        report.total_files_scanned += hl.total_files_scanned;
        homelab_messages = hl.messages;
        for v in hl.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Subsistema de Infraestrutura (Compose, Systemd, SOPS) ──────────────
    if let Some(inf) = infra_res {
        report.total_files_scanned += inf.total_files_scanned;
        for msg in inf.messages {
            homelab_messages.push(msg);
        }
        for v in inf.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Subsistema Vault (Obsidian & Governança) ───────────────────────────
    let mut vault_messages = Vec::new();
    if let Some(vl) = vault_res {
        report.total_files_scanned += vl.total_files_scanned;
        vault_messages = vl.messages;
        for v in vl.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Subsistema de Currículo Bilíngue (curriculum-vitae/) ───────────────
    let mut cv_messages = Vec::new();
    if let Some(cv) = cv_res {
        report.total_files_scanned += cv.total_files_scanned;
        cv_messages = cv.messages;
        for v in cv.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.compact {
        for v in &report.violations {
            let sev = match v.severity {
                Severity::Error => "ERROR",
                Severity::Warning => "WARN",
            };
            if let Some(ref sug) = v.suggestion {
                println!(
                    "[{}] {}:{}: [{}] {} - {} (💡 {})",
                    sev, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message, sug
                );
            } else {
                println!(
                    "[{}] {}:{}: [{}] {} - {}",
                    sev, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message
                );
            }
        }
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.github_format {
        for v in &report.violations {
            let level = match v.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            if let Some(ref sug) = v.suggestion {
                println!(
                    "::{} file={},line={},title=[{}] {}::{} (💡 Sugestão: {})",
                    level, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message, sug
                );
            } else {
                println!(
                    "::{} file={},line={},title=[{}] {}::{}",
                    level, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message
                );
            }
        }
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!(
        "{} {}",
        "StenioSentinel (Rust Engine v3.0) — Sistema Universal de Governança"
            .cyan()
            .bold(),
        format!("[{:.2?}]", report.duration).yellow()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );

    // Auditoria de Governança (AGENTS.md)
    if should_audit_gov {
        println!(
            "{}",
            "── Subsistema de Governança & Leis do Agente ──────────────────".dimmed()
        );
        for msg in gov_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria de Documentação (docs/)
    if should_audit_doc {
        println!(
            "{}",
            "── Subsistema de Rastreabilidade & Documentação ───────────────".dimmed()
        );
        for msg in doc_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria de GPU & Modelos
    if should_audit_gpu {
        println!(
            "{}",
            "── Subsistema GPU & Modelos (RTX 5050 / Blackwell) ─────────".dimmed()
        );
        for msg in gpu_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria de Banco de Dados & Migrações (SQLx)
    if should_audit_mig {
        println!(
            "{}",
            "── Subsistema de Banco de Dados & Migrações (SQLx) ────────────".dimmed()
        );
        for msg in mig_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria do Homelab (Mnemocine)
    if is_homelab_active && !homelab_messages.is_empty() {
        println!(
            "{}",
            "── Subsistema Homelab Mnemocine (Infraestrutura) ───────────────".dimmed()
        );
        for msg in homelab_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria do Vault Obsidian (Governança Universal)
    if is_vault_active && !vault_messages.is_empty() {
        println!(
            "{}",
            "── Subsistema Vault Obsidian & Governança Universal ───────────".dimmed()
        );
        for msg in vault_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Auditoria de Currículo Bilíngue
    if is_cv_active && !cv_messages.is_empty() {
        println!(
            "{}",
            "── Subsistema Currículo Bilíngue (curriculum-vitae/) ──────────".dimmed()
        );
        for msg in cv_messages {
            println!("   {}", msg);
        }
        println!();
    }

    println!(
        "Arquivos escaneados: {} | Violações encontradas: {}",
        report.total_files_scanned.to_string().bold(),
        report.total_violations.to_string().bold()
    );

    if report.total_fixed > 0 {
        println!(
            "{}",
            format!(
                "✨ Auto-fix: {} violação(ões) corrigida(s) automaticamente com sucesso!",
                report.total_fixed
            )
            .green()
            .bold()
        );
    }
    println!();

    if report.violations.is_empty() {
        println!(
            "{}",
            "✨ Nenhuma violação encontrada! Repositório 100% em conformidade com as regras."
                .green()
                .bold()
        );
        println!();
        return Ok(());
    }

    for v in &report.violations {
        let badge = match v.severity {
            Severity::Error => "[ERROR]".red().bold(),
            Severity::Warning => "[WARN] ".yellow().bold(),
        };

        println!(
            "{} {} {}: {}",
            badge,
            v.rule_id.cyan().bold(),
            v.rule_name.bold(),
            v.message
        );
        println!(
            "       Local: {}:{}",
            v.file_path.dimmed(),
            v.line_number.to_string().bold()
        );
        println!("       Trecho: \"{}\"", v.snippet.trim().dimmed());
        if let Some(ref sug) = v.suggestion {
            println!("       💡 {}", sug.green().bold());
        }
        println!();
    }

    println!(
        "Resumo: {} erro(s), {} aviso(s)",
        report.error_count.to_string().red().bold(),
        report.warning_count.to_string().yellow().bold()
    );
    println!();

    if args.strict && report.error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}
