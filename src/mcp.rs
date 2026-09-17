use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::baseline::Whitelist;
use crate::engine::Engine;
use crate::guardian::audit_stenio_integrity;
use crate::rule::{Rule, Severity};

#[derive(Debug, Deserialize)]
struct McpRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct McpResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub fn run_mcp_server(repo_root: &Path, rules: Vec<Rule>, whitelist: Whitelist) -> Result<()> {
    eprintln!("🦀 StenioSentinel MCP Server inicializado em stdio (JSON-RPC 2.0)");
    let engine = Engine::new(rules.clone(), whitelist.clone())?;

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: McpRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("Erro ao deserializar MCP request: {}", err);
                continue;
            }
        };

        let req_id = req.id.clone().unwrap_or(Value::Null);

        match req.method.as_str() {
            "initialize" => {
                let resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "stenio-sentinel",
                            "version": "3.1.0"
                        }
                    })),
                    error: None,
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // Notificação: sem resposta necessária
            }
            "ping" => {
                let resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(json!({})),
                    error: None,
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "stenio_scan",
                            "description": "Audita um arquivo ou diretório usando as regras universais de governança do StenioSentinel e retorna as violações de forma concisa.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Caminho do arquivo ou diretório a auditar"
                                    },
                                    "tag": {
                                        "type": "string",
                                        "description": "Filtrar por tag específica (ex: sec, arch, frontend, infra, doc)"
                                    },
                                    "only_rule": {
                                        "type": "string",
                                        "description": "Executar apenas uma regra (ex: SEC-SUDO, ARCH-RUST-CMD-LEGACY)"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_diff",
                            "description": "Executa auditoria cirúrgica ultrarrápida (<5ms) apenas nos arquivos modificados no Git (staged ou última revisão).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rev": {
                                        "type": "string",
                                        "description": "Alvo do diff (ex: 'staged', 'HEAD~1'). Default: arquivos em staging/modificados"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_guardian",
                            "description": "Verifica a integridade criptográfica SHA-256 e mecanismos anti-tampering do núcleo do Stênio.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "stenio_context",
                            "description": "Retorna o contexto canônico de governança, arquitetura e infraestrutura do ecossistema SUMÆNIMÁ / Homelab.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "stenio_explain",
                            "description": "Explica detalhadamente o porquê de uma regra existir, fornecendo exemplos de código incorreto, código correto e remediação passo-a-passo para agentes e LLMs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rule_id": {
                                        "type": "string",
                                        "description": "ID da regra (ex: SEC-SUDO, RUST-NO-UNWRAP, ARCH-RUST-TOOLS, VAULT-FRONTMATTER, HOMELAB-NAMING) ou vazio para listar todas"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_dry",
                            "description": "Audita duplicação de código usando o Princípio DRY Absoluto com Rolling Block Hash (<15ms). Detecta blocos clonados entre arquivos ou dentro do mesmo arquivo.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Caminho raiz a inspecionar (default: .)"
                                    },
                                    "min_lines": {
                                        "type": "number",
                                        "description": "Número mínimo de linhas substantivas idênticas para flag de duplicação (default: 6)"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_gate",
                            "description": "Quality Gate Pré-Entrega: executa uma auditoria rigorosa de tolerância zero (regras críticas, governança, artefatos e duplicação DRY). O agente DEVE chamar esta ferramenta antes de declarar conclusão da tarefa e garantir que retorne APROVADO.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Caminho raiz a inspecionar (default: .)"
                                    }
                                }
                            }
                        }
                    ]
                });

                let resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(tools),
                    error: None,
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
            "tools/call" => {
                let tool_name = req
                    .params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let arguments = req.params.get("arguments").cloned().unwrap_or(json!({}));

                let content_text = match tool_name {
                    "stenio_scan" => {
                        let path_str = arguments
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or(".");
                        let tag = arguments.get("tag").and_then(|v| v.as_str());
                        let only = arguments.get("only_rule").and_then(|v| v.as_str());
                        let target_path = repo_root.join(path_str);

                        if target_path.is_file() {
                            let violations = engine.scan_file(&target_path, tag, only);
                            if violations.is_empty() {
                                format!("✨ Arquivo '{}' 100% conforme. Zero violações.", path_str)
                            } else {
                                let mut lines = Vec::new();
                                for v in violations {
                                    let sev = match v.severity {
                                        Severity::Error => "ERROR",
                                        Severity::Warning => "WARN",
                                    };
                                    lines.push(format!(
                                        "[{}] {}:{}: [{}] {} (💡 {})",
                                        sev,
                                        v.file_path,
                                        v.line_number,
                                        v.rule_id,
                                        v.message,
                                        v.suggestion.as_deref().unwrap_or("N/A")
                                    ));
                                }
                                lines.join("\n")
                            }
                        } else {
                            match engine.scan_directory(&target_path, tag, only, false, None, false)
                            {
                                Ok(report) => {
                                    if report.violations.is_empty() {
                                        format!("✨ Diretório '{}' 100% conforme. Zero violações em {} arquivos.", path_str, report.total_files_scanned)
                                    } else {
                                        let mut lines = Vec::new();
                                        lines.push(format!(
                                            "Auditoria em '{}': {} erro(s), {} aviso(s) em {} arquivo(s)",
                                            path_str, report.error_count, report.warning_count, report.total_files_scanned
                                        ));
                                        for v in report.violations.iter().take(30) {
                                            let sev = match v.severity {
                                                Severity::Error => "ERROR",
                                                Severity::Warning => "WARN",
                                            };
                                            lines.push(format!(
                                                "[{}] {}:{}: [{}] {} (💡 {})",
                                                sev,
                                                v.file_path,
                                                v.line_number,
                                                v.rule_id,
                                                v.message,
                                                v.suggestion.as_deref().unwrap_or("N/A")
                                            ));
                                        }
                                        if report.violations.len() > 30 {
                                            lines.push(format!(
                                                "... e mais {} violações.",
                                                report.violations.len() - 30
                                            ));
                                        }
                                        lines.join("\n")
                                    }
                                }
                                Err(e) => format!("Erro ao auditar diretório: {}", e),
                            }
                        }
                    }
                    "stenio_diff" => {
                        let rev = arguments.get("rev").and_then(|v| v.as_str());
                        match engine.scan_directory(repo_root, None, None, false, rev, false) {
                            Ok(report) => {
                                if report.violations.is_empty() {
                                    format!("✨ Scan cirúrgico limpo! Zero violações nos {} arquivos modificados.", report.total_files_scanned)
                                } else {
                                    let mut lines = Vec::new();
                                    lines.push(format!(
                                        "Scan cirúrgico: {} erro(s), {} aviso(s) nos arquivos modificados:",
                                        report.error_count, report.warning_count
                                    ));
                                    for v in &report.violations {
                                        let sev = match v.severity {
                                            Severity::Error => "ERROR",
                                            Severity::Warning => "WARN",
                                        };
                                        lines.push(format!(
                                            "[{}] {}:{}: [{}] {} (💡 {})",
                                            sev,
                                            v.file_path,
                                            v.line_number,
                                            v.rule_id,
                                            v.message,
                                            v.suggestion.as_deref().unwrap_or("N/A")
                                        ));
                                    }
                                    lines.join("\n")
                                }
                            }
                            Err(e) => format!("Erro ao executar diff: {}", e),
                        }
                    }
                    "stenio_guardian" => {
                        let rep = audit_stenio_integrity(repo_root);
                        if rep.is_intact {
                            format!(
                                "🛡️ Guardian: Íntegro. Zero adulteração. Executável SHA-256: {}",
                                rep.binary_hash
                            )
                        } else {
                            format!(
                                "🚨 Guardian: ADULTERAÇÃO DETECTADA!\n{}",
                                rep.tamper_alerts.join("\n")
                            )
                        }
                    }
                    "stenio_context" => {
                        format!(
                            "# Contexto Canônico StenioSentinel v3.1\n\n\
                            - Plataforma: Monorepo / Vault Obsidian em /mnt/NVME_PCI/agentic-ai\n\
                            - Homelab Mnemocine: psicopompo (dev/gpu), ybyra (edge), kuaray (media), ybytu (cloud exit), kavure (services)\n\
                            - GPU: RTX 5050 Blackwell com aceleração local CUDA\n\
                            - Regras fundamentais: Proibido sudo puro (usar pkexec em scripts), proibido ferramentas GNU em Rust (usar xh, walkdir, regex), soft mount NFS obrigatório.\n\
                            - Ferramentas CLI: use stenio --diff para scan rápido de alterações."
                        )
                    }
                    "stenio_explain" => {
                        let rule_id = arguments
                            .get("rule_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if rule_id.is_empty() || rule_id.eq_ignore_ascii_case("all") {
                            crate::explain::list_all_explanations()
                        } else if let Some(exp) = crate::explain::get_explanation(rule_id) {
                            crate::explain::format_explanation_plain(exp)
                        } else {
                            format!(
                                "Nenhuma explicação encontrada para a regra '{}'.\n\n{}",
                                rule_id,
                                crate::explain::list_all_explanations()
                            )
                        }
                    }
                    "stenio_gate" => {
                        let path_str = arguments
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or(".");
                        let target_path = repo_root.join(path_str);
                        match engine.scan_directory(&target_path, None, None, false, None, false) {
                            Ok(report) => {
                                let mut errors = Vec::new();
                                for v in &report.violations {
                                    if v.severity == Severity::Error {
                                        errors.push(format!(
                                            "[{}] {}:{}: {} (💡 {})",
                                            v.rule_id,
                                            v.file_path,
                                            v.line_number,
                                            v.message,
                                            v.suggestion.as_deref().unwrap_or("N/A")
                                        ));
                                    }
                                }
                                let gov = crate::gov::audit_governance(&target_path);
                                for err in &gov.errors {
                                    errors.push(format!("[GOV] {}", err));
                                }

                                let (dry_violations, _, _) =
                                    crate::dry::scan_dry_directory(&target_path, 6, &whitelist);
                                for dv in &dry_violations {
                                    errors.push(format!(
                                        "[DRY] {}:{}: {} (💡 {})",
                                        dv.file_path,
                                        dv.line_number,
                                        dv.message,
                                        dv.suggestion.as_deref().unwrap_or("Abstraia a lógica duplicada.")
                                    ));
                                }

                                if errors.is_empty() {
                                    format!(
                                        "🎉 [GATE APROVADO] Parabéns! Zero erros impeditivos e zero duplicações em {} arquivos. Código 100% conforme. A tarefa está aprovada para entrega!",
                                        report.total_files_scanned
                                    )
                                } else {
                                    format!(
                                        "🛑 [GATE REJEITADO — BLOQUEIO MANDATÓRIO DE ENTREGA]\n\
                                        A tarefa NÃO PODE ser declarada concluída. É ESTRITAMENTE PROIBIDO:\n\
                                        1. Propor alterar o motor do Stênio ou criar novas crates de governança (Violação ARCH-SCOPE-ISOLATION).\n\
                                        2. Alegar que erros ou duplicações DRY são 'problemas pré-existentes' para fugir da correção.\n\
                                        3. Substituir unwrap() por expect() (Ambos violam RUST-NO-UNWRAP com erro fatal).\n\
                                        4. Adicionar comentários // stenio-ignore (Violação AGENT-NO-SUPPRESSION-DIRECTIVES).\n\n\
                                        O modelo DEVE corrigir as seguintes {} violações diretamente no código da aplicação antes de finalizar:\n\n{}\n\n\
                                        Consulte 'stenio_explain' com o rule_id para ver a remediação oficial.",
                                        errors.len(),
                                        errors.join("\n")
                                    )
                                }
                            }
                            Err(e) => format!("Erro ao executar Quality Gate: {}", e),
                        }
                    }
                    "stenio_dry" => {
                        let path_str = arguments
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or(".");
                        let min_lines = arguments
                            .get("min_lines")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(6) as usize;
                        let target_path = repo_root.join(path_str);
                        let (dry_violations, dry_count, dry_dur) =
                            crate::dry::scan_dry_directory(&target_path, min_lines, &whitelist);

                        if dry_violations.is_empty() {
                            format!(
                                "✨ [DRY APROVADO] Zero duplicações detectadas em {} arquivos (tempo: {:?}). Princípio DRY 100% cumprido!",
                                dry_count, dry_dur
                            )
                        } else {
                            let mut msg = format!(
                                "⚠️ [DRY DETECTADO] {} bloco(s) de código duplicado(s) detectado(s) em {} arquivos (tempo: {:?}):\n\n",
                                dry_violations.len(),
                                dry_count,
                                dry_dur
                            );
                            for v in &dry_violations {
                                msg.push_str(&format!(
                                    "• {}:{} - {}\n  Snippet:\n{}\n  💡 Sugestão: {}\n\n",
                                    v.file_path,
                                    v.line_number,
                                    v.message,
                                    v.snippet,
                                    v.suggestion.as_deref().unwrap_or("Abstraia a lógica duplicada.")
                                ));
                            }
                            msg
                        }
                    }
                    other => format!("Ferramenta desconhecida: '{}'", other),
                };

                let resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": content_text
                            }
                        ]
                    })),
                    error: None,
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
            other => {
                let resp = McpResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req_id,
                    result: None,
                    error: Some(json!({
                        "code": -32601,
                        "message": format!("Método '{}' não encontrado", other)
                    })),
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}
