use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::Violation;
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
    eprintln!("🦀 StenioSentinel MCP Server initialized on stdio (JSON-RPC 2.0)");
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
                eprintln!("Error deserializing MCP request: {}", err);
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
                            "version": "4.0.0"
                        }
                    })),
                    error: None,
                };
                let out = serde_json::to_string(&resp)?;
                writeln!(stdout, "{}", out)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // Notification: no response needed
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
                            "description": "Audits a file or directory using StenioSentinel universal governance rules and returns violations concisely.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Path to file or directory to audit"
                                    },
                                    "tag": {
                                        "type": "string",
                                        "description": "Filter by specific tag (e.g., sec, arch, frontend, infra, doc)"
                                    },
                                    "only_rule": {
                                        "type": "string",
                                        "description": "Execute only a single rule by ID (e.g., SEC-SUDO, ARCH-RUST-CMD-LEGACY)"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_diff",
                            "description": "Executes sub-millisecond surgical audit (<5ms) only on files modified in Git (staged or given revision).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rev": {
                                        "type": "string",
                                        "description": "Target git revision (e.g., 'staged', 'HEAD~1'). Default: staged/modified files"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_guardian",
                            "description": "Verifies SHA-256 cryptographic integrity and anti-tampering defenses of Stenio Sentinel core.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "stenio_context",
                            "description": "Returns canonical governance, architecture, and homelab infrastructure context for the SUMÆNIMÁ / Homelab ecosystem.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
                            }
                        },
                        {
                            "name": "stenio_explain",
                            "description": "Explains rule rationale in detail with bad code examples, good code patterns, and step-by-step remediation guidance for agents and LLMs.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rule_id": {
                                        "type": "string",
                                        "description": "Rule ID (e.g., SEC-SUDO, RUST-NO-UNWRAP, ARCH-RUST-TOOLS, VAULT-FRONTMATTER, HOMELAB-NAMING) or empty to list all"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_dry",
                            "description": "Audits code duplication using the Absolute DRY Principle with Rolling Block Hash (<15ms). Detects duplicate blocks across or within files.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {
                                        "type": "string",
                                        "description": "Root path to inspect (default: .)"
                                    },
                                    "min_lines": {
                                        "type": "number",
                                        "description": "Minimum identical substantive lines required to trigger duplication (default: 6)"
                                    }
                                }
                            }
                        },
                        {
                            "name": "stenio_gate",
                            "description": "Pre-Delivery Quality Gate: executes zero-tolerance audit (critical rules, governance, test artifacts, and DRY duplication). Agents MUST call this tool before declaring task completion and ensure it returns PASSED.",
                            "inputSchema": path_input_schema()
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
                                format!("✨ File '{}' 100% compliant. Zero violations.", path_str)
                            } else {
                                let lines: Vec<String> =
                                    violations.iter().map(format_violation_line).collect();
                                lines.join("\n")
                            }
                        } else {
                            match engine.scan_directory(&target_path, tag, only, false, None, false)
                            {
                                Ok(report) => {
                                    if report.violations.is_empty() {
                                        format!(
                                            "✨ Directory '{}' 100% compliant. Zero violations across {} files.",
                                            path_str, report.total_files_scanned
                                        )
                                    } else {
                                        let mut lines = Vec::new();
                                        lines.push(format!(
                                            "Audit on '{}': {} error(s), {} warning(s) across {} file(s)",
                                            path_str, report.error_count, report.warning_count, report.total_files_scanned
                                        ));
                                        for v in report.violations.iter().take(30) {
                                            lines.push(format_violation_line(v));
                                        }
                                        if report.violations.len() > 30 {
                                            lines.push(format!(
                                                "... and {} more violation(s).",
                                                report.violations.len() - 30
                                            ));
                                        }
                                        lines.join("\n")
                                    }
                                }
                                Err(e) => format!("Error auditing directory: {}", e),
                            }
                        }
                    }
                    "stenio_diff" => {
                        let rev = arguments.get("rev").and_then(|v| v.as_str());
                        match engine.scan_directory(repo_root, None, None, false, rev, false) {
                            Ok(report) => {
                                if report.violations.is_empty() {
                                    format!(
                                        "✨ Clean surgical scan! Zero violations in {} modified files.",
                                        report.total_files_scanned
                                    )
                                } else {
                                    let mut lines = Vec::new();
                                    lines.push(format!(
                                        "Surgical scan: {} error(s), {} warning(s) in modified files:",
                                        report.error_count, report.warning_count
                                    ));
                                    for v in &report.violations {
                                        lines.push(format_violation_line(v));
                                    }
                                    lines.join("\n")
                                }
                            }
                            Err(e) => format!("Error executing diff: {}", e),
                        }
                    }
                    "stenio_guardian" => {
                        let rep = audit_stenio_integrity(repo_root);
                        if rep.is_intact {
                            format!(
                                "🛡️ Guardian: Intact. Zero tampering detected. Executable SHA-256: {}",
                                rep.binary_hash
                            )
                        } else {
                            format!(
                                "🚨 Guardian: TAMPERING DETECTED!\n{}",
                                rep.tamper_alerts.join("\n")
                            )
                        }
                    }
                    "stenio_context" => {
                        format!(
                            "# Canonical Context StenioSentinel v4.0\n\n\
                            - Platform: Monorepo / Obsidian Vault at /mnt/NVME_PCI/agentic-ai\n\
                            - Homelab Mnemocine: psicopompo (dev/gpu), ybyra (edge), kuaray (media), ybytu (cloud exit), kavure (services)\n\
                            - GPU: RTX 5050 Blackwell with local CUDA acceleration\n\
                            - Core Rules: Raw sudo forbidden (use sudoers NOPASSWD or SOPS), GNU legacy tools forbidden in Rust (use xh, walkdir, regex), soft NFS mounts mandatory.\n\
                            - CLI Tools: use stenio --diff for fast delta scans."
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
                                "No explanation found for rule '{}'.\n\n{}",
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
                                        dv.suggestion
                                            .as_deref()
                                            .unwrap_or("Extract and deduplicate common logic.")
                                    ));
                                }

                                if errors.is_empty() {
                                    format!(
                                        "🎉 [GATE PASSED] Congratulations! Zero blocking errors and zero duplications across {} files. Code is 100% compliant. Task approved for delivery!",
                                        report.total_files_scanned
                                    )
                                } else {
                                    format!(
                                        "🛑 [GATE REJECTED — MANDATORY DELIVERY BLOCK]\n\
                                        The task CANNOT be marked as complete. STRICTLY FORBIDDEN:\n\
                                        1. Proposing changes to the Stenio governance engine or creating new governance crates (ARCH-SCOPE-ISOLATION violation).\n\
                                        2. Claiming errors or DRY duplications are 'pre-existing issues' to avoid fixing them.\n\
                                        3. Replacing unwrap() with expect() (Both violate RUST-NO-UNWRAP with fatal error).\n\
                                        4. Adding // stenio-ignore comments or suppression directives (AGENT-NO-SUPPRESSION-DIRECTIVES violation).\n\n\
                                        The model MUST resolve the following {} violation(s) directly in the application code before finishing:\n\n{}\n\n\
                                        Consult 'stenio_explain' with the rule_id for official remediation instructions.",
                                        errors.len(),
                                        errors.join("\n")
                                    )
                                }
                            }
                            Err(e) => format!("Error executing Quality Gate: {}", e),
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
                                "✨ [DRY PASSED] Zero duplications detected across {} files (duration: {:?}). Absolute DRY Principle 100% satisfied!",
                                dry_count, dry_dur
                            )
                        } else {
                            let mut msg = format!(
                                "⚠️ [DRY DETECTED] {} duplicate code block(s) detected across {} files (duration: {:?}):\n\n",
                                dry_violations.len(),
                                dry_count,
                                dry_dur
                            );
                            for v in &dry_violations {
                                msg.push_str(&format!(
                                    "• {}:{} - {}\n  Snippet:\n{}\n  💡 Suggestion: {}\n\n",
                                    v.file_path,
                                    v.line_number,
                                    v.message,
                                    v.snippet,
                                    v.suggestion
                                        .as_deref()
                                        .unwrap_or("Extract and deduplicate common logic.")
                                ));
                            }
                            msg
                        }
                    }
                    other => format!("Unknown tool: '{}'", other),
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
                        "message": format!("Method '{}' not found", other)
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

fn format_violation_line(v: &Violation) -> String {
    let sev = crate::util::severity_label(v.severity);
    format!(
        "[{}] {}:{}: [{}] {} (💡 {})",
        sev,
        v.file_path,
        v.line_number,
        v.rule_id,
        v.message,
        v.suggestion.as_deref().unwrap_or("N/A")
    )
}

fn path_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Root path to inspect (default: .)"
            }
        }
    })
}
