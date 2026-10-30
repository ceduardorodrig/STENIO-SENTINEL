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

#[derive(Debug, Clone, Deserialize)]
pub struct McpRequest {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Dispatches an MCP request deterministically across stdio or HTTP SSE.
pub fn dispatch_mcp_request(
    req: &McpRequest,
    repo_root: &Path,
    engine: &Engine,
    whitelist: &Whitelist,
) -> Option<McpResponse> {
    let req_id = req.id.clone().unwrap_or(Value::Null);

    match req.method.as_str() {
        "initialize" => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req_id,
            result: Some(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "stenio-sentinel",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
            error: None,
        }),
        "notifications/initialized" => None,
        "ping" => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req_id,
            result: Some(json!({})),
            error: None,
        }),
        "tools/list" => {
            let tools = json!({
                "tools": [
                    {
                        "name": "stenio_scan",
                        "description": "Audits a file or directory using StenioSentinel universal governance rules and returns violations concisely.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Path to file or directory to audit" },
                                "tag": { "type": "string", "description": "Filter by specific tag (e.g., sec, arch, frontend, infra, doc)" },
                                "only_rule": { "type": "string", "description": "Execute only a single rule by ID (e.g., SEC-SUDO, ARCH-RUST-CMD-LEGACY)" }
                            }
                        }
                    },
                    {
                        "name": "stenio_diff",
                        "description": "Executes sub-millisecond surgical audit (<5ms) only on files modified in Git (staged or given revision).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "rev": { "type": "string", "description": "Target git revision (e.g., 'staged', 'HEAD~1'). Default: staged/modified files" }
                            }
                        }
                    },
                    {
                        "name": "stenio_guardian",
                        "description": "Verifies SHA-256 cryptographic integrity and anti-tampering defenses of Stenio Sentinel core.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "stenio_context",
                        "description": "Returns canonical governance, architecture, and homelab infrastructure context for the SUMÆNIMÁ / Homelab ecosystem.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "stenio_explain",
                        "description": "Explains rule rationale in detail with bad code examples, good code patterns, and step-by-step remediation guidance for agents and LLMs.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "rule_id": { "type": "string", "description": "Rule ID (e.g., SEC-SUDO, RUST-NO-UNWRAP, ARCH-RUST-TOOLS) or empty to list all" }
                            }
                        }
                    },
                    {
                        "name": "stenio_dry",
                        "description": "Audits code duplication using the Absolute DRY Principle with Rolling Block Hash (<15ms). Detects duplicate blocks across or within files.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Root path to inspect (default: .)" },
                                "min_lines": { "type": "number", "description": "Minimum identical substantive lines required to trigger duplication (default: 6)" }
                            }
                        }
                    },
                    {
                        "name": "stenio_gate",
                        "description": "Pre-Delivery Quality Gate: executes zero-tolerance audit (critical rules, governance, test artifacts, and DRY duplication). Agents MUST call this tool before declaring task completion and ensure it returns PASSED.",
                        "inputSchema": path_input_schema()
                    },
                    {
                        "name": "stenio_directus",
                        "description": "Audits Directus schemas, relational foreign keys, BRL currency formatting, singleton anti-stutter, and ADR consistency in <5ms.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "url": { "type": "string", "description": "Directus base URL (default: http://100.94.209.99:8055)" },
                                "token": { "type": "string", "description": "Directus API Bearer token" }
                            }
                        }
                    },
                    {
                        "name": "stenio_docker",
                        "description": "Audits live Docker containers, failed services, and insecure wildcard 0.0.0.0 binds directly via Docker socket in <20ms.",
                        "inputSchema": { "type": "object", "properties": {} }
                    },
                    {
                        "name": "stenio_graph",
                        "description": "Audits the Vault Knowledge Graph topology using petgraph: detects hubs, orphan documents, broken links, and SCC cyclic clusters.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "show_orphans": { "type": "boolean", "description": "Whether to list unreferenced orphan documents" }
                            }
                        }
                    },
                    {
                        "name": "stenio_semantic",
                        "description": "Performs local offline semantic search across the vault using TF-IDF cosine similarity in <5ms (zero external API keys).",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": { "type": "string", "description": "Search query or natural language question" },
                                "top_k": { "type": "number", "description": "Number of top results (default: 5)" }
                            },
                            "required": ["query"]
                        }
                    }
                ]
            });

            Some(McpResponse {
                jsonrpc: "2.0".to_string(),
                id: req_id,
                result: Some(tools),
                error: None,
            })
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
                        match engine.scan_directory(&target_path, tag, only, false, None, false) {
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
                            Err(e) => format!("Error scanning directory: {}", e),
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
                        "# Canonical Context StenioSentinel v4.10.0\n\n\
                        - Platform: Monorepo / Obsidian Vault at /mnt/NVME_PCI/agentic-ai\n\
                        - Homelab Mnemocine: psicopompo (dev/gpu), ybyra (edge), kuaray (media), ybytu (cloud exit), kavure (services)\n\
                        - GPU: RTX 5050 Blackwell with local CUDA acceleration\n\
                        - Core Rules: Raw sudo forbidden (use sudoers NOPASSWD or SOPS), GNU legacy tools forbidden in Rust (use xh, walkdir, regex), soft NFS mounts mandatory.\n\
                        - CLI Tools: use stenio --diff for fast delta scans, stenio --scope directus for Directus governance."
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
                                crate::dry::scan_dry_directory(&target_path, 6, whitelist);
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
                                    "🎉 [GATE PASSED] Zero blocking errors and zero duplications across {} files. Code is 100% compliant. Task approved for delivery!",
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
                        crate::dry::scan_dry_directory(&target_path, min_lines, whitelist);

                    if dry_violations.is_empty() {
                        format!(
                            "✨ [DRY PASSED] Zero duplications detected across {} files ({:?}).",
                            dry_count, dry_dur
                        )
                    } else {
                        format!(
                            "⚠️ [DRY DETECTED] {} duplicate code block(s) detected across {} files.",
                            dry_violations.len(),
                            dry_count
                        )
                    }
                }
                "stenio_directus" => {
                    let env_url = std::env::var("DIRECTUS_URL").ok();
                    let base_url = arguments
                        .get("url")
                        .and_then(|v| v.as_str())
                        .or(env_url.as_deref())
                        .unwrap_or("http://100.94.209.99:8055");
                    let token = arguments.get("token").and_then(|v| v.as_str());

                    match crate::directus::audit_directus_live(base_url, token) {
                        Ok(report) => {
                            let errors = report
                                .violations
                                .iter()
                                .filter(|v| v.severity == crate::directus::Severity::Error)
                                .count();
                            let warnings = report
                                .violations
                                .iter()
                                .filter(|v| v.severity == crate::directus::Severity::Warning)
                                .count();
                            if report.violations.is_empty() {
                                format!(
                                    "✨ [DIRECTUS PASSED] All {} relational and schema checks passed in {:.2}ms.",
                                    report.checks_passed, report.execution_time_ms
                                )
                            } else {
                                format!(
                                    "⚠️ [DIRECTUS VIOLATIONS] {} error(s), {} warning(s) in {:.2}ms:\n{}",
                                    errors,
                                    warnings,
                                    report.execution_time_ms,
                                    report
                                        .violations
                                        .iter()
                                        .map(|v| format!(
                                            "• [{}] {}: {}",
                                            v.rule, v.location, v.message
                                        ))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )
                            }
                        }
                        Err(e) => format!("Error connecting to Directus: {}", e),
                    }
                }
                "stenio_docker" => {
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(r) => r,
                        Err(e) => {
                            return Some(McpResponse {
                                jsonrpc: "2.0".to_string(),
                                id: req_id,
                                result: Some(
                                    json!({ "content": [{ "type": "text", "text": format!("Tokio runtime error: {}", e) }] }),
                                ),
                                error: None,
                            });
                        }
                    };
                    match rt.block_on(crate::docker::audit_docker_live()) {
                        Ok(report) => {
                            let errors = report
                                .violations
                                .iter()
                                .filter(|v| v.severity == crate::docker::DockerSeverity::Error)
                                .count();
                            let warnings = report
                                .violations
                                .iter()
                                .filter(|v| v.severity == crate::docker::DockerSeverity::Warning)
                                .count();
                            if report.violations.is_empty() {
                                format!(
                                    "✨ [DOCKER PASSED] {} containers inspected ({:.2}ms). All running clean.",
                                    report.total_containers, report.execution_time_ms
                                )
                            } else {
                                format!(
                                    "⚠️ [DOCKER ANOMALIES] {} total, {} running, {} error(s), {} warning(s):\n{}",
                                    report.total_containers,
                                    report.running_containers,
                                    errors,
                                    warnings,
                                    report
                                        .violations
                                        .iter()
                                        .map(|v| format!(
                                            "• [{}] {}: {}",
                                            v.rule, v.container, v.message
                                        ))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )
                            }
                        }
                        Err(e) => format!("Error auditing Docker daemon: {}", e),
                    }
                }
                "stenio_graph" => {
                    let show_orphans = arguments
                        .get("show_orphans")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let (_vault_graph, analysis) = crate::graph::build_vault_graph(repo_root);
                    let mut msg = format!(
                        "📊 Vault Graph Topology:\n• Documents: {}\n• References: {}\n• Density: {:.4}%\n• Cyclic Clusters (SCC): {}\n• Orphan Notes: {}\n• Broken Links: {}\n\nTop Hubs:\n",
                        analysis.total_nodes,
                        analysis.total_edges,
                        analysis.density * 100.0,
                        analysis.clusters_count,
                        analysis.orphan_nodes.len(),
                        analysis.broken_links.len()
                    );
                    for (name, in_deg, out_deg) in analysis.hub_nodes.iter().take(5) {
                        msg.push_str(&format!("• {} ({} in / {} out)\n", name, in_deg, out_deg));
                    }
                    if show_orphans && !analysis.orphan_nodes.is_empty() {
                        msg.push_str(&format!(
                            "\nOrphans (first 10 of {}):\n",
                            analysis.orphan_nodes.len()
                        ));
                        for orphan in analysis.orphan_nodes.iter().take(10) {
                            msg.push_str(&format!("• {}\n", orphan));
                        }
                    }
                    msg
                }
                "stenio_semantic" => {
                    let query = arguments
                        .get("query")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let top_k =
                        arguments.get("top_k").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
                    let index = crate::semantic::SemanticIndex::build(repo_root);
                    let results = index.search(query, top_k);
                    if results.is_empty() {
                        format!("No relevant documents found for query: '{}'", query)
                    } else {
                        let mut msg = format!(
                            "🔍 Top {} semantic matches for '{}':\n\n",
                            results.len(),
                            query
                        );
                        for (i, r) in results.iter().enumerate() {
                            msg.push_str(&format!(
                                "{}. **{}** ({:.1}% match)\n   📁 `{}`\n   💬 _{}_\n\n",
                                i + 1,
                                r.title,
                                (r.score * 100.0).min(100.0),
                                r.path,
                                r.snippet
                            ));
                        }
                        msg
                    }
                }
                other => format!("Unknown tool: '{}'", other),
            };

            Some(McpResponse {
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
            })
        }
        other => Some(McpResponse {
            jsonrpc: "2.0".to_string(),
            id: req_id,
            result: None,
            error: Some(json!({
                "code": -32601,
                "message": format!("Method '{}' not found", other)
            })),
        }),
    }
}

pub fn run_mcp_server(repo_root: &Path, rules: Vec<Rule>, whitelist: Whitelist) -> Result<()> {
    eprintln!("🦀 StenioSentinel MCP Server initialized on stdio (JSON-RPC 2.0)");
    let engine = Engine::new(rules, whitelist.clone())?;

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

        if let Some(resp) = dispatch_mcp_request(&req, repo_root, &engine, &whitelist) {
            let out = serde_json::to_string(&resp)?;
            writeln!(stdout, "{}", out)?;
            stdout.flush()?;
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
