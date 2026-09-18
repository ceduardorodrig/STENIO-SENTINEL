use ignore::WalkBuilder;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DocAuditResult {
    pub total_docs: usize,
    pub broken_links: Vec<String>,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_documentation(repo_root: &Path) -> DocAuditResult {
    let mut messages = Vec::new();
    let mut broken_links = Vec::new();
    let mut violations = Vec::new();
    let mut total_docs = 0;

    // ── 1. Auditoria de Serviços do Homelab (Docs-as-Code & Service Catalog) ────
    let mnemocine_dir = repo_root.join("mnemocine");
    let services_dir = mnemocine_dir.join("services");
    let servers_dir = mnemocine_dir.join("servers");
    let readme_mnemocine = mnemocine_dir.join("README.md");
    let homepage_doc = services_dir.join("homepage.md");

    let mut catalog_corpus = String::new();
    if let Ok(c) = fs::read_to_string(&readme_mnemocine) {
        catalog_corpus.push_str(&c);
        catalog_corpus.push('\n');
    }
    if let Ok(c) = fs::read_to_string(&homepage_doc) {
        catalog_corpus.push_str(&c);
        catalog_corpus.push('\n');
    }
    if servers_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&servers_dir) {
            for entry in entries.flatten() {
                if let Ok(c) = fs::read_to_string(entry.path()) {
                    catalog_corpus.push_str(&c);
                    catalog_corpus.push('\n');
                }
            }
        }
    }

    let valid_hosts = [
        "psicopompo",
        "kavure",
        "kuaray",
        "ybytu",
        "ybyra",
        "swarm",
        "docker-swarm",
        "cloud",
        "distribuída",
        "distribuido",
        "malha",
        "host",
    ];

    if services_dir.is_dir() {
        let mut service_files = Vec::new();
        collect_md_files(&services_dir, &mut service_files);

        for service_path in service_files {
            let file_name = service_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if file_name == "README.md" || file_name == "health-endpoints.md" {
                continue;
            }
            total_docs += 1;

            if let Ok(content) = fs::read_to_string(&service_path) {
                let path_display = service_path
                    .strip_prefix(repo_root)
                    .unwrap_or(&service_path)
                    .to_string_lossy()
                    .to_string();

                // Regra 1.1: Documentação de serviço deve referenciar o servidor/host onde opera
                let is_subdoc = service_path.parent().map_or(false, |p| p != services_dir);
                let has_server_field = is_subdoc
                    || content.lines().any(|l| {
                        let tl = l.trim().to_lowercase();
                        (tl.contains("servidor") || tl.contains("host")) && tl.contains(':')
                    });

                if !has_server_field {
                    violations.push(Violation {
                        rule_id: "DOC-SERVICE-MISSING-HOST".to_string(),
                        rule_name: "Serviço sem Hospedeiro Vinculado".to_string(),
                        severity: Severity::Error,
                        file_path: path_display.clone(),
                        line_number: 1,
                        snippet: file_name.to_string(),
                        message: format!("A documentação do serviço '{}' não declara em qual servidor/host opera.", file_name),
                        suggestion: Some("Adicione no topo do documento: '**Servidor:** psicopompo|kavure|kuaray|ybytu|ybyra|malha'.".to_string()),
                    });
                } else if !is_subdoc {
                    // Validar se o servidor citado é um dos nós válidos
                    let mut found_valid = false;
                    for line in content.lines() {
                        let tl = line.trim().to_lowercase();
                        if (tl.contains("servidor") || tl.contains("host")) && tl.contains(':') {
                            if valid_hosts.iter().any(|&vh| tl.contains(vh)) {
                                found_valid = true;
                                break;
                            }
                        }
                    }

                    if !found_valid {
                        violations.push(Violation {
                            rule_id: "DOC-SERVICE-INVALID-HOST".to_string(),
                            rule_name: "Hospedeiro de Serviço Inválido".to_string(),
                            severity: Severity::Warning,
                            file_path: path_display.clone(),
                            line_number: 1,
                            snippet: file_name.to_string(),
                            message: format!("O servidor declarado em '{}' não foi reconhecido entre os nós do homelab.", file_name),
                            suggestion: Some("Utilize um dos hosts canônicos: psicopompo, kavure, kuaray, ybytu, ybyra ou malha.".to_string()),
                        });
                    }
                }

                // Regra 1.2: Detector de Documentação Órfã (Service Catalog Drift)
                // O serviço deve estar indexado em mnemocine/README.md, homepage.md ou servers/*.md
                let service_stem = service_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if !service_stem.is_empty()
                    && !catalog_corpus.contains(service_stem)
                    && !catalog_corpus.contains(file_name)
                {
                    violations.push(Violation {
                        rule_id: "DOC-SERVICE-UNINDEXED".to_string(),
                        rule_name: "Documentação de Serviço Não Indexada (Órfã)".to_string(),
                        severity: Severity::Warning,
                        file_path: path_display.clone(),
                        line_number: 1,
                        snippet: file_name.to_string(),
                        message: format!("O serviço '{}' não está catalogado em mnemocine/README.md, homepage.md nem nos servidores.", file_name),
                        suggestion: Some("Adicione o link do serviço no catálogo oficial em mnemocine/README.md.".to_string()),
                    });
                }
            }
        }
    }

    // ── 2. Auditoria de Servidores (Integridade de Referências de Serviços) ───
    if servers_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&servers_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("md") {
                    total_docs += 1;
                    let path_display = path
                        .strip_prefix(repo_root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .to_string();
                    if let Ok(content) = fs::read_to_string(&path) {
                        for (idx, line) in content.lines().enumerate() {
                            if line.contains("services/") && line.contains("](") {
                                if let Some(start) = line.find("](") {
                                    let sub = &line[start + 2..];
                                    if let Some(end) = sub.find(')') {
                                        let link =
                                            sub[..end].split('#').next().unwrap_or("").trim();
                                        if link.ends_with(".md") && !link.starts_with("http") {
                                            let target_path = if link.starts_with('/') {
                                                repo_root.join(&link[1..])
                                            } else {
                                                path.parent().unwrap_or(repo_root).join(link)
                                            };
                                            if !target_path.exists() {
                                                violations.push(Violation {
                                                    rule_id: "DOC-SERVER-BROKEN-SERVICE-REF".to_string(),
                                                    rule_name: "Referência a Serviço Inexistente no Servidor".to_string(),
                                                    severity: Severity::Error,
                                                    file_path: path_display.clone(),
                                                    line_number: idx + 1,
                                                    snippet: line.trim().to_string(),
                                                    message: format!("Servidor referencia serviço inexistente: '{}'.", link),
                                                    suggestion: Some("Crie o arquivo de documentação em services/ ou remova a referência.".to_string()),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── 3. Auditoria de Integridade de Projetos em Cold Storage ──────────────
    let cold_storage_dir = repo_root.join("projects").join("cold-storage");
    if cold_storage_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&cold_storage_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                    let project_dir = entry.path();
                    let project_name = entry.file_name().to_string_lossy().to_string();

                    let mut has_archive = false;
                    let mut has_sha256 = false;
                    let has_manifest = project_dir.join("MANIFEST.md").is_file();

                    if let Ok(files) = fs::read_dir(&project_dir) {
                        for f in files.flatten() {
                            let n = f.file_name().to_string_lossy().to_string();
                            if n.ends_with(".tar.zst") || n.ends_with(".tar.gz") {
                                has_archive = true;
                            }
                            if n.ends_with(".sha256") {
                                has_sha256 = true;
                            }
                        }
                    }

                    if !has_archive || !has_sha256 || !has_manifest {
                        let missing = format!(
                            "{}{}{}",
                            if !has_archive {
                                "[tarball ausente] "
                            } else {
                                ""
                            },
                            if !has_sha256 {
                                "[.sha256 ausente] "
                            } else {
                                ""
                            },
                            if !has_manifest {
                                "[MANIFEST.md ausente] "
                            } else {
                                ""
                            }
                        );
                        violations.push(Violation {
                            rule_id: "DOC-COLD-STORAGE-INCOMPLETE".to_string(),
                            rule_name: "Projeto em Cold Storage Incompleto".to_string(),
                            severity: Severity::Error,
                            file_path: format!("projects/cold-storage/{}", project_name),
                            line_number: 1,
                            snippet: project_name.clone(),
                            message: format!("Cold storage de '{}' está incompleto: {}", project_name, missing.trim()),
                            suggestion: Some("Gere o arquivo compactado (.tar.zst), checksum .sha256 e MANIFEST.md.".to_string()),
                        });
                    }
                }
            }
        }
    }

    // ── 4. Auditoria de Software, ADRs e Links Canônicos em docs/ ────────────
    let docs_dirs = [
        repo_root.join("docs"),
        repo_root
            .join("sumaenimahub")
            .join("sumaenima-hub")
            .join("docs"),
        repo_root
            .join("sumaenimahub")
            .join("SUMAENIMA-HUB")
            .join("docs"),
    ];

    for docs_dir in &docs_dirs {
        if !docs_dir.is_dir() {
            continue;
        }

        let mut doc_files = Vec::new();
        collect_md_files(docs_dir, &mut doc_files);

        for doc_path in doc_files {
            total_docs += 1;
            let path_display = doc_path
                .strip_prefix(repo_root)
                .unwrap_or(&doc_path)
                .to_string_lossy()
                .to_string();

            if let Ok(content) = fs::read_to_string(&doc_path) {
                // Checar ADRs
                if doc_path.to_string_lossy().contains("/adr/") {
                    let has_status = content.contains("Status:")
                        || content.contains("## Status")
                        || content.contains("**Status:**")
                        || content.contains("status:");
                    if !has_status {
                        violations.push(Violation {
                            rule_id: "DOC-ADR-MISSING-STATUS".to_string(),
                            rule_name: "ADR sem Status Formal".to_string(),
                            severity: Severity::Warning,
                            file_path: path_display.clone(),
                            line_number: 1,
                            snippet: doc_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(),
                            message: "Registro de Decisão Arquitetural (ADR) não contém status (Aceito/Proposto/Substituído).".to_string(),
                            suggestion: Some("Adicione a seção ou campo 'Status: Aceito' no topo do ADR.".to_string()),
                        });
                    }
                }

                // Checar links quebrados
                for (line_idx, line) in content.lines().enumerate() {
                    if line.contains("](")
                        && !line.contains("http://")
                        && !line.contains("https://")
                        && !line.contains("mailto:")
                    {
                        let mut start_idx = 0;
                        while let Some(open) = line[start_idx..].find("](") {
                            let actual_open = start_idx + open + 2;
                            if let Some(close) = line[actual_open..].find(')') {
                                let link_target = line[actual_open..actual_open + close]
                                    .split('#')
                                    .next()
                                    .unwrap_or("")
                                    .trim();
                                if !link_target.is_empty() && link_target.ends_with(".md") {
                                    let target_path = if link_target.starts_with('/') {
                                        repo_root.join(&link_target[1..])
                                    } else {
                                        doc_path.parent().unwrap_or(repo_root).join(link_target)
                                    };
                                    if !target_path.exists() {
                                        let err_msg = format!(
                                            "{}: link para '{}' inexistente",
                                            path_display, link_target
                                        );
                                        broken_links.push(err_msg.clone());
                                        violations.push(Violation {
                                            rule_id: "DOC-BROKEN-LINK".to_string(),
                                            rule_name: "Link Quebrado na Documentação".to_string(),
                                            severity: Severity::Warning,
                                            file_path: path_display.clone(),
                                            line_number: line_idx + 1,
                                            snippet: line.trim().to_string(),
                                            message: format!("Link aponta para arquivo inexistente: '{}'", link_target),
                                            suggestion: Some("Corrija o caminho do link ou crie o documento correspondente.".to_string()),
                                        });
                                    }
                                }
                                start_idx = actual_open + close + 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if violations.is_empty() && broken_links.is_empty() {
        messages.push(format!("✅ {} documentos técnicos (serviços, servidores, ADRs e cold storage) auditados e íntegros.", total_docs));
    } else {
        messages.push(format!(
            "ℹ️ {} desvio(s) de documentação e Docs-as-Code detectados em {} arquivos.",
            violations.len(),
            total_docs
        ));
    }

    DocAuditResult {
        total_docs,
        broken_links,
        messages,
        violations,
    }
}

fn collect_md_files(dir: &Path, files: &mut Vec<PathBuf>) {
    // Usa WalkBuilder (crate ignore) para respeitar .gitignore e .stignore do Syncthing.
    // Isso evita auditar arquivos em .stversions/, .smart-env/ e outros diretórios ignorados.
    let mut walker = WalkBuilder::new(dir);
    walker.hidden(true).git_ignore(true).parents(true);

    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
        let path_str = path.to_string_lossy();

        // Exclusões explícitas adicionais (proteção contra stversions, archives e external docs)
        if path_str.contains("/.stversions/")
            || path_str.contains("/.smart-env/")
            || path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/.venv/")
            || path_str.contains("/archive/")
            || path_str.contains("/external/")
        {
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) == Some("md") {
            files.push(path);
        }
    }
}
