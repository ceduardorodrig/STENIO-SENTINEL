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

    // ── 1. Homelab Service Audit (Docs-as-Code & Service Catalog) ─────────────
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
        "distributed",
        "malha",
        "mesh",
        "host",
        "server",
    ];

    if services_dir.is_dir() {
        let service_files = collect_md_files(&services_dir);

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

                // Rule 1.1: Service documentation must reference the host/server where it runs
                let is_subdoc = service_path.parent().map_or(false, |p| p != services_dir);
                let has_server_field = is_subdoc
                    || content.lines().any(|l| {
                        let tl = l.trim().to_lowercase();
                        (tl.contains("servidor") || tl.contains("host") || tl.contains("server")) && tl.contains(':')
                    });

                if !has_server_field {
                    violations.push(Violation {
                        rule_id: "DOC-SERVICE-MISSING-HOST".to_string(),
                        rule_name: "Service Missing Host Binding".to_string(),
                        severity: Severity::Error,
                        file_path: path_display.clone(),
                        line_number: 1,
                        snippet: file_name.to_string(),
                        message: format!("Documentation for service '{}' does not declare which server/host it operates on.", file_name),
                        suggestion: Some("Add at the top of document: '**Server:** psicopompo|kavure|kuaray|ybytu|ybyra|mesh'.".to_string()),
                    });
                } else if !is_subdoc {
                    // Validate whether cited server is one of valid homelab nodes
                    let mut found_valid = false;
                    for line in content.lines() {
                        let tl = line.trim().to_lowercase();
                        if (tl.contains("servidor") || tl.contains("host") || tl.contains("server")) && tl.contains(':') {
                            if valid_hosts.iter().any(|&vh| tl.contains(vh)) {
                                found_valid = true;
                                break;
                            }
                        }
                    }

                    if !found_valid {
                        violations.push(Violation {
                            rule_id: "DOC-SERVICE-INVALID-HOST".to_string(),
                            rule_name: "Invalid Service Host".to_string(),
                            severity: Severity::Warning,
                            file_path: path_display.clone(),
                            line_number: 1,
                            snippet: file_name.to_string(),
                            message: format!("The server declared in '{}' was not recognized among homelab nodes.", file_name),
                            suggestion: Some("Use one of canonical hosts: psicopompo, kavure, kuaray, ybytu, ybyra or mesh.".to_string()),
                        });
                    }
                }

                // Rule 1.2: Orphan Documentation Detector (Service Catalog Drift)
                // Service must be indexed in mnemocine/README.md, homepage.md, or servers/*.md
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
                        rule_name: "Unindexed Service Documentation (Orphan)".to_string(),
                        severity: Severity::Warning,
                        file_path: path_display.clone(),
                        line_number: 1,
                        snippet: file_name.to_string(),
                        message: format!("Service '{}' is not cataloged in mnemocine/README.md, homepage.md or server manifests.", file_name),
                        suggestion: Some("Add the service link to the official catalog in mnemocine/README.md.".to_string()),
                    });
                }
            }
        }
    }

    // ── 2. Server Audit (Integrity of Service References) ─────────────────────
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
                                                    rule_name: "Non-Existent Service Reference on Server".to_string(),
                                                    severity: Severity::Error,
                                                    file_path: path_display.clone(),
                                                    line_number: idx + 1,
                                                    snippet: line.trim().to_string(),
                                                    message: format!("Server references non-existent service: '{}'.", link),
                                                    suggestion: Some("Create the documentation file in services/ or remove the reference.".to_string()),
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

    // ── 3. Cold Storage Project Integrity Audit ──────────────────────────────
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
                                "[missing tarball] "
                            } else {
                                ""
                            },
                            if !has_sha256 {
                                "[missing .sha256] "
                            } else {
                                ""
                            },
                            if !has_manifest {
                                "[missing MANIFEST.md] "
                            } else {
                                ""
                            }
                        );
                        violations.push(Violation {
                            rule_id: "DOC-COLD-STORAGE-INCOMPLETE".to_string(),
                            rule_name: "Incomplete Cold Storage Project".to_string(),
                            severity: Severity::Error,
                            file_path: format!("projects/cold-storage/{}", project_name),
                            line_number: 1,
                            snippet: project_name.clone(),
                            message: format!("Cold storage for '{}' is incomplete: {}", project_name, missing.trim()),
                            suggestion: Some("Generate compressed archive (.tar.zst), .sha256 checksum, and MANIFEST.md.".to_string()),
                        });
                    }
                }
            }
        }
    }

    // ── 4. Software Documentation, ADRs, and Canonical Links in docs/ ─────────
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

        let doc_files = collect_md_files(docs_dir);

        for doc_path in doc_files {
            total_docs += 1;
            let path_display = doc_path
                .strip_prefix(repo_root)
                .unwrap_or(&doc_path)
                .to_string_lossy()
                .to_string();

            if let Ok(content) = fs::read_to_string(&doc_path) {
                // Check ADRs
                if doc_path.to_string_lossy().contains("/adr/") {
                    let has_status = content.contains("Status:")
                        || content.contains("## Status")
                        || content.contains("**Status:**")
                        || content.contains("status:");
                    if !has_status {
                        violations.push(Violation {
                            rule_id: "DOC-ADR-MISSING-STATUS".to_string(),
                            rule_name: "ADR Missing Formal Status".to_string(),
                            severity: Severity::Warning,
                            file_path: path_display.clone(),
                            line_number: 1,
                            snippet: doc_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string(),
                            message: "Architectural Decision Record (ADR) does not contain formal status (Accepted/Proposed/Superseded).".to_string(),
                            suggestion: Some("Add section or field 'Status: Accepted' at the top of the ADR.".to_string()),
                        });
                    }
                }

                // Check broken links
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
                                            "{}: link to '{}' not found",
                                            path_display, link_target
                                        );
                                        broken_links.push(err_msg.clone());
                                        violations.push(Violation {
                                            rule_id: "DOC-BROKEN-LINK".to_string(),
                                            rule_name: "Broken Link in Documentation".to_string(),
                                            severity: Severity::Warning,
                                            file_path: path_display.clone(),
                                            line_number: line_idx + 1,
                                            snippet: line.trim().to_string(),
                                            message: format!("Link points to non-existent file: '{}'", link_target),
                                            suggestion: Some("Fix the link path or create the corresponding document.".to_string()),
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

    // ── 5. Stenio Governance Disclaimer Audit (DOC-VIBE-DISCLAIMER) ──────────
    let mut check_targets = Vec::new();

    // Target 1: README.md at root of scope being audited
    let root_readme = repo_root.join("README.md");
    if root_readme.is_file() {
        check_targets.push(root_readme);
    }

    // Target 2: If auditing the general vault, audit curriculum-vitae/README.md as well
    let cv_readme = repo_root.join("curriculum-vitae").join("README.md");
    if cv_readme.is_file() && !check_targets.contains(&cv_readme) {
        check_targets.push(cv_readme);
    }

    // Target 3: Repositories managed in /mnt/NVME_PCI/homelab and ~/homelab/
    for base_dir in &[
        PathBuf::from("/mnt/NVME_PCI/homelab"),
        PathBuf::from("/home/edu/homelab"),
    ] {
        if base_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(base_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if !p.join(".git").exists() {
                        // Also inspect 1-level subdirectories (e.g. sumaenimahub/sumaenima-hub)
                        if let Ok(subentries) = fs::read_dir(&p) {
                            for sub in subentries.flatten() {
                                let sub_p = sub.path();
                                if sub_p.join(".git").exists() {
                                    let sub_readme = sub_p.join("README.md");
                                    if sub_readme.is_file() && !check_targets.contains(&sub_readme) {
                                        check_targets.push(sub_readme);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    let repo_readme = p.join("README.md");
                    if repo_readme.is_file() && !check_targets.contains(&repo_readme) {
                        check_targets.push(repo_readme);
                    }
                }
            }
        }
    }

    for readme_path in check_targets {
        total_docs += 1;
        if let Ok(content) = fs::read_to_string(&readme_path) {
            let path_display = readme_path
                .strip_prefix(repo_root)
                .unwrap_or(&readme_path)
                .to_string_lossy()
                .to_string();

            let has_modern_title = content.contains("Human-in-the-Loop Agentic Engineering & Deterministic Governance");
            let has_legacy_vibe = content.contains("**Yes... This is a Vibe Coded project**")
                || content.contains("Yes... This is a Vibe Coded project")
                || content.contains("Vibe Coded with StenioSentinel")
                || content.contains("vibe-coded")
                || content.contains("badge/vibe-coded");
            let has_gov = content.contains("StenioSentinel");
            let has_author =
                content.contains("Carlos Eduardo Rodrigues") || content.contains("ceduardorodrig");

            let is_valid = has_modern_title && !has_legacy_vibe && has_gov && has_author;

            if !is_valid {
                let (reason, suggestion) = if has_legacy_vibe {
                    (
                        "README contains legacy 'vibe-coded' badge or mention incompatible with current governance.",
                        "Replace legacy badge with '[![Governance](https://img.shields.io/badge/governance-StenioSentinel-brightgreen)](https://github.com/ceduardorodrig/STENIO-SENTINEL)' and ensure the 'Human-in-the-Loop Agentic Engineering & Deterministic Governance' footer.",
                    )
                } else if !has_modern_title {
                    (
                        "Disclaimer 'Human-in-the-Loop Agentic Engineering & Deterministic Governance' not found in README.",
                        "Add the standardized Stenio governance disclaimer block to the footer of README.md.",
                    )
                } else {
                    (
                        "Incomplete disclaimer (missing author Carlos Eduardo Rodrigues or StenioSentinel reference).",
                        "Ensure the governance block contains full references to StenioSentinel and the author.",
                    )
                };

                violations.push(Violation {
                    rule_id: "DOC-VIBE-DISCLAIMER".to_string(),
                    rule_name: "Missing or Outdated Standard Governance Disclaimer".to_string(),
                    severity: Severity::Error,
                    file_path: path_display,
                    line_number: content.lines().count().max(1),
                    snippet: "Human-in-the-Loop Agentic Engineering & Deterministic Governance".to_string(),
                    message: format!("README '{}': {}", readme_path.display(), reason),
                    suggestion: Some(format!(
                        "{}\nMandatory format:\n<div align=\"center\">\n\n### 🛡️ Human-in-the-Loop Agentic Engineering & Deterministic Governance\n\n> **Architected by an Anthropologist, Built with Autonomous AI Agents, Governed by Deterministic Code.**\n> \n> This project was developed through rigorous human-AI pair programming led by **Carlos Eduardo Rodrigues** ([@ceduardorodrig](https://github.com/ceduardorodrig)) — an anthropologist and product architect using autonomous coding agents under strict, sub-millisecond static governance.\n>\n> Every commit, driver, and system architecture is continuously audited and enforced by 🤖 **[StenioSentinel](https://github.com/ceduardorodrig/STENIO-SENTINEL)** (our native Rust quality gate) with zero tolerance for hallucinated tests, blind merges, or bypassed checks.\n\n</div>",
                        suggestion
                    )),
                });
            }
        }
    }

    if violations.is_empty() && broken_links.is_empty() {
        messages.push(format!("✅ {} technical documents (services, servers, ADRs and cold storage) audited and intact.", total_docs));
    } else {
        messages.push(format!(
            "ℹ️ {} documentation and Docs-as-Code issue(s) detected across {} files.",
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

fn collect_md_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    // Uses WalkBuilder (ignore crate) to respect .gitignore and Syncthing's .stignore.
    // Avoids auditing files in .stversions/, .smart-env/ and other ignored directories.
    let mut walker = WalkBuilder::new(dir);
    walker.hidden(true).git_ignore(true).parents(true);

    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
        let path_str = path.to_string_lossy();

        // Additional explicit exclusions (protection against stversions, archives, and external docs)
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
    files
}
