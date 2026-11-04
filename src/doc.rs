use ignore::WalkBuilder;
use regex::Regex;
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
                        (tl.contains("servidor") || tl.contains("host") || tl.contains("server"))
                            && tl.contains(':')
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
                        if (tl.contains("servidor") || tl.contains("host") || tl.contains("server"))
                            && tl.contains(':')
                        {
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

                // Rule 4.3: Tier A Documentation Language (DOC-LANGUAGE-EN)
                let is_hub_doc = doc_path.to_string_lossy().contains("sumaenima-hub")
                    || doc_path.to_string_lossy().contains("SUMAENIMA-HUB")
                    || repo_root.ends_with("sumaenima-hub")
                    || repo_root.ends_with("SUMAENIMA-HUB");

                if is_hub_doc {
                    let file_name = doc_path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    if file_name != "handoff-log.md"
                        && file_name != "cockpit-flight.md"
                        && !file_name.contains("ptbr")
                        && !doc_path.to_string_lossy().contains("/archive/")
                        && !doc_path.to_string_lossy().contains("/external/")
                    {
                        let mut in_code_fence = false;
                        let mut pt_lines = 0;
                        let mut first_pt_line = 0;
                        let mut first_snippet = String::new();

                        for (line_idx, line) in content.lines().enumerate() {
                            let trimmed = line.trim();
                            if trimmed.starts_with("```") {
                                in_code_fence = !in_code_fence;
                                continue;
                            }
                            if in_code_fence || trimmed.is_empty() {
                                continue;
                            }
                            // Strip inline code `...`
                            let mut stripped = String::new();
                            let mut in_inline = false;
                            for ch in trimmed.chars() {
                                if ch == '`' {
                                    in_inline = !in_inline;
                                } else if !in_inline {
                                    stripped.push(ch);
                                }
                            }
                            if crate::comments::is_portuguese_comment(&stripped) {
                                pt_lines += 1;
                                if first_pt_line == 0 {
                                    first_pt_line = line_idx + 1;
                                    first_snippet = trimmed.to_string();
                                }
                            }
                        }

                        if pt_lines > 0 {
                            violations.push(Violation {
                                rule_id: "DOC-LANGUAGE-EN".to_string(),
                                rule_name: "Non-English Technical Documentation".to_string(),
                                severity: Severity::Warning,
                                file_path: path_display.clone(),
                                line_number: first_pt_line,
                                snippet: first_snippet,
                                message: format!(
                                    "Document '{}' contains {} line(s) in Portuguese. Tier A policy mandates English.",
                                    file_name, pt_lines
                                ),
                                suggestion: Some("Translate document prose to English per governance/language-policy.md (tracked in SB-017).".to_string()),
                            });
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
                                    if sub_readme.is_file() && !check_targets.contains(&sub_readme)
                                    {
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

            // The short title is a substring of the earlier long one
            // ("... & Deterministic Governance"), so READMEs that still carry the long
            // form remain valid and no fleet-wide rewrite is forced.
            let has_modern_title = content.contains("Human-in-the-Loop Agentic Engineering");
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
                        "Replace legacy badge with '[![Governance](https://img.shields.io/badge/governance-StenioSentinel-brightgreen)](https://github.com/ceduardorodrig/STENIO-SENTINEL)' and ensure the 'Human-in-the-Loop Agentic Engineering' footer.",
                    )
                } else if !has_modern_title {
                    (
                        "Disclaimer 'Human-in-the-Loop Agentic Engineering' not found in README.",
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
                    snippet: "Human-in-the-Loop Agentic Engineering".to_string(),
                    message: format!("README '{}': {}", readme_path.display(), reason),
                    suggestion: Some(format!(
                        "{}\nMandatory format:\n<div align=\"center\">\n\n### 🛡️ Human-in-the-Loop Agentic Engineering\n\nDeveloped by [Carlos Eduardo Rodrigues](https://github.com/ceduardorodrig) with AI coding agents.\nEvery change is verified by the deterministic quality gate [StenioSentinel](https://github.com/ceduardorodrig/STENIO-SENTINEL).\n\n</div>",
                        suggestion
                    )),
                });
            }
        }
    }

    // ── 6. Claims about hardware and access must carry a verification date (GB-007) ──
    // Two documented defects cost a full task on 2026-11-03: a server note claimed an `axp20x`
    // PMIC with a `voltage_max` sysfs knob (the charger is a Summit SMB327 at I2C `6-0034`
    // exposing `sec-charger/{reg,data}`), and an inherited "no administrative path" claim had
    // been false for three weeks. Prose cannot be proven wrong statically, so both rules are
    // Warnings: they mark the claim, they do not judge it. A nearby verification marker
    // ("verified/measured/implemented/confirmed ... YYYY-MM-DD") silences the finding.
    audit_unverified_claims(repo_root, &mut violations, &mut total_docs);

    if violations.is_empty() && broken_links.is_empty() {
        messages.push(format!("✅ {} technical documents (services, servers, ADRs and cold storage) audited and intact.", total_docs));
    } else {
        messages.push(format!(
            "ℹ️ {} documentation and Docs-as-Code issue(s) detected across {} files.",
            violations.len(),
            total_docs
        ));
    }

    // ── Product backlog queues (Hub `SB-`, Miracena `MB-`): structure, lifecycle, state, recurrence ──
    let product_queues = crate::backlog::audit_product_queues(repo_root);
    violations.extend(product_queues.violations);
    messages.extend(product_queues.messages);

    DocAuditResult {
        total_docs,
        broken_links,
        messages,
        violations,
    }
}

/// Words that turn an ISO date into a verification marker: together they say "someone looked at
/// the host and wrote down when". One shared list, so the two claim rules cannot drift apart.
const VERIFICATION_MARKERS: &[&str] = &[
    "verified",
    "measured",
    "implemented",
    "confirmed",
    "checked",
    "read on",
];

/// True when the line carries an ISO date **and** one of the verification words.
fn is_verification_marker(line: &str, iso_date: &Regex) -> bool {
    if !iso_date.is_match(line) {
        return false;
    }
    let lower = line.to_lowercase();
    VERIFICATION_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Heading level of a Markdown ATX heading (1-6), or None. Requires the space after the hashes,
/// so a shell comment inside a fenced block (`# Inspect the register`) is not a heading.
fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if hashes == 0 || hashes > 6 || !line[hashes..].starts_with(' ') {
        return None;
    }
    Some(hashes)
}

/// Heading positions with their level, ignoring anything inside a fenced code block.
fn collect_headings(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut headings = Vec::new();
    let mut in_fence = false;
    for (idx, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(level) = heading_level(line) {
            headings.push((idx, level));
        }
    }
    headings
}

/// How far from a claim a verification marker may sit and still cover it.
const CLAIM_WINDOW: usize = 25;

/// True when the claim at `idx` is anchored to a date: a marker inside its own section (or within
/// `CLAIM_WINDOW` lines), or in the text of any ancestor heading. An ancestor heading such as
/// `## Battery charge cap ... implemented 2026-11-03` vouches for its subsections; a sibling
/// section's body never does, which is what keeps the rule from going vacuous in a long file.
fn has_nearby_verification(
    lines: &[&str],
    headings: &[(usize, usize)],
    idx: usize,
    iso_date: &Regex,
) -> bool {
    let position = headings.iter().rposition(|(line_idx, _)| *line_idx <= idx);
    let (start, level) = match position {
        Some(p) => (headings[p].0, headings[p].1),
        None => (0, 0),
    };
    let end = headings
        .iter()
        .find(|(line_idx, lvl)| *line_idx > idx && *lvl <= level)
        .map(|(line_idx, _)| *line_idx)
        .unwrap_or(lines.len());

    let lo = start.max(idx.saturating_sub(CLAIM_WINDOW));
    let hi = end.min(idx + CLAIM_WINDOW + 1);
    if lines[lo..hi]
        .iter()
        .any(|candidate| is_verification_marker(candidate, iso_date))
    {
        return true;
    }

    if let Some(p) = position {
        let mut child_level = headings[p].1;
        for (line_idx, lvl) in headings[..p].iter().rev() {
            if *lvl < child_level {
                if is_verification_marker(lines[*line_idx], iso_date) {
                    return true;
                }
                child_level = *lvl;
            }
        }
    }

    false
}

/// Rules `DOC-UNVERIFIED-INTERFACE` and `DOC-STALE-ACCESS-CLAIM` (GB-007).
///
/// Both flag a claim that is not anchored to a date: a hardware interface (sysfs path, I2C
/// address, charger/PMIC name) named without a verification, and an inaccessibility claim
/// ("no administrative path", "no admin access") with nothing to say when it was last true.
/// Warning severity, never Error: prose cannot be proven false statically, only stale.
fn audit_unverified_claims(
    repo_root: &Path,
    violations: &mut Vec<Violation>,
    total_docs: &mut usize,
) {
    let mnemocine = repo_root.join("mnemocine");
    if !mnemocine.is_dir() {
        return;
    }

    let interface_re = match Regex::new(
        r"/sys/(?:class|bus|devices)/|\b\d-00[0-9a-f]{2}\b|\b(?:axp2[0-9a-z]{2}|smb3[0-9]{2}|bq25[0-9]{2})\b",
    ) {
        Ok(re) => re,
        Err(_) => return,
    };
    let claim_re = match Regex::new(
        r"(?i)\bno administrat(?:ive|or)\s+(?:path|access)\b|\bno admin\s+(?:path|access)\b|sem caminho administrativo",
    ) {
        Ok(re) => re,
        Err(_) => return,
    };
    let iso_re = match Regex::new(r"\d{4}-\d{2}-\d{2}") {
        Ok(re) => re,
        Err(_) => return,
    };

    const MAX_PER_FILE: usize = 3;

    for path in collect_md_files(&mnemocine) {
        let path_str = path.to_string_lossy().to_string();
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        *total_docs += 1;

        let display = path
            .strip_prefix(repo_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let lines: Vec<&str> = content.lines().collect();
        let headings = collect_headings(&lines);
        // Hardware claims only mean something where the hardware is described.
        let hardware_scope = path_str.contains("/servers/") || path_str.contains("/services/");

        let mut interface_hits = 0usize;
        let mut claim_hits = 0usize;

        for (idx, line) in lines.iter().enumerate() {
            let wants_interface = hardware_scope && interface_re.is_match(line);
            let wants_claim = claim_re.is_match(line);
            if !wants_interface && !wants_claim {
                continue;
            }

            if has_nearby_verification(&lines, &headings, idx, &iso_re) {
                continue;
            }

            let snippet = line.trim().to_string();
            let snippet: String = snippet.chars().take(160).collect();

            if wants_interface && interface_hits < MAX_PER_FILE {
                interface_hits += 1;
                violations.push(Violation {
                    rule_id: "DOC-UNVERIFIED-INTERFACE".to_string(),
                    rule_name: "Hardware Interface Claim Without Verification Date".to_string(),
                    severity: Severity::Warning,
                    file_path: display.clone(),
                    line_number: idx + 1,
                    snippet: snippet.clone(),
                    message: "Names a sysfs path, I2C address or charger/PMIC chip with no verification date in the same section.".to_string(),
                    suggestion: Some(
                        "Record how it was read and when: bus:address and the kernel source file, plus a `Verified YYYY-MM-DD` marker in the section.".to_string(),
                    ),
                });
            }

            if wants_claim && claim_hits < MAX_PER_FILE {
                claim_hits += 1;
                violations.push(Violation {
                    rule_id: "DOC-STALE-ACCESS-CLAIM".to_string(),
                    rule_name: "Access Limitation Claim Without Verification Date".to_string(),
                    severity: Severity::Warning,
                    file_path: display.clone(),
                    line_number: idx + 1,
                    snippet,
                    message: "Asserts that a host has no administrative path or access, with no date saying when that was last checked.".to_string(),
                    suggestion: Some(
                        "Probe the host and date the claim (`Verified YYYY-MM-DD`, with the command used), or point at the backlog item that tracks access recovery.".to_string(),
                    ),
                });
            }
        }
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

#[cfg(test)]
mod claim_tests {
    use super::*;

    fn iso() -> Regex {
        match Regex::new(r"\d{4}-\d{2}-\d{2}") {
            Ok(re) => re,
            Err(_) => panic!("the ISO date pattern is a compile-time constant"),
        }
    }

    #[test]
    fn heading_level_requires_the_space_after_the_hashes() {
        assert_eq!(
            heading_level("## Battery cap (verified 2026-11-03)"),
            Some(2)
        );
        assert_eq!(heading_level("### Implementation"), Some(3));
        assert_eq!(heading_level("#register write"), None);
        assert_eq!(heading_level("plain prose"), None);
    }

    #[test]
    fn fenced_shell_comments_are_not_headings() {
        let lines = vec![
            "## Real heading",
            "```sh",
            "# Inspect the register",
            "echo 2 > /sys/class/power_supply/sec-charger/reg",
            "```",
            "text",
        ];
        let headings = collect_headings(&lines);
        assert_eq!(headings.len(), 1);
        assert_eq!(headings[0], (0, 2));
    }

    #[test]
    fn marker_in_the_section_silences_the_claim() {
        let lines = vec![
            "## Battery cap (implemented 2026-11-03)",
            "Writes `0x42` to `/sys/class/power_supply/sec-charger/reg`.",
        ];
        let headings = collect_headings(&lines);
        assert!(has_nearby_verification(&lines, &headings, 1, &iso()));
    }

    #[test]
    fn ancestor_heading_vouches_for_its_subsection() {
        let lines = vec![
            "## Battery cap — implemented 2026-11-03",
            "### Implementation & Persistence (commit 92d82f9)",
            "Boot hook writes `/sys/class/power_supply/sec-charger/reg`.",
        ];
        let headings = collect_headings(&lines);
        assert!(has_nearby_verification(&lines, &headings, 2, &iso()));
    }

    #[test]
    fn sibling_body_marker_does_not_vouch_across_sections() {
        let lines = vec![
            "## DNS (verified 2026-11-03)",
            "Unrelated body mentioning /sys/class/power_supply/.",
            "## Hardware",
            "Charger is a Summit SMB327 on I2C 6-0034.",
        ];
        let headings = collect_headings(&lines);
        assert!(!has_nearby_verification(&lines, &headings, 3, &iso()));
        // Control: the first section's own line is covered by its heading.
        assert!(has_nearby_verification(&lines, &headings, 1, &iso()));
    }
}
