use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct DocAuditResult {
    pub total_docs: usize,
    pub broken_links: Vec<String>,
    pub messages: Vec<String>,
}

pub fn audit_documentation(repo_root: &Path) -> DocAuditResult {
    let mut messages = Vec::new();
    let mut broken_links = Vec::new();
    let docs_dir = repo_root.join("docs");

    if !docs_dir.is_dir() {
        return DocAuditResult {
            total_docs: 0,
            broken_links,
            messages,
        };
    }

    let mut doc_count = 0;
    let mut files_to_check = Vec::new();

    if let Ok(entries) = fs::read_dir(&docs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("md") {
                doc_count += 1;
                files_to_check.push(path);
            }
        }
    }

    let adr_dir = docs_dir.join("adr");
    if adr_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&adr_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("md") {
                    doc_count += 1;
                    files_to_check.push(path);
                }
            }
        }
    }

    // Checagem rápida de referências relativas comuns
    for doc in &files_to_check {
        if let Ok(content) = fs::read_to_string(doc) {
            for line in content.lines() {
                // Procura links em markdown do tipo [texto](caminho)
                if line.contains("](") && !line.contains("http://") && !line.contains("https://") {
                    if let Some(start) = line.find("](") {
                        let sub = &line[start + 2..];
                        if let Some(end) = sub.find(')') {
                            let link_target = &sub[..end].split('#').next().unwrap_or("").trim();
                            if !link_target.is_empty() && !link_target.starts_with("mailto:") {
                                let target_path = if link_target.starts_with('/') {
                                    repo_root.join(&link_target[1..])
                                } else {
                                    doc.parent().unwrap_or(repo_root).join(link_target)
                                };
                                if !target_path.exists() && link_target.ends_with(".md") {
                                    broken_links.push(format!(
                                        "{}: link para '{}' inexistente",
                                        doc.file_name().and_then(|s| s.to_str()).unwrap_or(""),
                                        link_target
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if broken_links.is_empty() {
        messages.push(format!("✅ {} documentos canônicos e ADRs em docs/ com links íntegros", doc_count));
    } else {
        for b in &broken_links {
            messages.push(format!("❌ Documentação: {}", b));
        }
    }

    DocAuditResult {
        total_docs: doc_count,
        broken_links,
        messages,
    }
}
