use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct CvReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_curriculum_vitae(root: &Path) -> CvReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();
    let mut scanned_count = 0;

    let cv_root = if root.join("curriculum-vitae").is_dir() {
        root.join("curriculum-vitae")
    } else if root.ends_with("curriculum-vitae") {
        root.to_path_buf()
    } else {
        root.to_path_buf()
    };

    let pt_dir = cv_root.join("pt-br");
    let en_dir = cv_root.join("en-us");

    // 1. Bilingual Parity Mapping PT-BR <-> EN-US
    // Expected correspondence:
    // 01-tech-pm-br.md           <-> 01-tech-pm-en.md
    // 01-tech-dados-negocios-br.md <-> 01-tech-business-data-en.md
    // 01-tech-produto-dados-br.md <-> 01-tech-product-data-en.md
    // 02-socioambiental-nichado-br.md <-> 02-socioenvironmental-niche-en.md
    // 02-socioambiental-tech-br.md    <-> 02-socioenvironmental-tech-en.md
    // 03-sumaenima-br.md              <-> 03-sumaenima-en.md

    let parity_pairs = [
        ("01-tech-pm-br.md", "01-tech-pm-en.md"),
        (
            "01-tech-dados-negocios-br.md",
            "01-tech-business-data-en.md",
        ),
        ("01-tech-produto-dados-br.md", "01-tech-product-data-en.md"),
        (
            "02-socioambiental-nichado-br.md",
            "02-socioenvironmental-niche-en.md",
        ),
        (
            "02-socioambiental-tech-br.md",
            "02-socioenvironmental-tech-en.md",
        ),
        ("03-sumaenima-br.md", "03-sumaenima-en.md"),
    ];

    let mut pt_files = HashMap::new();
    let mut en_files = HashMap::new();

    if pt_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&pt_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".md") {
                        scanned_count += 1;
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            pt_files.insert(name.to_string(), content);
                        }
                    }
                }
            }
        }
    }

    if en_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&en_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".md") {
                        scanned_count += 1;
                        if let Ok(content) = fs::read_to_string(entry.path()) {
                            en_files.insert(name.to_string(), content);
                        }
                    }
                }
            }
        }
    }

    // Parity verification
    for (pt_file, en_file) in parity_pairs {
        let has_pt = pt_files.contains_key(pt_file);
        let has_en = en_files.contains_key(en_file);

        if has_pt && !has_en {
            violations.push(Violation {
                rule_id: "CV-BILINGUAL-PARITY".to_string(),
                rule_name: "Missing Bilingual Parity (EN Missing)".to_string(),
                severity: Severity::Error,
                file_path: format!("en-us/{}", en_file),
                line_number: 1,
                snippet: "".to_string(),
                message: format!(
                    "English version '{}' missing for Portuguese counterpart '{}'.",
                    en_file, pt_file
                ),
                suggestion: Some(format!(
                    "Create 'en-us/{}' by translating content from 'pt-br/{}'.",
                    en_file, pt_file
                )),
            });
        } else if !has_pt && has_en {
            violations.push(Violation {
                rule_id: "CV-BILINGUAL-PARITY".to_string(),
                rule_name: "Missing Bilingual Parity (PT Missing)".to_string(),
                severity: Severity::Error,
                file_path: format!("pt-br/{}", pt_file),
                line_number: 1,
                snippet: "".to_string(),
                message: format!(
                    "Portuguese version '{}' missing for English counterpart '{}'.",
                    pt_file, en_file
                ),
                suggestion: Some(format!(
                    "Create 'pt-br/{}' by translating content from 'en-us/{}'.",
                    pt_file, en_file
                )),
            });
        }
    }

    // 2. Continuous README Narrative Validation ("The Thread")
    let readme_path = cv_root.join("README.md");
    if readme_path.is_file() {
        scanned_count += 1;
        if let Ok(content) = fs::read_to_string(&readme_path) {
            let has_thread_pt =
                content.contains("O Fio da Meada") || content.contains("Fio da Meada");
            let has_thread_en = content.contains("The Thread") || content.contains("Common Thread");

            if !has_thread_pt && !has_thread_en {
                violations.push(Violation {
                    rule_id: "CV-README-THREAD".to_string(),
                    rule_name: "Missing README Continuous Narrative".to_string(),
                    severity: Severity::Warning,
                    file_path: "README.md".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: "The CV README must maintain continuous career narrative ('The Thread').".to_string(),
                    suggestion: Some("Update 'The Thread' section in README.md.".to_string()),
                });
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} bilingual CVs audited with 100% PT↔EN parity.",
            scanned_count
        ));
        messages
            .push("✅ 'The Thread' / 'O Fio da Meada' narrative intact in README.".to_string());
    } else {
        messages.push(format!(
            "ℹ️ {} deviation(s) found across curriculum vitae documents.",
            violations.len()
        ));
    }

    CvReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
