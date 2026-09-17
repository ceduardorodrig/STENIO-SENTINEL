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

    // 1. Mapeamento de Paridade Bilíngue PT-BR <-> EN-US
    // Correspondência esperada:
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

    // Checagem de paridade
    for (pt_file, en_file) in parity_pairs {
        let has_pt = pt_files.contains_key(pt_file);
        let has_en = en_files.contains_key(en_file);

        if has_pt && !has_en {
            violations.push(Violation {
                rule_id: "CV-BILINGUAL-PARITY".to_string(),
                rule_name: "Paridade Bilíngue Ausente (Falta EN)".to_string(),
                severity: Severity::Error,
                file_path: format!("en-us/{}", en_file),
                line_number: 1,
                snippet: "".to_string(),
                message: format!(
                    "Versão em inglês '{}' ausente para o correspondente em português '{}'.",
                    en_file, pt_file
                ),
                suggestion: Some(format!(
                    "Crie o arquivo 'en-us/{}' traduzindo o conteúdo de 'pt-br/{}'.",
                    en_file, pt_file
                )),
            });
        } else if !has_pt && has_en {
            violations.push(Violation {
                rule_id: "CV-BILINGUAL-PARITY".to_string(),
                rule_name: "Paridade Bilíngue Ausente (Falta PT)".to_string(),
                severity: Severity::Error,
                file_path: format!("pt-br/{}", pt_file),
                line_number: 1,
                snippet: "".to_string(),
                message: format!(
                    "Versão em português '{}' ausente para o correspondente em inglês '{}'.",
                    pt_file, en_file
                ),
                suggestion: Some(format!(
                    "Crie o arquivo 'pt-br/{}' traduzindo o conteúdo de 'en-us/{}'.",
                    pt_file, en_file
                )),
            });
        }
    }

    // 2. Validação da Narrativa do README ("O Fio da Meada" e "The Thread")
    let readme_path = cv_root.join("README.md");
    if readme_path.is_file() {
        scanned_count += 1;
        if let Ok(content) = fs::read_to_string(&readme_path) {
            let has_thread_pt =
                content.contains("O Fio da Meada") || content.contains("Fio da Meada");
            let has_thread_en = content.contains("The Thread");

            if !has_thread_pt || !has_thread_en {
                violations.push(Violation {
                    rule_id: "CV-README-THREAD".to_string(),
                    rule_name: "Narrativa Contínua do README Ausente".to_string(),
                    severity: Severity::Warning,
                    file_path: "README.md".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: "O README deve manter a história contínua em ambas as línguas ('O Fio da Meada' e 'The Thread').".to_string(),
                    suggestion: Some("Atualize a seção 'O Fio da Meada' / 'The Thread' no README.md.".to_string()),
                });
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} currículos bilíngues auditados com 100% de paridade PT↔EN.",
            scanned_count
        ));
        messages
            .push("✅ Narrativa 'O Fio da Meada' / 'The Thread' íntegra no README.".to_string());
    } else {
        messages.push(format!(
            "ℹ️ {} desvio(s) encontrados na base de currículos.",
            violations.len()
        ));
    }

    CvReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
