use colored::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::baseline::Whitelist;
use crate::engine::Violation;
use crate::rule::Severity;

#[derive(Debug, Clone)]
pub struct SubstantiveLine {
    pub line_no: usize,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub path: PathBuf,
    pub rel_path: String,
    pub has_ignore: bool,
    pub substantive: Vec<SubstantiveLine>,
}

/// Normaliza uma linha de código, ignorando ruído de sintaxe trivial, comentários e imports.
/// Retorna `Some(linha_normalizada)` se a linha contiver lógica substantiva, ou `None` caso contrário.
pub fn normalize_substantive_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Ignora comentários (linha única e blocos comuns)
    if trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
        || trimmed.starts_with('#')
        || trimmed.starts_with("<!--")
    {
        return None;
    }

    // Ignora divisores e molduras visuais de terminal
    if trimmed.contains("═════") || trimmed.contains("─────") || trimmed.contains("-----")
    {
        return None;
    }

    // Ignora pontuação pura e fechamentos estruturais
    match trimmed {
        "{" | "}" | "};" | "});" | ");" | ")" | "(" | "]" | "];" | "]," | "[" | "else {"
        | "return;" | "return true;" | "return false;" | "return null;" | "return undefined;"
        | "break;" | "continue;" | "<>" | "</>" | "</div>" | "</span>" | "</p>" | "</button>" => {
            return None;
        }
        _ => {}
    }

    // Ignora imports, exports, derives e decorators que são boilerplate inevitável
    if trimmed.starts_with("import ")
        || trimmed.starts_with("export ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("pub use ")
        || trimmed.starts_with("#[")
        || trimmed.starts_with('@')
    {
        return None;
    }

    Some(trimmed.to_string())
}

/// Verifica se um arquivo deve participar da análise DRY.
pub fn is_dry_eligible(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Ignora pastas de build, cache, dependências e lockfiles
    if crate::baseline::is_common_ignored_path(&path_str)
        || path_str.contains("/build/")
        || path_str.contains("/llm_model_cache/")
        || path_str.contains("/migrations/")
        || path_str.ends_with(".d.ts")
        || path_str.ends_with(".min.js")
        || path_str.ends_with(".min.css")
        || path_str.ends_with(".lock")
    {
        return false;
    }

    // Ignora arquivos de teste onde repetições de setup/fixtures são padrão aceitável
    if path_str.contains("/tests/")
        || path_str.ends_with("_test.rs")
        || path_str.ends_with(".test.ts")
        || path_str.ends_with(".test.tsx")
        || path_str.ends_with(".spec.ts")
        || path_str.ends_with(".spec.tsx")
    {
        return false;
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    matches!(
        ext.as_str(),
        "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "sh" | "css"
    )
}

/// Extrai linhas substantivas de um arquivo de texto.
pub fn parse_file_substantive(path: &Path, content: &str) -> FileRecord {
    let mut substantive = Vec::new();
    let has_ignore = false; // Princípio DRY é inviolável: não pode ser ignorado por comentário inline

    for (idx, line) in content.lines().enumerate() {
        if let Some(norm) = normalize_substantive_line(line) {
            substantive.push(SubstantiveLine {
                line_no: idx + 1,
                text: norm,
            });
        }
    }

    FileRecord {
        path: path.to_path_buf(),
        rel_path: path.to_string_lossy().to_string(),
        has_ignore,
        substantive,
    }
}

/// Motor Universal de Detecção de Duplicação de Código (DRY).
/// Utiliza janela deslizante de hashing combinatório (Rolling Block Hash) e extensão maximal
/// para encontrar blocos duplicados idênticos em tempo <15ms.
pub fn detect_dry_duplication(
    files: &[FileRecord],
    min_lines: usize,
    whitelist: &Whitelist,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    if files.is_empty() || min_lines == 0 {
        return violations;
    }

    // Mapa de hash -> lista de (file_idx, sub_idx)
    let mut window_map: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();

    for (f_idx, file) in files.iter().enumerate() {
        if file.has_ignore || file.substantive.len() < min_lines {
            continue;
        }

        for i in 0..=(file.substantive.len() - min_lines) {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            use std::hash::Hasher;
            for j in 0..min_lines {
                hasher.write(file.substantive[i + j].text.as_bytes());
                hasher.write_u8(0);
            }
            let h = hasher.finish();
            window_map.entry(h).or_default().push((f_idx, i));
        }
    }

    // Rastreia intervalos substantivos já cobertos por blocos maximalmente estendidos
    // Chave: (file_idx, sub_idx)
    let mut reported_positions: HashSet<(usize, usize)> = HashSet::new();

    for (_hash, occurrences) in window_map {
        if occurrences.len() < 2 {
            continue;
        }

        // Compara cada par de ocorrências
        for i in 0..occurrences.len() {
            let (f1, idx1) = occurrences[i];

            for j in (i + 1)..occurrences.len() {
                let (f2, idx2) = occurrences[j];

                // Se for no mesmo arquivo, não pode haver auto-sobreposição do bloco
                if f1 == f2 && idx2 < idx1 + min_lines {
                    continue;
                }

                // Se ambos os inícios já foram relatados em um bloco maximal anterior, pula
                if reported_positions.contains(&(f1, idx1))
                    && reported_positions.contains(&(f2, idx2))
                {
                    continue;
                }

                // Validação de paridade estrita do bloco base de tamanho `min_lines`
                let matches_base = (0..min_lines).all(|k| {
                    files[f1].substantive[idx1 + k].text == files[f2].substantive[idx2 + k].text
                });

                if !matches_base {
                    continue;
                }

                // Extensão maximal para a frente: expande o bloco duplicado enquanto as linhas forem iguais
                let mut ext_len = min_lines;
                while (idx1 + ext_len < files[f1].substantive.len())
                    && (idx2 + ext_len < files[f2].substantive.len())
                    && (files[f1].substantive[idx1 + ext_len].text
                        == files[f2].substantive[idx2 + ext_len].text)
                {
                    if f1 == f2 && idx1 + ext_len >= idx2 {
                        break;
                    }
                    ext_len += 1;
                }

                // Registra posições cobertas para evitar violações redundantes
                for k in 0..ext_len {
                    reported_positions.insert((f1, idx1 + k));
                    reported_positions.insert((f2, idx2 + k));
                }

                let start_line1 = files[f1].substantive[idx1].line_no;
                let end_line1 = files[f1].substantive[idx1 + ext_len - 1].line_no;
                let start_line2 = files[f2].substantive[idx2].line_no;
                let end_line2 = files[f2].substantive[idx2 + ext_len - 1].line_no;

                let file1_str = files[f1].path.to_string_lossy().to_string();
                let file2_str = files[f2].path.to_string_lossy().to_string();

                if whitelist.is_ignored(&file1_str, "ARCH-DRY-DUPLICATION", &file2_str) {
                    continue;
                }

                // Snippet representativo (primeiras 3 linhas do bloco)
                let preview_count = 3.min(ext_len);
                let snippet = files[f1].substantive[idx1..(idx1 + preview_count)]
                    .iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");

                let message = if f1 == f2 {
                    format!(
                        "Duplicação interna de {} linhas substantivas (L{}-L{} é idêntico a L{}-L{}). Viola o Princípio DRY Absoluto.",
                        ext_len, start_line1, end_line1, start_line2, end_line2
                    )
                } else {
                    format!(
                        "Bloco de {} linhas substantivas duplicado com '{}' (L{}-L{}). Viola o Princípio DRY Absoluto.",
                        ext_len, files[f2].rel_path, start_line2, end_line2
                    )
                };

                violations.push(Violation {
                    rule_id: "ARCH-DRY-DUPLICATION".to_string(),
                    rule_name: "Duplicação de Código (Princípio DRY)".to_string(),
                    severity: Severity::Warning,
                    file_path: file1_str,
                    line_number: start_line1,
                    snippet: format!("{}\n...", snippet),
                    message,
                    suggestion: Some(
                        "Extraia a lógica duplicada para um hook customizado ('features/<dominio>/hooks/'), componente atômico ou função utilitária compartilhada."
                            .to_string(),
                    ),
                });
            }
        }
    }

    violations
}

/// Executa a varredura DRY em um diretório ou árvore de arquivos.
pub fn scan_dry_directory(
    root: &Path,
    min_lines: usize,
    whitelist: &Whitelist,
) -> (Vec<Violation>, usize, std::time::Duration) {
    let t0 = Instant::now();
    let mut file_records = Vec::new();

    let walker = crate::baseline::create_standard_walker(root);

    for entry in walker.build().flatten() {
        if entry.file_type().map_or(false, |ft| ft.is_file()) {
            let p = entry.path();
            if is_dry_eligible(p) {
                if let Ok(content) = fs::read_to_string(p) {
                    file_records.push(parse_file_substantive(p, &content));
                }
            }
        }
    }

    let files_count = file_records.len();
    let violations = detect_dry_duplication(&file_records, min_lines, whitelist);
    (violations, files_count, t0.elapsed())
}

/// Renderiza relatório formatado para o terminal.
pub fn print_dry_report(
    violations: &[Violation],
    files_count: usize,
    duration: std::time::Duration,
) {
    println!(
        "\n{}",
        "═══ MOTOR DRY (Don't Repeat Yourself) ═══".cyan().bold()
    );
    println!(
        "Arquivos analisados: {} | Duração: {:?}",
        files_count.to_string().yellow().bold(),
        duration
    );

    if violations.is_empty() {
        println!(
            "{}",
            "✨ Princípio DRY 100% cumprido: Zero duplicações de blocos encontradas!"
                .green()
                .bold()
        );
        return;
    }

    println!(
        "{}",
        format!(
            "⚠️ {} ocorrência(s) de blocos de código duplicados detectada(s):",
            violations.len()
        )
        .yellow()
        .bold()
    );

    for v in violations {
        println!(
            "\n  {} {} {}",
            "⚠️".yellow(),
            v.file_path.bold(),
            format!("(L{})", v.line_number).dimmed()
        );
        println!("    {}", v.message);
        if let Some(ref sugg) = v.suggestion {
            println!("    {} {}", "💡 Sugestão:".green(), sugg);
        }
        println!("    {}", "Snippet do bloco duplicado:".dimmed());
        for s_line in v.snippet.lines() {
            println!("      │ {}", s_line.dimmed());
        }
    }
}
