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

/// Normalizes a line of code, ignoring trivial syntax noise, comments, and imports.
/// Returns `Some(normalized_line)` if the line contains substantive logic, or `None` otherwise.
pub fn normalize_substantive_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Ignore comments (single line and common block markers)
    if trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("*/")
        || trimmed.starts_with('#')
        || trimmed.starts_with("<!--")
    {
        return None;
    }

    // Ignore dividers and visual terminal borders
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

/// Checks whether a file should participate in DRY analysis.
pub fn is_dry_eligible(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Ignore build directories, caches, dependencies, and lockfiles
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

    // Ignore test files where setup/fixtures repetition is an acceptable standard pattern
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

/// Extracts substantive lines from a text file.
pub fn parse_file_substantive(path: &Path, content: &str) -> FileRecord {
    let mut substantive = Vec::new();
    let has_ignore = false; // DRY principle is inviolable: cannot be suppressed via inline comments

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

                // If within the same file, block cannot self-overlap
                if f1 == f2 && idx2 < idx1 + min_lines {
                    continue;
                }

                // If both start positions were already reported in an earlier maximal block, skip
                if reported_positions.contains(&(f1, idx1))
                    && reported_positions.contains(&(f2, idx2))
                {
                    continue;
                }

                // Strict parity check for base block of size `min_lines`
                let matches_base = (0..min_lines).all(|k| {
                    files[f1].substantive[idx1 + k].text == files[f2].substantive[idx2 + k].text
                });

                if !matches_base {
                    continue;
                }

                // Maximal forward extension: expand duplicate block while lines remain identical
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

                // Record covered positions to avoid redundant violation reports
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

                // Representative snippet (first 3 lines of block)
                let preview_count = 3.min(ext_len);
                let snippet = files[f1].substantive[idx1..(idx1 + preview_count)]
                    .iter()
                    .map(|l| l.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");

                let message = if f1 == f2 {
                    format!(
                        "Internal duplication of {} substantive lines (L{}-L{} is identical to L{}-L{}). Violates the Absolute DRY Principle.",
                        ext_len, start_line1, end_line1, start_line2, end_line2
                    )
                } else {
                    format!(
                        "Block of {} substantive lines duplicated with '{}' (L{}-L{}). Violates the Absolute DRY Principle.",
                        ext_len, files[f2].rel_path, start_line2, end_line2
                    )
                };

                violations.push(Violation {
                    rule_id: "ARCH-DRY-DUPLICATION".to_string(),
                    rule_name: "Code Duplication (DRY Principle)".to_string(),
                    severity: Severity::Error,
                    file_path: file1_str,
                    line_number: start_line1,
                    snippet: format!("{}\n...", snippet),
                    message,
                    suggestion: Some(
                        "Extract duplicate logic into a custom hook ('features/<domain>/hooks/'), atomic component, or shared utility function."
                            .to_string(),
                    ),
                });
            }
        }
    }

    violations
}

/// Executes DRY scan across a directory or file tree.
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
        "Files analyzed: {} | Duration: {:?}",
        files_count.to_string().yellow().bold(),
        duration
    );

    if violations.is_empty() {
        println!(
            "{}",
            "✨ DRY Principle 100% compliant: Zero duplicated code blocks found!"
                .green()
                .bold()
        );
        return;
    }

    println!(
        "{}",
        format!(
            "⚠️ {} duplicated code block occurrence(s) detected:",
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
            println!("    {} {}", "💡 Suggestion:".green(), sugg);
        }
        println!("    {}", "Duplicated block snippet:".dimmed());
        for s_line in v.snippet.lines() {
            println!("      │ {}", s_line.dimmed());
        }
    }
}
