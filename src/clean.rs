use anyhow::Result;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanCategory {
    RustTarget,
    TempJunk,
    Cache,
    Docker,
}

impl CleanCategory {
    pub fn label(&self) -> &'static str {
        match self {
            CleanCategory::RustTarget => "Build Rust",
            CleanCategory::TempJunk => "Arquivo Temporário",
            CleanCategory::Cache => "Cache Descartável",
            CleanCategory::Docker => "Docker Descartável",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CleanItem {
    pub path: PathBuf,
    pub rel_path: String,
    pub bytes: u64,
    pub is_dir: bool,
    pub category: CleanCategory,
    pub description: String,
}

pub struct CleanReport {
    pub items: Vec<CleanItem>,
    pub total_bytes: u64,
    pub mode: String,
    pub dry_run: bool,
    pub duration: std::time::Duration,
}

/// Formata bytes em formato legível humano (B, KiB, MiB, GiB)
pub fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Calcula o tamanho total de um diretório recursivamente
pub fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    total += dir_size(&p);
                } else {
                    total += meta.len();
                }
            }
        }
    }
    total
}

/// Verifica se um arquivo é considerado lixo temporário por nome/extensão
fn is_temp_file(name: &str) -> bool {
    name.ends_with('~')
        || name.ends_with(".swp")
        || name.ends_with(".swo")
        || name.ends_with(".bak")
        || name.ends_with(".orig")
        || name.ends_with(".tmp")
        || name.ends_with(".tmp.log")
        || name.ends_with(".log.tmp")
        || name == ".DS_Store"
        || name == "Thumbs.db"
        || name == ".eslintcache"
        || (name.ends_with(".pyc") || name.ends_with(".pyo"))
}

/// Converte strings de tamanho do Docker (ex: "1.849GB (52%)", "5.583MB", "117.5MB", "9.106kB") em bytes
pub fn parse_docker_size(size_str: &str) -> u64 {
    let clean = size_str.split('(').next().unwrap_or("").trim();
    if clean.is_empty() || clean == "0B" {
        return 0;
    }
    let lower = clean.to_lowercase();
    let (num_part, multiplier) = if lower.ends_with("gib") || lower.ends_with("gb") {
        (
            lower.trim_end_matches("gib").trim_end_matches("gb").trim(),
            1024 * 1024 * 1024,
        )
    } else if lower.ends_with("mib") || lower.ends_with("mb") {
        (
            lower.trim_end_matches("mib").trim_end_matches("mb").trim(),
            1024 * 1024,
        )
    } else if lower.ends_with("kib") || lower.ends_with("kb") {
        (
            lower.trim_end_matches("kib").trim_end_matches("kb").trim(),
            1024,
        )
    } else if lower.ends_with('b') {
        (lower.trim_end_matches('b').trim(), 1)
    } else {
        (lower.as_str(), 1)
    };
    if let Ok(val) = num_part.parse::<f64>() {
        (val * multiplier as f64) as u64
    } else {
        0
    }
}

/// Executa a varredura e higienização inteligente do workspace
pub fn run_clean(root: &Path, mode: &str, dry_run: bool) -> Result<CleanReport> {
    let t0 = Instant::now();
    let mut items = Vec::new();
    let clean_targets = mode == "targets" || mode == "safe" || mode == "all";
    let clean_temps = mode == "temp" || mode == "safe" || mode == "all";
    let clean_docker = mode == "docker" || mode == "safe" || mode == "all";
    let deep_target_wipe = mode == "all" || mode == "targets";

    // ── 1. Localização e Limpeza de Pastas target/ Rust ─────────────────────
    if clean_targets {
        let mut walker = ignore::WalkBuilder::new(root);
        walker
            .hidden(false)
            .parents(true)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false);

        for entry in walker.build().flatten() {
            let p = entry.path();
            let path_str = p.to_string_lossy();

            // Proteção contra .git
            if path_str.contains("/.git/") || path_str.ends_with("/.git") {
                continue;
            }

            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name == "target" {
                        // Confirma se é um target de Cargo (pasta irmã tem Cargo.toml)
                        let parent = p.parent().unwrap_or(root);
                        if parent.join("Cargo.toml").is_file() {
                            let rel = p
                                .strip_prefix(root)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .to_string();

                            if deep_target_wipe {
                                // Limpeza total do target/
                                let sz = dir_size(p);
                                if sz > 0 {
                                    items.push(CleanItem {
                                        path: p.to_path_buf(),
                                        rel_path: rel,
                                        bytes: sz,
                                        is_dir: true,
                                        category: CleanCategory::RustTarget,
                                        description: "Árvore completa de build Rust (target/)"
                                            .to_string(),
                                    });
                                }
                            } else {
                                // Modo safe: limpa target/debug e target/incremental, preservando target/release
                                let debug_dir = p.join("debug");
                                if debug_dir.is_dir() {
                                    let sz = dir_size(&debug_dir);
                                    if sz > 0 {
                                        items.push(CleanItem {
                                            path: debug_dir,
                                            rel_path: format!("{}/debug", rel),
                                            bytes: sz,
                                            is_dir: true,
                                            category: CleanCategory::RustTarget,
                                            description: "Artefatos de compilação debug"
                                                .to_string(),
                                        });
                                    }
                                }

                                let incr_dir = p.join("incremental");
                                if incr_dir.is_dir() {
                                    let sz = dir_size(&incr_dir);
                                    if sz > 0 {
                                        items.push(CleanItem {
                                            path: incr_dir,
                                            rel_path: format!("{}/incremental", rel),
                                            bytes: sz,
                                            is_dir: true,
                                            category: CleanCategory::RustTarget,
                                            description: "Cache de compilação incremental"
                                                .to_string(),
                                        });
                                    }
                                }

                                let doc_dir = p.join("doc");
                                if doc_dir.is_dir() {
                                    let sz = dir_size(&doc_dir);
                                    if sz > 0 {
                                        items.push(CleanItem {
                                            path: doc_dir,
                                            rel_path: format!("{}/doc", rel),
                                            bytes: sz,
                                            is_dir: true,
                                            category: CleanCategory::RustTarget,
                                            description: "Documentação HTML gerada (rustdoc)"
                                                .to_string(),
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

    // ── 2. Localização e Limpeza de Arquivos Temporários e Caches ───────────
    if clean_temps {
        let mut walker = ignore::WalkBuilder::new(root);
        walker
            .hidden(false)
            .parents(true)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(true);

        for entry in walker.build().flatten() {
            let p = entry.path();
            let path_str = p.to_string_lossy();

            if path_str.contains("/.git/") || path_str.ends_with("/.git") {
                continue;
            }

            // Ignora ambientes virtuais Python e dependências Node
            if path_str.contains("/.venv/")
                || path_str.contains("/venv/")
                || path_str.contains("/node_modules/")
            {
                continue;
            }

            // Não varrer dentro de pastas target/ já tratadas
            if path_str.contains("/target/") {
                continue;
            }

            let rel = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .to_string();

            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    let desc = if name == "__pycache__" && !path_str.contains("/.venv/") {
                        Some("Bytecode Python em cache (__pycache__)")
                    } else if name == ".pytest_cache" {
                        Some("Cache do executor de testes Pytest")
                    } else {
                        None
                    };

                    if let Some(description) = desc {
                        items.push(CleanItem {
                            path: p.to_path_buf(),
                            rel_path: rel,
                            bytes: dir_size(p),
                            is_dir: true,
                            category: CleanCategory::Cache,
                            description: description.to_string(),
                        });
                    }
                }
            } else if entry.file_type().map_or(false, |ft| ft.is_file()) {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if is_temp_file(name) {
                        let sz = entry.metadata().map_or(0, |m| m.len());
                        items.push(CleanItem {
                            path: p.to_path_buf(),
                            rel_path: rel,
                            bytes: sz,
                            is_dir: false,
                            category: CleanCategory::TempJunk,
                            description: "Arquivo temporário residual".to_string(),
                        });
                    }
                }
            }
        }
    }

    // ── 2.5. Localização de Desperdício Docker (Imagens órfãs, containers e cache) ──
    if clean_docker {
        if let Ok(output) = std::process::Command::new("docker")
            .args(["system", "df", "--format", "{{json .}}"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                        let row_type = val.get("Type").and_then(|v| v.as_str()).unwrap_or("");
                        let active = val.get("Active").and_then(|v| v.as_str()).unwrap_or("0");
                        let total = val
                            .get("TotalCount")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0");
                        let reclaimable = val
                            .get("Reclaimable")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let bytes = parse_docker_size(reclaimable);

                        if bytes > 0 {
                            match row_type {
                                "Images" => {
                                    items.push(CleanItem {
                                        path: PathBuf::from("docker://images/dangling"),
                                        rel_path: "docker/images (dangling & unused)".to_string(),
                                        bytes,
                                        is_dir: false,
                                        category: CleanCategory::Docker,
                                        description: format!(
                                            "Imagens Docker descartáveis ({}/{} ativas)",
                                            active, total
                                        ),
                                    });
                                }
                                "Containers" => {
                                    items.push(CleanItem {
                                        path: PathBuf::from("docker://containers/stopped"),
                                        rel_path: "docker/containers (stopped)".to_string(),
                                        bytes,
                                        is_dir: false,
                                        category: CleanCategory::Docker,
                                        description: format!(
                                            "Containers finalizados ({}/{} ativos)",
                                            active, total
                                        ),
                                    });
                                }
                                "Build Cache" if mode == "docker" || mode == "all" => {
                                    items.push(CleanItem {
                                        path: PathBuf::from("docker://builder/cache"),
                                        rel_path: "docker/build-cache".to_string(),
                                        bytes,
                                        is_dir: false,
                                        category: CleanCategory::Docker,
                                        description: "Cache intermediário de builds Docker"
                                            .to_string(),
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    // ── 3. Remoção Física (quando não for dry-run) ──────────────────────────
    let total_bytes: u64 = items.iter().map(|i| i.bytes).sum();

    if !dry_run {
        for item in &items {
            if item.category == CleanCategory::Docker {
                continue;
            }
            if item.is_dir {
                let _ = fs::remove_dir_all(&item.path);
            } else {
                let _ = fs::remove_file(&item.path);
            }
        }

        if clean_docker {
            let _ = std::process::Command::new("docker")
                .args(["image", "prune", "-f"])
                .output();
            let _ = std::process::Command::new("docker")
                .args(["container", "prune", "-f"])
                .output();
            if mode == "docker" || mode == "all" {
                let _ = std::process::Command::new("docker")
                    .args(["builder", "prune", "-f"])
                    .output();
            }
        }
    }

    Ok(CleanReport {
        items,
        total_bytes,
        mode: mode.to_string(),
        dry_run,
        duration: t0.elapsed(),
    })
}

/// Renderiza o relatório visual da zeladoria no terminal
pub fn print_clean_report(report: &CleanReport) {
    let badge = format!("[{:?}]", report.duration);
    crate::baseline::print_banner_with_badge(
        "StenioSentinel (Clean Engine v3.1.0) — Zeladoria e Higiene Inteligente",
        &badge,
    );

    let mode_desc = match report.mode.as_str() {
        "targets" => "Build Targets Rust",
        "temp" => "Arquivos Temporários e Caches",
        "docker" => "Higiene do Ecossistema Docker (Imagens + Containers + Cache)",
        "all" => "Limpeza Profunda Total (Targets + Caches + Temporários + Docker)",
        _ => "Modo Seguro (Debug/Incremental + Temporários + Docker Prune)",
    };

    println!(
        "Modo: {} | Status: {}",
        mode_desc.yellow().bold(),
        if report.dry_run {
            "SIMULAÇÃO (Dry Run)".yellow().bold()
        } else {
            "EXECUÇÃO REAL".green().bold()
        }
    );
    println!();

    if report.items.is_empty() {
        println!(
            "{}",
            "✨ O workspace já está 100% limpo! Zero lixo acumulado encontrado."
                .green()
                .bold()
        );
        println!();
        return;
    }

    println!(
        "{}",
        "Itens catalogados para higienização (ordenados por tamanho):".bold()
    );
    let mut sorted_items = report.items.clone();
    sorted_items.sort_by(|a, b| b.bytes.cmp(&a.bytes));

    let max_display = 25;
    for (idx, item) in sorted_items.iter().enumerate() {
        if idx >= max_display {
            let remaining = sorted_items.len() - max_display;
            let remaining_bytes: u64 = sorted_items[max_display..].iter().map(|i| i.bytes).sum();
            println!(
                "  {}",
                format!(
                    "... e mais {} itens menores ({})",
                    remaining,
                    format_bytes(remaining_bytes)
                )
                .dimmed()
                .italic()
            );
            break;
        }

        let cat_tag = match item.category {
            CleanCategory::RustTarget => item.category.label().magenta().bold(),
            CleanCategory::TempJunk => item.category.label().red().bold(),
            CleanCategory::Cache => item.category.label().blue().bold(),
            CleanCategory::Docker => item.category.label().cyan().bold(),
        };

        println!(
            "  [{}] {} ({}) — {}",
            cat_tag,
            item.rel_path.white().bold(),
            format_bytes(item.bytes).yellow(),
            item.description.dimmed()
        );
    }

    println!();
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────────".dimmed()
    );

    if report.dry_run {
        println!(
            "🔍 Total recuperável: {} em {} item(ns).",
            format_bytes(report.total_bytes).green().bold(),
            report.items.len().to_string().yellow().bold()
        );
        println!(
            "{}",
            "💡 Modo Dry Run ativo: Nenhum arquivo foi excluído fisicamente.".yellow()
        );
        println!(
            "   Para efetivar a limpeza e recuperar espaço, rode: {}",
            format!("stenio --clean {}", report.mode).cyan().bold()
        );
    } else {
        println!(
            "🧹 Espaço recuperado com sucesso: {} em {} item(ns).",
            format_bytes(report.total_bytes).green().bold(),
            report.items.len().to_string().yellow().bold()
        );
        println!(
            "{}",
            "✨ Higienização concluída! Workspace pronto e enxuto."
                .green()
                .bold()
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_is_temp_file() {
        assert!(is_temp_file("test.tmp"));
        assert!(is_temp_file("test.bak"));
        assert!(is_temp_file("test.swp"));
        assert!(is_temp_file(".DS_Store"));
        assert!(!is_temp_file("main.rs"));
        assert!(!is_temp_file("Cargo.toml"));
    }

    #[test]
    fn test_parse_docker_size() {
        assert_eq!(
            parse_docker_size("1.849GB (52%)"),
            (1.849 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(
            parse_docker_size("5.583MB (73%)"),
            (5.583 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(
            parse_docker_size("117.5MB"),
            (117.5 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_docker_size("9.106kB (100%)"), (9.106 * 1024.0) as u64);
        assert_eq!(parse_docker_size("0B"), 0);
    }
}
