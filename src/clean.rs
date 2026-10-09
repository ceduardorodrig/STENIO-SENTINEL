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
            CleanCategory::RustTarget => "Rust Build",
            CleanCategory::TempJunk => "Temporary File",
            CleanCategory::Cache => "Disposable Cache",
            CleanCategory::Docker => "Disposable Docker",
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

/// Formats bytes into human-readable format (B, KiB, MiB, GiB)
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

/// Calculates total size of a directory recursively
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

/// Checks if a file is considered temporary junk by name/extension
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

/// Converts Docker size strings (e.g. "1.849GB (52%)", "5.583MB", "117.5MB", "9.106kB") to bytes
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

/// Executes workspace scanning and smart hygiene
pub fn run_clean(root: &Path, mode: &str, dry_run: bool) -> Result<CleanReport> {
    let t0 = Instant::now();
    let mut items = Vec::new();
    let clean_targets = mode == "targets" || mode == "safe" || mode == "all";
    let clean_temps = mode == "temp" || mode == "safe" || mode == "all";
    let clean_docker = mode == "docker" || mode == "safe" || mode == "all";
    let deep_target_wipe = mode == "all" || mode == "targets";

    // ── 1. Locate and Clean Rust target/ Directories ────────────────────
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

            // Protection against .git
            if path_str.contains("/.git/") || path_str.ends_with("/.git") {
                continue;
            }

            if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name == "target" {
                        // Confirm if it is a Cargo target (parent directory has Cargo.toml)
                        let parent = p.parent().unwrap_or(root);
                        if parent.join("Cargo.toml").is_file() {
                            let rel = p
                                .strip_prefix(root)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .to_string();

                            if deep_target_wipe {
                                // Total target/ cleanup
                                let sz = dir_size(p);
                                if sz > 0 {
                                    items.push(CleanItem {
                                        path: p.to_path_buf(),
                                        rel_path: rel,
                                        bytes: sz,
                                        is_dir: true,
                                        category: CleanCategory::RustTarget,
                                        description: "Complete Rust build tree (target/)"
                                            .to_string(),
                                    });
                                }
                            } else {
                                // Safe mode: cleans target/debug and target/incremental, preserving target/release
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
                                            description: "Debug compilation artifacts"
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
                                            description: "Incremental compilation cache"
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
                                            description: "Generated HTML documentation (rustdoc)"
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

    // ── 2. Locate and Clean Temporary Files and Caches ───────────
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

            // Ignore Python virtual environments and Node dependencies
            if path_str.contains("/.venv/")
                || path_str.contains("/venv/")
                || path_str.contains("/node_modules/")
            {
                continue;
            }

            // Do not scan inside already handled target/ directories
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
                        Some("Cached Python bytecode (__pycache__)")
                    } else if name == ".pytest_cache" {
                        Some("Pytest test runner cache")
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
                            description: "Residual temporary file".to_string(),
                        });
                    }
                }
            }
        }
    }

    // ── 2.5. Locate Docker Waste (Dangling images, containers, and build cache) ──
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
                                            "Disposable Docker images ({}/{} active)",
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
                                            "Stopped containers ({}/{} active)",
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
                                        description: "Intermediate Docker build cache"
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

    // ── 3. Physical Removal (when not dry-run) ──────────────────────────
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

/// Renders the visual hygiene report in the terminal
pub fn print_clean_report(report: &CleanReport) {
    let badge = format!("[{:?}]", report.duration);
    crate::baseline::print_banner_with_badge(
        "StenioSentinel (Clean Engine v3.1.0) — Smart Workspace Hygiene",
        &badge,
    );

    let mode_desc = match report.mode.as_str() {
        "targets" => "Rust Build Targets",
        "temp" => "Temporary Files and Caches",
        "docker" => "Docker Ecosystem Hygiene (Images + Containers + Cache)",
        "all" => "Total Deep Clean (Targets + Caches + Temporary + Docker)",
        _ => "Safe Mode (Debug/Incremental + Temporary + Docker Prune)",
    };

    println!(
        "Mode: {} | Status: {}",
        mode_desc.yellow().bold(),
        if report.dry_run {
            "SIMULATION (Dry Run)".yellow().bold()
        } else {
            "LIVE EXECUTION".green().bold()
        }
    );
    println!();

    if report.items.is_empty() {
        println!(
            "{}",
            "✨ The workspace is already 100% clean! Zero accumulated junk found."
                .green()
                .bold()
        );
        println!();
        return;
    }

    println!(
        "{}",
        "Cataloged items for hygiene (sorted by size):".bold()
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
                    "... and {} smaller items ({})",
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
            "🔍 Total reclaimable: {} across {} item(s).",
            format_bytes(report.total_bytes).green().bold(),
            report.items.len().to_string().yellow().bold()
        );
        println!(
            "{}",
            "💡 Dry Run mode active: No files were physically deleted.".yellow()
        );
        println!(
            "   To execute cleanup and reclaim space, run: {}",
            format!("stenio --clean {}", report.mode).cyan().bold()
        );
    } else {
        println!(
            "🧹 Space successfully reclaimed: {} across {} item(s).",
            format_bytes(report.total_bytes).green().bold(),
            report.items.len().to_string().yellow().bold()
        );
        println!(
            "{}",
            "✨ Hygiene complete! Workspace lean and ready."
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
