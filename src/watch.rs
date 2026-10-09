use anyhow::Result;
use colored::*;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::channel;

use crate::engine::Engine;

pub fn start_watch_mode(
    root: &Path,
    engine: &Engine,
    tag_filter: Option<&str>,
    only_rule: Option<&str>,
) -> Result<()> {
    crate::baseline::print_banner("StenioSentinel — Real-Time Watchdog Daemon (Inotify/Rust)");
    println!(
        "   👀 Watching for changes in: {}",
        root.display().to_string().green().bold()
    );
    println!(
        "   ⚡ Any file save made by OpenCode, IDEs, or agents will be audited in <5ms."
    );
    println!("   🛑 Press Ctrl+C to terminate.");
    println!();

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(root, RecursiveMode::Recursive)?;

    for res in rx {
        match res {
            Ok(event) => {
                if let EventKind::Modify(_) | EventKind::Create(_) = event.kind {
                    for path in event.paths {
                        let path_str = path.to_string_lossy();
                        if path_str.contains("/.git/")
                            || path_str.contains("/target/")
                            || path_str.contains("/node_modules/")
                            || path_str.contains("/.stversions/")
                        {
                            continue;
                        }
                        if path.is_file() {
                            let t0 = std::time::Instant::now();
                            let violations = engine.scan_file(&path, tag_filter, only_rule);
                            let elapsed = t0.elapsed();
                            if violations.is_empty() {
                                println!(
                                    "   {} {:<55} {}",
                                    "✨".green(),
                                    path.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .dimmed(),
                                    format!("[{:.2?}]", elapsed).dimmed()
                                );
                            } else {
                                println!(
                                    "   {} {:<55} {}",
                                    "🚨".red(),
                                    path.display().to_string().bold(),
                                    format!("[{:.2?}]", elapsed).yellow()
                                );
                                for v in violations {
                                    let badge = crate::util::severity_badge(v.severity);
                                    println!(
                                        "      {} {}:{} [{}] {}",
                                        badge,
                                        v.file_path.dimmed(),
                                        v.line_number,
                                        v.rule_id.cyan(),
                                        v.message
                                    );
                                    if let Some(sug) = v.suggestion {
                                        println!("         💡 {}", sug.green());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Error in inotify watchdog: {:?}", e),
        }
    }

    Ok(())
}
