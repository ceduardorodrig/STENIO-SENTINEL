//! Small shared helpers extracted to satisfy `ARCH-DRY-DUPLICATION` across
//! modules (Fase 2 debt pay-down, 2026-10-09).

use std::path::Path;

use colored::Colorize;

use crate::rule::Severity;

/// Plain severity label (`ERROR` / `WARN`).
pub fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "ERROR",
        Severity::Warning => "WARN",
    }
}

/// Colored severity badge (`[ERROR]` / `[WARN] `).
pub fn severity_badge(sev: Severity) -> colored::ColoredString {
    match sev {
        Severity::Error => "[ERROR]".red().bold(),
        Severity::Warning => "[WARN] ".yellow().bold(),
    }
}

/// Lowercased file extension of `path` (`""` when absent or non-UTF8).
pub fn lower_ext(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase()
}

/// Splits a CSV line into trimmed fields.
pub fn csv_fields(line: &str) -> Vec<&str> {
    line.split(',').map(|s| s.trim()).collect()
}
