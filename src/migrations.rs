use regex::Regex;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct MigrationAuditResult {
    pub total_migrations: usize,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
}

pub fn check_sql_idempotency(sql: &str) -> Option<String> {
    let lower = sql.to_lowercase();
    if lower.contains("drop table ") && !lower.contains("drop table if exists ") {
        return Some("contains DROP TABLE without IF EXISTS (breaks rollback/re-execution)".to_string());
    }
    if lower.contains("drop index ") && !lower.contains("drop index if exists ") {
        return Some("contains DROP INDEX without IF EXISTS (non-idempotent)".to_string());
    }
    if lower.contains("create table ") && !lower.contains("create table if not exists ") {
        return Some("contains CREATE TABLE without IF NOT EXISTS (fails upon re-execution)".to_string());
    }
    if lower.contains("create index ") && !lower.contains("create index if not exists ") {
        return Some("contains CREATE INDEX without IF NOT EXISTS (fails upon re-execution)".to_string());
    }
    None
}

pub fn audit_migrations(root: &Path) -> MigrationAuditResult {
    let mut messages = Vec::new();
    let mut errors = Vec::new();

    let mig_dir = root.join("migrations");
    if !mig_dir.is_dir() {
        return MigrationAuditResult {
            total_migrations: 0,
            errors,
            messages,
        };
    }

    let file_pattern = match Regex::new(r"^v([0-9]+)\.([0-9]+)_[a-z0-9_]+\.sql$") {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!(
                "Internal failure compiling migrations regex: {}",
                e
            ));
            return MigrationAuditResult {
                total_migrations: 0,
                errors,
                messages,
            };
        }
    };

    let entries = match fs::read_dir(&mig_dir) {
        Ok(e) => e,
        Err(err) => {
            errors.push(format!("Failed to read migrations/ directory: {}", err));
            return MigrationAuditResult {
                total_migrations: 0,
                errors,
                messages,
            };
        }
    };

    let mut sql_files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let filename = match path.file_name().and_then(|s| s.to_str()) {
                Some(f) => f.to_string(),
                None => continue,
            };

            // Reject non-SQL files in migrations/
            if !filename.ends_with(".sql") {
                let err = format!(
                    "Invalid file in migrations/: '{}' (only .sql allowed)",
                    filename
                );
                errors.push(err.clone());
                messages.push(format!("❌ {}", err));
                continue;
            }

            // Validate vX.Y_description.sql convention
            let caps = match file_pattern.captures(&filename) {
                Some(c) => c,
                None => {
                    let err = format!(
                        "Invalid naming in migrations/: '{}' (expected: v<major>.<minor>_<desc>.sql)",
                        filename
                    );
                    errors.push(err.clone());
                    messages.push(format!("❌ {}", err));
                    continue;
                }
            };

            let major: u32 = caps
                .get(1)
                .map(|m| m.as_str().parse().unwrap_or(0))
                .unwrap_or(0);
            let minor: u32 = caps
                .get(2)
                .map(|m| m.as_str().parse().unwrap_or(0))
                .unwrap_or(0);

            // Validate content integrity
            match fs::read_to_string(&path) {
                Ok(content) => {
                    if content.trim().is_empty() {
                        let err = format!("Empty migration detected: {}", filename);
                        errors.push(err.clone());
                        messages.push(format!("❌ {}", err));
                    }

                    // Check for mandatory idempotency (IF NOT EXISTS / IF EXISTS)
                    if let Some(reason) = check_sql_idempotency(&content) {
                        let err = format!("Migration {} {}", filename, reason);
                        errors.push(err.clone());
                        messages.push(format!("❌ {}", err));
                    }
                }
                Err(e) => {
                    let err = format!("Failed to read migration {}: {}", filename, e);
                    errors.push(err.clone());
                    messages.push(format!("❌ {}", err));
                }
            }

            sql_files.push((major, minor, filename));
        }
    }

    // Sort by version
    sql_files.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));

    let total = sql_files.len();
    if errors.is_empty() {
        if total > 0 {
            let last = &sql_files[total - 1].2;
            messages.push(format!(
                "✅ {} SQLx migrations in migrations/ valid and sequential (head: {})",
                total, last
            ));
        } else {
            messages.push("ℹ️ Zero migrations found in migrations/".to_string());
        }
    }

    MigrationAuditResult {
        total_migrations: total,
        errors,
        messages,
    }
}
