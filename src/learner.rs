use anyhow::{Context, Result, bail};
use colored::*;
use regex::Regex;
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct LearnPayload {
    pub id: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub message: Option<String>,
    pub pattern: String,
    pub extensions: Option<Vec<String>>,
    pub file_extensions: Option<Vec<String>>,
    pub severity: Option<String>,
    pub tag: Option<String>,
    pub must_match: Option<bool>,
    pub suggestion: Option<String>,
    pub fix_replacement: Option<String>,
    pub path_include: Option<Vec<String>>,
    pub path_exclude: Option<Vec<String>>,
}

pub fn handle_learn(repo_root: &Path, raw_payload: &str) -> Result<()> {
    let payload: LearnPayload = serde_json::from_str(raw_payload)
        .context("Failed to parse learn JSON payload. Expected format: '{\"id\":\"...\", \"pattern\":\"...\", \"extensions\":[\"...\"]}'")?;

    // 1. Regex validation
    if let Err(err) = Regex::new(&payload.pattern) {
        bail!("Invalid Regex pattern ('{}'): {}", payload.pattern, err);
    }

    let id = payload
        .id
        .unwrap_or_else(|| format!("CUSTOM-{}", chrono::Utc::now().timestamp_millis()));
    let name = payload.name.unwrap_or_else(|| id.clone());
    let description = payload
        .description
        .or(payload.message)
        .unwrap_or_else(|| format!("Violation detected by learned rule {}", id));
    let severity = payload
        .severity
        .map(|s| s.to_lowercase())
        .filter(|s| s == "warning" || s == "warn")
        .map(|_| "warning".to_string())
        .unwrap_or_else(|| "error".to_string());
    let tag = payload.tag.unwrap_or_else(|| "custom".to_string());
    let extensions = payload
        .extensions
        .or(payload.file_extensions)
        .unwrap_or_else(|| vec!["ts".to_string(), "tsx".to_string(), "rs".to_string()]);
    let must_match = payload.must_match.unwrap_or(false);
    let suggestion = payload.suggestion;

    // 2. Read and verify duplicates in steniocheck.toml
    let toml_path = repo_root.join("steniocheck.toml");
    if !toml_path.is_file() {
        bail!(
            "Configuration file steniocheck.toml not found in {:?}",
            repo_root
        );
    }

    let current_content = fs::read_to_string(&toml_path)?;
    let id_marker = format!("id = \"{}\"", id);
    if current_content.contains(&id_marker) {
        bail!("Rule with ID '{}' already exists in steniocheck.toml!", id);
    }

    // 3. TOML block formatting
    let extensions_fmt = extensions
        .iter()
        .map(|e| format!("\"{}\"", e))
        .collect::<Vec<_>>()
        .join(", ");

    // Safe escaping for TOML string
    let escaped_pattern = payload.pattern.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_desc = description.replace('\\', "\\\\").replace('"', "\\\"");
    let escaped_name = name.replace('\\', "\\\\").replace('"', "\\\"");
    let suggestion_line = match &suggestion {
        Some(s) => format!(
            "suggestion = \"{}\"\n",
            s.replace('\\', "\\\\").replace('"', "\\\"")
        ),
        None => "".to_string(),
    };
    let fix_line = match &payload.fix_replacement {
        Some(f) => format!(
            "fix_replacement = \"{}\"\n",
            f.replace('\\', "\\\\").replace('"', "\\\"")
        ),
        None => "".to_string(),
    };
    let path_inc_line = match &payload.path_include {
        Some(inc) => {
            let list = inc
                .iter()
                .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(", ");
            format!("path_include = [{}]\n", list)
        }
        None => "".to_string(),
    };
    let path_exc_line = match &payload.path_exclude {
        Some(exc) => {
            let list = exc
                .iter()
                .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(", ");
            format!("path_exclude = [{}]\n", list)
        }
        None => "".to_string(),
    };

    let toml_entry = format!(
        "\n[[custom_rules]]\nid = \"{}\"\ntag = \"{}\"\nseverity = \"{}\"\nname = \"{}\"\ndescription = \"{}\"\npattern = \"{}\"\nextensions = [{}]\nmust_match = {}\n{}{}{}{}",
        id,
        tag,
        severity,
        escaped_name,
        escaped_desc,
        escaped_pattern,
        extensions_fmt,
        must_match,
        suggestion_line,
        fix_line,
        path_inc_line,
        path_exc_line
    );

    // 4. Atomic persistence / append
    let mut file = OpenOptions::new()
        .create(false)
        .append(true)
        .open(&toml_path)
        .context("Failed to open steniocheck.toml for writing")?;

    file.write_all(toml_entry.as_bytes())
        .context("Failed to write learned rule into steniocheck.toml")?;

    crate::baseline::print_banner_green(&format!(
        "✨ StenioKernel — New Rule Learned Successfully! [{}]",
        id
    ));
    println!("   {} {}", "ID:          ".dimmed(), id.cyan().bold());
    println!("   {} {}", "Name:        ".dimmed(), name.bold());
    println!("   {} {}", "Tag:         ".dimmed(), tag.yellow());
    println!(
        "   {} {}",
        "Severity:    ".dimmed(),
        if severity == "error" {
            severity.red().bold()
        } else {
            severity.yellow().bold()
        }
    );
    println!(
        "   {} {}",
        "Pattern:     ".dimmed(),
        payload.pattern.magenta()
    );
    println!("   {} [{}]", "Extensions:  ".dimmed(), extensions_fmt);
    println!("   {} {}", "Description: ".dimmed(), description);
    println!();
    println!(
        "ℹ️ Rule persisted to {} and active immediately.",
        "steniocheck.toml".bold()
    );
    println!();

    Ok(())
}
