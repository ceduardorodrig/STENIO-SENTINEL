use crate::config::{CustomRuleConfig, SteniocheckConfig};
use anyhow::{Context, Result, bail};
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
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

#[derive(Serialize)]
struct LearnedRules {
    custom_rules: Vec<CustomRuleConfig>,
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
    let severity = match payload.severity.map(|s| s.to_lowercase()) {
        Some(s) if s == "warn" => "warning".to_string(),
        Some(s) => s,
        None => "error".to_string(),
    };
    let tag = payload.tag.unwrap_or_else(|| "custom".to_string());
    let extensions = payload
        .extensions
        .or(payload.file_extensions)
        .unwrap_or_else(|| vec!["ts".to_string(), "tsx".to_string(), "rs".to_string()]);
    let extensions_fmt = extensions.join(", ");

    // 2. The current file must parse before anything is added to it
    let toml_path = repo_root.join(crate::config::FILE_NAME);
    if !toml_path.is_file() {
        bail!(
            "Configuration file steniocheck.toml not found in {:?}",
            repo_root
        );
    }
    let current = SteniocheckConfig::load_from_file(&toml_path)?;
    if current
        .custom_rules
        .iter()
        .flatten()
        .any(|r| r.id.eq_ignore_ascii_case(&id))
    {
        bail!("Rule with ID '{}' already exists in steniocheck.toml!", id);
    }

    // 3. Serialization by the TOML library, then a parse of the whole new file
    let block = LearnedRules {
        custom_rules: vec![CustomRuleConfig {
            id: id.clone(),
            tag: Some(tag.clone()),
            severity: Some(severity.clone()),
            name: name.clone(),
            description: description.clone(),
            pattern: payload.pattern.clone(),
            extensions,
            must_match: Some(payload.must_match.unwrap_or(false)),
            suggestion: payload.suggestion,
            fix_replacement: payload.fix_replacement,
            path_include: payload.path_include,
            path_exclude: payload.path_exclude,
        }],
    };
    let entry = toml::to_string(&block).context("Failed to serialize the learned rule")?;
    let mut next = fs::read_to_string(&toml_path)?;
    if !next.ends_with('\n') {
        next.push('\n');
    }
    next.push('\n');
    next.push_str(&entry);
    if let Err(cause) = SteniocheckConfig::parse(&next) {
        bail!("the new rule would break steniocheck.toml, nothing was written: {cause}");
    }

    // 4. Atomic persistence: temporary file beside the target, then rename
    let temp = repo_root.join(format!(".steniocheck.toml.{}.tmp", std::process::id()));
    let permissions = fs::metadata(&toml_path)?.permissions();
    if permissions.readonly() {
        bail!("steniocheck.toml is read-only, nothing was written");
    }
    let target = fs::canonicalize(&toml_path)?;
    let written = fs::write(&temp, &next)
        .and_then(|()| fs::set_permissions(&temp, permissions))
        .and_then(|()| fs::rename(&temp, &target));
    if let Err(e) = written {
        let _ = fs::remove_file(&temp);
        return Err(e).context("Failed to write learned rule into steniocheck.toml");
    }

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
