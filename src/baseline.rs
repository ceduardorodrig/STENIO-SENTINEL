use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct Whitelist {
    ignored_patterns: HashSet<String>,
}

impl Whitelist {
    pub fn load_from_file(path: &Path) -> Self {
        let mut ignored_patterns = HashSet::new();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = val.as_object() {
                        for (file_key, _) in obj {
                            ignored_patterns.insert(file_key.clone());
                        }
                    }
                }
            }
        }
        Self { ignored_patterns }
    }

    pub fn is_ignored(&self, file_path: &str, rule_id: &str, line_content: &str) -> bool {
        // Regras Canônicas Invioláveis: NUNCA podem ser ignoradas por comentário inline,
        // nem por IAs, nem por humanos. Tentativas de supressão são rejeitadas.
        let is_inviolable = rule_id.starts_with("SEC-")
            || rule_id.starts_with("AGENT-")
            || rule_id.starts_with("ARCH-")
            || rule_id.starts_with("RUST-")
            || rule_id.starts_with("CONF-")
            || rule_id == "TEST-NO-SILENT-SKIP";

        if is_inviolable {
            return false;
        }

        // 1. Suporte a comentário inline com regra específica: # stenio-ignore: RULE_ID
        // NOTA DE SEGURANÇA: 'stenio-ignore: all' é expressamente PROIBIDO e não tem efeito.
        if line_content.contains("# stenio-ignore") || line_content.contains("// stenio-ignore") {
            // Proibição estrita de bypass global 'all'
            if line_content.contains("stenio-ignore: all")
                || line_content.contains("stenio-ignore:all")
            {
                return false;
            }
            if line_content.contains(rule_id) {
                return true;
            }
        }

        // 2. nosemgrep: compatível com semgrep CLI (apenas regras específicas não-críticas)
        if line_content.contains("# nosemgrep") || line_content.contains("// nosemgrep") {
            if let Some(after) = line_content.split("nosemgrep").nth(1) {
                let trimmed_after = after.trim();
                if trimmed_after.is_empty() || !trimmed_after.starts_with(':') {
                    // nosemgrep genérico é proibido para evitar supressão cega por IAs
                    return false;
                }
                // nosemgrep: RULE_ID — ignora apenas se rule_id bater
                if trimmed_after.contains(rule_id) {
                    return true;
                }
                return false;
            }
            return false;
        }

        // 3. Checa whitelist de arquivo (.steniocheck-whitelist-registry.json)
        for pattern in &self.ignored_patterns {
            if file_path.contains(pattern) {
                return true;
            }
        }

        false
    }
}

pub fn print_banner(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!("{}", title.cyan().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
}

pub fn print_banner_with_badge(title: &str, badge: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
    println!("{} {}", title.cyan().bold(), badge.yellow());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .cyan()
            .bold()
    );
}

pub fn print_banner_green(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .green()
            .bold()
    );
    println!("{}", title.green().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .green()
            .bold()
    );
}

pub fn print_banner_red(title: &str) {
    use colored::*;
    println!();
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .red()
            .bold()
    );
    println!("{}", title.red().bold());
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════════════════"
            .red()
            .bold()
    );
}

pub fn parse_tags_file(tags_file: &Path) -> HashSet<String> {
    let mut valid_tags = HashSet::new();
    if tags_file.is_file() {
        if let Ok(content) = fs::read_to_string(tags_file) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("- `#") || trimmed.starts_with("- `") {
                    if let Some(first_tick) = trimmed.find('`') {
                        if let Some(second_tick) = trimmed[first_tick + 1..].find('`') {
                            let tag_clean = trimmed[first_tick + 1..first_tick + 1 + second_tick]
                                .trim_start_matches('#')
                                .trim();
                            if !tag_clean.is_empty() {
                                valid_tags.insert(tag_clean.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    valid_tags
}

pub fn is_common_ignored_path(path_str: &str) -> bool {
    path_str.contains("/target/")
        || path_str.contains("/node_modules/")
        || path_str.contains("/.venv/")
        || path_str.contains("/.git/")
        || path_str.contains("/dist/")
        || path_str.contains("/.obsidian/")
        || path_str.contains("/dependencies/")
        || path_str.contains("/archive/")
        || path_str.contains("/cold-storage/")
}

pub fn build_file_walker(root: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    let mut walker = ignore::WalkBuilder::new(root);
    walker.hidden(true).git_ignore(true);
    walker.build().flatten().filter_map(|entry| {
        if entry.file_type().map_or(false, |ft| ft.is_file()) {
            Some(entry.into_path())
        } else {
            None
        }
    })
}

pub fn create_standard_walker(root: &Path) -> ignore::WalkBuilder {
    let mut walker = ignore::WalkBuilder::new(root);
    walker
        .hidden(true)
        .parents(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true);
    walker
}
