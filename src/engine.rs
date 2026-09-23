use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::baseline::Whitelist;
use crate::frontend::audit_frontend_file;
use crate::rule::{Rule, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub snippet: String,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub total_files_scanned: usize,
    pub total_violations: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub total_fixed: usize,
    pub duration: Duration,
    pub violations: Vec<Violation>,
}

pub struct Engine {
    rules: Vec<Rule>,
    compiled_regexes: Vec<Regex>,
    whitelist: Whitelist,
}

impl Engine {
    pub fn new(rules: Vec<Rule>, whitelist: Whitelist) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in &rules {
            let re = Regex::new(&rule.pattern)?;
            compiled.push(re);
        }
        Ok(Self {
            rules,
            compiled_regexes: compiled,
            whitelist,
        })
    }

    pub fn check_scope_isolation(file_paths: &[PathBuf]) -> Option<Violation> {
        let has_hub_files = file_paths.iter().any(|p| {
            let s = p.to_string_lossy();
            s.contains("sumaenimahub") || s.contains("/app/")
        });
        let has_stenio_engine_files = file_paths.iter().any(|p| {
            let s = p.to_string_lossy();
            s.contains("governance/stenio/src/")
        });

        if has_hub_files && has_stenio_engine_files {
            Some(Violation {
                rule_id: "ARCH-SCOPE-ISOLATION".to_string(),
                rule_name: "Violação de Isolamento de Escopo Monorepo".to_string(),
                severity: Severity::Error,
                file_path: "governance/stenio".to_string(),
                line_number: 1,
                snippet: "Diff misto contendo código do App (sumaenimahub/) e motor de governança (governance/stenio/src/)".to_string(),
                message: "Violação de Governança: É proibido alterar código da aplicação e o motor do Stênio no mesmo commit/tarefa.".to_string(),
                suggestion: Some("Isole as tarefas: submeta primeiro a evolução do Stênio em commit isolado, ou desfaça a alteração de governança se o foco for a aplicação.".to_string()),
            })
        } else {
            None
        }
    }

    pub fn scan_directory(
        &self,
        root: &Path,
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
        fast_mode: bool,
        diff_target: Option<&str>,
        auto_fix: bool,
    ) -> Result<ScanReport> {
        let t0 = Instant::now();

        let file_paths = if let Some(diff_spec) = diff_target {
            self.get_diff_files(root, Some(diff_spec))
        } else if fast_mode {
            self.get_changed_files(root)
        } else {
            self.collect_all_files(root)?
        };

        let total_files_scanned = file_paths.len();

        let mut total_fixed = 0;
        if auto_fix {
            total_fixed = self.apply_auto_fixes(&file_paths, tag_filter, only_rule);
        }

        // Processa todos os arquivos em paralelo com Rayon
        let mut violations: Vec<Violation> = file_paths
            .par_iter()
            .flat_map(|path| self.scan_file(path, tag_filter, only_rule))
            .collect();

        // Verificação Automática de Isolamento de Escopo (Single Responsibility Worktree)
        // Impede que uma LLM misture alterações de aplicação com adulterações no motor do Stênio em diffs/commits
        if diff_target.is_some() || fast_mode {
            if let Some(v) = Self::check_scope_isolation(&file_paths) {
                violations.push(v);
            }
        }

        let mut error_count = 0;
        let mut warning_count = 0;
        for v in &violations {
            match v.severity {
                Severity::Error => error_count += 1,
                Severity::Warning => warning_count += 1,
            }
        }

        Ok(ScanReport {
            total_files_scanned,
            total_violations: violations.len(),
            error_count,
            warning_count,
            total_fixed,
            duration: t0.elapsed(),
            violations,
        })
    }

    fn apply_auto_fixes(
        &self,
        paths: &[PathBuf],
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
    ) -> usize {
        let mut fixed_count = 0;
        for path in paths {
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };

            let mut new_content = content.clone();
            let mut file_changed = false;

            for (idx, rule) in self.rules.iter().enumerate() {
                if !rule.matches_filter(tag_filter, only_rule, &ext) {
                    continue;
                }
                let Some(ref replacement) = rule.fix_replacement else {
                    continue;
                };

                let re = &self.compiled_regexes[idx];
                if re.is_match(&new_content) {
                    let replaced = re
                        .replace_all(&new_content, replacement.as_str())
                        .to_string();
                    if replaced != new_content {
                        new_content = replaced;
                        file_changed = true;
                        fixed_count += 1;
                    }
                }
            }

            if file_changed {
                let _ = fs::write(path, new_content);
            }
        }
        fixed_count
    }

    fn collect_all_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let walker = crate::baseline::create_standard_walker(root);

        let mut file_paths = Vec::new();
        for result in walker.build() {
            let entry = result?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                let path = entry.into_path();
                let path_str = path.to_string_lossy();
                if path_str.contains("/target/")
                    || path_str.contains("/node_modules/")
                    || path_str.contains("/.venv/")
                    || path_str.contains("/.git/")
                    || path_str.contains("/llm_model_cache/")
                    || path_str.contains("/dist/")
                    || path_str.contains("/.obsidian/")
                    || path_str.contains("/.smart-env/")
                    || path_str.contains("/fixtures/")
                    || path_str.contains("/archive/")
                    || path_str.ends_with("/rule.rs")
                    || path_str.ends_with("/frontend.rs")
                    || path_str.ends_with("/explain.rs")
                {
                    continue;
                }
                file_paths.push(path);
            }
        }
        Ok(file_paths)
    }

    pub fn get_diff_files(&self, root: &Path, diff_target: Option<&str>) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // 1. Entrada via Stdin (ex: git diff --name-only | stenio --diff -)
        if let Some(target) = diff_target {
            if target == "-" {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                for line in stdin.lock().lines().flatten() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let p = root.join(trimmed);
                        if p.is_file() {
                            files.push(p);
                        }
                    }
                }
                return files;
            }
        }

        // 2. Consulta via git diff
        let mut args = vec!["diff", "--name-only", "--diff-filter=ACMR"];
        let mut custom_rev = None;
        if let Some(target) = diff_target {
            let t = target.trim();
            if t == "staged" || t == "cached" {
                args.push("--cached");
            } else if !t.is_empty() {
                custom_rev = Some(t);
            }
        }
        if let Some(rev) = custom_rev {
            args.push(rev);
        }

        let output = Command::new("git").current_dir(root).args(&args).output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let p = root.join(trimmed);
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
        }

        // Se o diff estiver vazio e não foi passada revisão específica, tenta git status (untracked/staged/modified)
        if files.is_empty()
            && diff_target.map_or(true, |t| t.is_empty() || t == "staged" || t == "cached")
        {
            return self.get_changed_files(root);
        }

        files
    }

    pub fn get_changed_files(&self, root: &Path) -> Vec<PathBuf> {
        let output = Command::new("git")
            .current_dir(root)
            .args(["status", "--porcelain"])
            .output();

        let mut files = Vec::new();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.len() > 3 {
                    let path_part = trimmed[3..].trim();
                    let actual_path = if let Some(idx) = path_part.find("->") {
                        path_part[idx + 2..].trim()
                    } else {
                        path_part
                    };
                    let p = root.join(actual_path);
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
        }
        files
    }

    pub fn scan_file(
        &self,
        path: &Path,
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
    ) -> Vec<Violation> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let path_str = path.to_string_lossy().to_string();
        // Arquivos internos de definição de regras e testes sintéticos do motor do Stênio
        // não devem ser sancionados pelas regras que eles próprios definem e testam
        if path_str.ends_with("/rule.rs")
            || path_str.ends_with("/frontend.rs")
            || path_str.ends_with("/explain.rs")
            || content.contains("fn run_self_tests")
        {
            return Vec::new();
        }
        let mut file_violations = Vec::new();

        // 1. Auditoria especializada de Leis de Frontend
        if (tag_filter.is_none() || tag_filter == Some("frontend"))
            && only_rule.map_or(true, |r| r.starts_with("FRONT-") || r.starts_with("PERF-"))
        {
            let fv = audit_frontend_file(path, &content, &self.whitelist);
            if let Some(target) = only_rule {
                file_violations.extend(
                    fv.into_iter()
                        .filter(|v| v.rule_id.eq_ignore_ascii_case(target)),
                );
            } else {
                file_violations.extend(fv);
            }
        }

        // 2. Auditoria por autômato de regras
        for (idx, rule) in self.rules.iter().enumerate() {
            if !rule.matches_filter(tag_filter, only_rule, &ext) {
                continue;
            }

            // Pula regras com marcador avaliadas exclusivamente por subsistemas dedicados
            if rule.pattern.contains("stenio-") && rule.pattern.contains("-marker") {
                continue;
            }

            // Regras exclusivas de runtime assíncrono do servidor (Axum/Tokio)
            if rule.id == "RUST-STRUCTURED-LOGGING"
                || rule.id == "RUST-ASYNC-BLOCKING-CMD"
                || rule.id == "RUST-NO-SYNC-MUTEX-AWAIT"
                || rule.id == "RUST-SPAWN-ERROR-HANDLING"
                || rule.id == "BACKEND-BLOCKING-IO"
                || rule.id == "BACKEND-NO-PANIC"
            {
                if !path_str.contains("app/server/src/")
                    || path_str.contains("/bin/")
                    || path_str.contains("/tests/")
                    || path_str.ends_with("_test.rs")
                    || path_str.ends_with("_tests.rs")
                {
                    continue;
                }
            }

            // Regras de boas práticas Rust que não se aplicam a testes ou build scripts
            if rule.id == "RUST-NO-UNWRAP"
                || rule.id == "RUST-NO-UNBOUNDED-CHANNEL"
                || rule.id == "RUST-IDIOMATIC-SLICES"
                || rule.id == "RUST-IDIOMATIC-ARC-CLONE"
            {
                if path_str.contains("/tests/")
                    || path_str.ends_with("_test.rs")
                    || path_str.ends_with("_tests.rs")
                    || path_str.contains("/examples/")
                    || path_str.contains("/build.rs")
                {
                    continue;
                }
            }

            if rule.id == "RUST-CANONICAL-REMOTE" {
                if path_str.ends_with("/remote.rs") || path_str.ends_with("/src/remote.rs") {
                    continue;
                }
            }

            if rule.id == "ARCH-NO-PYTHON"
                || rule.id.starts_with("SEC-BAN-")
                || rule.id == "ARCH-BANNED-MODULES"
            {
                if !path_str.contains("sumaenimahub") && !path_str.contains("/app/") {
                    continue;
                }
            }

            let re = &self.compiled_regexes[idx];

            if rule.must_match {
                if !re.is_match(&content) {
                    if !self.whitelist.is_ignored(&path_str, &rule.id, "") {
                        file_violations.push(Violation {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                            file_path: path_str.clone(),
                            line_number: 1,
                            snippet: "".to_string(),
                            message: rule.description.clone(),
                            suggestion: rule.suggestion.clone(),
                        });
                    }
                }
            } else {
                // Fast-reject: se o buffer inteiro não contém o padrão, pula a iteração linha a linha
                if !re.is_match(&content) {
                    continue;
                }

                let mut in_test_scope = false;
                for (line_idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("#[cfg(test)]") || trimmed == "#[test]" {
                        in_test_scope = true;
                    }

                    if re.is_match(line) {
                        // Se for regra exclusiva de código de produção Rust, ignora dentro de escopo de teste
                        if in_test_scope
                            && (rule.id == "RUST-NO-UNWRAP"
                                || rule.id == "BACKEND-NO-PANIC"
                                || rule.id == "RUST-NO-UNBOUNDED-CHANNEL")
                        {
                            continue;
                        }

                        if !self.whitelist.is_ignored(&path_str, &rule.id, line) {
                            file_violations.push(Violation {
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                severity: rule.severity,
                                file_path: path_str.clone(),
                                line_number: line_idx + 1,
                                snippet: line.trim().to_string(),
                                message: rule.description.clone(),
                                suggestion: rule.suggestion.clone(),
                            });
                        }
                    }
                }
            }
        }

        file_violations
    }
}
