use anyhow::Result;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::baseline::Whitelist;
use crate::config::{FILE_NAME, SteniocheckConfig};
use crate::frontend::audit_frontend_file;
use crate::rule::{Rule, Severity};
use crate::testscope::TestLines;

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
    /// Files a rule should have judged and could not read.
    pub total_files_skipped: usize,
    pub total_violations: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub total_fixed: usize,
    pub duration: Duration,
    pub violations: Vec<Violation>,
}

impl ScanReport {
    /// The counters are derived from the findings, never kept by hand.
    pub fn recount(&mut self) {
        self.total_violations = self.violations.len();
        self.error_count = self
            .violations
            .iter()
            .filter(|v| v.severity == Severity::Error)
            .count();
        self.warning_count = self.total_violations - self.error_count;
    }
}

pub const UNREADABLE_ID: &str = "SCAN-FILE-UNREADABLE";
pub const FIX_FAILED_ID: &str = "SCAN-FIX-NOT-WRITTEN";
const CONFIG_INVALID_ID: &str = "SCAN-CONFIG-INVALID";

/// The file selection could not be built (Git failed): the run judged nothing.
#[derive(Debug)]
pub struct ScanRefused(pub String);

impl std::fmt::Display for ScanRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScanRefused {}

fn engine_finding(
    rule_id: &str,
    rule_name: &str,
    path: &str,
    message: String,
    suggestion: &str,
) -> Violation {
    Violation {
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        severity: Severity::Error,
        file_path: path.to_string(),
        line_number: 1,
        snippet: String::new(),
        message,
        suggestion: Some(suggestion.to_string()),
    }
}

/// The path below the scanned tree, so that the folders above it exempt nothing.
fn below<'a>(root: &Path, path: &'a Path) -> &'a Path {
    path.strip_prefix(root).unwrap_or(path)
}

fn has_component(path: &Path, names: &[&str]) -> bool {
    path.parent().is_some_and(|dir| {
        dir.components()
            .any(|c| names.iter().any(|n| c.as_os_str() == *n))
    })
}

/// Build output, dependencies and caches: nobody authors these, no rule reads them.
fn is_generated_path(root: &Path, path: &Path) -> bool {
    has_component(
        below(root, path),
        &[
            "target",
            "node_modules",
            ".venv",
            ".git",
            "dist",
            ".obsidian",
            "dependencies",
            "llm_model_cache",
            ".smart-env",
        ],
    )
}

/// True inside the checkout of this engine, identified by its package manifest.
fn in_engine_tree(path: &Path) -> bool {
    let absolute = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    absolute.ancestors().skip(1).any(|dir| {
        fs::read_to_string(dir.join("Cargo.toml")).is_ok_and(|manifest| {
            manifest
                .lines()
                .any(|l| l.trim() == "name = \"stenio-sentinel\"")
        })
    })
}

/// Files where only credential rules apply: fixtures and archives anywhere, and in the engine
/// checkout the sources that define and test the rules. A name or a line of content exempts
/// nothing in any other repository.
fn secrets_only(root: &Path, path: &Path, content: &str) -> bool {
    if has_component(below(root, path), &["fixtures", "archive", "cold-storage"]) {
        return true;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let rule_source = matches!(name, "rule.rs" | "frontend.rs" | "explain.rs")
        || content.contains("fn run_self_tests")
        || path.components().any(|c| c.as_os_str() == "fixtures");
    rule_source && in_engine_tree(path)
}

pub struct Engine {
    rules: Vec<Rule>,
    compiled_regexes: Vec<Regex>,
    compiled_requires: Vec<Option<Regex>>,
    whitelist: Whitelist,
}

impl Engine {
    pub fn new(rules: Vec<Rule>, whitelist: Whitelist) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        let mut compiled_requires = Vec::with_capacity(rules.len());
        for rule in &rules {
            let re = Regex::new(&rule.pattern)?;
            compiled.push(re);
            compiled_requires.push(match &rule.requires_pattern {
                Some(p) => Some(Regex::new(p)?),
                None => None,
            });
        }
        Ok(Self {
            rules,
            compiled_regexes: compiled,
            compiled_requires,
            whitelist,
        })
    }

    pub fn check_scope_isolation(file_paths: &[PathBuf]) -> Option<Violation> {
        let has_stenio_engine_files = file_paths.iter().any(|p| {
            let s = p.to_string_lossy();
            s.contains("governance/stenio/src/")
        });
        let has_app_or_project_files = file_paths.iter().any(|p| {
            let s = p.to_string_lossy();
            !s.contains("governance/stenio/")
        });

        if has_stenio_engine_files && has_app_or_project_files {
            Some(Violation {
                rule_id: "ARCH-SCOPE-ISOLATION".to_string(),
                rule_name: "Monorepo Scope Isolation Violation".to_string(),
                severity: Severity::Error,
                file_path: "governance/stenio".to_string(),
                line_number: 1,
                snippet: "Mixed diff containing application/project code and governance engine code (governance/stenio/src/)".to_string(),
                message: "Governance Violation: Modifying application/project code and the Stenio engine in the same commit/task is strictly forbidden.".to_string(),
                suggestion: Some("Isolate tasks: submit engine modifications in an isolated commit, or revert governance changes if the focus is application code.".to_string()),
            })
        } else {
            None
        }
    }

    pub fn check_mirror_mutation(file_paths: &[PathBuf]) -> Option<Violation> {
        for p in file_paths {
            let s = p.to_string_lossy();
            if s.contains("/configs-homelab/")
                || s.contains("/mnt/BACKUP/")
                || s.contains("configs-homelab")
            {
                return Some(Violation {
                    rule_id: "ARCH-NO-EDIT-MIRROR".to_string(),
                    rule_name: "Prohibited Direct Modification of Automated Backup Mirror".to_string(),
                    severity: Severity::Error,
                    file_path: s.to_string(),
                    line_number: 1,
                    snippet: s.to_string(),
                    message: "Governance Violation: Direct modification of automated backup mirror files (/mnt/BACKUP/) is strictly forbidden.".to_string(),
                    suggestion: Some("Revert all changes in the backup mirror. Log into the source host via SSH to apply changes at the root source, then let config-backup mirror them to the NAS.".to_string()),
                });
            }
        }
        None
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

        let selected = diff_target.is_some() || fast_mode;
        let file_paths = if let Some(diff_spec) = diff_target {
            crate::gitfiles::changed(root, diff_spec).map_err(ScanRefused)?
        } else if fast_mode {
            crate::gitfiles::changed(root, "").map_err(ScanRefused)?
        } else {
            self.collect_all_files(root)?
        };

        let mut total_fixed = 0;
        let mut fix_failures = Vec::new();
        if auto_fix {
            (total_fixed, fix_failures) =
                self.apply_auto_fixes(root, &file_paths, tag_filter, only_rule);
        }

        // A full scan adds the dot files, for the credential rules only; a changed dot file
        // is selected by Git and judged like any other changed file.
        let dot_files = if selected {
            Vec::new()
        } else {
            let walked: std::collections::HashSet<&PathBuf> = file_paths.iter().collect();
            crate::hidden::files(root, |p| is_generated_path(root, p))
                .map_err(ScanRefused)?
                .into_iter()
                .filter(|p| !walked.contains(p))
                .collect::<Vec<_>>()
        };

        // Process all files in parallel with Rayon
        let mut violations: Vec<Violation> = file_paths
            .par_iter()
            .flat_map(|path| self.scan_file(root, path, tag_filter, only_rule))
            .chain(
                dot_files
                    .par_iter()
                    .flat_map(|path| self.scan_as(root, path, tag_filter, only_rule, true)),
            )
            .collect();
        let total_files_skipped = violations
            .iter()
            .filter(|v| v.rule_id == UNREADABLE_ID)
            .count();
        let total_files_scanned = file_paths.len() + dot_files.len() - total_files_skipped;
        violations.extend(fix_failures);

        // Automatic Scope Isolation Check (Single Responsibility Worktree)
        // Prevents an LLM from mixing application changes with Stenio engine modifications in diffs/commits
        if diff_target.is_some() || fast_mode {
            if let Some(v) = Self::check_scope_isolation(&file_paths) {
                violations.push(v);
            }
            if let Some(v) = Self::check_mirror_mutation(&file_paths) {
                violations.push(v);
            }
        }

        let mut report = ScanReport {
            total_files_scanned,
            total_files_skipped,
            total_violations: 0,
            error_count: 0,
            warning_count: 0,
            total_fixed,
            duration: t0.elapsed(),
            violations,
        };
        report.recount();
        Ok(report)
    }

    /// Applies the fixes and counts only those whose new content reached the disk; every file
    /// that could not be rewritten is a finding.
    fn apply_auto_fixes(
        &self,
        root: &Path,
        paths: &[PathBuf],
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
    ) -> (usize, Vec<Violation>) {
        let mut fixed_count = 0;
        let mut failures = Vec::new();
        for path in paths {
            let path_str = path.to_string_lossy();
            if path_str.contains("/configs-homelab/")
                || path_str.contains("/mnt/BACKUP/")
                || path_str.contains("configs-homelab")
            {
                continue;
            }

            let ext = crate::util::lower_ext(path);

            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            if secrets_only(root, path, &content) {
                continue;
            }

            let mut new_content = content.clone();
            let mut file_fixes = 0;

            for (idx, rule) in self.rules.iter().enumerate() {
                if !rule.matches_filter(tag_filter, only_rule, &ext) || !rule.covers_path(&path_str)
                {
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
                        file_fixes += 1;
                    }
                }
            }

            if file_fixes == 0 {
                continue;
            }
            let written = fs::write(path, &new_content).and_then(|()| fs::read_to_string(path));
            match written {
                Ok(on_disk) if on_disk == new_content => fixed_count += file_fixes,
                other => {
                    let cause = match other {
                        Err(e) => e.to_string(),
                        Ok(_) => "the content on disk differs from what was written".to_string(),
                    };
                    failures.push(engine_finding(
                        FIX_FAILED_ID,
                        "Auto-fix Not Written",
                        &path_str,
                        format!("--fix could not rewrite this file: {cause}"),
                        "Make the file writable, or fix it by hand.",
                    ));
                }
            }
        }
        (fixed_count, failures)
    }

    fn collect_all_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let walker = crate::baseline::create_standard_walker(root);

        let mut file_paths = Vec::new();
        for result in walker.build() {
            let entry = result?;
            if entry.file_type().map_or(false, |ft| ft.is_file()) {
                let path = entry.into_path();
                if !is_generated_path(root, &path) {
                    file_paths.push(path);
                }
            }
        }
        Ok(file_paths)
    }

    pub fn scan_file(
        &self,
        root: &Path,
        path: &Path,
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
    ) -> Vec<Violation> {
        self.scan_as(root, path, tag_filter, only_rule, false)
    }

    /// `credentials_only` is how a full scan judges the dot files.
    fn scan_as(
        &self,
        root: &Path,
        path: &Path,
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
        credentials_only: bool,
    ) -> Vec<Violation> {
        let ext = crate::rule::effective_extension(path);
        let path_str = path.to_string_lossy().to_string();

        let dot_file = crate::hidden::is_hidden(root, path);
        // `prod.env` and `.env` alike (GB-401): the key-name heuristic judges every walked one.
        let dotenv = crate::guardian::is_env_like_name(
            &path.file_name().unwrap_or_default().to_string_lossy(),
        );
        let read = if credentials_only {
            match crate::hidden::read_text(path) {
                Ok(Some(text)) => Ok(text),
                Ok(None) => return Vec::new(),
                Err(e) => Err(e),
            }
        } else {
            fs::read_to_string(path)
        };
        let content = match read {
            Ok(c) => c,
            Err(e) => {
                // A file no active rule reads (an image, a binary) is not a gap.
                let judged = credentials_only
                    || self
                        .rules
                        .iter()
                        .any(|r| r.matches_filter(tag_filter, only_rule, &ext));
                if !judged {
                    return Vec::new();
                }
                return vec![engine_finding(
                    UNREADABLE_ID,
                    "File Skipped: Not Read",
                    &path_str,
                    format!("not judged: it could not be read as UTF-8 text: {e}"),
                    "Save it as UTF-8, make it readable, or exclude it with .gitignore if it is not source.",
                )];
            }
        };

        let restricted = credentials_only || secrets_only(root, path, &content);
        let test_lines = std::cell::OnceCell::new();
        let mut file_violations = Vec::new();

        // Directory rules read the nearest configuration: every one of them must parse.
        if !restricted && path.file_name().is_some_and(|n| n == FILE_NAME) {
            if let Err(cause) = SteniocheckConfig::parse(&content) {
                file_violations.push(engine_finding(
                    CONFIG_INVALID_ID,
                    "Configuration Not Readable",
                    &path_str,
                    format!("configuration error: {cause}"),
                    "Fix the file: an unreadable configuration switches its rules off.",
                ));
            }
        }

        // 1. Specialized Frontend and SEO Rules Audit
        if !restricted
            && (tag_filter.is_none() || tag_filter == Some("frontend") || tag_filter == Some("seo"))
            && only_rule.map_or(true, |r| {
                r.starts_with("FRONT-") || r.starts_with("PERF-") || r.starts_with("SEO-")
            })
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

        let plaintext = crate::hidden::PLAINTEXT_ID;
        if dotenv
            && tag_filter.is_none_or(|t| t == "sec")
            && only_rule.is_none_or(|r| r.eq_ignore_ascii_case(plaintext))
        {
            file_violations.extend(
                crate::hidden::dotenv_findings(path, &content)
                    .into_iter()
                    .filter(|v| {
                        let line = content.lines().nth(v.line_number - 1).unwrap_or("");
                        !self.whitelist.is_ignored(&path_str, plaintext, line)
                    }),
            );
        }

        // 2. Rule Automaton Audit
        for (idx, rule) in self.rules.iter().enumerate() {
            // A credential in a dot file counts whatever its extension.
            let judged_as = match rule.file_extensions.first() {
                Some(any) if dot_file && rule.id.starts_with("SEC-SECRET") => any.as_str(),
                _ => ext.as_str(),
            };
            if !rule.matches_filter(tag_filter, only_rule, judged_as) {
                continue;
            }

            if !rule.covers_path(&path_str) {
                continue;
            }

            // Fixtures, archives and the engine rule sources: only credentials are judged.
            if restricted && !rule.id.starts_with("SEC-SECRET") {
                continue;
            }

            // Skip marked rules evaluated exclusively by dedicated subsystems
            if rule.pattern.contains("stenio-") && rule.pattern.contains("-marker") {
                continue;
            }

            // A rule over declared targets is inert until something declares them.
            if rule.declared_targets.as_ref().is_some_and(Vec::is_empty) {
                continue;
            }

            // Server async runtime rules (Axum/Tokio)
            if rule.id == "RUST-STRUCTURED-LOGGING"
                || rule.id == "RUST-ASYNC-BLOCKING-CMD"
                || rule.id == "RUST-NO-SYNC-MUTEX-AWAIT"
                || rule.id == "RUST-SPAWN-ERROR-HANDLING"
                || rule.id == "BACKEND-BLOCKING-IO"
                || rule.id == "BACKEND-NO-PANIC"
                || rule.id == "BACKEND-NO-HARDCODED-TEXT"
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

            // Rust best-practice rules that do not apply to tests or build scripts
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

            if rule.id == "ARCH-BANNED-MODULES" {
                if !path_str.contains("sumaenima-hub")
                    && !path_str.contains("SUMAENIMA-HUB")
                    && !path_str.contains("/app/")
                {
                    continue;
                }
            }

            let re = &self.compiled_regexes[idx];

            // Optional context: `RUST-ASYNC-SLEEP` is Error only in truly
            // async files; in sync code it remains Warning (visible without blocking).
            // Without configured requires-context, severity defaults to rule's standard severity.
            let severity = match (&self.compiled_requires[idx], rule.severity_without_requires) {
                (Some(req), without) => {
                    if req.is_match(&content) {
                        rule.severity
                    } else {
                        match without {
                            Some(s) => s,
                            None => continue,
                        }
                    }
                }
                _ => rule.severity,
            };

            if rule.must_match {
                if !re.is_match(&content) {
                    if !self.whitelist.is_ignored(&path_str, &rule.id, "") {
                        file_violations.push(Violation {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity,
                            file_path: path_str.clone(),
                            line_number: 1,
                            snippet: "".to_string(),
                            message: rule.description.clone(),
                            suggestion: rule.suggestion.clone(),
                        });
                    }
                }
            } else {
                // Fast-reject: if the entire buffer does not contain the pattern, skip line-by-line iteration
                if !re.is_match(&content) {
                    continue;
                }

                // Rules exclusive to production Rust code skip the items marked as test code.
                let production_only = matches!(
                    rule.id.as_str(),
                    "RUST-NO-UNWRAP"
                        | "BACKEND-NO-PANIC"
                        | "BACKEND-NO-HARDCODED-TEXT"
                        | "RUST-NO-UNBOUNDED-CHANNEL"
                );
                for (line_idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();

                    if re.is_match(line) {
                        if rule.declared_targets.is_some()
                            && !re
                                .captures(line)
                                .and_then(|c| c.name("target"))
                                .is_some_and(|t| rule.names_undeclared(t.as_str()))
                        {
                            continue;
                        }

                        // Skip pure comments for hardcoded text rules
                        if rule.id == "BACKEND-NO-HARDCODED-TEXT"
                            && (trimmed.starts_with("//")
                                || trimmed.starts_with("/*")
                                || trimmed.starts_with("*"))
                        {
                            continue;
                        }

                        if production_only
                            && test_lines
                                .get_or_init(|| TestLines::of(&content))
                                .contains(line_idx + 1)
                        {
                            continue;
                        }

                        // GB-287: the rule's regex only preselects lines; the wide comment detector
                        // decides, and every comment it flags is an ERROR.
                        let mut severity = severity;
                        if rule.id == "CODE-NO-PORTUGUESE-COMMENTS" {
                            let comment_opt = crate::comments::extract_comment(&ext, line);
                            match comment_opt.and_then(crate::comments::portuguese_severity) {
                                Some(sev) => severity = sev,
                                None => continue,
                            }
                        }

                        if !self.whitelist.is_ignored(&path_str, &rule.id, line) {
                            file_violations.push(Violation {
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                severity,
                                file_path: path_str.clone(),
                                line_number: line_idx + 1,
                                // No line of a dotenv file is printed: it may hold a value.
                                snippet: if dotenv || rule.id.starts_with("SEC-SECRET") {
                                    crate::infra::mask_snippet(line)
                                } else {
                                    line.trim().to_string()
                                },
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
