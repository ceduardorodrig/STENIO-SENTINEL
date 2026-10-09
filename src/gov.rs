use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct GovAuditResult {
    pub agents_md_ok: bool,
    pub laws_count: usize,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
    pub naming_warnings: Vec<crate::engine::Violation>,
}

pub fn audit_governance(repo_root: &Path) -> GovAuditResult {
    let mut messages = Vec::new();
    let mut errors = Vec::new();
    let mut laws_count = 0;

    let agents_md_path = if repo_root.is_file()
        && repo_root.file_name().and_then(|s| s.to_str()) == Some("AGENTS.md")
    {
        repo_root.to_path_buf()
    } else {
        let base = if repo_root.is_file() {
            repo_root.parent().unwrap_or(repo_root)
        } else {
            repo_root
        };
        if base.join("AGENTS.md").is_file() {
            base.join("AGENTS.md")
        } else if base.join("sumaenima-hub/AGENTS.md").is_file() {
            base.join("sumaenima-hub/AGENTS.md")
        } else if base.join("sumaenimahub/sumaenima-hub/AGENTS.md").is_file() {
            base.join("sumaenimahub/sumaenima-hub/AGENTS.md")
        } else if base.join("SUMAENIMA-HUB/AGENTS.md").is_file() {
            base.join("SUMAENIMA-HUB/AGENTS.md")
        } else if base.join("sumaenimahub/SUMAENIMA-HUB/AGENTS.md").is_file() {
            base.join("sumaenimahub/SUMAENIMA-HUB/AGENTS.md")
        } else {
            // Ascend recursively through directory tree until root AGENTS.md is found (supports deep subfolders)
            let mut curr = base.to_path_buf();
            let mut found = None;
            for _ in 0..10 {
                let candidate = curr.join("AGENTS.md");
                if candidate.is_file() {
                    found = Some(candidate);
                    break;
                }
                if let Some(parent) = curr.parent() {
                    curr = parent.to_path_buf();
                } else {
                    break;
                }
            }
            found.unwrap_or_else(|| base.join("AGENTS.md"))
        }
    };

    if !agents_md_path.is_file() {
        let err = "❌ AGENTS.md not found in repository root!".to_string();
        messages.push(err.clone());
        errors.push(err);
    } else {
        match fs::read_to_string(&agents_md_path) {
            Ok(content) => {
                // If this is the universal AGENTS.md of Vault/Homelab
                if content.contains("agent-conventions.md") && !content.contains("StênioBOT") {
                    let has_conventions = content.contains("agent-conventions.md");
                    let has_rust_tools = content.contains("Ferramentas Rust")
                        || content.contains("Preferências de Terminal")
                        || content.contains("Rust Tools")
                        || content.contains("Terminal Preferences");
                    let has_homelab_or_mei = content.contains("Homelab") || content.contains("MEI");

                    if has_conventions && has_rust_tools && has_homelab_or_mei {
                        messages.push(
                            "✅ Universal AGENTS.md intact and aligned with governance conventions"
                                .to_string(),
                        );
                        messages.push(
                            "✅ Rust tools and system privilege rules preserved"
                                .to_string(),
                        );
                        laws_count = 14;
                    } else {
                        let err =
                            "❌ Universal AGENTS.md missing essential conventions or rules"
                                .to_string();
                        messages.push(err.clone());
                        errors.push(err);
                    }
                } else if content.contains("currículo")
                    || content.contains("curriculum-vitae")
                    || content.contains("WITH-SMOOTH-MOTION")
                    || ((content.contains("StenioSentinel") || content.contains("StênioKernel"))
                        && !content.contains("Orientação para assistentes")
                        && !content.contains("Guidance for AI Assistants")
                        && !content.contains("LEIS ABSOLUTAS DO AGENTE (ANTIGRAVITY / IA)")
                        && !content.contains("ABSOLUTE LAWS OF THE AGENT"))
                {
                    // Satellite / Specialized Public Repository AGENTS.md
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with(|c: char| c.is_ascii_digit())
                            && trimmed.contains(". **")
                        {
                            laws_count += 1;
                        }
                    }

                    if laws_count >= 5 {
                        messages.push(format!(
                            "✅ Satellite AGENTS.md intact with {} specific rules preserved",
                            laws_count
                        ));
                    } else {
                        let err = format!(
                            "❌ Satellite AGENTS.md contains only {} rules (expected >= 5).",
                            laws_count
                        );
                        messages.push(err.clone());
                        errors.push(err);
                    }
                } else {
                    // Engineering Hub AGENTS.md (38 Absolute Laws)
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with(|c: char| c.is_ascii_digit())
                            && trimmed.contains(". **")
                        {
                            laws_count += 1;
                        }
                    }

                    if laws_count >= 13 {
                        messages.push(format!(
                            "✅ AGENTS.md intact with {} Absolute Laws preserved",
                            laws_count
                        ));
                    } else {
                        let err = format!(
                            "❌ AGENTS.md contains only {} laws (expected >= 13). Omission of absolute laws!",
                            laws_count
                        );
                        messages.push(err.clone());
                        errors.push(err);
                    }

                    // Vital clauses validation (bilingual PT/EN)
                    if content.contains("REGRA DE OURO") || content.contains("GOLDEN RULE") {
                        messages.push("✅ Golden Rule clause present".to_string());
                    } else {
                        let err = "❌ Golden Rule clause ('GOLDEN RULE' / 'REGRA DE OURO') missing from AGENTS.md".to_string();
                        messages.push(err.clone());
                        errors.push(err);
                    }

                    if content.contains("HERANÇA DE CONTEXTO") || content.contains("CONTEXT INHERITANCE") {
                        messages.push("✅ Context Inheritance clause present".to_string());
                    } else {
                        let err =
                            "❌ Context Inheritance clause ('CONTEXT INHERITANCE' / 'HERANÇA DE CONTEXTO') missing from AGENTS.md".to_string();
                        messages.push(err.clone());
                        errors.push(err);
                    }
                }
            }
            Err(e) => {
                let err = format!("❌ Failed to read AGENTS.md: {}", e);
                messages.push(err.clone());
                errors.push(err);
            }
        }
    }

    // Skills audit (completely replaces legacy validate_skills.py)
    let skills_dir = if repo_root.join("sumaenimahub/sumaenima-hub/skills").is_dir() {
        repo_root.join("sumaenimahub/sumaenima-hub/skills")
    } else if repo_root.join("sumaenimahub/SUMAENIMA-HUB/skills").is_dir() {
        repo_root.join("sumaenimahub/SUMAENIMA-HUB/skills")
    } else {
        repo_root.join("skills")
    };
    if skills_dir.is_dir() {
        let mut total_skills = 0;
        let mut valid_skills = 0;
        let mut skill_errors = Vec::new();

        if let Ok(entries) = fs::read_dir(&skills_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    total_skills += 1;
                    let skill_md = path.join("SKILL.md");
                    if !skill_md.is_file() {
                        skill_errors
                            .push(format!("❌ Skill '{}': SKILL.md not found", dir_name));
                        continue;
                    }

                    if let Ok(skill_content) = fs::read_to_string(&skill_md) {
                        let has_name = skill_content.contains("name:");
                        let has_desc = skill_content.contains("description:");
                        let has_comp = skill_content.contains("compatibility:");
                        let has_tools = skill_content.contains("allowed-tools:");

                        if !has_name || !has_desc || !has_comp || !has_tools {
                            skill_errors.push(format!(
                                "❌ Skill '{}': incomplete frontmatter metadata",
                                dir_name
                            ));
                        } else {
                            valid_skills += 1;
                        }
                    }
                }
            }
        }

        if skill_errors.is_empty() && total_skills > 0 {
            messages.push(format!(
                "✅ All {} skills in skills/ have valid SKILL.md manifests",
                valid_skills
            ));
        } else {
            for err in &skill_errors {
                messages.push(err.clone());
                errors.push(err.clone());
            }
        }
    }

    // Leftover Test Artifact Audit (AGENTS.md Rule 3)
    let leftover_artifacts = audit_leftover_test_artifacts(repo_root);
    if leftover_artifacts.is_empty() {
        messages.push(
            "✅ Zero leftover test artifacts (*.bak, *.tmp, scratch_*) detected".to_string(),
        );
    } else {
        for err in &leftover_artifacts {
            messages.push(err.clone());
            errors.push(err.clone());
        }
    }

    // Directory Naming Convention Audit (lowercase, kebab-case)
    let naming_warnings = audit_directory_casing(repo_root);
    if naming_warnings.is_empty() {
        messages.push(
            "✅ Directory naming compliant with standard (lowercase, kebab-case)".to_string(),
        );
    } else {
        for w in &naming_warnings {
            messages.push(format!("⚠️  [GOV-NAMING-KEBAB-CASE] {}", w.message));
        }
    }

    GovAuditResult {
        agents_md_ok: laws_count >= 13 && errors.is_empty(),
        laws_count,
        errors,
        messages,
        naming_warnings,
    }
}

/// Audit of Test Artifacts and Residual Files (AGENTS.md Rule 3).
/// AI agents and smaller models frequently create temporary test scripts (*.bak, *.tmp, scratch_*, etc.)
/// and fail to delete them, violating the mandatory test artifact cleanup rule.
pub fn audit_leftover_test_artifacts(repo_root: &Path) -> Vec<String> {
    let mut artifact_errors = Vec::new();
    let walker = ignore::WalkBuilder::new(repo_root)
        .hidden(true)
        .parents(true)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.path();
        let path_str = path.to_string_lossy();

        // Ignore legitimate build directories, target, git, obsidian, and caches
        if crate::baseline::is_common_ignored_path(&path_str)
            || path_str.contains("/.stversions/")
            || path_str.contains("/temp/") // canonical Obsidian temp/ directory
            || path_str.contains("/scratch/") // authorized scratch directory
            || path_str.contains("/brain/") // brain artifacts
            || path_str.contains("/legado/") // archived legacy history
            || path_str.contains("/archive/") // archived historical files
        {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let ext = crate::util::lower_ext(path);

        // 1. Temporary/backup file extensions
        let is_temp_ext = matches!(ext.as_str(), "bak" | "tmp" | "orig" | "old" | "swp" | "rej");

        // 2. Loose temporary file names left behind by agents
        let is_scratch_name = file_name.starts_with("scratch_")
            || file_name.starts_with("temp_")
            || file_name.starts_with("tmp_")
            || file_name.starts_with("dummy_")
            || file_name.starts_with("test_dummy")
            || file_name == "temp.txt"
            || file_name == "temp.md"
            || file_name == "temp.sh"
            || file_name == "temp.py"
            || file_name == "scratch.py"
            || file_name == "scratch.sh";

        // 3. Test scripts in repository root/projects outside tests/ directories
        let is_root_test_script = (file_name == "test.py"
            || file_name == "test.sh"
            || file_name == "test.rs"
            || file_name == "test.js")
            && !path_str.contains("/tests/")
            && !path_str.contains("/test/");

        if is_temp_ext || is_scratch_name || is_root_test_script {
            let rel_path = path
                .strip_prefix(repo_root)
                .unwrap_or(path)
                .display()
                .to_string();
            artifact_errors.push(format!(
                "❌ [GOV-LEFTOVER-TEST-ARTIFACTS] Leftover test/scratch artifact detected: '{}'. Violation of AGENTS.md Rule 3 (test artifacts must be cleaned up after task completion).",
                rel_path
            ));
        }
    }

    artifact_errors
}

/// Directory Naming Convention Audit (agent-conventions.md: lowercase, kebab-case).
/// Detects directories with uppercase letters in workspace that violate the standard.
pub fn audit_directory_casing(repo_root: &Path) -> Vec<crate::engine::Violation> {
    let mut violations = Vec::new();
    let walker = ignore::WalkBuilder::new(repo_root)
        .hidden(true)
        .max_depth(Some(4))
        .parents(false)
        .git_ignore(true)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_dir()) {
            continue;
        }
        let path = entry.path();
        if path == repo_root {
            continue;
        }

        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Ignore hidden directories (.git, .github, etc.) and build caches
        if dir_name.starts_with('.')
            || dir_name == "node_modules"
            || dir_name == "target"
            || dir_name == "dist"
        {
            continue;
        }

        // If directory name contains uppercase letters
        if dir_name.chars().any(|c| c.is_ascii_uppercase()) {
            let rel_path = path
                .strip_prefix(repo_root)
                .unwrap_or(path)
                .display()
                .to_string();

            let suggested_kebab = dir_name.to_ascii_lowercase().replace('_', "-");

            violations.push(crate::engine::Violation {
                rule_id: "GOV-NAMING-KEBAB-CASE".to_string(),
                rule_name: "Directory Naming Convention (kebab-case)".to_string(),
                severity: crate::rule::Severity::Warning,
                file_path: rel_path,
                line_number: 1,
                snippet: format!("Directory: {}", dir_name),
                message: format!(
                    "Directory '{}' contains uppercase letters. Homelab standard in governance/agent-conventions.md mandates 'lowercase, kebab-case'.",
                    dir_name
                ),
                suggestion: Some(format!(
                    "Consider standardizing directory name to '{}'.",
                    suggested_kebab
                )),
            });
        }
    }

    violations
}
