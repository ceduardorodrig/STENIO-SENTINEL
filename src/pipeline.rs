//! The one audit behind every entry point: the command line scan, `--gate`, `--pre-commit check`
//! and the MCP tools ask this module, so they cannot disagree about a tree.

use std::path::{Path, PathBuf};

use crate::backlog::{self, audit_backlog};
use crate::baseline::Whitelist;
use crate::config::SteniocheckConfig;
use crate::cv::audit_curriculum_vitae;
use crate::doc::audit_documentation;
use crate::engine::{self, Engine, ScanReport, Violation};
use crate::gov::audit_governance;
use crate::gpu::audit_gpu_subsystem;
use crate::homelab::audit_homelab;
use crate::infra::{self, audit_compose_dir, audit_infrastructure};
use crate::migrations::audit_migrations;
use crate::rule::{Rule, Severity, get_rules_from_config};
use crate::vault::audit_vault;
use crate::{
    ci, config_schema, dependabot, docrules, dry, entrypoints, frappe, gitfiles, guardian,
    hook_fixtures, hostops, i18n, lockparity, relativize, resolve_scan_target, secrets_suite,
    selectors, shell, should_audit_queues, staged,
};

/// What a caller asks for. Every field left at its default means a full scan of `path`.
#[derive(Default, Clone)]
pub struct Request {
    pub path: PathBuf,
    /// False only when the command line left `--path` at its default.
    pub path_explicit: bool,
    pub scope: Option<String>,
    pub tag: Option<String>,
    pub only: Option<String>,
    pub fast: bool,
    pub diff: Option<String>,
    pub fix: bool,
    pub history: bool,
    pub config: Option<PathBuf>,
    /// The delivery gate: governance, documentation and queue audits in every scope, plus the
    /// duplication detector and the engine integrity check.
    pub gate: bool,
}

pub struct Outcome {
    pub report: ScanReport,
    pub rules_run: usize,
    pub scan_target: PathBuf,
    /// Subsystem narration of the full text report.
    pub sections: Vec<(&'static str, Vec<String>)>,
}

pub struct Prepared {
    pub config: SteniocheckConfig,
    pub config_file: Option<PathBuf>,
    /// The rules of the requested scope.
    pub rules: Vec<Rule>,
    /// Every loaded rule, whatever the scope.
    pub all_rules: Vec<Rule>,
    /// The scope named by the caller or the configuration; empty when auto-detected.
    pub declared_scope: String,
}

/// Loads the configuration and refuses a request the engine cannot honour.
pub fn prepare(req: &Request) -> Result<Prepared, String> {
    if !req.path.exists() {
        return Err(format!("path '{}' does not exist", req.path.display()));
    }
    let (config, config_file) =
        SteniocheckConfig::for_run(&req.path, req.config.as_deref()).map_err(|e| e.to_string())?;
    let mut rules = get_rules_from_config(&config);
    let all_rules = rules.clone();
    let declared_scope = req
        .scope
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| config.general.as_ref().and_then(|g| g.scope.clone()))
        .unwrap_or_default();
    let is = |names: &[&str]| names.iter().any(|n| declared_scope.eq_ignore_ascii_case(n));
    if !declared_scope.is_empty() {
        selectors::check_scope(&declared_scope)?;
    }
    if let Some(tag) = req.tag.as_deref() {
        if is(&["frappe"]) {
            return Err("--tag does not apply to --scope frappe; use --only".to_string());
        }
        selectors::check_tag(tag, &all_rules)?;
    }
    if let Some(only) = req.only.as_deref() {
        selectors::check_only(only, &declared_scope, &all_rules)?;
    }
    // A derived repository (third-party fork) keeps what protects its author; the laws that
    // describe how the author builds their own software do not apply to upstream code.
    if is(&["fork", "derived"]) {
        let kept = [
            "SEC-",
            "VAULT-",
            "DOC-",
            "GOV-LEFTOVER-TEST-ARTIFACTS",
            "HOMELAB-",
            "INFRA-",
        ];
        rules.retain(|r| kept.iter().any(|p| r.id.starts_with(p)));
    }
    // A generated mirror of live configuration: secrets and infrastructure syntax only.
    if is(&["mirror", "snapshot", "generated"]) {
        let kept = ["SEC-", "INFRA-", "GOV-LEFTOVER-TEST-ARTIFACTS"];
        rules.retain(|r| kept.iter().any(|p| r.id.starts_with(p)));
    }
    Ok(Prepared {
        config,
        config_file,
        rules,
        all_rules,
        declared_scope,
    })
}

/// `--scope frappe`: the Frappe rules and the language gate.
fn run_frappe(req: &Request, config: &SteniocheckConfig) -> Result<Vec<Violation>, String> {
    let fc = config.frappe.clone().unwrap_or_default();
    let mut violations = frappe::audit(&req.path, &fc)?;
    violations.extend(docrules::language_findings(&req.path));
    Ok(violations)
}

pub fn run(req: &Request) -> Result<Outcome, String> {
    let prepared = prepare(req)?;
    run_prepared(req, prepared)
}

pub fn run_prepared(req: &Request, prepared: Prepared) -> Result<Outcome, String> {
    let started = std::time::Instant::now();
    // `--diff staged` over a working copy that differs from the index audits the index.
    let staged_request = matches!(
        req.diff.as_deref().map(str::trim),
        Some("staged" | "cached")
    );
    let snapshot = if staged_request {
        staged::snapshot(&req.path)?
    } else {
        None
    };
    if snapshot.is_some() && req.fix {
        return Err("--fix cannot rewrite staged content that differs from the working copy: stage or stash the other changes first".to_string());
    }
    let asked = req;
    let judged = Request {
        path: snapshot
            .as_ref()
            .map_or_else(|| asked.path.clone(), |s| s.map(&asked.path)),
        ..asked.clone()
    };
    let req = &judged;
    let registry = asked.path.join(".steniocheck-whitelist-registry.json");
    let whitelist = Whitelist::load_from_file(&registry, &req.path)?;
    let diagnostics = config_schema::diagnose(prepared.config_file.as_deref());
    // An exemption is stale against the tree the user edits, not against the snapshot.
    let exemption_findings = match &snapshot {
        Some(_) => Whitelist::load_from_file(&registry, &asked.path)?.stale_findings(),
        None => whitelist.stale_findings(),
    };
    let Prepared {
        config,
        rules,
        all_rules,
        declared_scope: scope_opt,
        ..
    } = prepared;
    let explicit_config = req.config.as_deref();
    // Configuration is always the one of the working copy.
    let config_of = |root: &Path| -> Result<SteniocheckConfig, String> {
        let root = snapshot
            .as_ref()
            .map_or_else(|| root.to_path_buf(), |s| s.unmap(root));
        SteniocheckConfig::for_run(&root, explicit_config)
            .map(|(c, _)| c)
            .map_err(|e| e.to_string())
    };

    if scope_opt.eq_ignore_ascii_case("frappe") && !req.gate {
        let mut violations = run_frappe(req, &config)?;
        violations.extend(diagnostics);
        violations.retain(|v| selectors::wanted(v, req.only.as_deref()));
        let mut report = ScanReport {
            total_files_scanned: 0,
            total_files_skipped: 0,
            total_violations: 0,
            error_count: 0,
            warning_count: 0,
            total_fixed: 0,
            duration: started.elapsed(),
            violations,
        };
        report.recount();
        return Ok(Outcome {
            report,
            rules_run: frappe::rule_table().count(),
            scan_target: req.path.clone(),
            sections: Vec::new(),
        });
    }

    let guardian_src = guardian::guardian_src_for_cli(Path::new("."));
    let dry_whitelist = whitelist.clone();
    let diff_target: Option<&str> = req.diff.as_deref();
    let tag_lower = req.tag.as_deref().map(|s| s.to_lowercase());
    let only_rule = req.only.as_deref();
    let p_canon = asked
        .path
        .canonicalize()
        .unwrap_or_else(|_| asked.path.clone());
    let p_str = p_canon.to_string_lossy();
    let scope = if !scope_opt.is_empty() {
        scope_opt.to_lowercase()
    } else {
        if p_str.contains("sumaenima-hub")
            || p_str.contains("SUMAENIMA-HUB")
            || (req.path.join("app").is_dir() && req.path.join("migrations").is_dir())
        {
            "hub".to_string()
        } else if p_str.contains("mnemocine") {
            "homelab".to_string()
        } else if p_str.contains("curriculum-vitae") {
            "cv".to_string()
        } else if p_str.contains("governance/stenio") {
            "rust".to_string()
        } else if p_str.contains("agentic-ai")
            && (p_str.contains("projects")
                || p_str.contains("personal")
                || p_str.contains("temp")
                || p_str.contains("templates")
                || p_str.contains("sumænimá")
                || p_str.contains("assets")
                || p_str.contains("docs"))
        {
            "vault".to_string()
        } else if req.path.join("mnemocine").is_dir() && req.path.join("governance").is_dir() {
            "all".to_string()
        } else {
            "project".to_string()
        }
    };

    let is_hub_active = scope == "all" || scope == "hub";
    let is_homelab_active = scope == "all" || scope == "homelab" || scope == "mnemocine";
    let is_vault_active = scope == "all" || scope == "vault" || scope == "docs";
    let is_cv_active = scope == "all" || scope == "cv";

    // The gate judges governance, documentation and the queues whatever the scope.
    let should_audit_gpu = is_hub_active
        && (tag_lower.as_deref() == Some("gpu") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("GPU-BLOAT-OR-MODEL"))
                .unwrap_or(false));
    let should_audit_gov = req.gate
        || is_hub_active
            && (tag_lower.as_deref() == Some("gov") || tag_lower.is_none())
            && (only_rule.is_none()
                || only_rule
                    .map(|s| s.eq_ignore_ascii_case("GOV-AGENT-LAWS"))
                    .unwrap_or(false));
    let should_audit_doc = (req.gate || is_hub_active || is_homelab_active || is_vault_active)
        && (tag_lower.as_deref() == Some("doc") || tag_lower.is_none())
        && only_rule.is_none_or(|s| s.starts_with("DOC-") || s.contains("BACKLOG-"));
    let should_audit_mig = is_hub_active
        && (tag_lower.as_deref() == Some("db")
            || tag_lower.as_deref() == Some("migrations")
            || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("DB-MIGRATION-INTEGRITY"))
                .unwrap_or(false));

    let hub_default = PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub");
    let scan_target = resolve_scan_target(
        &scope,
        &req.path,
        &p_str,
        if req.path_explicit {
            None
        } else {
            Some(&hub_default)
        },
    );

    let rules_run = rules.len();
    let engine = Engine::new(rules, whitelist).map_err(|e| e.to_string())?;

    // Execute repository scanning and auxiliary subsystems in parallel
    let (
        (scan_res, (gov_res, doc_res)),
        ((gpu_res, mig_res), (((homelab_res, infra_res), vault_res), cv_res)),
    ) = rayon::join(
        || {
            rayon::join(
                || {
                    engine.scan_directory(
                        &scan_target,
                        tag_lower.as_deref(),
                        only_rule,
                        req.fast,
                        diff_target,
                        req.fix,
                    )
                },
                || {
                    let g = if should_audit_gov {
                        Some(audit_governance(&req.path))
                    } else {
                        None
                    };
                    let d = if should_audit_doc {
                        Some(audit_documentation(&req.path))
                    } else {
                        None
                    };
                    (g, d)
                },
            )
        },
        || {
            rayon::join(
                || {
                    let gp = if should_audit_gpu {
                        Some(audit_gpu_subsystem())
                    } else {
                        None
                    };
                    let m = if should_audit_mig {
                        Some(audit_migrations(&req.path))
                    } else {
                        None
                    };
                    (gp, m)
                },
                || {
                    rayon::join(
                        || {
                            // ⚠️ SECURITY FIX (2026-09-29):
                            // `audit_infrastructure` now runs also under the scope
                            // Security infrastructure checks run across homelab, fork, derived, and mirror scopes.
                            // Evaluates: SEC-PLAINTEXT-SECRET, SEC-PRIVATE-KEY-CLEARTEXT, SEC-PERM-LEAK, SEC-SOPS-UNENCRYPTED.
                            let runs_infra_audit = is_homelab_active
                                || scope_opt.eq_ignore_ascii_case("fork")
                                || scope_opt.eq_ignore_ascii_case("derived")
                                || scope_opt.eq_ignore_ascii_case("mirror");

                            let (h, inf) = if is_homelab_active {
                                // Homelab scope audits vault tree AND host compose mirror (/mnt/BACKUP/configs-homelab).
                                let mut infra = audit_infrastructure(&req.path, true);
                                let mirror = Path::new("/mnt/BACKUP/configs-homelab");
                                if req.path.join("mnemocine").is_dir() && mirror.is_dir() {
                                    // The mirror holds the real composes, so it must be
                                    // governed by the vault's data file, not the fallback.
                                    let gpu_consumers = infra::load_gpu_consumers(&req.path);
                                    let mirror_report = audit_compose_dir(mirror, &gpu_consumers);
                                    infra.total_files_scanned += mirror_report.total_files_scanned;
                                    infra.violations.extend(mirror_report.violations);
                                    infra.messages.extend(mirror_report.messages);
                                }
                                (Some(audit_homelab(&req.path)), Some(infra))
                            } else if runs_infra_audit {
                                // Runs infrastructure security audits without homelab-specific documentation constraints.
                                (None, Some(audit_infrastructure(&req.path, false)))
                            } else {
                                (None, None)
                            };
                            let v = if is_vault_active {
                                Some(audit_vault(&req.path))
                            } else {
                                None
                            };
                            ((h, inf), v)
                        },
                        || {
                            if is_cv_active {
                                Some(audit_curriculum_vitae(&req.path))
                            } else {
                                None
                            }
                        },
                    )
                },
            )
        },
    );

    let mut report = match scan_res {
        Ok(report) => report,
        Err(e) => match e.downcast_ref::<engine::ScanRefused>() {
            Some(refused) => return Err(refused.0.clone()),
            None => return Err(e.to_string()),
        },
    };

    // ── Opt-in git history scan (--history) ────────────────────────────────
    if req.history {
        match guardian::scan_git_history(&asked.path) {
            Ok(mut found) => {
                selectors::retain_tag(&mut found, tag_lower.as_deref(), &all_rules);
                report.violations.extend(found);
            }
            Err(e) => return Err(format!("--history: {e}")),
        }
    }

    // ── Governance Subsystem (AGENTS.md & skills) ──────────────────────────
    let mut gov_messages = Vec::new();
    if let Some(gov) = gov_res {
        gov_messages = gov.messages;
        if !gov.errors.is_empty() {
            for err in gov.errors {
                report.violations.push(engine::Violation {
                    rule_id: "GOV-AGENT-LAWS".to_string(),
                    rule_name: "Governance & Agent Laws".to_string(),
                    severity: Severity::Error,
                    file_path: "AGENTS.md".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: err,
                    suggestion: Some(
                        "Maintain the Absolute Laws and Golden Rule in AGENTS.md.".to_string(),
                    ),
                });
            }
        }
        for mut warn in gov.naming_warnings {
            warn.severity = Severity::Warning;
            report.violations.push(warn);
        }
    }

    // ── Documentation Subsystem (docs/ & ADRs) ─────────────────────────────
    let mut doc_messages = Vec::new();
    if let Some(doc) = doc_res {
        doc_messages = doc.messages;
        report.violations.extend(doc.violations);
    }

    // ── Document rules (src/docrules/) ─────────────────────────────────────
    if scope != "mirror" && docrules::applies(&req.path, tag_lower.as_deref(), only_rule) {
        report
            .violations
            .extend(docrules::audit(&req.path, tag_lower.as_deref(), only_rule));
    }

    // ── Linked queues under the vault scope, and a queue file named by --path ──
    // The homelab subsystem already audits the linked queues; `--scope vault` alone did not, so a
    // stale `pending:` link (GB-252) or a foreign row (GB-251) was invisible there.
    let mut queue_findings = Vec::new();
    if should_audit_queues(
        is_vault_active || req.gate,
        is_homelab_active,
        tag_lower.as_deref(),
    ) {
        queue_findings.extend(audit_backlog(&req.path).violations);
    }
    if req.path.is_file() && tag_lower.as_deref().is_none_or(|t| t == "doc") {
        queue_findings.extend(backlog::integrity::audit_file(&req.path));
    }
    report.violations.extend(queue_findings);

    // ── Harness entry points (AGENT-ENTRYPOINT-RULES, GB-033) ──────────────
    let should_audit_entrypoints = (is_vault_active || is_homelab_active)
        && (tag_lower.is_none() || tag_lower.as_deref() == Some("agent"))
        && only_rule.map(entrypoints::owns).unwrap_or(true);
    if should_audit_entrypoints {
        let ep = entrypoints::audit(&req.path);
        doc_messages.extend(ep.messages);
        report.violations.extend(ep.violations);
    }

    // ── Host and operations lints (`stenio hostops`) ───────────────────────
    let hostops_only = only_rule.filter(|r| hostops::is_lint_rule(r));
    if hostops_only.is_some() || (is_homelab_active && tag_lower.is_none() && only_rule.is_none()) {
        let (messages, found) = hostops::audit(&req.path, hostops_only);
        doc_messages.extend(messages);
        report.violations.extend(found);
    }

    // ── Agent hook fixtures (AGENT-HOOK-FIXTURES-IN-PIPELINE, GB-275) ──────
    let should_audit_hook_fixtures = (is_vault_active || is_homelab_active)
        && (tag_lower.is_none() || tag_lower.as_deref() == Some("agent"))
        && only_rule
            .map(|s| s.eq_ignore_ascii_case(hook_fixtures::RULE_ID))
            .unwrap_or(true);
    if should_audit_hook_fixtures {
        let hf = hook_fixtures::audit(&req.path);
        doc_messages.extend(hf.messages);
        for mut v in hf.violations {
            v.severity = Severity::Warning;
            report.violations.push(v);
        }
    }

    // ── Secret and environment gates (src/secrets_suite) ──────────────────
    let suite = secrets_suite::Selection {
        scope: &scope_opt,
        tag: tag_lower.as_deref(),
        only_rule,
    };
    report
        .violations
        .extend(secrets_suite::audit(&req.path, &suite));

    // ── Gettext catalogues (locale/*.po and the sources next to them) ──────
    let should_audit_i18n = (tag_lower.as_deref() == Some("i18n") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case(i18n::RULE_ID))
                .unwrap_or(false));
    if should_audit_i18n {
        for mut v in i18n::audit_gettext(&req.path).violations {
            v.severity = Severity::Error;
            report.violations.push(v);
        }
    }

    // ── Dependabot lockfile coverage (DEPENDABOT-LOCKFILE-COVERAGE, GB-264) ─
    let should_audit_dependabot = (tag_lower.as_deref() == Some("deps") || tag_lower.is_none())
        && only_rule
            .map(|s| s.eq_ignore_ascii_case(dependabot::RULE_ID))
            .unwrap_or(true);
    if should_audit_dependabot {
        // The path the user passed wins; the scope's resolved target only helps when `--path`
        // is a parent folder of the repository (hub scope).
        let dep_root = dependabot::repo_root(&req.path, &scan_target);
        let dep = dependabot::audit(dep_root, &config_of(dep_root)?);
        doc_messages.extend(dep.messages);
        report.violations.extend(dep.violations);
    }

    // ── Shell scripts (GB-212/221/222/224/248/249) and lockfile parity (GB-070) ──
    let repo_ids: Vec<&str> = shell::IDS
        .into_iter()
        .chain([lockparity::RULE_ID])
        .collect();
    let wants = |r: &str| only_rule.is_none_or(|o| o.eq_ignore_ascii_case(r));
    if tag_lower.as_deref().is_none_or(|t| t == "shell") && repo_ids.iter().any(|r| wants(r)) {
        let repo = dependabot::repo_root(&req.path, &scan_target);
        let mut found = shell::audit(repo);
        found.extend(lockparity::audit(repo));
        if let Some(base) = diff_target {
            let changed = match gitfiles::changed(repo, base) {
                Ok(files) => files,
                Err(e) => return Err(e),
            };
            found.retain(|v| {
                changed.iter().any(|c| {
                    let name = c.strip_prefix(repo).unwrap_or(c);
                    Path::new(&v.file_path).ends_with(name)
                })
            });
        }
        report.violations.extend(found);
    }

    // ── CI workflow rules (CI-STEP-STENIO-PARITY GB-262, CI-RUST-COMPILE-ON-DEPENDENCY-PR GB-272, CI-RULE-SCOPE-NEVER-INVOKED GB-283)
    let should_audit_ci = (tag_lower.as_deref() == Some("ci") || tag_lower.is_none())
        && only_rule
            .map(|s| {
                s.eq_ignore_ascii_case(ci::PARITY_ID)
                    || s.eq_ignore_ascii_case(ci::COMPILE_ID)
                    || s.eq_ignore_ascii_case(ci::SCOPE_ID)
                    || s.eq_ignore_ascii_case(ci::TAG_FAIL_ID)
                    || s.eq_ignore_ascii_case(ci::LOG_EN_ID)
            })
            .unwrap_or(true);
    if should_audit_ci {
        let ci_root = dependabot::repo_root(&req.path, &scan_target);
        let found = ci::audit(ci_root, &config_of(ci_root)?);
        doc_messages.extend(found.messages);
        for mut v in found.violations {
            v.severity = Severity::Warning;
            report.violations.push(v);
        }
    }

    // ── GPU & AI Models Subsystem (RTX / NVMe) ────────────────────────────
    let mut gpu_messages = Vec::new();
    if let Some(gpu) = gpu_res {
        gpu_messages = gpu.messages;
        if !gpu.errors.is_empty() {
            for gpu_err in gpu.errors {
                report.violations.push(engine::Violation {
                    rule_id: "GPU-BLOAT-OR-MODEL".to_string(),
                    rule_name: "GPU & AI Models Integrity".to_string(),
                    severity: Severity::Error,
                    file_path: "llm_model_cache".to_string(),
                    line_number: 1,
                    snippet: "".to_string(),
                    message: gpu_err,
                    suggestion: Some("Check GGML file in /mnt/NVME_PCI/homelab/sumaenimahub/llm_model_cache/whisper-ggml/.".to_string()),
                });
            }
        }
    }

    // ── Database & Migrations Subsystem (migrations/) ─────────────────────
    let mut mig_messages = Vec::new();
    if let Some(mig) = mig_res {
        mig_messages = mig.messages;
        for err in &mig.errors {
            report.violations.push(Violation {
                rule_id: "DB-IDEMPOTENT-MIGRATION".to_string(),
                rule_name: "Non-Idempotent SQL Migration".to_string(),
                severity: Severity::Error,
                file_path: "migrations/".to_string(),
                line_number: 1,
                snippet: err.clone(),
                message: err.clone(),
                suggestion: Some(
                    "Use 'IF NOT EXISTS' in CREATE TABLE/INDEX or 'IF EXISTS' in DROP TABLE/INDEX."
                        .to_string(),
                ),
            });
        }
    }

    // ── Homelab Subsystem (mnemocine/) ────────────────────────────────────
    let mut homelab_messages = Vec::new();
    if let Some(hl) = homelab_res {
        report.total_files_scanned += hl.total_files_scanned;
        homelab_messages = hl.messages;
        let mut found = hl.violations;
        selectors::retain_tag(&mut found, tag_lower.as_deref(), &all_rules);
        report.violations.extend(found);
    }

    // ── Infrastructure Subsystem (Compose, Systemd, SOPS) ─────────────────
    if let Some(inf) = infra_res {
        report.total_files_scanned += inf.total_files_scanned;
        for msg in inf.messages {
            homelab_messages.push(msg);
        }
        let mut found = inf.violations;
        selectors::retain_tag(&mut found, tag_lower.as_deref(), &all_rules);
        report.violations.extend(found);
    }

    // ── Obsidian Vault Subsystem (Universal Governance) ───────────────────
    let mut vault_messages = Vec::new();
    if let Some(vl) = vault_res {
        report.total_files_scanned += vl.total_files_scanned;
        vault_messages = vl.messages;
        let mut found = vl.violations;
        selectors::retain_tag(&mut found, tag_lower.as_deref(), &all_rules);
        report.violations.extend(found);
    }

    // ── Bilingual Curriculum Vitae Subsystem (curriculum-vitae/) ──────────
    let mut cv_messages = Vec::new();
    if let Some(cv) = cv_res {
        report.total_files_scanned += cv.total_files_scanned;
        cv_messages = cv.messages;
        let mut found = cv.violations;
        selectors::retain_tag(&mut found, tag_lower.as_deref(), &all_rules);
        report.violations.extend(found);
    }

    report
        .violations
        .retain(|v| selectors::wanted(v, only_rule));
    report.recount();

    if req.gate {
        let integrity = guardian::audit_stenio_integrity(&guardian_src);
        for alert in integrity.tamper_alerts {
            report.violations.push(Violation {
                rule_id: "GUARDIAN-TAMPER".to_string(),
                rule_name: "Engine Integrity".to_string(),
                severity: Severity::Error,
                file_path: "stenio".to_string(),
                line_number: 1,
                snippet: String::new(),
                message: alert,
                suggestion: Some("Restore the engine sources and rebuild.".to_string()),
            });
        }
        let (found, _, _) = dry::scan_dry_directory(&req.path, 6, &dry_whitelist);
        report.violations.extend(found);
    }
    report.violations.extend(diagnostics);
    report.violations.extend(exemption_findings);
    // Two audits may report the same defect (the queue audit of the vault and of the homelab).
    let mut seen = std::collections::HashSet::new();
    report.violations.retain(|v| {
        seen.insert((
            v.rule_id.clone(),
            v.file_path.clone(),
            v.line_number,
            v.message.clone(),
        ))
    });
    report.recount();
    for v in &mut report.violations {
        v.file_path = relativize(&v.file_path, &scan_target);
        if let Some(s) = &snapshot {
            v.file_path = s.restore(&v.file_path);
            v.message = s.restore(&v.message);
        }
    }

    let mut sections = Vec::new();
    for (shown, title, messages) in [
        (
            should_audit_gov,
            "Governance Subsystem & Agent Laws",
            gov_messages,
        ),
        (
            should_audit_doc,
            "Documentation & Traceability Subsystem",
            doc_messages,
        ),
        (should_audit_gpu, "GPU & AI Models Subsystem", gpu_messages),
        (
            should_audit_mig,
            "Database & Migrations Subsystem (SQLx)",
            mig_messages,
        ),
        (
            is_homelab_active && !homelab_messages.is_empty(),
            "Mnemocine Homelab Subsystem (Infrastructure)",
            homelab_messages,
        ),
        (
            is_vault_active && !vault_messages.is_empty(),
            "Obsidian Vault & Universal Governance Subsystem",
            vault_messages,
        ),
        (
            is_cv_active && !cv_messages.is_empty(),
            "Bilingual Curriculum Vitae Subsystem (curriculum-vitae/)",
            cv_messages,
        ),
    ] {
        if shown {
            sections.push((title, messages));
        }
    }
    let scan_target = match &snapshot {
        Some(s) => {
            for (_, messages) in &mut sections {
                for message in messages.iter_mut() {
                    *message = s.restore(message);
                }
            }
            s.unmap(&scan_target)
        }
        None => scan_target,
    };
    Ok(Outcome {
        report,
        rules_run,
        scan_target,
        sections,
    })
}

/// One line per finding that rejects a delivery, as the gate prints it.
pub fn blockers(findings: &[Violation]) -> Vec<String> {
    findings
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .map(|v| {
            format!(
                "[{}] {}:{}: {} (💡 {})",
                v.rule_id,
                v.file_path,
                v.line_number,
                v.message,
                v.suggestion.as_deref().unwrap_or("See --explain")
            )
        })
        .collect()
}
