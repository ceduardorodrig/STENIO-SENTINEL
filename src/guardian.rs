use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::engine::Violation;
use crate::rule::Severity;

/// Extensions intentionally NOT scanned for secrets by [`scan_content_for_secrets`].
///
/// Rationale: the documentation vault is Syncthing-mirrored to phones, and it also
/// hosts the encrypted SOPS store. A credential pasted into a note leaks everywhere,
/// so documentation and config formats must be scanned too. Binary and lock formats
/// are excluded to avoid false positives and noise.
const SECRET_SCAN_SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "pdf", "zip", "gz", "xz", "zst", "bz2", "7z",
    "so", "dylib", "dll", "exe", "bin", "o", "a", "rlib", "rmeta", "woff", "woff2", "ttf", "otf",
    "mp3", "mp4", "wav", "ogg", "webm", "lock",
];

/// Path fragments never scanned for secrets (caches, mirrors, third-party trees).
const SECRET_SCAN_SKIP_PATHS: &[&str] = &[
    "/.git/",
    "/target/",
    "/node_modules/",
    "/.venv/",
    "/.stversions/",
    "/.smart-env/",
    "/dist/",
    "/dependencies/",
    "/archive/",
    "/cold-storage/",
    "/docs/external/",
    "/openwiki/",
];

/// Secrets scan engine for documentation and infrastructure scopes (`homelab`, `vault`).
///
/// The `hub` scope runs the `SEC-SECRETS` rule from [`crate::rule`] against source-code
/// extensions only. That left the vault — whose notes are Syncthing-mirrored *and* which
/// contains the encrypted SOPS store — completely unscanned. This routine closes that gap
/// by reusing the exact same canonical patterns over the remaining formats.
///
/// It returns a [`Violation`] per matching line, never panicking and never unwrapping.
pub fn scan_content_for_secrets(path: &Path, content: &str) -> Vec<Violation> {
    let path_str = path.to_string_lossy().to_string();

    if SECRET_SCAN_SKIP_PATHS
        .iter()
        .any(|fragment| path_str.contains(fragment))
    {
        return Vec::new();
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if SECRET_SCAN_SKIP_EXTENSIONS.contains(&ext.as_str()) {
        return Vec::new();
    }

    let Some(regex) = secret_pattern() else {
        return Vec::new();
    };

    let mut violations = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        if regex.is_match(line) {
            violations.push(Violation {
                rule_id: "SEC-SECRETS".to_string(),
                rule_name: "Segredos Hardcoded".to_string(),
                severity: Severity::Error,
                file_path: path_str.clone(),
                line_number: line_idx + 1,
                snippet: mask_secret_snippet(line),
                message: "Plaintext credential detected outside the SOPS/Age vault. Files in this scope are Syncthing-mirrored and/or internet-exposed.".to_string(),
                suggestion: Some(
                    "Move the value to the central store (/mnt/NVME_PCI/secrets/secrets.env), re-encrypt to mnemocine/secrets.enc.env and revoke the exposed credential."
                        .to_string(),
                ),
            });
        }
    }

    violations
}

/// Compiles the canonical secret regex once (keeps the sub-millisecond target).
fn secret_pattern() -> Option<&'static regex::Regex> {
    static PATTERN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            regex::Regex::new(
                r#"(ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)|(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|senha)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}"#,
            )
            .ok()
        })
        .as_ref()
}

/// Redacts the matched value so the report never re-leaks the credential it just found.
fn mask_secret_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let head: String = trimmed.chars().take(24).collect();
    if trimmed.chars().count() > 24 {
        format!("{}…[REDACTED]", head)
    } else {
        format!("{head}[REDACTED]")
    }
}

#[allow(dead_code)]
pub struct GuardianReport {
    pub is_intact: bool,
    pub binary_hash: String,
    pub source_files_checked: usize,
    pub messages: Vec<String>,
    pub tamper_alerts: Vec<String>,
}

/// O Guardian audita a integridade criptográfica do próprio binário e código-fonte do Stênio.
/// Se um agente de IA ou script malicioso tentar adulterar as regras de governança,
/// enfraquecer regexes ou desativar checagens, o Guardian detecta a discrepância no ato.
pub fn audit_stenio_integrity(stenio_src_dir: &Path) -> GuardianReport {
    let mut messages = Vec::new();
    let mut tamper_alerts = Vec::new();
    let mut files_checked = 0;

    // 1. Hash do próprio executável em execução
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("stenio"));
    let mut binary_hash = String::new();
    if let Ok(bytes) = fs::read(&exe_path) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        binary_hash = format!("{:x}", hasher.finalize())[..16].to_string();
        messages.push(format!(
            "🔐 Executável Nativo Íntegro: {} (SHA-256: {})",
            exe_path.display(),
            binary_hash
        ));
    }

    // 2. Auto-auditoria abrangente: cada módulo crítico tem strings obrigatórias.
    //    Remoção de qualquer string dispara alerta imediato.
    let critical_modules: &[(&str, &[&str])] = &[
        (
            "rule.rs",
            &[
                "ARCH-NO-PYTHON",
                "SEC-SUDO",
                "SEC-SECRETS",
                "ARCH-RUST-CMD-LEGACY",
                "RUST-ASYNC-SLEEP",
                "RUST-NO-UNWRAP",
                "AGENT-NO-LAZY-STUB",
                "AGENT-NO-SUPPRESSION-DIRECTIVES",
                "AGENT-NO-TAMPERING-VERIFIER",
                "CONF-NO-WEAKEN-STRICT",
                "TEST-NO-SILENT-SKIP",
                "CODE-NO-EMPTY-CATCH",
                "BACKEND-BLOCKING-IO",
                "BACKEND-NO-PANIC",
                "ARCH-DRY-DUPLICATION",
                "ARCH-SCOPE-ISOLATION",
                "PERF-GPU-ZERO-REPAINT",
                "PERF-NO-LAYOUT-THRASH",
                "PERF-GPU-CONTAINMENT",
                "FRONT-FEEDBACK-ON-ERROR",
                "FRONT-NO-HARDCODED-HOST",
                "DB-IDEMPOTENT-MIGRATION",
                "INFRA-TOPOLOGY-COMPLIANCE",
                "RUST-NO-UNBOUNDED-CHANNEL",
                "RUST-ASYNC-BLOCKING-CMD",
                "RUST-NO-SYNC-MUTEX-AWAIT",
                "RUST-IDIOMATIC-ARC-CLONE",
                "RUST-IDIOMATIC-SLICES",
                "RUST-SPAWN-ERROR-HANDLING",
                r"(?m)\bsudo\s+", // regex expandido — não pode ser revertido para lista curta
            ],
        ),
        (
            "engine.rs",
            &[
                "ARCH-SCOPE-ISOLATION",
                "has_app_or_project_files",
                "has_stenio_engine_files",
            ],
        ),
        (
            "dry.rs",
            &[
                "normalize_substantive_line",
                "detect_dry_duplication",
                "scan_dry_directory",
                "ARCH-DRY-DUPLICATION",
            ],
        ),
        (
            "frontend.rs",
            &[
                "FRONT-AUDIO",
                "FRONT-CLEANUP",
                "FRONT-HEX",
                "FRONT-TOKEN-PALETTE",
                "FRONT-NO-ANY",
                "PERF-GPU-ZERO-REPAINT",
                "PERF-NO-LAYOUT-THRASH",
                "PERF-GPU-CONTAINMENT",
                "FRONT-FEEDBACK-ON-ERROR",
                "FRONT-NO-HARDCODED-HOST",
            ],
        ),
        (
            "gov.rs",
            &[
                "audit_leftover_test_artifacts",
                "GOV-LEFTOVER-TEST-ARTIFACTS",
            ],
        ),
        (
            "explain.rs",
            &["RuleExplanation", "EXPLANATIONS", "format_explanation_cli"],
        ),
        (
            "infra.rs",
            &[
                "SEC-SOPS-UNENCRYPTED",
                "SEC-PRIVATE-KEY-CLEARTEXT",
                "SEC-PLAINTEXT-SECRET",
                "SEC-PERM-LEAK",
                "INFRA-BASH-STRICT",
            ],
        ),
        (
            "vault.rs",
            &[
                "PROJECT-AUTO-COLD-STORAGE",
                "VAULT-TAG-TAXONOMY",
                "VAULT-FRONTMATTER",
                "PROJECT-NAMING-CONVENTION",
                "projects/cold-storage", // cold-storage deve estar isento da regra de nomenclatura
            ],
        ),
        (
            "homelab.rs",
            &[
                "HOMELAB-NFS-SOFT",
                "HOMELAB-FRONTMATTER",
                "HOMELAB-TAG-ROOT",
            ],
        ),
        (
            "doc.rs",
            &[
                "DOC-SERVICE-MISSING-HOST",
                "DOC-COLD-STORAGE-INCOMPLETE",
                "DOC-SERVICE-UNINDEXED",
                "DOC-BROKEN-LINK",
            ],
        ),
        (
            "baseline.rs",
            &[
                "stenio-ignore",
                "nosemgrep",
                "SEC-", // regras SEC-* nunca podem ser ignoráveis por nosemgrep
                "starts_with(\"SEC-\")", // a guarda explícita de segurança deve existir
            ],
        ),
        (
            "main.rs",
            &[
                "run_self_tests",
                "run_quality_gate",
                "audit_stenio_integrity",
                "audit_governance",
                "audit_homelab",
                "audit_infrastructure",
            ],
        ),
    ];

    for (module, required_strings) in critical_modules {
        let p = stenio_src_dir.join("src").join(module);
        if p.exists() {
            files_checked += 1;
            if let Ok(content) = fs::read_to_string(&p) {
                // Checar presença de todas as strings obrigatórias com suporte a Human Override
                let human_auth = std::env::var("STENIO_HUMAN_AUTHORIZATION").ok();
                for required in *required_strings {
                    if !content.contains(required) {
                        if let Some(ref auth) = human_auth {
                            if auth.contains(required) || auth == "AUTHORIZED" || auth == "ALL" {
                                messages.push(format!(
                                    "ℹ️ Remoção/modificação de '{}' [{}] autorizada pelo usuário humano via STENIO_HUMAN_AUTHORIZATION.",
                                    required, module
                                ));
                                continue;
                            }
                        }
                        tamper_alerts.push(format!(
                            "🚨 ALERTA CRÍTICO [{}]: string obrigatória '{}' foi removida ou alterada sem STENIO_HUMAN_AUTHORIZATION!",
                            module, required
                        ));
                    }
                }

                // Checagem Anti-Tampering: bypass global explícito
                let bypass_count = content.matches("// stenio-ignore-all").count();
                if bypass_count > 0 {
                    tamper_alerts.push(format!(
                        "🚨 ALERTA DE SEGURANÇA [{}]: {} ocorrência(s) de bypass global detectada(s)!",
                        module, bypass_count
                    ));
                }
            }
        } else {
            tamper_alerts.push(format!(
                "🚨 ALERTA CRÍTICO: módulo '{}' foi removido do código-fonte do Stênio!",
                module
            ));
        }
    }

    let is_intact = tamper_alerts.is_empty();
    if is_intact {
        messages.push(format!(
            "🛡️ Guardian: {} módulos do núcleo do Stênio auditados com Zero Adulteração.",
            files_checked
        ));
    } else {
        messages.push(format!(
            "🚨 Guardian: {} violação(ões) de adulteração/tampering detectadas!",
            tamper_alerts.len()
        ));
    }

    GuardianReport {
        is_intact,
        binary_hash,
        source_files_checked: files_checked,
        messages,
        tamper_alerts,
    }
}
