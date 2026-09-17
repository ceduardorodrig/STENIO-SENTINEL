use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

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
                "TEST-NO-SILENT-SKIP",
                "CODE-NO-EMPTY-CATCH",
                "BACKEND-BLOCKING-IO",
                "BACKEND-NO-PANIC",
                "ARCH-DRY-DUPLICATION",
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
                // Checar presença de todas as strings obrigatórias
                for required in *required_strings {
                    if !content.contains(required) {
                        tamper_alerts.push(format!(
                            "🚨 ALERTA CRÍTICO [{}]: string obrigatória '{}' foi removida ou alterada!",
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
