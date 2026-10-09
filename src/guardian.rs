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
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "pdf", "zip", "gz", "xz", "zst", "bz2",
    "7z", "so", "dylib", "dll", "exe", "bin", "o", "a", "rlib", "rmeta", "woff", "woff2", "ttf",
    "otf", "mp3", "mp4", "wav", "ogg", "webm", "lock",
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
        let Some(m) = regex.find(line) else {
            continue;
        };
        let matched = m.as_str();
        // Nothing is being exposed by a documented placeholder (`TEST-xxx`,
        // `CHANGE_ME`, `your_password`). Without this, the wider Markdown branch
        // would flag the `.env` examples that exist precisely to teach the
        // pattern — and a rule that cries wolf gets ignored.
        if is_placeholder_value(matched) {
            continue;
        }
        // Nor by a *reference* to the store: notes legitimately say
        // "senha `GRAFANA_ADMIN_PASSWORD` no store sops" and shell snippets call
        // `sops-decrypt.sh REGISTRY_PASSWORD`. The token after the keyword is
        // then a variable NAME, not the secret — the leak happened already if the
        // name is the value, but that is not what these lines show. We only
        // suppress when the captured text looks like an ALL_CAPS env var name.
        if is_variable_name_reference(matched) {
            continue;
        }
        violations.push(Violation {
            rule_id: "SEC-SECRETS".to_string(),
            rule_name: "Hardcoded Secrets".to_string(),
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

    violations
}

/// True when the matched fragment carries a placeholder rather than a credential.
///
/// Kept deliberately narrow: only well-known sentinels and the `xxx`/`...`
/// ellipsis style used in `docs/` examples. A real secret never looks like
/// `TEST-xxx`, and false positives here are expensive — they erode trust in the
/// gate and end up suppressed.
fn is_placeholder_value(matched: &str) -> bool {
    let lowered = matched.to_ascii_lowercase();
    let sentinels = [
        "change_me",
        "changeme",
        "change-me",
        "your_password",
        "your-password",
        "yourpassword",
        "sua_senha",
        "seu_segredo",
        "placeholder",
        "example",
        "adminpz123",
        "admin123",
        "password123",
        "test-xxx",
        "test_xxx",
        "xxx",
        "<",
        "...",
    ];
    sentinels.iter().any(|s| lowered.contains(s))
}

/// True when the matched fragment captures an environment-variable NAME rather
/// than a value — e.g. `` senha `GRAFANA_ADMIN_PASSWORD` no store sops `` or
/// `sops-decrypt.sh REGISTRY_PASSWORD`.
///
/// Shape test, not a word list: a var name is `[A-Z][A-Z0-9_]*` with at least
/// one underscore and **no lowercase**. Real passwords on these hosts are
/// mixed-case (`HalVeim1235`, `TuVaiMorre`), so they never satisfy it. A password
/// that *is* an all-caps var name would be its own problem, but that is not this
/// case and the false-positive cost is higher.
fn is_variable_name_reference(matched: &str) -> bool {
    // The captured text starts with the keyword (`senha`, `password`, …). Drop
    // everything up to the separator if there is one, otherwise up to the first
    // whitespace/backtick, so only the candidate VALUE is left.
    let after_keyword = if let Some((_, v)) = matched.rsplit_once([':', '=', '|']) {
        v
    } else {
        let klen = matched
            .find(|c: char| c.is_whitespace() || c == '`')
            .unwrap_or(0);
        &matched[klen..]
    };

    let value = after_keyword.trim_matches(|c: char| {
        c.is_whitespace() || c == '`' || c == '*' || c == '_' || c == '"' || c == '\''
    });

    if value.len() < 4 || !value.contains('_') {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Compiles the canonical secret regex once (keeps the sub-millisecond target).
///
/// Two branches, and the second one matters more than it looks:
///
/// 1. **Self-identifying tokens** (`ghp_…`, `sk-…`, PEM headers): unmistakable.
/// 2. **Keyword-anchored values** (`password`, `senha`, `api_key`, …).
///
/// The keyword branch has to cover *prose* and *Markdown tables*, not just
/// `key=value`. This was a real false negative (29/09/2026): the Valheim server
/// password sat in `mnemocine/services/valheim/*.md` as `| **Senha** | \`…\` |`
/// and `**Senha:** \`…\``, and `--scope vault` reported **0 violations** over
/// four occurrences. The vault is Syncthing-mirrored to phones, so that is
/// exactly the leak the rule exists to stop.
///
/// The separator class therefore accepts `:`/`=` **and** Markdown table/bold
/// punctuation, and the value may be wrapped in backticks. The freeform
/// `key=value` floor stays at 16 chars (short values there are usually
/// references like `password=CHANGE_ME`), while an explicit keyword in a
/// declaration gets the lower 8-char floor — a declared password is worth
/// flagging even when short.
fn secret_pattern() -> Option<&'static regex::Regex> {
    static PATTERN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            regex::Regex::new(
                concat!(
                    // 1) Self-identifying credentials.
                    r"ghp_[A-Za-z0-9]{36}",
                    r"|sk-[A-Za-z0-9]{48}",
                    r"|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
                    // 2) Keyword-anchored, `key=value` / `key: value` form.
                    r"|(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|senha)\s*[:=]\s*[\x22']?[A-Za-z0-9_\-]{16,}",
                    // 3) Keyword-anchored in Markdown/prose: `| **Senha** | `x` |`,
                    //    `**Senha:** `x``, `Senha \`x\``. Backticks optional.
                    r"|(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|senha)",
                    r"[\s*_`]*[:=|][\s*_`]*[`\x22']?[A-Za-z0-9_\-]{8,}",
                    // 4) Prose form with an explicit backtick-wrapped value:
                    //    `senha \`x\``. The backticks are what make this safe to
                    //    accept a bare space as the separator.
                    r"|(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|senha)\s+`[A-Za-z0-9_\-]{8,}`",
                ),
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

/// Guardian audits the cryptographic integrity of the Stenio binary and source code.
/// If an AI agent or malicious script attempts to tamper with governance rules,
/// weaken regexes, or disable checks, Guardian immediately flags the tampering.
pub fn audit_stenio_integrity(stenio_src_dir: &Path) -> GuardianReport {
    let mut messages = Vec::new();
    let mut tamper_alerts = Vec::new();
    let mut files_checked = 0;

    // 1. Hash of running executable itself
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("stenio"));
    let mut binary_hash = String::new();
    if let Ok(bytes) = fs::read(&exe_path) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        binary_hash = format!("{:x}", hasher.finalize())[..16].to_string();
        messages.push(format!(
            "🔐 Verified Native Executable: {} (SHA-256: {})",
            exe_path.display(),
            binary_hash
        ));
    }

    // 2. Comprehensive self-audit: each critical module has mandatory anchor strings.
    //    Removal of any anchor immediately triggers a tamper alert.
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
                "SEO-INDEX-METADATA",
                "SEO-ROBOTS-SITEMAP",
                "SEO-FAVICON-SPEC",
                "SEO-IMG-ALT",
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
                "SEC-", // SEC-* rules can never be suppressed by nosemgrep
                "starts_with(\"SEC-\")", // explicit security guard must exist
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
                                    "ℹ️ Modification/removal of '{}' [{}] authorized by human via STENIO_HUMAN_AUTHORIZATION.",
                                    required, module
                                ));
                                continue;
                            }
                        }
                        tamper_alerts.push(format!(
                            "🚨 CRITICAL TAMPER ALERT [{}]: mandatory invariant string '{}' was removed or altered without STENIO_HUMAN_AUTHORIZATION!",
                            module, required
                        ));
                    }
                }

                // Checagem Anti-Tampering: bypass global explícito
                let bypass_count = content.matches("// stenio-ignore-all").count();
                if bypass_count > 0 {
                    tamper_alerts.push(format!(
                        "🚨 SECURITY ALERT [{}]: {} global bypass occurrence(s) detected!",
                        module, bypass_count
                    ));
                }
            }
        } else {
            tamper_alerts.push(format!(
                "🚨 CRITICAL ALERT: core module '{}' was deleted from Stenio source tree!",
                module
            ));
        }
    }

    let is_intact = tamper_alerts.is_empty();
    if is_intact {
        messages.push(format!(
            "🛡️ Guardian: {} Stenio core modules audited with Zero Tampering.",
            files_checked
        ));
    } else {
        messages.push(format!(
            "🚨 Guardian: {} tampering violation(s) detected!",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Builds a throwaway path with a scannable extension.
    fn doc() -> PathBuf {
        PathBuf::from("vault/mnemocine/services/example.md")
    }

    fn flagged(line: &str) -> bool {
        !scan_content_for_secrets(&doc(), line).is_empty()
    }

    /// The regression this suite exists for: the Valheim password sat in
    /// Syncthing-mirrored notes as a Markdown table cell and `--scope vault`
    /// reported **0 violations** over four occurrences (29/09/2026).
    #[test]
    fn detects_markdown_table_password() {
        assert!(flagged("| **Senha** | `HalVeim1235` |"));
        assert!(flagged("| Senha | `HalVeim1235` |"));
    }

    #[test]
    fn detects_bold_and_prose_password() {
        assert!(flagged("**Senha:** `HalVeim1235`"));
        assert!(flagged("3. Senha `TuVaiMorre`."));
        assert!(flagged("4. Conectar → digitar a senha `HalVeim1235`."));
    }

    #[test]
    fn detects_classic_key_value() {
        assert!(flagged("DB_PASSWORD=sup3rS3cretValue!!"));
        assert!(flagged("password: aVeryLongSecretValue123"));
        // Built at compile time so this file contains no literal token that the
        // gate itself would (correctly) flag — same reason `main.rs` marks its
        // fixture. Splitting the prefix breaks the pattern in the source only.
        let github_token = concat!("ghp_", "123456789012345678901234567890123456");
        assert!(flagged(&format!("api_key = {github_token}")));
    }

    /// References to the store are the opposite of a leak — they are the fix.
    #[test]
    fn ignores_store_variable_references() {
        assert!(!flagged("| Senha | `REGISTRY_PASSWORD` no store sops |"));
        assert!(!flagged(
            "**Grafana:** `http://host:3002` (admin, senha `GRAFANA_ADMIN_PASSWORD` no store sops)"
        ));
        assert!(!flagged("$ sops-decrypt.sh REGISTRY_PASSWORD"));
    }

    /// Placeholders exist to teach the pattern; flagging them trains people to
    /// ignore the rule.
    #[test]
    fn ignores_placeholders_and_examples() {
        assert!(!flagged("MERCADOPAGO_ACCESS_TOKEN=TEST-xxx"));
        assert!(!flagged("password: CHANGE_ME"));
        assert!(!flagged("| **Password:** in the sops store (VAR) |"));
        assert!(!flagged("password: \"{{ .Config.password }}\""));
        assert!(!flagged(
            "1. Garantir `ADMINPASSWORD=adminpz123` e `STEAMAPPBRANCH=public`"
        ));
    }

    #[test]
    fn ignores_short_values_in_freeform_assignments() {
        // The 16-char floor on `key=value` stays; only explicit password
        // declarations in prose get the lower floor.
        assert!(!flagged("PASSWORD=short"));
    }

    #[test]
    fn ignores_unrelated_prose() {
        assert!(!flagged("| `/api/auth/logout` | POST |"));
        assert!(!flagged("csrf_token = secrets.token_urlsafe(32)"));
    }
}
