use ignore::WalkBuilder;
use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct InfraReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

/// Redacts the matched value so the report never re-leaks the credential it found.
fn mask_snippet(line: &str) -> String {
    let trimmed = line.trim();
    let head: String = trimmed.chars().take(28).collect();
    if trimmed.chars().count() > 28 {
        format!("{head}…[REDACTED]")
    } else {
        format!("{head}[REDACTED]")
    }
}

/// Distinguishes a real credential from prose that merely mentions one.
///
/// Documentation frequently shows illustrative values ("Garantir
/// `ADMINPASSWORD=adminpz123` em ...") or lists variable names as a concept.
/// Those are not leaks: nothing is being exposed. Real leaks have random-looking
/// values; examples are short, dictionary-like, or match a well-known demo
/// value. This keeps the rule actionable instead of training everyone to
/// ignore it.
fn is_documentation_example(line: &str, value: &str) -> bool {
    // Prose markers around the assignment (bullets in guides, "definir X em ...",
    // backticked inline examples).
    let prose_markers = [
        "Garantir",
        "definir",
        "ex.:",
        "exemplo",
        "Exemplo",
        "por exemplo",
    ];
    if prose_markers.iter().any(|m| line.contains(m)) {
        return true;
    }
    if line
        .trim_start()
        .starts_with(['1', '2', '3', '4', '5', '6', '7', '8', '9'])
        && line.contains(". ")
    {
        // numbered list item in a guide, e.g. "1. Garantir ..."
        return true;
    }

    // Well-known demo values used in docs.
    let demo_values = [
        "adminpz123",
        "password123",
        "secret123",
        "admin123",
        "changeme123",
        "example123",
        "test1234",
        "mysecret",
        "supersecret",
        "sua_senha",
        "seu_segredo",
        "yourpassword",
    ];
    let lowered = value.to_ascii_lowercase();
    if demo_values.iter().any(|d| lowered == *d) {
        return true;
    }

    // Very short or purely alphabetic values are almost always words in prose,
    // not generated credentials (which mix case, digits and symbols).
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value.chars().any(|c| !c.is_alphanumeric());
    let all_lower_alpha = value.chars().all(|c| c.is_ascii_lowercase());
    value.len() < 12 && !has_symbol && (!has_digit || all_lower_alpha)
}

/// Detects whether a path belongs to an automated backup mirror (e.g. `/mnt/BACKUP/configs-homelab/`).
/// Returns `Some((host_name, relative_path_on_host))` if matched.
fn parse_mirror_path(path_str: &str) -> Option<(&str, &str)> {
    if let Some(idx) = path_str.find("configs-homelab/") {
        let after = &path_str[idx + "configs-homelab/".len()..];
        let mut parts = after.splitn(2, '/');
        let host = parts.next()?;
        let rel_path = parts.next().unwrap_or(after);
        Some((host, rel_path))
    } else {
        None
    }
}

/// One structural finding for a compose service, as
/// `(rule_id, rule_name, severity, message, suggestion)`.
type ComposeFinding = (&'static str, &'static str, Severity, String, Option<String>);

/// Builds a Compose structural [`Violation`] with the fields shared by every
/// rule in `check_compose_file` (`severity`, `file_path`, `line_number: 1`,
/// `snippet`, `message`, `suggestion`). Centralizing the struct literal keeps
/// the three call sites DRY (ARCH-DRY-DUPLICATION).
fn compose_violation(
    rule_id: &str,
    rule_name: &str,
    severity: Severity,
    file_path: &str,
    snippet: &str,
    message: String,
    suggestion: Option<String>,
) -> Violation {
    Violation {
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        severity,
        file_path: file_path.to_string(),
        line_number: 1,
        snippet: snippet.to_string(),
        message,
        suggestion,
    }
}

/// Structural checks for a Docker Compose file: YAML syntax, restart policy and
/// healthcheck presence.
///
/// Extracted into its own function so the exact same rules run both on the vault
/// tree (`audit_infrastructure`) and on the NAS mirror of the hosts' composes
/// (`audit_compose_dir`) — without duplicating the logic (ARCH-DRY-DUPLICATION).
fn check_compose_file(path_str: &str, content: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mirror_info = parse_mirror_path(path_str);
    let display_path = if let Some((host, rel_path)) = mirror_info {
        format!("[READ-ONLY MIRROR: host '{}'] {}", host, rel_path)
    } else {
        path_str.to_string()
    };

    match serde_yaml::from_str::<serde_yaml::Value>(content) {
        Ok(yaml_val) => {
            if let Some(services) = yaml_val.get("services").and_then(|s| s.as_mapping()) {
                for (svc_key, svc_val) in services {
                    let svc_name = svc_key.as_str().unwrap_or("unknown");
                    let snippet = format!("{}:", svc_name);
                    let mut findings: Vec<ComposeFinding> = Vec::new();

                    // Restart policy
                    let has_restart = svc_val.get("restart").is_some()
                        || svc_val
                            .get("deploy")
                            .and_then(|d| d.get("restart_policy"))
                            .is_some();
                    if !has_restart {
                        let (message, suggestion) = if let Some((host, rel_path)) = mirror_info {
                            (
                                format!(
                                    "Service '{}' on node '{}' (detected in automated backup mirror) does not define 'restart: unless-stopped' or 'restart: always'.",
                                    svc_name, host
                                ),
                                Some(format!(
                                    "⛔ [AUTOMATED READ-ONLY MIRROR — DO NOT EDIT DIRECTLY] This file is a backup replica. Log into '{}' via SSH, add 'restart: unless-stopped' to '~/{rel_path}', and run 'sudo /usr/local/bin/config-backup'.",
                                    host
                                )),
                            )
                        } else {
                            (
                                format!("Service '{}' does not define 'restart: unless-stopped' or 'restart: always'.", svc_name),
                                Some("Add 'restart: unless-stopped' to the service in compose.yml.".to_string()),
                            )
                        };

                        findings.push((
                            "INFRA-COMPOSE-RESTART",
                            "Service Missing Restart Policy",
                            Severity::Warning,
                            message,
                            suggestion,
                        ));
                    }

                    // Healthcheck (or explicit exception label for distroless images).
                    // Accepts label as map (`labels: {homelab.healthcheck: watchdog}`)
                    // or list (`labels: ["homelab.healthcheck=watchdog"]`).
                    let has_healthcheck = svc_val.get("healthcheck").is_some();
                    let has_watchdog_label = svc_val
                        .get("labels")
                        .map(|labels| match labels {
                            serde_yaml::Value::Mapping(m) => m.iter().any(|(k, v)| {
                                k.as_str() == Some("homelab.healthcheck")
                                    && v.as_str() == Some("watchdog")
                            }),
                            serde_yaml::Value::Sequence(seq) => seq.iter().any(|item| {
                                item.as_str()
                                    .map(|s| s.trim() == "homelab.healthcheck=watchdog")
                                    .unwrap_or(false)
                            }),
                            _ => false,
                        })
                        .unwrap_or(false);
                    if !has_healthcheck && !has_watchdog_label {
                        let (message, suggestion) = if let Some((host, rel_path)) = mirror_info {
                            (
                                format!(
                                    "Service '{}' on node '{}' (detected in automated backup mirror) does not define 'healthcheck' (nor the 'homelab.healthcheck: watchdog' exception label).",
                                    svc_name, host
                                ),
                                Some(format!(
                                    "⛔ [AUTOMATED READ-ONLY MIRROR — DO NOT EDIT DIRECTLY] This file is an automated backup mirror of host '{}'. Direct edits in /mnt/BACKUP/ will be erased at 05:00 by config-backup. To remediate: log into host '{}' via SSH, update the upstream compose file at '~/{rel_path}', validate with 'docker compose config -q', deploy with 'docker compose up -d', and run 'sudo /usr/local/bin/config-backup'.",
                                    host, host
                                )),
                            )
                        } else {
                            (
                                format!(
                                    "Service '{}' does not define 'healthcheck' (nor the 'homelab.healthcheck: watchdog' exception label).",
                                    svc_name
                                ),
                                Some(
                                    "Add 'healthcheck' to the service (see mnemocine/guides/docker-healthchecks.md) or label 'homelab.healthcheck: watchdog' for distroless images.".to_string(),
                                ),
                            )
                        };

                        findings.push((
                            "INFRA-COMPOSE-HEALTHCHECK",
                            "Service Missing Healthcheck",
                            Severity::Warning,
                            message,
                            suggestion,
                        ));
                    }

                    // Single materialization point for every structural finding
                    // of this service (keeps the emission DRY).
                    for (rule_id, rule_name, severity, message, suggestion) in findings {
                        violations.push(compose_violation(
                            rule_id,
                            rule_name,
                            severity,
                            &display_path,
                            &snippet,
                            message,
                            suggestion,
                        ));
                    }
                }
            }
        }
        Err(e) => {
            let (message, suggestion) = if let Some((host, rel_path)) = mirror_info {
                (
                    format!("Invalid syntax in compose file on host '{}': {}", host, e),
                    Some(format!(
                        "⛔ [AUTOMATED READ-ONLY MIRROR — DO NOT EDIT DIRECTLY] Log into '{}' via SSH to fix YAML formatting in '~/{rel_path}'.",
                        host
                    )),
                )
            } else {
                (
                    format!("Invalid syntax in compose file: {}", e),
                    Some("Fix YAML formatting in the compose.yml file.".to_string()),
                )
            };

            violations.push(compose_violation(
                "INFRA-COMPOSE-SYNTAX",
                "Docker Compose Syntax Error",
                Severity::Error,
                &display_path,
                &e.to_string(),
                message,
                suggestion,
            ));
        }
    }

    violations
}

/// Applies only the Compose structural checks to every compose file under `root`.
///
/// Used for the NAS mirror of the hosts' configs (`/mnt/BACKUP/configs-homelab`),
/// where the compose hygiene rules matter but the `SEC-*` rules do not: the mirror
/// is captured content, not our authored tree (see `audit_infrastructure` for the
/// `code_debt` rationale).
pub fn audit_compose_dir(root: &Path) -> InfraReport {
    let mut report = InfraReport {
        total_files_scanned: 0,
        messages: Vec::new(),
        violations: Vec::new(),
    };

    if !root.is_dir() {
        return report;
    }

    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(false);

    for result in walker.build().flatten() {
        let path = result.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let is_compose = file_name == "compose.yml"
            || file_name == "compose.yaml"
            || file_name == "docker-compose.yml"
            || file_name == "docker-compose.yaml";
        if !is_compose {
            continue;
        }
        let path_str = path.display().to_string();
        // `golden/` contains copies from `config-backup` of the SAME composes — scanning
        // both causes duplicate findings. Ignore the golden copy.
        if path_str.contains("/golden/") {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        report.total_files_scanned += 1;
        report
            .violations
            .extend(check_compose_file(&path_str, &content));
    }

    report
}

/// `code_debt` gates the rules that only make sense for code WE own.
///
/// `homelab` passes `true`: a loose `.py` in our own tree is debt to migrate.
/// `fork`/`mirror` pass `false`: a `.py` in a derived repo or in a snapshot of
/// the hosts is **third-party or captured content**, not our code to migrate —
/// flagging it is an error of category (the mirror captured 72 Home Assistant
/// files that we neither wrote nor maintain). Security rules (`SEC-*`) are NOT
/// gated here; they always run, for every scope.
pub fn audit_infrastructure(root: &Path, code_debt: bool) -> InfraReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();
    let mut scanned_count = 0;

    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(true);

    for result in walker.build().flatten() {
        if !result.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = result.into_path();
        let path_str = path.to_string_lossy().to_string();

        if path_str.contains("/.git/")
            || path_str.contains("/target/")
            || path_str.contains("/node_modules/")
            || path_str.contains("/.venv/")
            || path_str.contains("/.stversions/")
        {
            continue;
        }

        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        // ── 1. SOPS / Age Deep Secret Guard (SEC-SOPS-UNENCRYPTED) ──────────────
        // Covers 100% of infrastructure text and configuration files
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        let is_text_or_config = matches!(
            ext,
            "yml" | "yaml" | "env" | "json" | "sh" | "conf" | "service" | "md"
        );

        if is_text_or_config {
            if let Ok(content) = fs::read_to_string(&path) {
                // File with .enc.* extension MUST contain SOPS or Age armor
                let is_sops_encrypted = content.contains("sops:") && content.contains("mac:");
                let is_age_armored = content.contains("-----BEGIN AGE ENCRYPTED FILE-----");

                if file_name.contains(".enc.") && !is_sops_encrypted && !is_age_armored {
                    violations.push(Violation {
                        rule_id: "SEC-SOPS-UNENCRYPTED".to_string(),
                        rule_name: ".enc File Missing SOPS/Age Encryption".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: content.lines().next().unwrap_or("").to_string(),
                        message: "File with .enc extension does not contain SOPS or Age encrypted header.".to_string(),
                        suggestion: Some("Encrypt with: sops --encrypt --age <KEY> file > file.enc.yaml".to_string()),
                    });
                }

                // Detects unprotected cleartext private keys
                if content.contains("-----BEGIN")
                    && content.contains("PRIVATE KEY-----")
                    && !is_age_armored
                {
                    violations.push(Violation {
                        rule_id: "SEC-PRIVATE-KEY-CLEARTEXT".to_string(),
                        rule_name: "Cleartext Private Key Detected".to_string(),
                        severity: Severity::Error,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: format!("{}-BEGIN PRIVATE KEY-{}", "----", "----"),
                        message: "Unprotected SSH/TLS private key found in repository.".to_string(),
                        suggestion: Some("Move to ~/.ssh/ or store encrypted with sops/age in mnemocine/secrets.enc.env.".to_string()),
                    });
                }

                // Detects literal tokens and passwords in plaintext (outside templates/examples)
                if !path_str.contains(".template")
                    && !path_str.contains(".example")
                    && !path_str.contains("templates/")
                {
                    for (line_idx, line) in content.lines().enumerate() {
                        let trimmed = line.trim();
                        // Ignore comments and empty lines
                        if trimmed.starts_with('#') || trimmed.starts_with("//") {
                            continue;
                        }

                        // Matches pattern even with YAML/Compose prefixes
                        // (`- VAR=value`), JSON/YAML keys (`VAR: value`), Markdown
                        // tables and bold (`**Password:** value`), and suffixes
                        // (`INITIAL_ADMIN_PASSWORD`, `MYSQL_ROOT_PASSWORD`).
                        let trimmed_no_prefix = trimmed
                            .trim_start_matches(['-', ' '])
                            .trim_start_matches("export ")
                            .replace("**", "")
                            .replace("[", "")
                            .replace("]", "")
                            .replace("`", " ");
                        let trimmed_no_prefix = trimmed_no_prefix.trim();
                        let (maybe_key, maybe_value) = trimmed_no_prefix
                            .split_once('=')
                            .or_else(|| trimmed_no_prefix.split_once(':'))
                            .unwrap_or(("", ""));
                        let key = maybe_key.trim().trim_matches('"');
                        let value = maybe_value.trim().trim_matches(['"', '\'']);
                        let key_upper = key.to_ascii_uppercase();

                        let looks_like_secret_key = key_upper.ends_with("PASSWORD")
                            || key_upper.ends_with("PASSWD")
                            || key_upper.ends_with("SECRET")
                            || key_upper.ends_with("API_KEY")
                            || key_upper.ends_with("ACCESS_TOKEN")
                            || key_upper.ends_with("AUTH_TOKEN")
                            || key_upper.ends_with("_TOKEN")
                            || key_upper == "PASSWORD"
                            || key_upper == "SECRET";

                        let value_is_literal = value.len() >= 8
                            && !value.is_empty()
                            && !value.contains("${")
                            && !value.contains("$(")
                            && !value.contains("ENC[AES256_GCM")
                            && value != "\"\""
                            && value != "''"
                            // Obvious placeholders are not secret leaks
                            && !value.eq_ignore_ascii_case("changeme")
                            && !value.eq_ignore_ascii_case("placeholder")
                            && !value.eq_ignore_ascii_case("example")
                            && !value.eq_ignore_ascii_case("your_password")
                            && !value.starts_with('<')
                            && !value.starts_with('%')
                            // Configuration templates are not plaintext secrets: values are
                            // populated at runtime (e.g. Go templates in indexers like `{{ .Config.password }}`).
                            && !value.contains("{{")
                            && !value.contains("}}")
                            && !value.contains("<%")
                            && !value.contains("${{")
                            // Vault reference declarations: referencing a secret in a store
                            // (e.g. `Password: in the sops store`) is a pointer, not a secret leak.
                            && !value.contains("sops")
                            && !value.contains("SOPS")
                            && !value.contains("secrets.env")
                            && !value.contains("cofre")
                            && !value.contains("secret manager")
                            && !value.contains("vault")
                            // Prose continuations: actual secrets do not begin with these prepositions.
                            && !value.starts_with("in ")
                            && !value.starts_with("no ")
                            && !value.starts_with("em ")
                            && !value.starts_with("(in ")
                            && !value.starts_with("(no ")
                            && !value.starts_with("(em ")
                            // Environment variable name instead of value: if the
                            // "value" is uppercase/underscore only, it is the variable
                            // identifier (e.g. `PI_HOLE_ADMIN_PASSWORD`), not the
                            // credential. Real values almost always have lowercase,
                            // digits, or symbols.
                            && !value
                                .chars()
                                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                            // Parenthesized text describes the source, not the value.
                            // Accepts open parenthesis on same line (e.g.
                            // `(in .env — NPM_ADMIN_PASSWORD / SOPS)`).
                            && !value.starts_with('(')
                            // File/config path is not a credential.
                            && !value.ends_with(".env")
                            && !value.ends_with(".yml")
                            && !value.ends_with(".yaml")
                            && !value.ends_with(".toml")
                            && !value.ends_with(".json");

                        let is_leak = (trimmed.starts_with("ghp_")
                            || trimmed.starts_with("github_pat_"))
                            || (looks_like_secret_key
                                && value_is_literal
                                && !is_documentation_example(trimmed, value));

                        if is_leak && !is_sops_encrypted && !is_age_armored {
                            violations.push(Violation {
                                rule_id: "SEC-PLAINTEXT-SECRET".to_string(),
                                rule_name: "Cleartext Secret Detected".to_string(),
                                severity: Severity::Error,
                                file_path: path_str.clone(),
                                line_number: line_idx + 1,
                                snippet: mask_snippet(trimmed),
                                message: "Cleartext credential or token found in infrastructure file.".to_string(),
                                suggestion: Some("Replace value with environment variable or encrypt via sops/age.".to_string()),
                            });
                            break; // 1 warning per file
                        }
                    }
                }
            }
        }

        // ── 2. Static Docker Compose Validation (INFRA-COMPOSE) ───────────────
        let is_compose = file_name == "compose.yml"
            || file_name == "compose.yaml"
            || file_name == "docker-compose.yml"
            || file_name == "docker-compose.yaml";

        if is_compose {
            scanned_count += 1;
            if let Ok(content) = fs::read_to_string(&path) {
                violations.extend(check_compose_file(&path_str, &content));
            }
        }

        // ── 3. Static Systemd Units Validation (INFRA-SYSTEMD-SYNTAX) ─────────
        if file_name.ends_with(".service") || file_name.ends_with(".timer") {
            scanned_count += 1;
            if let Ok(content) = fs::read_to_string(&path) {
                let has_unit = content.contains("[Unit]");
                let has_service_or_timer =
                    content.contains("[Service]") || content.contains("[Timer]");
                let has_install = content.contains("[Install]");

                if !has_unit || !has_service_or_timer || !has_install {
                    violations.push(Violation {
                        rule_id: "INFRA-SYSTEMD-SYNTAX".to_string(),
                        rule_name: "Incomplete Systemd Unit Structure".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: "".to_string(),
                        message: "Systemd unit file must contain [Unit], [Service]/[Timer], and [Install] sections.".to_string(),
                        suggestion: Some("Add mandatory standard systemd sections.".to_string()),
                    });
                }
            }
        }

        // ── 4. Strict Bash Scripting Practices (INFRA-BASH-STRICT) ───────────
        if file_name.ends_with(".sh") {
            scanned_count += 1;
            if let Ok(content) = fs::read_to_string(&path) {
                if !content.contains("set -euo pipefail") && !content.contains("set -e") {
                    violations.push(Violation {
                        rule_id: "INFRA-BASH-STRICT".to_string(),
                        rule_name: "Bash Script Missing Strict Mode (set -euo pipefail)".to_string(),
                        severity: Severity::Warning,
                        file_path: path_str.clone(),
                        line_number: 1,
                        snippet: content.lines().next().unwrap_or("").to_string(),
                        message: "Automation scripts in Homelab must contain 'set -euo pipefail' for rapid fail-fast on error.".to_string(),
                        suggestion: Some("Add 'set -euo pipefail' right below the shebang (#!/bin/bash).".to_string()),
                    });
                }
            }
        }

        // ── 5. Technical Debt Detection: Loose Python (ARCH-LEGACY-PYTHON) ────
        // Rule: scripts/archive/ is the proper place for legacy scripts — total silence there.
        // Dedicated Rust projects (docx-extractor/, validador-roteiro/) have their own
        // steniocheck.toml; they are not audited here.
        // Only trigger WARN for loose .py scripts outside archive and outside dedicated projects.
        // Only in OUR code (`code_debt`): in a mirror/fork, `.py` files belong to upstream.
        if code_debt && file_name.ends_with(".py") {
            scanned_count += 1;
            let in_archive =
                path_str.contains("/scripts/archive/") || path_str.contains("/archive/");
            let in_dedicated_project = path_str.contains("/scripts/docx-extractor/")
                || path_str.contains("/scripts/validador-roteiro/");

            if !in_archive && !in_dedicated_project {
                violations.push(Violation {
                    rule_id: "ARCH-LEGACY-PYTHON".to_string(),
                    rule_name: "Unarchived Loose Python Script".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: format!("File: {}", file_name),
                    message: "Python script detected outside scripts/archive/. Legacy scripts must be moved to archive/ or migrated to Rust.".to_string(),
                    suggestion: Some("Move to scripts/archive/ if legacy/reference, or rewrite in Rust if in active use.".to_string()),
                });
            }
        }

        // ── 6. Insecure POSIX Permissions on Secrets Audit (SEC-PERM-LEAK) ────
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file_name == "secrets.env"
                || file_name == "keys.txt"
                || file_name.contains("id_ed25519")
                || file_name.contains("id_rsa")
            {
                if let Ok(meta) = fs::metadata(&path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode > 0o600 {
                        violations.push(Violation {
                            rule_id: "SEC-PERM-LEAK".to_string(),
                            rule_name: "Insecure POSIX Permissions on Secret File".to_string(),
                            severity: Severity::Error,
                            file_path: path_str.clone(),
                            line_number: 1,
                            snippet: format!("Current mode: 0{:o}", mode),
                            message: format!("Sensitive file '{}' has permissions 0{:o} (must be 0600 or 0400).", file_name, mode),
                            suggestion: Some("Remediate immediately by executing: chmod 0600 <file>.".to_string()),
                        });
                    }
                }
            }
        }
    }

    // ── 7. Production Static Parity Verification (OPS-STATIC-PARITY) ──────
    if let Some(parity) = crate::deploy::check_static_parity(root) {
        if !parity.in_sync {
            violations.push(Violation {
                rule_id: "OPS-STATIC-PARITY".to_string(),
                rule_name: "Production Frontend Static Parity Drift".to_string(),
                severity: Severity::Warning,
                file_path: "app/frontend-v2/dist/index.html".to_string(),
                line_number: 1,
                snippet: format!("Local: {} | Remote: {}", parity.local_bundle, parity.remote_bundle),
                message: format!(
                    "Production edge node is serving a legacy bundle ('{}'), diverging from local build ('{}').",
                    parity.remote_bundle, parity.local_bundle
                ),
                suggestion: Some("Synchronize production immediately by executing: stenio --deploy front".to_string()),
            });
        }
    }

    // ── 8. Release Integrity Audit (REL-PKGBUILD-SYNC & REL-TAG-DRIFT) ─────
    let pkgbuild_path = root.join("PKGBUILD");
    let cargo_path = root.join("Cargo.toml");
    if pkgbuild_path.exists() && cargo_path.exists() {
        if let (Ok(pkg_content), Ok(cargo_content)) = (
            fs::read_to_string(&pkgbuild_path),
            fs::read_to_string(&cargo_path),
        ) {
            let mut cargo_ver = None;
            for line in cargo_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("version = \"") && trimmed.ends_with('"') {
                    cargo_ver = Some(
                        trimmed
                            .trim_start_matches("version = \"")
                            .trim_end_matches('"'),
                    );
                    break;
                }
            }

            let mut pkg_ver = None;
            for line in pkg_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("pkgver=") {
                    pkg_ver = Some(trimmed.trim_start_matches("pkgver=").trim());
                    break;
                }
            }

            if let (Some(cver), Some(pver)) = (cargo_ver, pkg_ver) {
                if cver != pver {
                    violations.push(Violation {
                        rule_id: "REL-PKGBUILD-SYNC".to_string(),
                        rule_name: "Version Mismatch Between Cargo.toml and PKGBUILD".to_string(),
                        severity: Severity::Error,
                        file_path: "PKGBUILD".to_string(),
                        line_number: 1,
                        snippet: format!("Cargo.toml: {} | PKGBUILD: {}", cver, pver),
                        message: format!(
                            "PKGBUILD package version ('{}') diverges from version declared in Cargo.toml ('{}').",
                            pver, cver
                        ),
                        suggestion: Some(format!("Synchronize pkgver={} in PKGBUILD per governance/release-policy.md.", cver)),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} infrastructure files (Compose/Systemd/SOPS) audited and compliant.",
            scanned_count
        ));
    } else {
        messages.push(format!(
            "ℹ️ {} infrastructure issue(s) detected.",
            violations.len()
        ));
    }

    InfraReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}
