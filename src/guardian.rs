use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::engine::Violation;
use crate::rule::{Severity, TOKEN_SHAPES};

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
    let Some(regex) = secret_pattern() else {
        return Vec::new();
    };
    scan_lines_with(path, content, regex)
}

/// Same scan restricted to the self-identifying token shapes (no keyword branch).
///
/// Used for machine-written JSON that syncs to phones (`.obsidian/*.json`,
/// `.pandoc/*.json`): keyword heuristics would be noise there, a token shape never is.
pub fn scan_content_for_token_shapes(path: &Path, content: &str) -> Vec<Violation> {
    let Some(regex) = token_pattern() else {
        return Vec::new();
    };
    scan_lines_with(path, content, regex)
}

fn scan_lines_with(path: &Path, content: &str, regex: &regex::Regex) -> Vec<Violation> {
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

    let mut violations = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        // SOPS output is ciphertext by construction: an `ENC[AES256_GCM,…]` value
        // and the `sops_*` metadata lines of a dotenv file must never fire.
        if is_sops_ciphertext_line(line) {
            continue;
        }
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
        if is_variable_name_reference(matched) || is_bearer_variable_reference(matched) {
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

/// True when the line carries a self-identifying token shape that is not a documented
/// placeholder, a variable-name reference or SOPS ciphertext.
pub fn line_has_token_shape(line: &str) -> bool {
    if is_sops_ciphertext_line(line) {
        return false;
    }
    let Some(regex) = token_pattern() else {
        return false;
    };
    regex.find_iter(line).any(|m| {
        let s = m.as_str();
        !is_placeholder_value(s) && !is_bearer_variable_reference(s)
    })
}

/// True for a dotenv line that SOPS produced: an encrypted value
/// (`KEY=ENC[AES256_GCM,data:…]`) or the `sops_*=` metadata block
/// (`sops_mac=`, `sops_version=`, `sops_age__list_0__map_enc=` …).
pub fn is_sops_ciphertext_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("sops_") || line.contains("ENC[AES256_GCM")
}

/// True when the content carries the SOPS dotenv markers (`sops_mac=`/`sops_version=`)
/// or at least one `ENC[AES256_GCM` value. Used to accept a `.enc.*` dotenv file as
/// encrypted, the way `sops:`+`mac:` already identifies the YAML/JSON formats.
pub fn has_sops_dotenv_markers(content: &str) -> bool {
    content.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("sops_mac=") || t.starts_with("sops_version=")
    }) || content.contains("ENC[AES256_GCM")
}

/// True when a bearer-header match carries a variable NAME (`Bearer ACCESS_TOKEN`),
/// not a token: same shape test as [`is_variable_name_reference`].
fn is_bearer_variable_reference(matched: &str) -> bool {
    let lowered = matched.to_ascii_lowercase();
    if !lowered.starts_with("authorization") {
        return false;
    }
    let value = matched
        .rsplit(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("");
    value.len() >= 4
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// True when `path` is a file whose job is to hold secrets or that syncs to phones and
/// must therefore be scanned even though dotfile walkers skip it: `.env`, `.env.*`,
/// `*.env`, `*.pem`, `*.key`, `.obsidian/*.json`, `.pandoc/*.json`, `.docker/config.json`.
pub fn is_secret_candidate(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.ends_with(".example") || name.ends_with(".sample") || name.ends_with(".template") {
        return false;
    }
    is_env_like_name(name) || is_key_material_name(name) || is_token_only_json(path)
}

/// `.env`, `.env.<anything>` and `<anything>.env`.
pub fn is_env_like_name(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
}

/// `*.pem` and `*.key`.
pub fn is_key_material_name(name: &str) -> bool {
    name.ends_with(".pem") || name.ends_with(".key")
}

/// Machine-written JSON that is synced or shipped: only token shapes are meaningful.
fn is_token_only_json(path: &Path) -> bool {
    let p = path.to_string_lossy();
    let is_json = p.ends_with(".json");
    is_json
        && (p.contains("/.obsidian/")
            || p.contains("/.pandoc/")
            || p.ends_with("/.docker/config.json"))
}

/// Walks `root` including dotfiles and `.gitignore`d files (Syncthing mirrors them all)
/// and scans every [`is_secret_candidate`] file. `extra_skips` are path fragments the
/// caller already covers elsewhere (e.g. the vault scope leaves `/mnemocine/` to the
/// homelab scope).
///
/// Content only: permission checks (`SEC-PERM-LEAK`) live in `infra.rs`.
pub fn secret_candidate_paths(root: &Path, extra_skips: &[&str]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let extra: Vec<String> = extra_skips.iter().map(|s| s.to_string()).collect();
    let skipped = move |p: &Path| {
        let s = format!("{}/", p.to_string_lossy());
        SECRET_SCAN_SKIP_PATHS.iter().any(|f| s.contains(f))
            || extra.iter().any(|f| s.contains(f.as_str()))
    };
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .filter_entry(move |e| !skipped(e.path()))
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if is_secret_candidate(path) {
            paths.push(path.to_path_buf());
        }
    }
    paths
}

/// Candidates the caller has not already visited with its own (gitignore-aware) walk.
pub fn ignored_secret_candidates(
    root: &Path,
    visited: &std::collections::HashSet<PathBuf>,
) -> Vec<PathBuf> {
    secret_candidate_paths(root, &[])
        .into_iter()
        .filter(|p| !visited.contains(p))
        .collect()
}

/// Scans every candidate under `root` (see [`secret_candidate_paths`]).
pub fn audit_secret_candidates(root: &Path, extra_skips: &[&str]) -> Vec<Violation> {
    let mut violations = Vec::new();
    for path in secret_candidate_paths(root, extra_skips) {
        let path = path.as_path();
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        if is_token_only_json(path) {
            violations.extend(scan_content_for_token_shapes(path, &content));
            continue;
        }
        let mut found = scan_content_for_secrets(path, &content);
        // Dotenv files also get the key-name heuristic of SEC-PLAINTEXT-SECRET
        // (`*_PASS`, `*_AUTHKEY`, …), minus the lines the keyword scan already flagged.
        if is_env_like_name(path.file_name().and_then(|s| s.to_str()).unwrap_or("")) {
            let flagged: std::collections::HashSet<usize> =
                found.iter().map(|v| v.line_number).collect();
            found.extend(
                crate::infra::plaintext_secret_violations(&path.to_string_lossy(), &content, false)
                    .into_iter()
                    .filter(|v| !flagged.contains(&v.line_number)),
            );
        }
        violations.extend(found);
    }
    violations
}

/// `--history`: scans the patches of `git log -p --all` of the repository at `root`
/// for the token shapes. Default off (it walks the whole history). A secret that was
/// committed and later deleted is still public once pushed; this is the only check
/// that sees it. Returns one violation per distinct (commit, file, line) hit.
pub fn scan_git_history(root: &Path) -> Result<Vec<Violation>, String> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let regex = token_pattern().ok_or_else(|| "token pattern failed to compile".to_string())?;
    let mut child = Command::new("git")
        .current_dir(root)
        .args(["log", "-p", "--all", "-U0", "--no-color", "--no-ext-diff"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run git: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "git produced no stdout".to_string())?;

    let mut violations = Vec::new();
    let mut commit = String::new();
    let mut file = String::new();
    let mut seen = std::collections::HashSet::new();
    for raw in BufReader::new(stdout).split(b'\n').flatten() {
        let line = String::from_utf8_lossy(&raw);
        if let Some(rest) = line.strip_prefix("commit ") {
            commit = rest.chars().take(12).collect();
        } else if let Some(rest) = line.strip_prefix("+++ b/") {
            file = rest.to_string();
        } else if line.starts_with('+') && !line.starts_with("+++") {
            let added = &line[1..];
            let Some(m) = regex.find(added) else {
                continue;
            };
            if is_placeholder_value(m.as_str())
                || is_bearer_variable_reference(m.as_str())
                || is_sops_ciphertext_line(added)
            {
                continue;
            }
            if !seen.insert((commit.clone(), file.clone(), added.len())) {
                continue;
            }
            violations.push(Violation {
                rule_id: "SEC-SECRETS-HISTORY".to_string(),
                rule_name: "Credential in Git History".to_string(),
                severity: Severity::Error,
                file_path: file.clone(),
                line_number: 1,
                snippet: format!("commit {commit}: {}", mask_secret_snippet(added)),
                message: "A credential shape was added in this commit. Deleting the line later does not remove it from history.".to_string(),
                suggestion: Some(
                    "Revoke the credential at the provider first; rewrite history only if the repository was never pushed."
                        .to_string(),
                ),
            });
        }
    }
    let _ = child.wait();
    Ok(violations)
}

/// Synthetic fixtures for `--self-test`: every row is (name, passed). Each rule path has
/// a case that must fire and one that must stay silent. Tokens are assembled with
/// `concat!` so this file never contains a literal that the gate itself would flag.
pub fn self_test_cases() -> Vec<(&'static str, bool)> {
    let fires =
        |name: &str, line: &str| !scan_content_for_secrets(Path::new(name), line).is_empty();
    let gh = concat!("ghp", "_", "abcdefghijklmnopqrstuvwxyz0123456789");
    let aws = concat!("AK", "IAABCDEFGHIJKLMNOP12");
    let goog = concat!("AI", "zaSyA1234567890abcdefghijklmnopqrstuv");
    let jwt = concat!(
        "ey",
        "Jhbgcioijiuzi1nij9.ey",
        "Jzdwiioixmjm0nta2nzg5mh0.abc123def456"
    );
    let enc = concat!(
        "DB_PASSWORD=ENC[AES",
        "256_GCM,data:abcdefabcdef,tag:xyz,type:str]"
    );
    vec![
        (
            "dotenv .env scanned",
            fires(".env", "POSTGRES_PASSWORD=Xk29sLm4Qp7vRt8z"),
        ),
        (
            "dotenv .env.prod scanned",
            fires(".env.prod", "API_KEY=Xk29sLm4Qp7vRt8zAB"),
        ),
        ("shape github", fires("n.md", &format!("x {gh}"))),
        ("shape aws", fires("n.txt", aws)),
        ("shape google", fires("n.cfg", goog)),
        ("shape jwt", fires("n.md", jwt)),
        (
            "shape bearer",
            fires(
                "n.sh",
                concat!("Authorization: Bea", "rer abcdefghijklmnopqrstuvwx"),
            ),
        ),
        (
            "shape ec key header",
            fires("k.pem", concat!("-----BEGIN EC ", "PRIVATE KEY-----")),
        ),
        ("sops value silent", !fires("secrets.enc.env", enc)),
        (
            "sops marker silent",
            !fires("secrets.enc.env", "sops_mac=ENC[AES256_GCM,data:abc]"),
        ),
        (
            "bearer var silent",
            !fires(
                "n.sh",
                concat!("Authorization: Bea", "rer ACCESS_TOKEN_VALUE_HERE"),
            ),
        ),
        (
            "plain prose silent",
            !fires("n.md", "the AKIA prefix and ghp_ are token prefixes"),
        ),
    ]
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
            // 1) Self-identifying credentials: `TOKEN_SHAPES` plus OpenAI keys.
            regex::Regex::new(&format!(
                "{TOKEN_SHAPES}|sk-[A-Za-z0-9]{{48}}{}",
                concat!(
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
                )
            ))
            .ok()
        })
        .as_ref()
}

/// Token shapes only (no keyword branch); see [`scan_content_for_token_shapes`].
fn token_pattern() -> Option<&'static regex::Regex> {
    static PATTERN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    PATTERN
        .get_or_init(|| regex::Regex::new(&format!("{TOKEN_SHAPES}|sk-[A-Za-z0-9]{{48}}")).ok())
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
                "BACKEND-NO-HARDCODED-TEXT",
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
                r"(?m)\bsudo\s+", // expanded regex — cannot be reverted to short list
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
                "FRONT-I18N-NAMESPACE",
                "FRONT-NO-HARDCODED-TEXT",
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
                "HOMELAB-NAMING-SERVICE",
            ],
        ),
        (
            "vault.rs",
            &[
                "PROJECT-AUTO-COLD-STORAGE",
                "VAULT-TAG-TAXONOMY",
                "VAULT-FRONTMATTER",
                "PROJECT-NAMING-CONVENTION",
                "projects/cold-storage", // cold-storage must be exempt from naming convention rule
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
            "i18n.rs",
            &["I18N-PO-INCOMPLETE", "no suppression directive"],
        ),
        (
            "backlog.rs",
            &[
                "DOC-BACKLOG-DRIFT",
                "HOMELAB-BACKLOG-MALFORMED",
                "HOMELAB-BACKLOG-LIFECYCLE",
            ],
        ),
        (
            "baseline.rs",
            &[
                "stenio-ignore",
                "nosemgrep",
                "SEC-",                  // SEC-* rules can never be suppressed by nosemgrep
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
                // Check presence of all required invariant strings with Human Override support
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

                // Anti-Tampering check: explicit global bypass
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

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("stenio-guardian-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn fixtures_all_pass() {
        for (name, ok) in self_test_cases() {
            assert!(ok, "fixture failed: {name}");
        }
    }

    #[test]
    fn dotfile_candidates_are_walked_and_scanned() {
        let dir = tmp_dir("walk");
        let obsidian = dir.join(".obsidian");
        let _ = fs::create_dir_all(&obsidian);
        let _ = fs::write(dir.join(".env"), "POSTGRES_PASSWORD=Xk29sLm4Qp7vRt8z\n");
        let _ = fs::write(dir.join(".env.prod"), "DB_PASS=Qp7vRt8zXk29sLm4\n");
        let google = concat!("AI", "zaSyA1234567890abcdefghijklmnopqrstuv");
        let _ = fs::write(
            obsidian.join("data.json"),
            format!("{{\"k\":\"{google}\"}}"),
        );
        let _ = fs::write(dir.join("clean.env"), "NAME=value\n");
        let found = audit_secret_candidates(&dir, &[]);
        let _ = fs::remove_dir_all(&dir);
        let files: Vec<String> = found.iter().map(|v| v.file_path.clone()).collect();
        assert!(files.iter().any(|f| f.ends_with("/.env")), "{files:?}");
        assert!(files.iter().any(|f| f.ends_with("/.env.prod")), "{files:?}");
        assert!(files.iter().any(|f| f.ends_with("data.json")), "{files:?}");
        assert!(!files.iter().any(|f| f.ends_with("clean.env")), "{files:?}");
    }

    #[test]
    fn sops_dotenv_never_fires() {
        let enc = concat!(
            "A_PASSWORD=ENC[AES",
            "256_GCM,data:abcdefabcdefabcd,type:str]"
        );
        let body = format!("{enc}\nsops_mac=ENC[AES256_GCM,data:zz]\nsops_version=3.9.0\n");
        assert!(scan_content_for_secrets(Path::new("secrets.enc.env"), &body).is_empty());
        assert!(has_sops_dotenv_markers(&body));
        assert!(!has_sops_dotenv_markers("A=b\n"));
    }

    #[test]
    fn history_finds_a_deleted_token() {
        let dir = tmp_dir("history");
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .current_dir(&dir)
                .args(["-c", "user.email=t@t", "-c", "user.name=t"])
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        let token = concat!("ghp", "_", "abcdefghijklmnopqrstuvwxyz0123456789");
        let ready = git(&["init", "-q"])
            && fs::write(dir.join("a.txt"), format!("t={token}\n")).is_ok()
            && git(&["add", "."])
            && git(&["commit", "-q", "-m", "add"])
            && fs::write(dir.join("a.txt"), "clean\n").is_ok()
            && git(&["commit", "-qam", "remove"]);
        let result = scan_git_history(&dir);
        let _ = fs::remove_dir_all(&dir);
        if !ready {
            return;
        }
        let found = result.unwrap_or_default();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule_id, "SEC-SECRETS-HISTORY");
    }
}
