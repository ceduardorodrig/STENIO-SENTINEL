use crate::config::SteniocheckConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rule {
    pub id: String,
    pub tag: String,
    pub severity: Severity,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub file_extensions: Vec<String>,
    pub must_match: bool,
    pub suggestion: Option<String>,
    pub fix_replacement: Option<String>,
    pub path_includes: Vec<String>,
    pub path_excludes: Vec<String>,
    /// Optional second regex describing the CONTEXT in which the rule applies
    /// at full severity (e.g. a Rust file that is actually async).
    pub requires_pattern: Option<String>,
    /// Severity to use when `requires_pattern` is set but does NOT match.
    /// `None` means "do not report at all"; `Some(Warning)` keeps the finding
    /// visible instead of silently dropping it (no silent gap).
    pub severity_without_requires: Option<Severity>,
}

impl Rule {
    pub fn new(
        id: &str,
        tag: &str,
        severity: Severity,
        name: &str,
        description: &str,
        pattern: &str,
        file_extensions: &[&str],
        suggestion: Option<&str>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tag: tag.to_string(),
            severity,
            name: name.to_string(),
            description: description.to_string(),
            pattern: pattern.to_string(),
            file_extensions: file_extensions.iter().map(|s| s.to_string()).collect(),
            must_match: false,
            suggestion: suggestion.map(|s| s.to_string()),
            fix_replacement: None,
            path_includes: Vec::new(),
            path_excludes: Vec::new(),
            requires_pattern: None,
            severity_without_requires: None,
        }
    }

    /// Makes the rule context-dependent: `requires_pattern` must match the file
    /// for the rule to keep its full severity; otherwise the finding is reported
    /// with `without` (or skipped when `without` is not provided).
    ///
    /// Used by `RUST-ASYNC-SLEEP`: `std::thread::sleep` is an **Error** in a file
    /// that is actually async, but only a **Warning** in synchronous code — so
    /// synchronous CLIs have a sanctioned path without `stenio-ignore`.
    pub fn with_context(mut self, requires_pattern: &str, without: Severity) -> Self {
        self.requires_pattern = Some(requires_pattern.to_string());
        self.severity_without_requires = Some(without);
        self
    }

    #[allow(dead_code)]
    pub fn with_fix(mut self, fix: &str) -> Self {
        self.fix_replacement = Some(fix.to_string());
        self
    }

    pub fn matches_filter(
        &self,
        tag_filter: Option<&str>,
        only_rule: Option<&str>,
        ext: &str,
    ) -> bool {
        if let Some(target) = only_rule {
            if !self.id.eq_ignore_ascii_case(target) {
                return false;
            }
        }
        if let Some(tag) = tag_filter {
            if self.tag != tag {
                return false;
            }
        }
        self.file_extensions.iter().any(|e| e == ext)
    }
}

pub fn get_rules_from_config(config: &SteniocheckConfig) -> Vec<Rule> {
    let mut rules = Vec::new();

    // ── 0. Rust Sovereignty: Total Prohibition of Python Files ─────────────
    rules.push(Rule::new(
        "ARCH-NO-PYTHON",
        "arch",
        Severity::Error,
        "Prohibited Python File",
        "The repository has migrated 100% to native Rust (ADR-036). No .py files may be created or maintained.",
        r".+",
        &["py"],
        Some("Remove the .py file and rewrite the functionality in native Rust inside app/server/src/."),
    ));

    // ── 1. Dynamic Banning of Python Packages (from steniocheck.toml) ───────
    let banned_pkgs = config
        .security
        .as_ref()
        .and_then(|s| s.banned_python_packages.clone())
        .unwrap_or_else(|| vec!["torch".to_string(), "ctranslate2".to_string()]);

    for pkg in banned_pkgs {
        let pattern = format!(r"(?m)^\s*(import\s+{}\b|from\s+{}\b)", pkg, pkg);
        rules.push(Rule::new(
            &format!("SEC-BAN-{}", pkg.to_uppercase()),
            "sec",
            Severity::Error,
            &format!("Banned Dependency: {}", pkg),
            &format!("Use of '{}' is prohibited following the migration to native Rust.", pkg),
            &pattern,
            &["py"],
            Some(&format!(
                "Eliminate the '{}' dependency and use the Rust engine in app/server.",
                pkg
            )),
        ));
    }

    // ── 2. Dynamic Banning of Decommissioned Legacy Modules ────────────────
    let banned_mods = config
        .architecture
        .as_ref()
        .and_then(|a| a.banned_modules.clone())
        .unwrap_or_else(|| {
            vec![
                "core.canvas".to_string(),
                "core.ocr_engine".to_string(),
                "worker_vision".to_string(),
                "run_vision".to_string(),
                "run_datavis".to_string(),
                "worker_datavis".to_string(),
                "core.whisper_pytorch".to_string(),
            ]
        });

    let mod_joined = banned_mods
        .iter()
        .map(|m| regex::escape(m))
        .collect::<Vec<_>>()
        .join("|");
    let mod_pattern = format!(r"(?m)^\s*(from|import)\s+({})\b", mod_joined);

    rules.push(Rule::new(
        "ARCH-BANNED-MODULES",
        "arch",
        Severity::Error,
        "Import of Decommissioned Legacy Module",
        "Do not import legacy vision, OCR, canvas, datavis, or whisper_pytorch modules.",
        &mod_pattern,
        &["py"],
        Some("Remove import of the decommissioned legacy module."),
    ));

    // ── 3. Sudo Usage and System Privileges (AGENTS.md Rule 10) ────────────
    // In professional automations, the machine user must possess a NOPASSWD sudoers rule
    // or credentials must be injected via .env/SOPS.
    // 'pkexec' is merely an optional graphical KDE mechanism on psicopompo; in server scripts
    // or recurring tasks it must be avoided to prevent fatigue from password dialogs.
    //
    // ⚠️ THE COVERAGE IS BROAD BY DESIGN — DO NOT NARROW (reviewed 2026-09-30).
    // The `\bsudo\s+` pattern matches ANY command. This is NOT a rule that
    // "accuses an error": it is a MANDATORY REVIEW POINT. The risk is not in the specific
    // command, but in the privilege pattern (scope, necessity, interactive password).
    //
    // History: on 2026-09-16 (commit ca05d47) the regex was expanded from a 6-command list
    // to `\bsudo\s+`. The short list was a LEAKY WHITELIST — any command outside it
    // escaped silently. Reverting to a short list reopens the gap, which is why this signature
    // is PINNED in `guardian.rs` (anti-tampering) with the note "cannot be reverted".
    //
    // ACCEPTED consequence with no shortcut: legitimate `sudo` is also flagged, and the rule
    // is **inviolable** — `SEC-*` does not accept `stenio-ignore` (see `baseline.rs`: `is_inviolable`).
    // There is no way to silence it case-by-case without breaking governance; the notice is permanent by design.
    // See `--explain SEC-SUDO`.
    rules.push(Rule::new(
        "SEC-SUDO",
        "sec",
        Severity::Warning,
        "Privileged Sudo Execution in Script",
        "Rule 10 of AGENTS.md: Automations must use sudoers (NOPASSWD) or .env/SOPS. Avoid interactive passwords or forcing pkexec on headless servers.",
        r"(?m)\bsudo\s+",
        &["sh", "bash"],
        Some("Configure a NOPASSWD sudoers rule for the machine user or inject credentials via .env/SOPS."),
    ));

    // ── 4. Universal Credentials & Secrets Scanner ─────────────────────────
    rules.push(Rule::new(
        "SEC-SECRETS",
        "sec",
        Severity::Error,
        "Hardcoded Secrets & Credentials",
        "API tokens or private keys must never appear in plaintext within code.",
        r#"(ghp_[A-Za-z0-9]{36}|-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----|sk-[A-Za-z0-9]{48})|(?i)(api_key|secret_key)\s*=\s*['"][A-Za-z0-9_\-]{20,}['"]"#,
        &["py", "rs", "ts", "tsx", "js", "sh"],
        Some("Remove the plaintext secret and inject via environment variable (.env) or system secret store."),
    ));

    // ── 5. SQL Security ────────────────────────────────────────────────────
    rules.push(Rule::new(
        "SEC-SQL",
        "sec",
        Severity::Warning,
        "Insecure SQL Interpolation",
        "Use parameterized queries instead of directly formatting strings into SQL statements.",
        r#"f["'].*?(SELECT\s+|INSERT\s+INTO\s+|UPDATE\s+\w+\s+SET\s+|DELETE\s+FROM\s+).*?\{"#,
        &["py"],
        Some("Use SQLx bind parameters ($1, $2) or prepared statements instead of string interpolation."),
    ));

    // ── 6. Error Handling without Bare Except ──────────────────────────────
    rules.push(Rule::new(
        "SEC-EXCEPT",
        "sec",
        Severity::Warning,
        "Prohibited Bare Except",
        "Except blocks must catch specific Exception types (avoid 'except:').",
        r"(?m)^\s*except\s*:",
        &["py"],
        Some("Specify the exception class (e.g. 'except Exception as err:' or specific error type)."),
    ));

    // ── 7. Frontend: Zustand Selector Stability (Infinite Loop Prevention) ─
    rules.push(Rule::new(
        "FRONT-ZUSTAND",
        "frontend",
        Severity::Warning,
        "Unstable Zustand Selector",
        "Objects returned by Zustand selectors trigger infinite re-renders without useShallow.",
        r"use[A-Za-z0-9]+Store\s*\(\s*\([^)]*\)\s*=>\s*\{",
        &["ts", "tsx"],
        Some("Wrap the selector function in useShallow(state => ({ ... })) imported from 'zustand/react/shallow'."),
    ));

    // ── 8. Frontend: Production Log Purity ─────────────────────────────────
    rules.push(Rule::new(
        "FRONT-LOGS",
        "frontend",
        Severity::Warning,
        "Residual Frontend Debug Logs",
        "Remove debugging console.log/console.debug before committing to production.",
        r"(?m)^\s*console\.(log|debug)\(",
        &["ts", "tsx"],
        Some("Remove console.log/debug or wrap in a development environment check."),
    ));

    // ── 9. Infra: Nginx WebSocket Buffering ────────────────────────────────
    rules.push(Rule::new(
        "INFRA-WS-BUFFERING",
        "infra",
        Severity::Warning,
        "Nginx WebSocket Buffering",
        "Nginx WebSocket proxy locations must specify 'proxy_buffering off' for real-time streaming.",
        r"proxy_pass\s+http://[^;]+;\s*#\s*ws",
        &["conf", "j2"],
        Some("Add 'proxy_buffering off;' and 'proxy_cache off;' to the WebSocket proxy configuration."),
    ));

    // ── 10. Architecture: Native Rust CLI Tools Preference ─────────────────
    rules.push(Rule::new(
        "ARCH-RUST-TOOLS",
        "arch",
        Severity::Warning,
        "Legacy GNU CLI Tools Usage",
        "Terminal preference rule from AGENTS.md: Prefer native Rust alternatives (eza, bat, rg, fd, dust).",
        r"(?m)^\s*(grep\s+-r|find\s+\.\s+-name|du\s+-sh)\b",
        &["sh"],
        Some("Replace GNU commands with native Rust equivalents: grep -> rg, find -> fd, du -> dust, ls -> eza."),
    ));

    // ── 11. Rust: Prohibition of Thread Sleep in Asynchronous Runtime ──────
    rules.push(
        Rule::new(
            "RUST-ASYNC-SLEEP",
            "rust",
            Severity::Error,
            "std::thread::sleep in Asynchronous Code",
            "In Tokio asynchronous code, use tokio::time::sleep to avoid blocking the runtime worker thread.",
            r"\bstd::thread::sleep\(",
            &["rs"],
            Some("Replace 'std::thread::sleep(dur);' with 'tokio::time::sleep(dur).await;'."),
        )
        .with_context(
            r"(async fn|\.await|#\[tokio::|tokio::|async_std::|smol::|futures::)",
            Severity::Warning,
        ),
    );

    // ── 12. Rust: Structured Logging in Web Server ─────────────────────────
    rules.push(Rule::new(
        "RUST-STRUCTURED-LOGGING",
        "rust",
        Severity::Warning,
        "Unstructured println! in Server Code",
        "In Axum web servers, use tracing crate macros (info!, warn!, error!, debug!) instead of raw println!.",
        r"(?m)^\s*(println!|eprintln!)\(",
        &["rs"],
        Some("Replace println!/eprintln! with tracing::info!, tracing::warn!, or tracing::error!."),
    ));

    // ── 13. Rust Sovereignty: Prohibition of GNU Tools in Rust Code ────────
    // Guarantees that Rust code does not invoke GNU binaries via Command::new().
    // Stênio is the guardian; it must not violate the rules it enforces.
    rules.push(Rule::new(
        "ARCH-RUST-CMD-LEGACY",
        "arch",
        Severity::Warning,
        "Legacy GNU Tool Invoked in Rust Source",
        "Command::new() invoking GNU tools violates AGENTS.md. Use Rust native alternatives: xh (curl), walkdir (find), regex (grep), statvfs/nix (df).",
        r#"Command::new\("(df|curl|find|grep|ls|cat|sed|du|awk|ps|top)"\)"#,
        &["rs"],
        Some("Replace with native Rust equivalent: curl -> xh, df -> statvfs/nix, find -> walkdir, grep -> regex."),
    ));

    // ── 14. Rust Sovereignty: Prohibition of unwrap()/expect() in Production
    rules.push(Rule::new(
        "RUST-NO-UNWRAP",
        "rust",
        Severity::Error,
        "Use of unwrap() or expect() in Production Code",
        "Both .unwrap() and .expect() cause unconditional runtime panics. Swapping unwrap for expect is strictly blocked. Handle errors with '?', match, or safe fallbacks (.unwrap_or_default).",
        r"\.(unwrap|expect)\(",
        &["rs"],
        Some("Replace .unwrap()/.expect() with '?' (try operator), pattern matching ('match'/'if let'), or safe fallbacks (.unwrap_or_default() / .ok_or(...))."),
    ));

    // ── 14.1 Rust Sovereignty: Canonical Remote Command Invocation ─────────
    rules.push(Rule::new(
        "RUST-CANONICAL-REMOTE",
        "rust",
        Severity::Error,
        "Raw Remote Command Prohibited (Use crate::remote)",
        "Direct invocation of 'Command::new(\"ssh\")' or 'Command::new(\"rsync\")' is prohibited. Use canonical unified driver 'crate::remote::run_ssh' or 'crate::remote::run_rsync' to guarantee timeouts, BatchMode flags, and Tailscale SSH support.",
        r#"Command::new\(["'](ssh|rsync)["']\)"#,
        &["rs"],
        Some("Replace raw Command::new(\"ssh\"/\"rsync\") with unified driver 'crate::remote::run_ssh' or 'crate::remote::run_rsync'."),
    ));

    // ── 15. Anti-Laziness: Prohibition of AI Stubs and Placeholders ────────
    rules.push(Rule::new(
        "AGENT-NO-LAZY-STUB",
        "gov",
        Severity::Error,
        "Lazy AI Stub or Placeholder",
        "AI models must not deliver incomplete code with stubs, 'todo!()', 'unimplemented!()', or '// rest of code'.",
        r#"(?i)(//\s*(\.\.\.|rest of (the )?code|existing code|code remains|TODO:?\s*implement|add logic here)|\b(todo!|unimplemented!)\(|\bthrow new Error\(["'](Not implemented|TODO)["']\))"#,
        &["rs", "ts", "tsx", "js", "py", "sh"],
        Some("Implement complete functional code. Using stubs, 'todo!()', or placeholders in deliverables is strictly forbidden."),
    ));

    // ── 15.1 Anti-Bypass: Prohibition of Suppression and Ignore Directives ─
    rules.push(Rule::new(
        "AGENT-NO-SUPPRESSION-DIRECTIVES",
        "gov",
        Severity::Error,
        "Prohibited Suppression or Bypass Directive",
        "Prohibits @ts-ignore, @ts-nocheck, eslint-disable, type: ignore, or inline stenio-ignore to mask errors.",
        r#"(?m)(//\s*@ts-(ignore|nocheck)|/\*\s*eslint-disable|#\s*type:\s*ignore|//\s*stenio-ignore:\s*(all|SEC-|AGENT-|ARCH-|RUST-|CONF-|TEST-)|#\s*stenio-ignore:\s*(all|SEC-|AGENT-|ARCH-|RUST-|CONF-|TEST-))"#,
        &["ts", "tsx", "js", "rs", "py", "sh"],
        Some("Fix code typing or actual compliance. Masking errors with suppression directives is strictly forbidden."),
    ));

    // ── 15.2 Anti-Tampering: Prohibition of Hook or Verifier Tampering ─────
    rules.push(Rule::new(
        "AGENT-NO-TAMPERING-VERIFIER",
        "gov",
        Severity::Error,
        "Verification Hook Tampering Attempt",
        "Prohibits disabling pre-commit hooks, commenting out stenio invocations, or tampering with audit configs.",
        r#"(?m)(stenio\s+.*--no-verify|git\s+commit\s+.*--no-verify|\.git/hooks/.*exit\s+0|rm\s+-f\s+\.git/hooks)"#,
        &["sh", "bash", "ts", "tsx", "js", "rs"],
        Some("Never bypass or disable validation hooks (--no-verify). StênioSentinel is the canonical delivery gatekeeper."),
    ));

    // ── 15.3 Build Integrity: Prohibition of Weakening Compiler Strict Mode ───
    rules.push(Rule::new(
        "CONF-NO-WEAKEN-STRICT",
        "gov",
        Severity::Error,
        "Compiler Strict Mode Weakening",
        "Prohibits disabling strict mode ('\"strict\": false') in tsconfig.json or disabling compiler safety checks.",
        r#""strict"\s*:\s*false|"noImplicitAny"\s*:\s*false"#,
        &["json"],
        Some("Keep '\"strict\": true' in the TypeScript compiler configuration to guarantee type safety."),
    ));

    // ── 16. Test Integrity: Prohibition of Silently Skipping Tests ─────────
    rules.push(Rule::new(
        "TEST-NO-SILENT-SKIP",
        "test",
        Severity::Error,
        "Disabled Test or Commented Assertion",
        "Prohibits #[ignore], test.skip, or commenting out assertions to bypass test failures.",
        r#"(?m)(^\s*#\[ignore\]|^\s*//\s*(assert!|assert_eq!|assert_ne!|expect\()|\b(it|test|describe)\.skip\(|\b(xit|xtest)\(|@pytest\.mark\.skip)"#,
        &["rs", "ts", "tsx", "js", "py"],
        Some("Do not disable tests or comment assertions to force passes. Identify and resolve root causes in code."),
    ));

    // ── 17. Reliability: Prohibition of Empty Catch Blocks ─────────────────
    rules.push(Rule::new(
        "CODE-NO-EMPTY-CATCH",
        "gov",
        Severity::Warning,
        "Silenced Error Handling (Empty Catch)",
        "Empty catch or except blocks silently swallow errors without logging or diagnostics.",
        r#"(?m)(catch\s*(\([^\)]*\))?\s*\{\s*\}|^\s*except(\s+\w+)?:\s*pass\s*$)"#,
        &["ts", "tsx", "js", "py"],
        Some("Log the error (tracing, logger, console.error) or propagate via '?'. Never swallow errors silently."),
    ));

    // ── 18. Backend: Prohibition of Blocking I/O in Tokio ──────────────────
    rules.push(Rule::new(
        "BACKEND-BLOCKING-IO",
        "rust",
        Severity::Error,
        "Blocking I/O (std::fs) in Async Runtime",
        "Using std::fs inside asynchronous handlers blocks Tokio worker threads. Use tokio::fs.",
        r"\bstd::fs::(read|write|read_to_string|remove_file|copy|rename|create_dir)\(",
        &["rs"],
        Some("Replace 'std::fs::*' with 'tokio::fs::*' using '.await' or wrap inside 'tokio::task::spawn_blocking'."),
    ));

    // ── 19. Backend: Prohibition of Panics and Asserts in Web Server ───────
    rules.push(Rule::new(
        "BACKEND-NO-PANIC",
        "rust",
        Severity::Warning,
        "Panic or Assert in Web Server Code",
        "Direct calls to panic!() or assert!() crash web server worker threads. Handle errors gracefully returning Result.",
        r"(?m)^\s*(panic!|assert!|assert_eq!|assert_ne!)\(",
        &["rs"],
        Some("Return a structured HTTP error (e.g. Err(AppError::BadRequest(...))) instead of crashing the server process."),
    ));

    // ── 20. Architecture: Mandatory DRY (Don't Repeat Yourself) Principle ──
    rules.push(Rule::new(
        "ARCH-DRY-DUPLICATION",
        "arch",
        Severity::Error,
        "Code Duplication (DRY Principle)",
        "Prohibits duplicated substantive code blocks (>6 identical lines). Extract logic into shared functions or hooks.",
        r"(?m)^.*stenio-dry-marker.*$",
        &["rs", "ts", "tsx", "py", "js"],
        Some("Extract duplicated logic into a custom hook ('features/<domain>/hooks/'), atomic component, or shared utility function."),
    ));

    // ── 20.1 Architecture: Monorepo Scope Isolation (Anti-Gaming) ──────────
    rules.push(Rule::new(
        "ARCH-SCOPE-ISOLATION",
        "arch",
        Severity::Error,
        "Monorepo Scope Isolation Violation",
        "Prohibits mixing application product changes (Sumaenima) with StênioSentinel engine internals in the same commit.",
        r"(?m)^.*stenio-scope-marker.*$",
        &["rs", "ts", "tsx", "py", "js"],
        Some("Isolate responsibilities: develop product features in sumaenimahub/ and governance sentinel engine changes in governance/stenio in separate tasks and commits."),
    ));

    // ── 21. Frontend & GPU: Zero-Repaint in 3D Animations & Hovers ─────────
    rules.push(Rule::new(
        "PERF-GPU-ZERO-REPAINT",
        "frontend",
        Severity::Warning,
        "Paint Transition in 3D Container / Hover",
        "Transitions on 'box-shadow', 'backdrop-filter', or 'background-color' force expensive GPU repaints every frame.",
        r"(?m)(transition:.*(box-shadow|backdrop-filter)|magic-card-tilt-container.*transition-(colors|all))",
        &["css", "tsx"],
        Some("Animate opacity (0 -> 1) on an isolated ::after pseudo-element on the GPU Compositor instead of transitioning shadows or filters."),
    ));

    // ── 22. Frontend & GPU: Prohibition of Layout Thrashing in Events ──────
    rules.push(Rule::new(
        "PERF-NO-LAYOUT-THRASH",
        "frontend",
        Severity::Warning,
        "Layout Thrashing in Event Handlers",
        "Synchronous geometry queries (getBoundingClientRect / offset*) in mouse handlers trigger forced synchronous reflows at 1000Hz.",
        r"\.getBoundingClientRect\(\)",
        &["ts", "tsx"],
        Some("Cache client rects in a useRef on onMouseEnter or buffer coordinates and process on requestAnimationFrame ticks."),
    ));

    // ── 23. Frontend & GPU: Arandu Card Grid Containment (.card-cell) ──────
    rules.push(Rule::new(
        "PERF-GPU-CONTAINMENT",
        "frontend",
        Severity::Warning,
        "Card Grid Missing CSS Containment",
        "Dense card grids with 3D tilt/hover require CSS containment (.card-cell) to prevent layout invalidation of sibling cards.",
        r"<MagicCard",
        &["tsx"],
        Some("Wrap each MagicCard in a container: <div className=\"card-cell\"><MagicCard ... /></div>."),
    ));

    // ── 24. Frontend & GPU: will-change Restricted to Interactive States ───
    rules.push(Rule::new(
        "PERF-GPU-WILL-CHANGE",
        "frontend",
        Severity::Warning,
        "Static will-change at Rest",
        "Static 'will-change' consumes persistent GPU textures at rest. Restrict strictly to :hover / interaction selectors.",
        r"will-change:\s*(transform|opacity)",
        &["css"],
        Some("Apply 'will-change: transform' strictly under interactive selectors (:hover, .is-hovered) and release at rest."),
    ));

    // ── 25. Frontend: Decoupling Network Calls from Pages ──────────────────
    rules.push(Rule::new(
        "FRONT-MODULAR-HOOKS",
        "frontend",
        Severity::Warning,
        "Direct Network Invocation in Page Layer",
        "Pages are pure layout orchestrators (<400 lines). Direct API or WebSocket calls violate architectural decoupling.",
        r"(fetch\(|axios\.|new WebSocket\()",
        &["tsx"],
        Some("Extract API calls and mutation logic into a Custom Hook in 'src/features/<domain>/hooks/'."),
    ));

    // ── 26. Frontend: Prohibition of Silenced Errors without Visual Feedback
    rules.push(Rule::new(
        "FRONT-FEEDBACK-ON-ERROR",
        "frontend",
        Severity::Warning,
        "UI Error without Visual Feedback",
        "Catch blocks that only log to console leave users without visual feedback when an action fails.",
        r"console\.(error|warn)\(",
        &["tsx", "ts"],
        Some("Add notification via toast.error('Message') or update component error state for visual feedback."),
    ));

    // ── 27. Frontend: Prohibition of Hardcoded Localhost URLs ─────────────
    rules.push(Rule::new(
        "FRONT-NO-HARDCODED-HOST",
        "frontend",
        Severity::Error,
        "Hardcoded Localhost URL in Frontend",
        "Absolute localhost URLs break in production behind reverse proxies.",
        r"(?m)^.*stenio-frontend-marker.*$",
        &["tsx", "ts", "js"],
        Some("Use relative paths (/api/...) or load URL via 'import.meta.env.VITE_API_URL'."),
    ));

    // ── 28. Database: Mandatory Idempotency in SQL Migrations ──────────────
    rules.push(Rule::new(
        "DB-IDEMPOTENT-MIGRATION",
        "db",
        Severity::Error,
        "Non-Idempotent SQL Migration",
        "DDL statements in migrations/ must use IF NOT EXISTS or IF EXISTS for safe re-execution.",
        r"(?m)^.*stenio-migration-marker.*$",
        &["sql"],
        Some("Add 'IF NOT EXISTS' to CREATE or 'IF EXISTS' to DROP to guarantee idempotency."),
    ));

    // ── 29. Infrastructure: Mesh Canonical Topology Compliance ────────────
    rules.push(Rule::new(
        "INFRA-TOPOLOGY-COMPLIANCE",
        "infra",
        Severity::Error,
        "Deploy Target Outside Active Topology",
        "Deployment scripts and stacks may only target active topology nodes (kavure, ybyra, psicopompo).",
        r"(?m)^.*stenio-topology-marker.*$",
        &["sh", "ini", "yml", "yaml"],
        Some("Target canonical topology nodes (kavure for backend/docker, ybyra for edge/frontend)."),
    ));

    // ── 30. Rust: Prohibition of Unbounded Asynchronous Channels ───────────
    rules.push(Rule::new(
        "RUST-NO-UNBOUNDED-CHANNEL",
        "rust",
        Severity::Error,
        "Unbounded Asynchronous Channel (Unbounded MPSC)",
        "Unbounded channels 'unbounded_channel()' apply no backpressure and risk Out-Of-Memory (OOM) crashes. Use bounded channels 'channel(N)'.",
        r"\b(tokio::sync::mpsc::|mpsc::)unbounded_channel\(",
        &["rs"],
        Some("Replace 'mpsc::unbounded_channel()' with 'mpsc::channel(buffer_size)' defining explicit backpressure capacity."),
    ));

    // ── 31. Rust: Prohibition of Synchronous Process Command in Tokio ──────
    rules.push(Rule::new(
        "RUST-ASYNC-BLOCKING-CMD",
        "rust",
        Severity::Error,
        "Synchronous Process Command in Async Runtime",
        "std::process::Command::new() blocks Tokio runtime threads. In async code, use tokio::process::Command.",
        r"\bstd::process::Command::new\(",
        &["rs"],
        Some("Replace 'std::process::Command::new' with 'tokio::process::Command::new' and use '.await', or wrap in 'tokio::task::spawn_blocking'."),
    ));

    // ── 32. Rust: Prohibition of Synchronous Mutex Held Across Await ───────
    rules.push(Rule::new(
        "RUST-NO-SYNC-MUTEX-AWAIT",
        "rust",
        Severity::Warning,
        "Synchronous Mutex Held Across Await Point",
        "Holding a std::sync::Mutex lock across .await points causes deadlocks and violates Send. Use tokio::sync::Mutex or drop guard before await.",
        r"\bstd::sync::Mutex\b",
        &["rs"],
        Some("Replace 'std::sync::Mutex' with 'tokio::sync::Mutex', or ensure synchronous guard is dropped via drop(guard) before any .await."),
    ));

    // ── 33. Rust: Idiomatic Arc::clone(&ptr) Convention ────────────────────
    rules.push(Rule::new(
        "RUST-IDIOMATIC-ARC-CLONE",
        "rust",
        Severity::Warning,
        "Non-Idiomatic Arc Cloning",
        "RFC 258 / Clippy convention: prefer 'Arc::clone(&ptr)' over 'ptr.clone()' to make atomic pointer duplication explicit.",
        r"\b[A-Za-z0-9_]+_arc\.clone\(\)|\b(arc_|shared_)[A-Za-z0-9_]*\.clone\(\)",
        &["rs"],
        Some("Replace 'ptr.clone()' with 'Arc::clone(&ptr)' to maintain idiomatic, explicit Rust code."),
    ));

    // ── 34. Rust: Preference for Slices (&str / &[T]) in Parameters ────────
    rules.push(Rule::new(
        "RUST-IDIOMATIC-SLICES",
        "rust",
        Severity::Warning,
        "Non-Idiomatic Signature with &String or &Vec<T>",
        "Function signatures should not take references to concrete collections (&String or &Vec<T>). Use slices '&str' and '&[T]'.",
        r"\bfn\s+[a-z0-9_]+\s*(?:<[^>]+>)?\s*\([^)]*:\s*&(?:mut\s+)?(String\b|Vec<)",
        &["rs"],
        Some("Replace parameter '&String' with '&str' and '&Vec<T>' with '&[T]' to avoid allocations and accept any slice or literal."),
    ));

    // ── 35. Rust: Mandatory Error Handling in tokio::spawn ─────────────────
    rules.push(Rule::new(
        "RUST-SPAWN-ERROR-HANDLING",
        "rust",
        Severity::Warning,
        "Orphan tokio::spawn without Error Handling or Tracing",
        "Async tasks spawned via 'tokio::spawn' without JoinHandle handling or tracing instrumentation silently swallow panics and errors.",
        r"(?m)^\s*tokio::spawn\s*\(\s*async\s+move\s*\{",
        &["rs"],
        Some("Retain JoinHandle (let handle = tokio::spawn(...)) or instrument task with '.instrument(tracing::info_span!(...))' for observability on panic."),
    ));

    // ── 36. Governance: Lowercase Kebab-Case Directory Naming ──────────────
    rules.push(Rule::new(
        "GOV-NAMING-KEBAB-CASE",
        "gov",
        Severity::Warning,
        "Directory Naming Violates Kebab-Case",
        "Workspace and homelab directories must follow lowercase kebab-case naming standard defined in agent-conventions.md.",
        r"(?m)^.*stenio-naming-marker.*$",
        &["*"],
        Some("Rename directory to lowercase kebab-case (e.g. sumaenima-hub, stirps-petri)."),
    ));

    // ── 37. Custom and Dynamically Learned Rules (steniocheck.toml) ────────

    if let Some(custom_rules) = &config.custom_rules {
        for cr in custom_rules {
            let sev = match cr.severity.as_deref().map(|s| s.to_lowercase()).as_deref() {
                Some("warning") | Some("warn") => Severity::Warning,
                _ => Severity::Error,
            };
            let rule = Rule {
                id: cr.id.clone(),
                tag: cr.tag.clone().unwrap_or_else(|| "custom".to_string()),
                severity: sev,
                name: cr.name.clone(),
                description: cr.description.clone(),
                pattern: cr.pattern.clone(),
                file_extensions: cr.extensions.clone(),
                must_match: cr.must_match.unwrap_or(false),
                suggestion: cr.suggestion.clone(),
                fix_replacement: cr.fix_replacement.clone(),
                path_includes: cr.path_include.clone().unwrap_or_default(),
                path_excludes: cr.path_exclude.clone().unwrap_or_default(),
                // Learned rules (`--learn`) do NOT expose context: these fields
                // are engine-only, preventing artificial context rule creation.
                requires_pattern: None,
                severity_without_requires: None,
            };
            rules.push(rule);
        }
    }

    rules
}
