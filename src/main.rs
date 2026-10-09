use anyhow::Result;
use clap::Parser;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};

mod baseline;
mod clean;
mod config;
mod context;
mod cv;
mod deploy;
mod doc;
mod dry;
mod dry_ast;
mod engine;
mod explain;
mod frontend;
mod gaming;
mod gov;
mod gpu;
mod guardian;
mod health;
mod homelab;
mod infra;
mod learner;
mod mcp;
mod mesh;
mod migrations;
mod ports;
pub mod remote;
mod rule;
mod tools;
mod typegen;
mod vault;
mod watch;

use guardian::audit_stenio_integrity;

use baseline::Whitelist;
use config::SteniocheckConfig;
use cv::audit_curriculum_vitae;
use doc::audit_documentation;
use dry::{print_dry_report, scan_dry_directory};
use engine::{Engine, Violation};
use gov::audit_governance;
use gpu::audit_gpu_subsystem;
use homelab::audit_homelab;
use infra::{audit_compose_dir, audit_infrastructure};
use migrations::audit_migrations;
use rule::{Rule, Severity, get_rules_from_config};
use vault::audit_vault;

#[derive(Parser, Debug)]
#[command(
    name = "stenio",
    author = "Sumænimá Platform",
    version = env!("CARGO_PKG_VERSION"),
    about = "StenioSentinel — Universal Governance & Homelab Engine in Rust"
)]
struct Args {
    #[arg(
        short = 's',
        long,
        help = "Audit scope: hub, homelab, vault, cv, fork (derived repo), mirror (generated repo), all [default: all]"
    )]
    scope: Option<String>,

    #[arg(
        short,
        long,
        help = "Filter rules by tag (e.g. sec, arch, frontend, infra, gov, gpu, doc, db, custom)"
    )]
    tag: Option<String>,

    #[arg(
        short,
        long,
        help = "Fast mode: scan only Git-modified files"
    )]
    fast: bool,

    #[arg(long, help = "Root path for scanning", default_value = ".")]
    path: PathBuf,

    #[arg(long, help = "Emit output in JSON format")]
    json: bool,

    #[arg(long, help = "Format errors as GitHub Actions annotations")]
    github_format: bool,

    #[arg(long, help = "Fail immediately with exit code 1 if errors are found")]
    strict: bool,

    #[arg(
        long,
        help = "Dynamically learn new rule and persist in steniocheck.toml (JSON)"
    )]
    learn: Option<String>,

    #[arg(long, help = "List all active rules and automata")]
    list: bool,

    #[arg(
        long,
        help = "Execute only a specific rule (e.g. --only FRONT-HEX)"
    )]
    only: Option<String>,

    #[arg(
        long,
        help = "Run synthetic self-test suite of engine rules"
    )]
    self_test: bool,

    #[arg(
        long,
        help = "Run full health diagnostics on infrastructure, disk, RAM, GPU and services"
    )]
    health: bool,

    #[arg(
        long,
        help = "Run Gaming Health diagnostics (session-aware: VRAM dmemcg, Hyprland scanout, game stack, kernel, shader cache)"
    )]
    gaming: bool,

    #[arg(
        long,
        help = "Audit Tailscale mesh connectivity across Homelab nodes via Tokio"
    )]
    mesh: bool,

    #[arg(
        long,
        help = "Audit local and remote attack surface and open ports against canonical catalog"
    )]
    ports: bool,

    #[arg(
        long,
        help = "Audit operational tools in /usr/local/bin against repository versioned state (source of truth)"
    )]
    tools: bool,

    #[arg(
        long,
        help = "Automatically generate TypeScript types from Rust structs"
    )]
    typegen: bool,

    #[arg(
        long,
        help = "Generate high-density canonical context for LLMs in Markdown"
    )]
    context: bool,

    #[arg(
        long,
        help = "Apply automatic repairs (auto-fix) on repairable violations"
    )]
    fix: bool,

    #[arg(
        long,
        help = "Audit cryptographic integrity and anti-tampering mechanisms of Stenio itself"
    )]
    guardian: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "",
        help = "Surgical scan only on Git-modified files (e.g. --diff, --diff HEAD~1, --diff - for stdin)"
    )]
    diff: Option<String>,

    #[arg(
        long,
        help = "Manage Git pre-commit hook: 'install' to install in repository, or 'check' to execute validation"
    )]
    pre_commit: Option<String>,

    #[arg(
        long,
        help = "Ultra-compact single-line output per violation (optimized for AI agents and LLMs)"
    )]
    compact: bool,

    #[arg(
        long,
        help = "Watchdog Daemon mode: monitor filesystem via inotify and audit saved files instantly (<5ms)"
    )]
    watch: bool,

    #[arg(
        long,
        alias = "mcp-server",
        help = "MCP Server mode: run as Model Context Protocol server (stdio/JSON-RPC 2.0) for OpenCode, Claude Code, Antigravity, Cursor"
    )]
    mcp: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "all",
        help = "Display detailed technical documentation, bad/good examples, and remediation for rules (e.g. --explain SEC-SUDO, --explain RUST-NO-UNWRAP)"
    )]
    explain: Option<String>,

    #[arg(
        long,
        help = "Pre-Delivery Quality Gate: zero-tolerance audit that blocks AI agents if any error is found"
    )]
    gate: bool,

    #[arg(
        long,
        help = "Audit code duplication using Absolute DRY Principle with Rolling Block Hash (<15ms)"
    )]
    dry: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "safe",
        help = "Intelligent Janitor & Housekeeping: cleans caches, temp files (*.tmp, *.bak), Rust build trees (target/) and Docker clutter (dangling images, stopped containers). Modes: 'safe' (default), 'targets', 'temp', 'docker', 'all'"
    )]
    clean: Option<String>,

    #[arg(
        long,
        help = "Simulate cleanup (--clean) displaying what would be removed and reclaimable space without modifying disk"
    )]
    dry_run: bool,

    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "front",
        help = "Automated deployment for Sumænimá ecosystem (e.g. --deploy front, --deploy sync)"
    )]
    deploy: Option<String>,
}

fn install_pre_commit_hook(start_dir: &Path) -> Result<()> {
    let canonical = if let Ok(c) = fs::canonicalize(start_dir) {
        c
    } else {
        start_dir.to_path_buf()
    };
    let mut current = canonical.as_path();
    loop {
        let git_dir = current.join(".git");
        if git_dir.is_dir() {
            let hooks_dir = git_dir.join("hooks");
            fs::create_dir_all(&hooks_dir)?;
            let hook_file = hooks_dir.join("pre-commit");
            let hook_script = r#"#!/usr/bin/env bash
# StenioSentinel Universal Pre-Commit Hook (v3.1)
# Auto-installed by StenioSentinel
set -euo pipefail

if command -v stenio >/dev/null 2>&1; then
    echo "🛡️  [StenioSentinel] Auditing staged files..."
    exec stenio --diff staged --strict
else
    echo "⚠️  [StenioSentinel] 'stenio' binary not found in PATH. Skipping verification."
fi
"#;
            fs::write(&hook_file, hook_script)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(&hook_file) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(&hook_file, perms);
                }
            }
            println!(
                "{} Pre-commit hook installed successfully at: {}",
                "✨".green().bold(),
                hook_file.display().to_string().cyan().bold()
            );
            return Ok(());
        }
        match current.parent() {
            Some(p) => current = p,
            None => break,
        }
    }
    anyhow::bail!(
        "No Git repository (.git) found starting from {:?}",
        start_dir
    );
}

/// Builds two synthetic files from `a`/`b` and returns the severity of the first
/// duplication the DRY engine reports between them (`None` = no duplication).
fn dry_run(a: &[&str], b: &[&str]) -> Option<Severity> {
    let mk = |name: &str, lines: &[&str]| dry::FileRecord {
        path: PathBuf::from(name),
        rel_path: name.to_string(),
        has_ignore: false,
        substantive: lines
            .iter()
            .enumerate()
            .map(|(i, t)| dry::SubstantiveLine {
                line_no: i + 1,
                text: t.trim().to_string(),
            })
            .collect(),
    };
    let fa = mk("CanaryA.rs", a);
    let fb = mk("CanaryB.rs", b);
    let whitelist = Whitelist::default();
    dry::detect_dry_duplication(&[fa, fb], 6, &whitelist)
        .first()
        .map(|v| v.severity)
}

/// Convenience predicate over [`dry_run`] for the boolean canaries.
fn dry_has_violation(a: &[&str], b: &[&str]) -> bool {
    dry_run(a, b).is_some()
}

fn run_self_tests(rules: &[Rule]) -> Result<()> {
    baseline::print_banner("StenioKernel — Synthetic Self-Test Suite");

    let mut passed = 0;
    let mut total = 0;

    macro_rules! check_case {
        ($name:expr, $pattern_id:expr, $sample:expr, $expected_match:expr) => {
            total += 1;
            let rule_opt = rules.iter().find(|r| r.id == $pattern_id);
            if let Some(rule) = rule_opt {
                let re = regex::Regex::new(&rule.pattern)?;
                let is_m = re.is_match($sample);
                if is_m == $expected_match {
                    passed += 1;
                    println!("   ✅ Test {:<24} [{}] - OK", $name, $pattern_id.cyan());
                } else {
                    println!(
                        "   ❌ Test {:<24} [{}] - FAILED (expected match={})",
                        $name,
                        $pattern_id.red(),
                        $expected_match
                    );
                }
            } else {
                println!("   ⚠️ Rule {} not found", $pattern_id.yellow());
            }
        };
    }

    check_case!("Banned Python", "ARCH-NO-PYTHON", "print('hello')", true);
    check_case!(
        "Tokio Thread Sleep",
        "RUST-ASYNC-SLEEP",
        "#[tokio::main] async fn main() { std::thread::sleep(std::time::Duration::from_millis(100)); }", // stenio-ignore: RUST-ASYNC-SLEEP
        true
    );
    // RUST-ASYNC-SLEEP is context-dependent: Error in async files, Warning in
    // sync code (visible without blocking). The probe uses `concat!` to avoid planting
    // the rule literal in this file itself.
    if let Some(rule) = rules.iter().find(|r| r.id == "RUST-ASYNC-SLEEP") {
        total += 1;
        let probe = concat!("std::thread::", "sleep(x);");
        let pattern = regex::Regex::new(&rule.pattern)?;
        let context = rule
            .requires_pattern
            .as_ref()
            .map(|p| regex::Regex::new(p))
            .transpose()?;
        let async_ctx = context
            .as_ref()
            .map(|r| r.is_match("async fn f() { g().await; }"))
            .unwrap_or(false);
        let sync_ctx = context
            .as_ref()
            .map(|r| r.is_match("let _ = 1;"))
            .unwrap_or(true);
        let ok = pattern.is_match(probe)
            && async_ctx
            && !sync_ctx
            && matches!(rule.severity_without_requires, Some(Severity::Warning));
        if ok {
            passed += 1;
            println!(
                "   ✅ Test {:<24} [{}] - OK",
                "Sleep: async context",
                "RUST-ASYNC-SLEEP".cyan()
            );
        } else {
            println!(
                "   ❌ Test {:<24} [{}] - FAILED",
                "Sleep: async context",
                "RUST-ASYNC-SLEEP".red()
            );
        }
    }
    check_case!(
        "Valid Tokio Sleep",
        "RUST-ASYNC-SLEEP",
        "tokio::time::sleep(Duration::from_millis(100)).await;",
        false
    );
    check_case!(
        "Hardcoded Secret",
        "SEC-SECRETS",
        "api_key = \"ghp_123456789012345678901234567890123456\"", // stenio-ignore: SEC-SECRETS
        true
    );
    check_case!(
        "Unprotected Sudo",
        "SEC-SUDO",
        "sudo systemctl restart nginx",
        true
    );
    check_case!(
        "Unprotected Sudo curl",
        "SEC-SUDO",
        "sudo curl https://example.com",
        true
    ); // New: matches any command
    check_case!(
        "Unprotected Sudo useradd",
        "SEC-SUDO",
        "sudo useradd -m user",
        true
    ); // New: was blind spot
    check_case!(
        "Valid Pkexec",
        "SEC-SUDO",
        "pkexec systemctl restart nginx",
        false
    );
    check_case!(
        "Forbidden Bare Except",
        "SEC-EXCEPT",
        "except:\n    pass",
        true
    );
    check_case!(
        "Typed Except",
        "SEC-EXCEPT",
        "except ValueError:\n    pass",
        false
    );
    check_case!(
        "GNU Tools in Shell",
        "ARCH-RUST-TOOLS",
        "grep -r pattern .",
        true
    ); // New: AGENTS.md terminal preference rule
    check_case!(
        "Valid Rust Tools",
        "ARCH-RUST-TOOLS",
        "rg 'pattern' .",
        false
    ); // New: rg does not trigger
    check_case!(
        "Forbidden Curl in Rust",
        "ARCH-RUST-CMD-LEGACY",
        r#"Command::new("curl")"#,
        true
    ); // New: ARCH-RUST-CMD-LEGACY rule
    check_case!(
        "Valid XH in Rust",
        "ARCH-RUST-CMD-LEGACY",
        r#"Command::new("xh")"#,
        false
    ); // New: xh does not trigger
    check_case!(
        "Forbidden Console.log",
        "FRONT-LOGS",
        "  console.log('debug info')",
        true
    ); // Novo: FRONT-LOGS
    check_case!(
        "Forbidden Unwrap",
        "RUST-NO-UNWRAP",
        "let val = opt.unwrap();",
        true
    );
    check_case!(
        "Forbidden Expect",
        "RUST-NO-UNWRAP",
        r#"let val = opt.expect("erro");"#,
        true
    );
    check_case!(
        "Valid Match",
        "RUST-NO-UNWRAP",
        "let val = match opt { Some(v) => v, None => return };",
        false
    );

    check_case!(
        "Stub Rest of Code",
        "AGENT-NO-LAZY-STUB",
        "// rest of code here\nfn foo() {}", // stenio-ignore: AGENT-NO-LAZY-STUB
        true
    );
    check_case!(
        "Stub Todo Rust",
        "AGENT-NO-LAZY-STUB",
        r#"todo!("implement later");"#, // stenio-ignore: AGENT-NO-LAZY-STUB
        true
    );
    check_case!(
        "Valid Complete Code",
        "AGENT-NO-LAZY-STUB",
        "fn calculate() -> i32 { 42 }",
        false
    );
    check_case!(
        "ts-ignore Suppression",
        "AGENT-NO-SUPPRESSION-DIRECTIVES",
        "// @ts-ignore\nconst x = 1;",
        true
    );
    check_case!(
        "eslint-disable Suppression",
        "AGENT-NO-SUPPRESSION-DIRECTIVES",
        "/* eslint-disable */\nconst x = 1;",
        true
    );
    check_case!(
        "stenio-ignore all Suppression",
        "AGENT-NO-SUPPRESSION-DIRECTIVES",
        "// stenio-ignore: all",
        true
    );
    check_case!(
        "no-verify Tampering",
        "AGENT-NO-TAMPERING-VERIFIER",
        "git commit -m 'bypass' --no-verify",
        true
    );
    check_case!(
        "Regular Commit OK",
        "AGENT-NO-TAMPERING-VERIFIER",
        "git commit -m 'feat: implement'",
        false
    );
    check_case!(
        "tsconfig Strict Disabled",
        "CONF-NO-WEAKEN-STRICT",
        "\"strict\": false,",
        true
    );
    check_case!(
        "tsconfig Strict OK",
        "CONF-NO-WEAKEN-STRICT",
        "\"strict\": true,",
        false
    );
    check_case!(
        "Ignored Test Forbidden",
        "TEST-NO-SILENT-SKIP",
        "#[test]\n#[ignore]\nfn test_failure() {}",
        true
    );
    check_case!(
        "Commented Assertion",
        "TEST-NO-SILENT-SKIP",
        "// assert_eq!(res, 42);",
        true
    );
    check_case!(
        "Valid Test",
        "TEST-NO-SILENT-SKIP",
        "#[test]\nfn test_valid() { assert_eq!(1, 1); }",
        false
    );
    check_case!(
        "Empty Catch Forbidden",
        "CODE-NO-EMPTY-CATCH",
        "try { run(); } catch (e) {}",
        true
    );
    check_case!(
        "Catch with Log OK",
        "CODE-NO-EMPTY-CATCH",
        "try { run(); } catch (e) { log(e); }",
        false
    );
    check_case!(
        "Blocking I/O Forbidden",
        "BACKEND-BLOCKING-IO",
        r#"std::fs::read_to_string("data.json");"#, // stenio-ignore: BACKEND-BLOCKING-IO
        true
    );
    check_case!(
        "Tokio Async I/O OK",
        "BACKEND-BLOCKING-IO",
        r#"tokio::fs::read_to_string("data.json").await;"#,
        false
    );
    check_case!(
        "Server Panic Forbidden",
        "BACKEND-NO-PANIC",
        r#"panic!("critical error");"#, // stenio-ignore: BACKEND-NO-PANIC
        true
    );
    check_case!(
        "Valid Result Return",
        "BACKEND-NO-PANIC",
        "return Err(AppError::NotFound);",
        false
    );
    check_case!(
        "Zero-Repaint Box-Shadow",
        "PERF-GPU-ZERO-REPAINT",
        "transition: box-shadow 0.3s ease;", // stenio-ignore: PERF-GPU-ZERO-REPAINT
        true
    );
    check_case!(
        "Zero-Repaint Opacity OK",
        "PERF-GPU-ZERO-REPAINT",
        "transition: opacity 0.25s ease;",
        false
    );
    check_case!(
        "Layout Thrashing rect",
        "PERF-NO-LAYOUT-THRASH",
        "const rect = el.getBoundingClientRect();",
        true
    );
    check_case!(
        "Static will-change",
        "PERF-GPU-WILL-CHANGE",
        "will-change: transform;",
        true
    );
    check_case!(
        "Front Modular Hooks",
        "FRONT-MODULAR-HOOKS",
        "const res = await fetch('/api/cards');",
        true
    );
    check_case!(
        "Feedback on Error",
        "FRONT-FEEDBACK-ON-ERROR",
        "console.error(\"erro\");",
        true
    );
    // ── Specialized Frontend Validation Tests (audit_frontend_file) ─────
    total += 1;
    let v_lh = frontend::audit_frontend_file(
        &PathBuf::from("frontend/src/api.ts"),
        "const url = \"http://localhost:8000/api\";",
        &Whitelist::default(),
    );
    if v_lh.iter().any(|v| v.rule_id == "FRONT-NO-HARDCODED-HOST") {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Hardcoded Localhost",
            "FRONT-NO-HARDCODED-HOST".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Hardcoded Localhost",
            "FRONT-NO-HARDCODED-HOST".red()
        );
    }

    total += 1;
    let v_ok = frontend::audit_frontend_file(
        &PathBuf::from("frontend/src/api.ts"),
        "const url = \"/api/v1/cards\";",
        &Whitelist::default(),
    );
    if !v_ok.iter().any(|v| v.rule_id == "FRONT-NO-HARDCODED-HOST") {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Valid Relative Host",
            "FRONT-NO-HARDCODED-HOST".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Valid Relative Host",
            "FRONT-NO-HARDCODED-HOST".red()
        );
    }

    // ── Specialized SEO Validation Tests (SEO-* Rules) ───────────────────
    total += 1;
    let v_seo_bad = frontend::audit_frontend_file(
        &PathBuf::from("frontend/index.html"),
        "<!doctype html><html><head><title>Test</title></head></html>",
        &Whitelist::default(),
    );
    if v_seo_bad.iter().any(|v| v.rule_id == "SEO-INDEX-METADATA") {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Missing SEO Meta Desc",
            "SEO-INDEX-METADATA".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Missing SEO Meta Desc",
            "SEO-INDEX-METADATA".red()
        );
    }

    total += 1;
    let v_sitemap_bad = frontend::audit_frontend_file(
        &PathBuf::from("public/sitemap.xml"),
        "not a valid xml sitemap",
        &Whitelist::default(),
    );
    if v_sitemap_bad.iter().any(|v| v.rule_id == "SEO-ROBOTS-SITEMAP") {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Invalid Sitemap XML",
            "SEO-ROBOTS-SITEMAP".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Invalid Sitemap XML",
            "SEO-ROBOTS-SITEMAP".red()
        );
    }

    total += 1;
    let v_img_bad = frontend::audit_frontend_file(
        &PathBuf::from("frontend/src/Card.tsx"),
        "<img src=\"/hero.jpg\" />",
        &Whitelist::default(),
    );
    if v_img_bad.iter().any(|v| v.rule_id == "SEO-IMG-ALT") {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Forbidden Image Missing Alt",
            "SEO-IMG-ALT".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Forbidden Image Missing Alt",
            "SEO-IMG-ALT".red()
        );
    }

    // ── SQL Idempotency Test (check_sql_idempotency) ───────────────────────
    total += 1;
    if migrations::check_sql_idempotency("CREATE TABLE users (id INT);").is_some() {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Non-Idempotent SQL",
            "DB-IDEMPOTENT-MIGRATION".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Non-Idempotent SQL",
            "DB-IDEMPOTENT-MIGRATION".red()
        );
    }

    total += 1;
    if migrations::check_sql_idempotency("CREATE TABLE IF NOT EXISTS users (id INT);").is_none() {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "Valid Idempotent SQL",
            "DB-IDEMPOTENT-MIGRATION".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Valid Idempotent SQL",
            "DB-IDEMPOTENT-MIGRATION".red()
        );
    }

    // ── Tests for 6 Anti-Laziness / Anti-Bug Rust Best Practices ──────────
    check_case!(
        "Unbounded Channel",
        "RUST-NO-UNBOUNDED-CHANNEL",
        "let (tx, rx) = tokio::sync::mpsc::unbounded_channel();",
        true
    );
    check_case!(
        "Bounded Channel OK",
        "RUST-NO-UNBOUNDED-CHANNEL",
        "let (tx, rx) = tokio::sync::mpsc::channel(64);",
        false
    );
    check_case!(
        "Sync Cmd in Async",
        "RUST-ASYNC-BLOCKING-CMD",
        "let out = std::process::Command::new(\"ls\");",
        true
    );
    check_case!(
        "Tokio Cmd OK",
        "RUST-ASYNC-BLOCKING-CMD",
        "let out = tokio::process::Command::new(\"ls\");",
        false
    );
    check_case!(
        "Sync Mutex in Async",
        "RUST-NO-SYNC-MUTEX-AWAIT",
        "let m: std::sync::Mutex<i32> = std::sync::Mutex::new(0);",
        true
    );
    check_case!(
        "Tokio Mutex OK",
        "RUST-NO-SYNC-MUTEX-AWAIT",
        "let m: tokio::sync::Mutex<i32> = tokio::sync::Mutex::new(0);",
        false
    );
    check_case!(
        "Non-Idiomatic Arc Clone",
        "RUST-IDIOMATIC-ARC-CLONE",
        "let state = server_arc.clone();",
        true
    );
    check_case!(
        "Idiomatic Arc Clone OK",
        "RUST-IDIOMATIC-ARC-CLONE",
        "let state = Arc::clone(&server_arc);",
        false
    );
    check_case!(
        "Parameter &String",
        "RUST-IDIOMATIC-SLICES",
        "fn fetch_user(name: &String) -> bool { true }",
        true
    );
    check_case!(
        "Parameter &str OK",
        "RUST-IDIOMATIC-SLICES",
        "fn fetch_user(name: &str) -> bool { true }",
        false
    );
    check_case!(
        "Orphan Tokio Spawn",
        "RUST-SPAWN-ERROR-HANDLING",
        "    tokio::spawn(async move {",
        true
    );

    // ── Synthetic Test for DRY Engine (Rolling Block Hash) ───────────────
    total += 1;
    let sample_f1 = dry::FileRecord {
        path: PathBuf::from("ComponentA.tsx"),
        rel_path: "ComponentA.tsx".to_string(),
        has_ignore: false,
        substantive: vec![
            dry::SubstantiveLine {
                line_no: 10,
                text: "const filtered = items.filter(x => x.active);".to_string(),
            },
            dry::SubstantiveLine {
                line_no: 11,
                text: "const sorted = filtered.sort((a, b) => a.order - b.order);".to_string(),
            },
            dry::SubstantiveLine {
                line_no: 12,
                text: "const paginated = sorted.slice(0, 20);".to_string(),
            },
            dry::SubstantiveLine {
                line_no: 13,
                text: "const totalCount = filtered.length;".to_string(),
            },
            dry::SubstantiveLine {
                line_no: 14,
                text: "const isMaxReached = totalCount >= 100;".to_string(),
            },
            dry::SubstantiveLine {
                line_no: 15,
                text: "return { paginated, totalCount, isMaxReached };".to_string(),
            },
        ],
    };
    let sample_f2 = dry::FileRecord {
        path: PathBuf::from("ComponentB.tsx"),
        rel_path: "ComponentB.tsx".to_string(),
        has_ignore: false,
        substantive: sample_f1.substantive.clone(),
    };
    let empty_whitelist = Whitelist::default();
    let dry_v = dry::detect_dry_duplication(&[sample_f1, sample_f2], 6, &empty_whitelist);
    if !dry_v.is_empty() && dry_v[0].rule_id == "ARCH-DRY-DUPLICATION" {
        passed += 1;
        println!(
            "   ✅ Test {:<24} [{}] - OK",
            "DRY Block Duplication",
            "ARCH-DRY-DUPLICATION".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "DRY Block Duplication",
            "ARCH-DRY-DUPLICATION".red()
        );
    }

    // ── DRY canaries: precision & recall guards (ARCH-DRY-DUPLICATION) ───
    let dry_logic: [&str; 6] = [
        "let filtered = items.iter().filter(|x| x.active).collect::<Vec<_>>();",
        "let ordered = filtered.iter().map(|x| x.order).collect::<Vec<_>>();",
        "let page = ordered.iter().skip(offset).take(limit).collect::<Vec<_>>();",
        "let total = filtered.len();",
        "let reached = total >= 100;",
        "return (page, total, reached);",
    ];
    let dry_declarative: [&str; 6] = [
        "severity: Severity::Warning,",
        "file_path: display_path.clone(),",
        "line_number: 1,",
        "snippet: format!(\"{}:\", svc_name),",
        "message,",
        "suggestion,",
    ];
    for (label, lines, expect) in [
        ("DRY logic clone", dry_logic, true),
        ("DRY declarative tail", dry_declarative, false),
    ] {
        total += 1;
        let got = dry_has_violation(&lines, &lines);
        if got == expect {
            passed += 1;
            println!(
                "   ✅ Test {:<26} [{}] - OK",
                label,
                "ARCH-DRY-DUPLICATION".cyan()
            );
        } else {
            println!(
                "   ❌ Test {:<26} [{}] - FAILED (got {}, expect {})",
                label,
                "ARCH-DRY-DUPLICATION".red(),
                got,
                expect
            );
        }
    }

    // ── DRY severity canary: mostly-declarative block -> Warning ─────────
    total += 1;
    let dry_mixed: [&str; 6] = [
        "let value = compute(input);",
        "severity: Severity::Warning,",
        "file_path: display_path.clone(),",
        "line_number: 1,",
        "message,",
        "suggestion,",
    ];
    if dry_run(&dry_mixed, &dry_mixed) == Some(Severity::Warning) {
        passed += 1;
        println!(
            "   ✅ Test {:<26} [{}] - OK",
            "DRY severity warning",
            "ARCH-DRY-DUPLICATION".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<26} [{}] - FAILED",
            "DRY severity warning",
            "ARCH-DRY-DUPLICATION".red()
        );
    }

    // ── AST structural canary (Fase 2): formatting-invariant detection ───
    total += 1;
    let ast_src = "fn lower(p: &std::path::Path) -> String {\n    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or(\"\").to_lowercase();\n    ext\n}\n";
    let ast_units = dry_ast::rust_units(ast_src, 8);
    let ast_files = vec![
        ("CanaryA.rs".to_string(), ast_units.clone()),
        ("CanaryB.rs".to_string(), ast_units),
    ];
    if !dry_ast::detect_ast_duplication(&ast_files, 8).is_empty() {
        passed += 1;
        println!(
            "   ✅ Test {:<26} [{}] - OK",
            "DRY ast structural",
            "ARCH-DRY-DUPLICATION".cyan()
        );
    } else {
        println!(
            "   ❌ Test {:<26} [{}] - FAILED",
            "DRY ast structural",
            "ARCH-DRY-DUPLICATION".red()
        );
    }

    // ── Monorepo Scope Isolation Test (ARCH-SCOPE-ISOLATION) ─────────────
    total += 1;
    let mixed_paths = vec![
        PathBuf::from(
            "/mnt/NVME_PCI/agentic-ai/sumaenimahub/sumaenima-hub/app/frontend-v2/src/App.tsx",
        ),
        PathBuf::from("/mnt/NVME_PCI/agentic-ai/governance/stenio/src/engine.rs"),
    ];
    if let Some(v) = engine::Engine::check_scope_isolation(&mixed_paths) {
        if v.rule_id == "ARCH-SCOPE-ISOLATION" {
            passed += 1;
            println!(
                "   ✅ Test {:<24} [{}] - OK",
                "Scope Isolation",
                "ARCH-SCOPE-ISOLATION".cyan()
            );
        } else {
            println!(
                "   ❌ Test {:<24} [{}] - FAILED",
                "Scope Isolation",
                "ARCH-SCOPE-ISOLATION".red()
            );
        }
    } else {
        println!(
            "   ❌ Test {:<24} [{}] - FAILED",
            "Scope Isolation",
            "ARCH-SCOPE-ISOLATION".red()
        );
    }

    println!();
    if passed == total {
        println!(
            "{}",
            format!(
                "✨ Self-test suite passed successfully! ({}/{} synthetic test suites valid)",
                passed, total
            )
            .green()
            .bold()
        );
    } else {
        println!(
            "{}",
            format!("❌ Self-test failure ({}/{} passed)", passed, total)
                .red()
                .bold()
        );
        std::process::exit(1);
    }
    println!();
    Ok(())
}

fn run_quality_gate(args: &Args, rules: &[Rule], whitelist: &Whitelist) -> Result<()> {
    baseline::print_banner("StenioSentinel Quality Gate (v3.2) — Rigorous Pre-Delivery Inspection");
    println!(
        "{}",
        "🛡️  Executing holistic zero-tolerance audit for task release...\n"
            .white()
    );

    let engine = Engine::new(rules.to_vec(), whitelist.clone())?;
    let report = engine.scan_directory(&args.path, None, None, false, None, false)?;

    let gov_result = audit_governance(&args.path);
    let doc_result = audit_documentation(&args.path);
    let guardian_report =
        audit_stenio_integrity(&PathBuf::from("/mnt/NVME_PCI/agentic-ai/governance/stenio"));

    let mut blocker_errors = Vec::new();

    // 1. Violations with severity Error
    for v in &report.violations {
        if v.severity == Severity::Error {
            blocker_errors.push(format!(
                "[{}] {}:{}: {} (💡 {})",
                v.rule_id.red().bold(),
                v.file_path,
                v.line_number,
                v.message,
                v.suggestion.as_deref().unwrap_or("See --explain")
            ));
        }
    }

    // 2. Governance errors (including GOV-LEFTOVER-TEST-ARTIFACTS)
    for err in &gov_result.errors {
        blocker_errors.push(format!("[GOVERNANCE] {}", err));
    }

    // 3. Corrupted documentation / broken links
    for v in &doc_result.violations {
        if v.severity == Severity::Error {
            blocker_errors.push(format!(
                "[DOC-ERROR] {}:{}: {}",
                v.file_path, v.line_number, v.message
            ));
        }
    }

    // 4. Guardian anti-tampering
    for alert in &guardian_report.tamper_alerts {
        blocker_errors.push(format!("[GUARDIAN] {}", alert));
    }

    // 5. Absolute DRY Principle (Zero Code Duplication)
    let (dry_violations, _dry_count, _dry_dur) = scan_dry_directory(&args.path, 6, whitelist);
    let mut dry_warnings = 0usize;
    for dv in &dry_violations {
        if dv.severity == Severity::Warning {
            // Adaptive severity: low logic-density duplication is surfaced but
            // does not block delivery (ARCH-DRY-DUPLICATION stays non-impeditive).
            dry_warnings += 1;
            continue;
        }
        blocker_errors.push(format!(
            "[{}] {}:{}: {} (💡 {})",
            dv.rule_id.red().bold(),
            dv.file_path,
            dv.line_number,
            dv.message,
            dv.suggestion
                .as_deref()
                .unwrap_or("Abstract duplicated logic")
        ));
    }

    if blocker_errors.is_empty() {
        baseline::print_banner_green(
            "🎉 [GATE PASSED] Congratulations! Code is 100% compliant with rules.",
        );
        println!(
            "   • {} files audited successfully.",
            report.total_files_scanned
        );
        println!("   • Zero blocking errors.");
        println!("   • Zero stubs or placeholders detected.");
        println!("   • Zero silenced tests.");
        if dry_warnings == 0 {
            println!("   • Zero code duplication (100% DRY).");
        } else {
            println!(
                "   • Zero blocking duplication; {} non-blocking DRY warning(s).",
                dry_warnings
            );
        }
        println!("   • Zero leftover test artifacts.");
        println!();
        println!(
            "{}",
            "✨ Task is formally APPROVED for delivery to user with full quality assurance!"
                .green()
                .bold()
        );
        println!();
        return Ok(());
    }

    // If there are any blocking errors
    baseline::print_banner_red("🛑 [GATE REJECTED] Delivery Blocked by StenioSentinel!");
    println!(
        "{}",
        format!(
            "AI agent is NOT allowed to complete the task. Found {} blocking violation(s):\n",
            blocker_errors.len()
        )
        .red()
    );

    for (idx, err) in blocker_errors.iter().enumerate() {
        println!("   {}. {}", idx + 1, err);
    }

    println!();
    println!(
        "{}",
        "💡 MANDATORY INSTRUCTIONS FOR AI AGENT:"
            .yellow()
            .bold()
    );
    println!("   1. You MUST fix every violation listed above before finishing.");
    println!(
        "   2. Run 'stenio --explain <RULE_ID>' to view compliant code and remediation."
    );
    println!(
        "   3. It is STRICTLY FORBIDDEN to bypass errors by disabling tests, adding stubs, or suppressing rules."
    );
    println!("   4. Re-run 'stenio --gate' until receiving [GATE PASSED].");
    println!();

    std::process::exit(1);
}

fn main() -> Result<()> {
    let args = Args::parse();

    // ── Modo Deploy Automatizado (--deploy [target]) ────────────────────────
    if let Some(ref target) = args.deploy {
        match target.as_str() {
            "front" | "frontend" => {
                deploy::execute_front_deploy(&args.path, true)?;
                return Ok(());
            }
            "sync" | "sync-front" => {
                deploy::execute_front_deploy(&args.path, false)?;
                return Ok(());
            }
            other => {
                eprintln!(
                    "{} Unknown deploy target: '{}'. Available options: 'front' (build + sync), 'sync' (sync without build).",
                    "⚠️".yellow(),
                    other
                );
                std::process::exit(1);
            }
        }
    }

    // ── Rule Explanation Mode (--explain [RULE_ID]) ───────────────────────
    if let Some(ref rule_target) = args.explain {
        if rule_target == "all" || rule_target.is_empty() {
            println!("{}", explain::list_all_explanations());
        } else if let Some(exp) = explain::get_explanation(rule_target) {
            println!("{}", explain::format_explanation_cli(exp));
        } else {
            eprintln!(
                "{} No explanation found for rule '{}'.",
                "⚠️".yellow(),
                rule_target
            );
            println!("{}", explain::list_all_explanations());
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Modo Aprendizado: Aprender nova regra e persistir no steniocheck.toml ──
    if let Some(ref payload) = args.learn {
        learner::handle_learn(&args.path, payload)?;
        return Ok(());
    }

    // ── Modo Raio-X de Infraestrutura (--health) ───────────────────────────
    if args.health {
        health::run_system_health()?;
        return Ok(());
    }

    // ── Modo Raio-X de Gaming Health (--gaming) ────────────────────────────
    if args.gaming {
        gaming::run_gaming_health()?;
        return Ok(());
    }

    // ── Modo Malha Tailscale Homelab (--mesh) ──────────────────────────────
    if args.mesh {
        let rt = tokio::runtime::Runtime::new()?;
        let start = std::time::Instant::now();
        let results = rt.block_on(mesh::audit_tailscale_mesh());
        mesh::print_mesh_report(&results, start.elapsed());
        return Ok(());
    }

    // ── Port Gatekeeper & Attack Surface Mode (--ports) ───────────────────
    if args.ports {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(ports::run_ports_audit(&args.path))?;
        return Ok(());
    }

    // ── Operation Tools Mode (--tools) ──────────────────────────────────────
    //
    // Cross-checks tools installed in `/usr/local/bin` across homelab hosts
    // with versioned scripts in `provisioning/`. Source of truth is
    // `install-homelab-tools.sh`.
    if args.tools {
        tools::run_tools_audit(&args.path)?;
        return Ok(());
    }

    // ── Automated Rust → TypeScript Typegen Mode (--typegen) ──────────────
    if args.typegen {
        let target_dir = if args.path.join("app/frontend-v2").is_dir() {
            args.path.clone()
        } else if PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub").is_dir() {
            PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub")
        } else if PathBuf::from("/mnt/NVME_PCI/agentic-ai/sumaenimahub/sumaenima-hub").is_dir() {
            PathBuf::from("/mnt/NVME_PCI/agentic-ai/sumaenimahub/sumaenima-hub")
        } else {
            args.path.clone()
        };
        typegen::generate_typescript_bindings(&target_dir)?;
        return Ok(());
    }

    // ── LLM Knowledge Context Engine Mode (--context) ─────────────────────
    if args.context {
        context::generate_llm_context(&args.path);
        return Ok(());
    }

    // ── Smart Cleanup & Repository Hygiene Mode (--clean) ─────────────────
    if let Some(ref mode) = args.clean {
        let rep = clean::run_clean(&args.path, mode, args.dry_run)?;
        clean::print_clean_report(&rep);
        return Ok(());
    }

    // ── Pre-Commit Hook Mode (--pre-commit install / check) ───────────────
    if let Some(ref action) = args.pre_commit {
        match action.as_str() {
            "install" => {
                install_pre_commit_hook(&args.path)?;
                return Ok(());
            }
            "check" => {
                // Continue execution in diff mode with staged target
            }
            other => {
                eprintln!(
                    "Unknown action for --pre-commit: '{}'. Use 'install' or 'check'.",
                    other
                );
                std::process::exit(1);
            }
        }
    }

    // ── Guardian Anti-Tampering & Self-Preservation Mode (--guardian) ────────
    if args.guardian {
        let stenio_src = PathBuf::from("/mnt/NVME_PCI/agentic-ai/governance/stenio");
        let rep = audit_stenio_integrity(&stenio_src);
        baseline::print_banner(
            "StenioSentinel — Guardian: Cryptographic Self-Defense & Anti-Tampering",
        );
        for m in &rep.messages {
            println!("   {}", m);
        }
        if !rep.tamper_alerts.is_empty() {
            println!();
            for a in &rep.tamper_alerts {
                println!("   {}", a.red().bold());
            }
        }
        println!();
        return Ok(());
    }

    let whitelist_path = args.path.join(".steniocheck-whitelist-registry.json");
    let whitelist = Whitelist::load_from_file(&whitelist_path);

    // Load canonical configuration steniocheck.toml
    let steniocheck_cfg = SteniocheckConfig::load_from_dir(&args.path);
    let mut rules = get_rules_from_config(&steniocheck_cfg);

    // ── Scope `fork`: DERIVED repository (third-party fork) ───────────────
    //
    // WHY IT EXISTS (2026-09-29): a fork receives the ecosystem's AUTHORIAL laws,
    // but they describe how the author builds their own software — not how to
    // contribute to an external project. Real case: `macrokey-driver` (fork of a
    // Python driver) produced ~305 `ARCH-NO-PYTHON` errors, requiring rewriting
    // upstream. A red gate that no one can fix is worse than having no gate:
    // it trains everyone to ignore the result.
    //
    // This scope retains only what protects a derived repository:
    //   SEC-*  (secrets, sudo, SQL, except)  — protect the author
    //   VAULT-* (frontmatter, taxonomy)      — note integrity
    //   DOC-*  (disclaimer, anchors)         — governance traceability
    //   GOV-LEFTOVER-TEST-ARTIFACTS          — test artifact cleanup
    //   HOMELAB-* / INFRA-* when target is infrastructure
    //
    // Excluded: ARCH-*, RUST-*, GOV-AGENT-LAWS, FRONT-*, BACKEND-*, TEST-*, DB-*,
    // PERF-*, CONF-*, AGENT-* — all presuppose authorial ecosystem code.
    //
    // See `governance/agent-conventions.md` §2b and
    // `governance/stenio-troubleshooting.md` §3.
    // `--scope` is optional (default `all`); compare without `unwrap` (RUST-NO-UNWRAP).
    let cfg_scope_val = steniocheck_cfg.general.as_ref().and_then(|g| g.scope.as_deref()).unwrap_or("");
    let scope_opt = if !args.scope.as_deref().unwrap_or("").is_empty() {
        args.scope.as_deref().unwrap_or("")
    } else {
        cfg_scope_val
    };
    if scope_opt.eq_ignore_ascii_case("fork") || scope_opt.eq_ignore_ascii_case("derived") {
        let allowed_prefixes: &[&str] = &[
            "SEC-",
            "VAULT-",
            "DOC-",
            "GOV-LEFTOVER-TEST-ARTIFACTS",
            "HOMELAB-",
            "INFRA-",
        ];
        rules.retain(|r| allowed_prefixes.iter().any(|p| r.id.starts_with(p)));
    }

    // ── Scope `mirror`: GENERATED repository (config snapshot mirror) ──────
    //
    // For automated config mirrors of live homelab hosts (e.g. MNEMOCINE-CONFIGS).
    // Filters out code laws (ARCH-*, RUST-*, FRONT-*) while strictly enforcing
    // cleartext secret detection (SEC-*) and compose/systemd syntax (INFRA-*).
    if scope_opt.eq_ignore_ascii_case("mirror")
        || scope_opt.eq_ignore_ascii_case("snapshot")
        || scope_opt.eq_ignore_ascii_case("generated")
    {
        let allowed_prefixes: &[&str] = &["SEC-", "INFRA-", "GOV-LEFTOVER-TEST-ARTIFACTS"];
        rules.retain(|r| allowed_prefixes.iter().any(|p| r.id.starts_with(p)));
    }

    // ── Pre-Delivery Quality Gate Mode (--gate) ─────────────────────────────
    if args.gate {
        run_quality_gate(&args, &rules, &whitelist)?;
        return Ok(());
    }

    // ── DRY Principle Detector Mode (--dry) ─────────────────────────────────
    if args.dry {
        let (violations, files_count, duration) = scan_dry_directory(&args.path, 6, &whitelist);
        print_dry_report(&violations, files_count, duration);
        if !violations.is_empty() && args.strict {
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── MCP Server Mode (JSON-RPC 2.0 stdio protocol for OpenCode, Antigravity, Claude) ──
    if args.mcp {
        mcp::run_mcp_server(&args.path, rules, whitelist)?;
        return Ok(());
    }

    // ── Real-Time Watchdog Mode (--watch with inotify) ────────────────────
    if args.watch {
        let engine = Engine::new(rules, whitelist)?;
        let tag_lower = args.tag.as_ref().map(|s| s.to_lowercase());
        let only_rule = args.only.as_deref();
        watch::start_watch_mode(&args.path, &engine, tag_lower.as_deref(), only_rule)?;
        return Ok(());
    }

    // ── Rules Catalog Listing Mode (--list) ───────────────────────────────
    if args.list {
        baseline::print_banner("StenioKernel — Active Rules & Automata Catalog");
        println!(
            "{:<26} {:<10} {:<8} {:<14} {}",
            "RULE ID".bold(),
            "TAG".bold(),
            "SEV".bold(),
            "EXTENSIONS".bold(),
            "NAME".bold()
        );
        println!(
            "{}",
            "──────────────────────────────────────────────────────────────────────────────"
                .dimmed()
        );

        for r in &rules {
            let sev_str = match r.severity {
                Severity::Error => "ERROR".red().bold(),
                Severity::Warning => "WARN ".yellow().bold(),
            };
            let exts = r.file_extensions.join(", ");
            println!(
                "{:<26} {:<10} {:<8} {:<14} {}",
                r.id.cyan().bold(),
                r.tag.yellow(),
                sev_str,
                format!("[{}]", exts).dimmed(),
                r.name
            );
        }
        println!();
        println!("Total active rules: {}", rules.len().to_string().bold());
        println!();
        return Ok(());
    }

    // ── Self-Test Mode (--self-test) ──────────────────────────────────────
    if args.self_test {
        run_self_tests(&rules)?;
        return Ok(());
    }

    let tag_lower = args.tag.as_deref().map(|s| s.to_lowercase());
    let only_rule = args.only.as_deref();
    let p_canon = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());
    let p_str = p_canon.to_string_lossy();
    let scope = if let Some(s) = args.scope.as_deref() {
        s.to_lowercase()
    } else if !cfg_scope_val.is_empty() {
        cfg_scope_val.to_lowercase()
    } else {
        if p_str.contains("sumaenima-hub")
            || p_str.contains("SUMAENIMA-HUB")
            || (args.path.join("app").is_dir() && args.path.join("migrations").is_dir())
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
        } else if args.path.join("mnemocine").is_dir() && args.path.join("governance").is_dir() {
            "all".to_string()
        } else {
            "project".to_string()
        }
    };

    let is_hub_active = scope == "all" || scope == "hub";
    let is_homelab_active = scope == "all" || scope == "homelab" || scope == "mnemocine";
    let is_vault_active = scope == "all" || scope == "vault" || scope == "docs";
    let is_cv_active = scope == "all" || scope == "cv";

    let should_audit_gpu = is_hub_active
        && (tag_lower.as_deref() == Some("gpu") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("GPU-BLOAT-OR-MODEL"))
                .unwrap_or(false));
    let should_audit_gov = is_hub_active
        && (tag_lower.as_deref() == Some("gov") || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("GOV-AGENT-LAWS"))
                .unwrap_or(false));
    let should_audit_doc = (is_hub_active || is_homelab_active || is_vault_active)
        && (tag_lower.as_deref() == Some("doc") || tag_lower.is_none())
        && (only_rule.is_none() || only_rule.map(|s| s.starts_with("DOC-")).unwrap_or(false));
    let should_audit_mig = is_hub_active
        && (tag_lower.as_deref() == Some("db")
            || tag_lower.as_deref() == Some("migrations")
            || tag_lower.is_none())
        && (only_rule.is_none()
            || only_rule
                .map(|s| s.eq_ignore_ascii_case("DB-MIGRATION-INTEGRITY"))
                .unwrap_or(false));

    let scan_target = if scope == "homelab" || scope == "mnemocine" {
        if args.path.join("mnemocine").is_dir() {
            args.path.join("mnemocine")
        } else {
            args.path.clone()
        }
    } else if scope == "hub" {
        if p_str.contains("sumaenima-hub") || p_str.contains("SUMAENIMA-HUB") {
            args.path.clone()
        } else if args.path.join("sumaenimahub/sumaenima-hub").is_dir() {
            args.path.join("sumaenimahub/sumaenima-hub")
        } else if args.path.join("sumaenimahub/SUMAENIMA-HUB").is_dir() {
            args.path.join("sumaenimahub/SUMAENIMA-HUB")
        } else if args.path.join("sumaenima-hub").is_dir() {
            args.path.join("sumaenima-hub")
        } else if PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub").is_dir() {
            PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub")
        } else {
            args.path.clone()
        }
    } else if scope == "cv" {
        if args.path.join("curriculum-vitae").is_dir() {
            args.path.join("curriculum-vitae")
        } else {
            args.path.clone()
        }
    } else {
        args.path.clone()
    };

    let diff_target: Option<&str> = if args.pre_commit.as_deref() == Some("check") {
        Some("staged")
    } else {
        args.diff.as_deref()
    };

    let engine = Engine::new(rules, whitelist)?;

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
                        args.fast,
                        diff_target,
                        args.fix,
                    )
                },
                || {
                    let g = if should_audit_gov {
                        Some(audit_governance(&args.path))
                    } else {
                        None
                    };
                    let d = if should_audit_doc {
                        Some(audit_documentation(&args.path))
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
                        Some(audit_migrations(&args.path))
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
                                let mut infra = audit_infrastructure(&args.path, true);
                                let mirror = Path::new("/mnt/BACKUP/configs-homelab");
                                if args.path.join("mnemocine").is_dir() && mirror.is_dir() {
                                    let mirror_report = audit_compose_dir(mirror);
                                    infra.total_files_scanned +=
                                        mirror_report.total_files_scanned;
                                    infra.violations.extend(mirror_report.violations);
                                    infra.messages.extend(mirror_report.messages);
                                }
                                (Some(audit_homelab(&args.path)), Some(infra))
                            } else if runs_infra_audit {
                                // Runs infrastructure security audits without homelab-specific documentation constraints.
                                (None, Some(audit_infrastructure(&args.path, false)))
                            } else {
                                (None, None)
                            };
                            let v = if is_vault_active {
                                Some(audit_vault(&args.path))
                            } else {
                                None
                            };
                            ((h, inf), v)
                        },
                        || {
                            if is_cv_active {
                                Some(audit_curriculum_vitae(&args.path))
                            } else {
                                None
                            }
                        },
                    )
                },
            )
        },
    );

    let mut report = scan_res?;

    // ── Governance Subsystem (AGENTS.md & skills) ──────────────────────────
    let mut gov_messages = Vec::new();
    if let Some(gov) = gov_res {
        gov_messages = gov.messages;
        if !gov.errors.is_empty() {
            report.error_count += gov.errors.len();
            report.total_violations += gov.errors.len();
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
        for warn in gov.naming_warnings {
            report.warning_count += 1;
            report.total_violations += 1;
            report.violations.push(warn);
        }
    }

    // ── Documentation Subsystem (docs/ & ADRs) ─────────────────────────────
    let mut doc_messages = Vec::new();
    if let Some(doc) = doc_res {
        doc_messages = doc.messages;
        for v in doc.violations {
            if v.severity == Severity::Error {
                report.error_count += 1;
            } else {
                report.warning_count += 1;
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── GPU & AI Models Subsystem (RTX / NVMe) ────────────────────────────
    let mut gpu_messages = Vec::new();
    if let Some(gpu) = gpu_res {
        gpu_messages = gpu.messages;
        if !gpu.errors.is_empty() {
            report.error_count += gpu.errors.len();
            report.total_violations += gpu.errors.len();
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
            report.error_count += 1;
            report.total_violations += 1;
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
        for v in hl.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Infrastructure Subsystem (Compose, Systemd, SOPS) ─────────────────
    if let Some(inf) = infra_res {
        report.total_files_scanned += inf.total_files_scanned;
        for msg in inf.messages {
            homelab_messages.push(msg);
        }
        for v in inf.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Obsidian Vault Subsystem (Universal Governance) ───────────────────
    let mut vault_messages = Vec::new();
    if let Some(vl) = vault_res {
        report.total_files_scanned += vl.total_files_scanned;
        vault_messages = vl.messages;
        for v in vl.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    // ── Bilingual Curriculum Vitae Subsystem (curriculum-vitae/) ──────────
    let mut cv_messages = Vec::new();
    if let Some(cv) = cv_res {
        report.total_files_scanned += cv.total_files_scanned;
        cv_messages = cv.messages;
        for v in cv.violations {
            match v.severity {
                Severity::Error => report.error_count += 1,
                Severity::Warning => report.warning_count += 1,
            }
            report.total_violations += 1;
            report.violations.push(v);
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.compact {
        for v in &report.violations {
            let sev = match v.severity {
                Severity::Error => "ERROR",
                Severity::Warning => "WARN",
            };
            if let Some(ref sug) = v.suggestion {
                println!(
                    "[{}] {}:{}: [{}] {} - {} (💡 {})",
                    sev, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message, sug
                );
            } else {
                println!(
                    "[{}] {}:{}: [{}] {} - {}",
                    sev, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message
                );
            }
        }
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if args.github_format {
        for v in &report.violations {
            let level = match v.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };
            if let Some(ref sug) = v.suggestion {
                println!(
                    "::{} file={},line={},title=[{}] {}::{} (💡 Suggestion: {})",
                    level, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message, sug
                );
            } else {
                println!(
                    "::{} file={},line={},title=[{}] {}::{}",
                    level, v.file_path, v.line_number, v.rule_id, v.rule_name, v.message
                );
            }
        }
        if args.strict && report.error_count > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    let banner_title = format!(
        "StenioSentinel (Rust Engine v{}) — Universal Governance System",
        env!("CARGO_PKG_VERSION")
    );
    let badge = format!("[{:.2?}]", report.duration);
    baseline::print_banner_with_badge(&banner_title, &badge);

    // Governance Audit (AGENTS.md)
    if should_audit_gov {
        println!(
            "{}",
            "── Governance Subsystem & Agent Laws ──────────────────────────".dimmed()
        );
        for msg in gov_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Documentation Audit (docs/)
    if should_audit_doc {
        println!(
            "{}",
            "── Documentation & Traceability Subsystem ─────────────────────".dimmed()
        );
        for msg in doc_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // GPU & AI Models Audit
    if should_audit_gpu {
        println!(
            "{}",
            "── GPU & AI Models Subsystem (RTX 5050 / Blackwell) ───────────".dimmed()
        );
        for msg in gpu_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Database & Migrations Audit (SQLx)
    if should_audit_mig {
        println!(
            "{}",
            "── Database & Migrations Subsystem (SQLx) ─────────────────────".dimmed()
        );
        for msg in mig_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Homelab Audit (Mnemocine)
    if is_homelab_active && !homelab_messages.is_empty() {
        println!(
            "{}",
            "── Mnemocine Homelab Subsystem (Infrastructure) ───────────────".dimmed()
        );
        for msg in homelab_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Obsidian Vault Audit (Universal Governance)
    if is_vault_active && !vault_messages.is_empty() {
        println!(
            "{}",
            "── Obsidian Vault & Universal Governance Subsystem ────────────".dimmed()
        );
        for msg in vault_messages {
            println!("   {}", msg);
        }
        println!();
    }

    // Bilingual Curriculum Vitae Audit
    if is_cv_active && !cv_messages.is_empty() {
        println!(
            "{}",
            "── Bilingual Curriculum Vitae Subsystem (curriculum-vitae/) ───".dimmed()
        );
        for msg in cv_messages {
            println!("   {}", msg);
        }
        println!();
    }

    println!(
        "Scanned files: {} | Violations found: {}",
        report.total_files_scanned.to_string().bold(),
        report.total_violations.to_string().bold()
    );

    if report.total_fixed > 0 {
        println!(
            "{}",
            format!(
                "✨ Auto-fix: {} violation(s) automatically repaired!",
                report.total_fixed
            )
            .green()
            .bold()
        );
    }
    println!();

    if report.violations.is_empty() {
        println!(
            "{}",
            "✨ Zero violations detected! Repository is 100% compliant with governance rules."
                .green()
                .bold()
        );
        println!();
        return Ok(());
    }

    for v in &report.violations {
        let badge = match v.severity {
            Severity::Error => "[ERROR]".red().bold(),
            Severity::Warning => "[WARN] ".yellow().bold(),
        };

        println!(
            "{} {} {}: {}",
            badge,
            v.rule_id.cyan().bold(),
            v.rule_name.bold(),
            v.message
        );
        println!(
            "       Location: {}:{}",
            v.file_path.dimmed(),
            v.line_number.to_string().bold()
        );
        println!("       Snippet:  \"{}\"", v.snippet.trim().dimmed());
        if let Some(ref sug) = v.suggestion {
            println!("       💡 {}", sug.green().bold());
        }
        println!();
    }

    println!(
        "Summary: {} error(s), {} warning(s)",
        report.error_count.to_string().red().bold(),
        report.warning_count.to_string().yellow().bold()
    );
    println!();

    if args.strict && report.error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}
