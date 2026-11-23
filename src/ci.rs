//! CI workflow rules (GB-262, GB-272): what a repository's GitHub Actions workflows must not
//! duplicate and must not omit. Both are offline and deterministic: they read
//! `.github/workflows/*.yml`, `.github/dependabot.yml` and the lockfiles, and never call the API.
//!
//! `CI-STEP-STENIO-PARITY` (GB-262, WARNING). A workflow `run:` block that re-implements a Stenio
//! rule can hold a stricter or looser copy of it. Evidence (2026-11-05..09): the inline Python step
//! "DocType JSON is valid and every Link target has a title" of Miracenar/miracena-plataforma-frappe
//! required `title_field` and `show_title_field_in_link`, while `FRAPPE-LINK-TITLE` also accepts
//! `search_fields`; CI was red on 57 of 60 runs and the red was tolerated. The heuristic is
//! deliberately narrow: a step is reported only when its script-like body (python, jq, rg, grep,
//! awk, node, ruby or perl) contains ALL the marker groups of one subject in [`SUBJECTS`], and it
//! does not invoke `stenio` itself. A deliberate copy is declared in `steniocheck.toml`:
//!
//! ```toml
//! [[ci.parity_exclude]]
//! rule = "FRAPPE-LINK-TITLE"
//! step = "DocType JSON is valid"     # optional; omitted means every step
//! reason = "checks a third-party app Stenio does not scan"
//! ```
//!
//! `CI-RUST-COMPILE-ON-DEPENDENCY-PR` (GB-272, WARNING). A repository with a `Cargo.lock` (next to
//! a `Cargo.toml`) and a `cargo` entry in `.github/dependabot.yml` needs a workflow step that
//! compiles (`cargo check|build|test|clippy|nextest|...`, a script or Makefile target that does, a
//! `docker build`) on `pull_request`; otherwise a Dependabot bump has green checks while nothing
//! compiled it (KURURU-TAB3LITE-LINUX PR #5, alacritty_terminal 0.25 -> 0.26, 2026-11-21; the Hub CI
//! compiles and caught 11 breaking errors on its PR #62). A reusable workflow (`workflow_call`) or a
//! job-level `uses:` of one counts as possibly compiling, because its body is not visible. A repo
//! that deliberately has no compiling CI declares it with the existing exclusion table:
//!
//! ```toml
//! [[dependabot.exclude]]
//! rule = "cargo-compile"
//! directory = "/"
//! reason = "scripts-only repo, compiled by hand on the host before every deploy"
//! ```
//!
//! An exclusion without a reason does not silence anything (WARNING), and one that matches a repo
//! that does compile is reported as stale (WARNING), so the list cannot rot.
//!
//! `CI-RULE-SCOPE-NEVER-INVOKED` (GB-283, WARNING). Stenio rules live in scopes and a scope only
//! runs when a command asks for it: `stenio --scope fork` and `--tag miracena` never execute a
//! `FRAPPE-*` rule, which exists only in scope `frappe` (`main.rs`: `--scope frappe` returns before
//! the generic scan). Evidence (2026-11-21, Miracena PR #2): `FRAPPE-LINK-TITLE` and
//! `FRAPPE-FIELD-ORDER` lived in a scope no CI pass ran while an inline Python copy was the only
//! gate. The check is offline: a repository that carries a Frappe app (a `[frappe]` table in
//! `steniocheck.toml`, or `doctype/<name>/<name>.json` files) needs one workflow step that invokes
//! stenio with `--scope frappe` (also `--scope=frappe`, `stenio pre-release`, `stenio verify-release`,
//! the stenio-check action with `scope: frappe`, a repository script such a step calls, or a
//! `[general] scope = "frappe"` default with a bare `stenio` call). A repository without workflows
//! is out of scope (no pass to compare), and a reusable-workflow job is opaque, so it counts as
//! possibly covering, like in GB-272.

use regex::Regex;
use serde_yaml::Value;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::config::{CiParityExclude, DependabotExclude, SteniocheckConfig};
use crate::engine::Violation;
use crate::rule::Severity;

pub const PARITY_ID: &str = "CI-STEP-STENIO-PARITY";
pub const COMPILE_ID: &str = "CI-RUST-COMPILE-ON-DEPENDENCY-PR";
/// `rule` value of a `[[dependabot.exclude]]` entry that silences [`COMPILE_ID`].
pub const COMPILE_KEY: &str = "cargo-compile";
pub const SCOPE_ID: &str = "CI-RULE-SCOPE-NEVER-INVOKED";
/// The scope that carries the `FRAPPE-*` rules.
const FRAPPE_SCOPE: &str = "frappe";

/// (Stenio rule, marker groups): a step re-implements the rule when every group has at least one
/// of its markers in the script body.
const SUBJECTS: [(&str, &[&[&str]]); 5] = [
    (
        "FRAPPE-LINK-TITLE",
        &[
            &["title_field"],
            &["show_title_field_in_link", "search_fields"],
        ],
    ),
    ("FRAPPE-FIELD-ORDER", &[&["field_order"], &["fieldname"]]),
    (
        "FRAPPE-FETCH-PARITY",
        &[&["fetch_from"], &["fetch_if_empty", "fieldname"]],
    ),
    (
        "DEPENDABOT-LOCKFILE-COVERAGE",
        &[&["Cargo.lock", "package-lock.json"], &["dependabot"]],
    ),
    ("I18N-PO-INCOMPLETE", &[&["msgstr"], &["msgid"]]),
];

#[derive(Debug, Clone, Default)]
pub struct Step {
    pub name: String,
    pub run: String,
    pub uses: String,
    /// `with: scope:` of an action step (the stenio-check action takes its scope there).
    pub with_scope: String,
}

#[derive(Debug, Clone, Default)]
pub struct Workflow {
    pub file: String,
    pub pull_request: bool,
    pub callable: bool,
    /// A job calls another workflow (`jobs.<id>.uses`): its body is not visible here.
    pub opaque_job: bool,
    pub steps: Vec<Step>,
}

pub struct CiReport {
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

fn key<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_mapping()?.get(Value::String(k.to_string()))
}

fn text(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or_default().to_string()
}

/// `on:` as a string, a list or a mapping; YAML 1.1 parsers turn a bare `on` key into `true`.
fn triggers(doc: &Value) -> (bool, bool) {
    let on = key(doc, "on").or_else(|| {
        doc.as_mapping()?
            .iter()
            .find_map(|(k, v)| (k == &Value::Bool(true)).then_some(v))
    });
    let names: Vec<String> = match on {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Sequence(s)) => s
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::Mapping(m)) => m
            .keys()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    (
        names.iter().any(|n| n == "pull_request"),
        names.iter().any(|n| n == "workflow_call"),
    )
}

/// Parses one workflow file; a document that is not valid YAML yields `None`.
pub fn parse_workflow(file: &str, yaml: &str) -> Option<Workflow> {
    let doc: Value = serde_yaml::from_str(yaml).ok()?;
    let (pull_request, callable) = triggers(&doc);
    let mut wf = Workflow {
        file: file.to_string(),
        pull_request,
        callable,
        ..Workflow::default()
    };
    let jobs = key(&doc, "jobs").and_then(Value::as_mapping);
    for job in jobs.into_iter().flat_map(|m| m.values()) {
        if key(job, "uses").is_some() {
            wf.opaque_job = true;
        }
        let steps = key(job, "steps").and_then(Value::as_sequence);
        for s in steps.into_iter().flatten() {
            wf.steps.push(Step {
                name: text(key(s, "name")),
                run: text(key(s, "run")),
                uses: text(key(s, "uses")),
                with_scope: key(s, "with")
                    .map(|w| text(key(w, "scope")))
                    .unwrap_or_default(),
            });
        }
    }
    Some(wf)
}

pub fn load_workflows(root: &Path) -> Vec<Workflow> {
    let dir = root.join(".github/workflows");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    files.sort();
    files
        .iter()
        .filter_map(|p| {
            let rel = format!(".github/workflows/{}", p.file_name()?.to_string_lossy());
            parse_workflow(&rel, &fs::read_to_string(p).ok()?)
        })
        .collect()
}

fn compile_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?m)\bcargo-(?:nextest|llvm-cov|tarpaulin|tauri)\b|\bcargo\s+(?:\+\S+\s+)?(?:check|build|b|test|t|clippy|nextest|bench|llvm-cov|tarpaulin|hack|zigbuild|xtask|tauri\s+build|ndk|c\b)|\bdocker\s+(?:buildx?\s+build|build|compose\s+build)\b|\bcross\s+(?:build|test)\b",
        )
        .ok()
    })
    .as_ref()
}

fn script_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:python3?|jq|rg|grep|awk|node|ruby|perl)\b").ok())
        .as_ref()
}

fn compiles_text(t: &str) -> bool {
    compile_re().is_some_and(|re| re.is_match(t))
}

/// True when a run block compiles Rust: directly, through an action, or through a repository
/// script / Makefile / justfile it calls (one level, read from `root`).
pub fn step_compiles(step: &Step, root: &Path) -> bool {
    let u = step.uses.to_lowercase();
    if u.starts_with("actions-rs/cargo")
        || u.starts_with("docker/build-push-action")
        || u.starts_with("tauri-apps/tauri-action")
    {
        return true;
    }
    if compiles_text(&step.run) {
        return true;
    }
    let mut files: Vec<String> = step
        .run
        .split_whitespace()
        .map(|t| {
            t.trim_matches(|c| c == '"' || c == '\'')
                .trim_start_matches("./")
        })
        .filter(|t| t.ends_with(".sh") && !t.contains("..") && !t.starts_with('/'))
        .map(str::to_string)
        .collect();
    for tool in ["make", "just"] {
        if step.run.split_whitespace().any(|t| t == tool) {
            files.extend(
                ["Makefile", "GNUmakefile", "justfile"]
                    .iter()
                    .map(|s| s.to_string()),
            );
        }
    }
    files
        .iter()
        .any(|f| fs::read_to_string(root.join(f)).is_ok_and(|t| compiles_text(&t)))
}

fn violation(
    rule_id: &str,
    name: &str,
    file: &str,
    line: usize,
    message: String,
    fix: &str,
) -> Violation {
    Violation {
        rule_id: rule_id.to_string(),
        rule_name: name.to_string(),
        severity: Severity::Warning,
        file_path: file.to_string(),
        line_number: line,
        snippet: String::new(),
        message,
        suggestion: Some(fix.to_string()),
    }
}

fn has_any(body: &str, group: &[&str]) -> bool {
    group.iter().any(|m| body.contains(m))
}

/// Pure decision for GB-262. `lines` maps a step to the line of its `run:` (1 when unknown).
pub fn evaluate_parity(
    workflows: &[Workflow],
    exclusions: &[CiParityExclude],
    line_of: &dyn Fn(&str, &Step) -> usize,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut used = vec![false; exclusions.len()];
    for wf in workflows {
        for step in &wf.steps {
            let body = &step.run;
            if body.contains("stenio") || !script_re().is_some_and(|re| re.is_match(body)) {
                continue;
            }
            for (rule, groups) in SUBJECTS {
                if !groups.iter().all(|g| has_any(body, g)) {
                    continue;
                }
                let hit = exclusions.iter().position(|e| {
                    e.rule.eq_ignore_ascii_case(rule)
                        && !e.reason.trim().is_empty()
                        && e.step.as_deref().is_none_or(|s| step.name.contains(s))
                });
                if let Some(i) = hit {
                    used[i] = true;
                    continue;
                }
                out.push(violation(
                    PARITY_ID,
                    "CI Step Duplicates A Stenio Rule",
                    &wf.file,
                    line_of(&wf.file, step),
                    format!(
                        "step {:?} re-implements {rule} inline; a workflow copy can be stricter or looser than the engine (GB-262: the copy of FRAPPE-LINK-TITLE ignored search_fields and kept CI red for 57 of 60 runs)",
                        step.name
                    ),
                    "Delete the inline script and let stenio run the rule (`stenio --tag <tag> --strict`); if the copy is deliberate, declare [[ci.parity_exclude]] with rule and reason in steniocheck.toml.",
                ));
            }
        }
    }
    for (e, was_used) in exclusions.iter().zip(&used) {
        let msg = if e.reason.trim().is_empty() {
            Some(format!(
                "[[ci.parity_exclude]] rule={} has no reason, so it silences nothing",
                e.rule
            ))
        } else if !was_used {
            Some(format!(
                "[[ci.parity_exclude]] rule={} matches no inline step (stale)",
                e.rule
            ))
        } else {
            None
        };
        if let Some(m) = msg {
            out.push(violation(
                PARITY_ID,
                "CI Step Duplicates A Stenio Rule",
                "steniocheck.toml",
                1,
                m,
                "Add a non-empty `reason`, or remove the exclusion.",
            ));
        }
    }
    out
}

pub(crate) fn is_compile_exclusion(e: &DependabotExclude) -> bool {
    e.rule
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case(COMPILE_KEY))
}

/// Pure decision for GB-272. Inert unless the repo has a Cargo.lock and a dependabot `cargo` entry.
/// `compiling` holds one flag per workflow: its steps compile Rust.
pub fn evaluate_compile(
    has_lock: bool,
    has_dependabot_cargo: bool,
    workflows: &[Workflow],
    compiling: &[bool],
    exclusions: &[DependabotExclude],
) -> Vec<Violation> {
    if !(has_lock && has_dependabot_cargo) {
        return Vec::new();
    }
    let on_pr = |i: usize| workflows[i].pull_request || workflows[i].callable;
    let covered = workflows
        .iter()
        .enumerate()
        .any(|(i, w)| on_pr(i) && (compiling.get(i).copied().unwrap_or(false) || w.opaque_job));
    let mine: Vec<&DependabotExclude> = exclusions
        .iter()
        .filter(|e| is_compile_exclusion(e))
        .collect();
    let mut out = Vec::new();
    let declared = mine.iter().any(|e| !e.reason.trim().is_empty());
    if !covered && !declared {
        let why = if workflows.is_empty() {
            "the repository has no workflow at all".to_string()
        } else {
            format!(
                "none of its {} workflow(s) compiles Rust on `pull_request`",
                workflows.len()
            )
        };
        out.push(violation(
            COMPILE_ID,
            "Dependabot Cargo PRs Are Never Compiled",
            ".github/workflows",
            1,
            format!(
                "Cargo.lock and a dependabot `cargo` entry exist but {why}: a Dependabot bump gets green checks while nothing compiled it (GB-272)"
            ),
            "Add a pull_request job with `cargo check --locked --workspace --all-targets` (or build/test); if the repo deliberately has no compiling CI, declare [[dependabot.exclude]] rule = \"cargo-compile\" with a reason in steniocheck.toml.",
        ));
    }
    for e in mine.iter().filter(|e| e.reason.trim().is_empty()) {
        out.push(violation(
            COMPILE_ID,
            "Dependabot Cargo PRs Are Never Compiled",
            "steniocheck.toml",
            1,
            format!(
                "[[dependabot.exclude]] rule=cargo-compile for '{}' has no reason, so it silences nothing",
                e.directory
            ),
            "Add a non-empty `reason`.",
        ));
    }
    if covered {
        for e in mine.iter().filter(|e| !e.reason.trim().is_empty()) {
            out.push(violation(
                COMPILE_ID,
                "Dependabot Cargo PRs Are Never Compiled",
                "steniocheck.toml",
                1,
                format!(
                    "[[dependabot.exclude]] rule=cargo-compile for '{}' is stale: a workflow already compiles on pull_request",
                    e.directory
                ),
                "Remove the exclusion.",
            ));
        }
    }
    out
}

fn scope_flag_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"--scope(?:=|\s+)["']?([A-Za-z_-]+)"#).ok())
        .as_ref()
}

fn frappe_command_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bstenio(?:\s+|[\x22']\s+)(?:pre-release|verify-release)\b").ok()
    })
    .as_ref()
}

/// Scopes one piece of text asks stenio to run. `default_scope` is the `[general] scope` of the
/// repository config: a bare `stenio` call without `--scope` runs it.
fn scopes_in_text(text: &str, default_scope: Option<&str>) -> Vec<String> {
    if !text.contains("stenio") {
        return Vec::new();
    }
    let mut out: Vec<String> = scope_flag_re()
        .map(|re| {
            re.captures_iter(text)
                .map(|c| c[1].to_lowercase())
                .collect()
        })
        .unwrap_or_default();
    // `stenio pre-release` and `stenio verify-release` run the frappe audit (pre_release.rs).
    if frappe_command_re().is_some_and(|re| re.is_match(text)) {
        out.push(FRAPPE_SCOPE.to_string());
    }
    if out.is_empty() {
        if let Some(d) = default_scope.filter(|d| !d.is_empty()) {
            out.push(d.to_lowercase());
        }
    }
    out
}

/// Scopes a step invokes: its own `run:` body, the `scope:` input of the stenio-check action, and
/// the repository scripts it calls (one level, read from `root`).
pub fn step_scopes(step: &Step, root: &Path, default_scope: Option<&str>) -> Vec<String> {
    let mut out = scopes_in_text(&step.run, default_scope);
    if step.uses.to_lowercase().contains("stenio-check") && !step.with_scope.is_empty() {
        out.push(step.with_scope.to_lowercase());
    }
    for tok in step.run.split_whitespace() {
        let f = tok
            .trim_matches(|c| c == '"' || c == '\'')
            .trim_start_matches("./");
        if f.ends_with(".sh") && !f.contains("..") && !f.starts_with('/') {
            if let Ok(body) = fs::read_to_string(root.join(f)) {
                out.extend(scopes_in_text(&body, default_scope));
            }
        }
    }
    out
}

/// True when the tree carries a Frappe app: a `[frappe]` table or `doctype/<n>/<n>.json` files.
fn has_frappe_app(root: &Path, cfg: &SteniocheckConfig) -> bool {
    cfg.frappe.is_some()
        || ignore::WalkBuilder::new(root)
            .max_depth(Some(7))
            .build()
            .filter_map(Result::ok)
            .any(|e| {
                let p = e.path();
                let dir = p.parent();
                p.extension().is_some_and(|x| x == "json")
                    && dir.and_then(|d| d.parent()).and_then(|d| d.file_name())
                        == Some(std::ffi::OsStr::new("doctype"))
                    && p.file_stem() == dir.and_then(Path::file_name)
            })
}

/// Pure decision for GB-283. `needed` holds the scopes the repository's rules live in; `invoked`
/// holds, per workflow, the scopes its steps run. Inert without workflows.
pub fn evaluate_scopes(
    needed: &[&str],
    workflows: &[Workflow],
    invoked: &[Vec<String>],
) -> Vec<Violation> {
    if workflows.is_empty() || workflows.iter().any(|w| w.opaque_job) {
        return Vec::new();
    }
    needed
        .iter()
        .filter(|scope| {
            !invoked
                .iter()
                .flatten()
                .any(|s| s.eq_ignore_ascii_case(scope))
        })
        .map(|scope| {
            violation(
                SCOPE_ID,
                "Stenio Scope No Workflow Invokes",
                ".github/workflows",
                1,
                format!(
                    "the repository carries rules of scope `{scope}` but none of its {} workflow(s) runs `stenio --scope {scope}`: those rules never execute in CI (GB-283: FRAPPE-LINK-TITLE and FRAPPE-FIELD-ORDER lived in scope frappe, which no pass ran, while an inline copy was the only gate)",
                    workflows.len()
                ),
                "Add a pass `stenio --scope frappe --compact` (the binary the stenio-check action leaves in RUNNER_TEMP, or the action with `scope: frappe`).",
            )
        })
        .collect()
}

/// Line (1-based) of the first line of the step's `run:` body in the workflow file, else 1.
fn line_in(root: &Path, file: &str, step: &Step) -> usize {
    let Ok(body) = fs::read_to_string(root.join(file)) else {
        return 1;
    };
    let first = step
        .run
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(str::trim);
    first
        .and_then(|f| body.lines().position(|l| l.contains(f)))
        .map_or(1, |p| p + 1)
}

/// Repository audit. Inert (INFO message) without `.github/workflows`.
pub fn audit(root: &Path, cfg: &SteniocheckConfig) -> CiReport {
    let mut report = CiReport {
        messages: Vec::new(),
        violations: Vec::new(),
    };
    let workflows = load_workflows(root);
    let parity: Vec<CiParityExclude> = cfg
        .ci
        .as_ref()
        .and_then(|c| c.parity_exclude.clone())
        .unwrap_or_default();
    report
        .violations
        .extend(evaluate_parity(&workflows, &parity, &|f, s| {
            line_in(root, f, s)
        }));
    let has_lock = crate::dependabot::find_lockfiles(root)
        .iter()
        .any(|l| l.ecosystem == "cargo");
    let has_cargo_entry = crate::dependabot::CONFIG_FILES
        .iter()
        .find_map(|rel| fs::read_to_string(root.join(rel)).ok())
        .and_then(|t| crate::dependabot::parse_updates(&t).ok())
        .is_some_and(|u| u.iter().any(|x| x.ecosystem.eq_ignore_ascii_case("cargo")));
    let compiling: Vec<bool> = workflows
        .iter()
        .map(|w| w.steps.iter().any(|s| step_compiles(s, root)))
        .collect();
    let exclusions = cfg
        .dependabot
        .as_ref()
        .and_then(|d| d.exclude.clone())
        .unwrap_or_default();
    report.violations.extend(evaluate_compile(
        has_lock,
        has_cargo_entry,
        &workflows,
        &compiling,
        &exclusions,
    ));
    let default_scope = cfg.general.as_ref().and_then(|g| g.scope.as_deref());
    let mut needed: Vec<&str> = Vec::new();
    if !workflows.is_empty() && has_frappe_app(root, cfg) {
        needed.push(FRAPPE_SCOPE);
    }
    let invoked: Vec<Vec<String>> = workflows
        .iter()
        .map(|w| {
            w.steps
                .iter()
                .flat_map(|s| step_scopes(s, root, default_scope))
                .collect()
        })
        .collect();
    report
        .violations
        .extend(evaluate_scopes(&needed, &workflows, &invoked));
    report.messages.push(format!(
        "{COMPILE_ID}/{PARITY_ID}/{SCOPE_ID}: {} workflow(s), {} finding(s)",
        workflows.len(),
        report.violations.len()
    ));
    report
}

const MIRACENA_STEP: &str = "      - name: DocType JSON has a title\n        run: |\n          python3 - <<'PY'\n          import glob, json\n          for x in fields:\n              if not (t.get(\"title_field\") and t.get(\"show_title_field_in_link\")) or t.get(\"search_fields\"): pass\n          PY\n";
const STENIO_STEP: &str =
    "      - name: Stenio\n        run: stenio --tag miracena --strict --compact\n";
const CARGO_YML: &str = "name: ci\non: [push, pull_request]\njobs:\n  rust:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo check --locked --workspace --all-targets\n";
const PUSH_ONLY_YML: &str = "name: ci\non:\n  push:\n    branches: [main]\njobs:\n  rust:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo check --locked\n";
const GOVERNANCE_YML: &str = "name: ci\non: [push, pull_request]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ceduardorodrig/STENIO-SENTINEL/.github/actions/stenio-check@v1\n";
const DEPENDABOT_CARGO: &str =
    "version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: \"/\"\n";

fn wf_of(job_steps: &str) -> Option<Workflow> {
    parse_workflow(
        ".github/workflows/ci.yml",
        &format!(
            "name: ci\non: [pull_request]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n{job_steps}"
        ),
    )
}

fn parity_count(step: &str, ex: &[CiParityExclude]) -> Option<usize> {
    Some(evaluate_parity(&[wf_of(step)?], ex, &|_, _| 1).len())
}

fn tree(files: &[(&str, &str)], tag: &str, cfg: &SteniocheckConfig) -> Option<Vec<Violation>> {
    let files: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| (p.to_string(), t.to_string()))
        .collect();
    let root = crate::frappe::write_fixture(tag, &files)?;
    let found = audit(&root, cfg).violations;
    let _ = fs::remove_dir_all(&root);
    Some(found)
}

fn compile_count(workflow: Option<&str>, tag: &str, cfg: &SteniocheckConfig) -> Option<usize> {
    let mut files = vec![
        ("Cargo.toml", "[package]\n"),
        ("Cargo.lock", "# lock\n"),
        (".github/dependabot.yml", DEPENDABOT_CARGO),
    ];
    if let Some(w) = workflow {
        files.push((".github/workflows/ci.yml", w));
    }
    Some(
        tree(&files, tag, cfg)?
            .iter()
            .filter(|v| v.rule_id == COMPILE_ID)
            .count(),
    )
}

fn cfg_with(ex: DependabotExclude) -> SteniocheckConfig {
    SteniocheckConfig {
        dependabot: Some(crate::config::DependabotConfig {
            exclude: Some(vec![ex]),
        }),
        ..SteniocheckConfig::default()
    }
}

fn compile_exclusion(reason: &str) -> DependabotExclude {
    DependabotExclude {
        directory: "/".to_string(),
        ecosystem: None,
        reason: reason.to_string(),
        rule: Some(COMPILE_KEY.to_string()),
    }
}

const FORK_ONLY_YML: &str = "name: ci\non: [push, pull_request]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ceduardorodrig/STENIO-SENTINEL/.github/actions/stenio-check@v1\n        with:\n          scope: fork\n      - run: '\"$RUNNER_TEMP/stenio/stenio\" --tag miracena --strict --compact'\n";
const FRAPPE_PASS_YML: &str = "name: ci\non: [push, pull_request]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ceduardorodrig/STENIO-SENTINEL/.github/actions/stenio-check@v1\n        with:\n          scope: fork\n      - run: '\"$RUNNER_TEMP/stenio/stenio\" --scope frappe --compact'\n";
const FRAPPE_ACTION_YML: &str = "name: ci\non: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ceduardorodrig/STENIO-SENTINEL/.github/actions/stenio-check@v1\n        with:\n          scope: frappe\n";
const FRAPPE_EQ_YML: &str = "name: ci\non: [push]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: stenio --scope=frappe --compact\n";
const DOCTYPE_FILES: [(&str, &str); 2] = [
    (
        "app/app/doctype/thing/thing.json",
        "{\"doctype\":\"DocType\",\"name\":\"Thing\",\"fields\":[]}",
    ),
    ("app/hooks.py", "app_name = \"app\"\n"),
];

/// Findings of GB-283 on a tree: the Frappe files (unless `frappe` is false) plus the workflow.
fn scope_count(workflow: Option<&str>, frappe: bool, tag: &str) -> Option<usize> {
    let mut files: Vec<(&str, &str)> = if frappe {
        DOCTYPE_FILES.to_vec()
    } else {
        vec![("README.md", "# repo\n")]
    };
    if let Some(w) = workflow {
        files.push((".github/workflows/ci.yml", w));
    }
    Some(
        tree(&files, tag, &SteniocheckConfig::default())?
            .iter()
            .filter(|v| v.rule_id == SCOPE_ID)
            .count(),
    )
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let none = SteniocheckConfig::default();
    let ex = |reason: &str| CiParityExclude {
        rule: "FRAPPE-LINK-TITLE".to_string(),
        step: Some("DocType".to_string()),
        reason: reason.to_string(),
    };
    vec![
        (
            "ci-parity: mutation, an inline script re-implementing a Stenio rule fires".to_string(),
            parity_count(MIRACENA_STEP, &[]) == Some(1),
        ),
        (
            "ci-parity: a step that runs stenio is green".to_string(),
            parity_count(STENIO_STEP, &[]) == Some(0),
        ),
        (
            "ci-parity: a non-script step with the same words is green".to_string(),
            parity_count(
                "      - name: note\n        run: echo title_field show_title_field_in_link\n",
                &[],
            ) == Some(0),
        ),
        (
            "ci-parity: declared exclusion needs a reason".to_string(),
            parity_count(MIRACENA_STEP, &[ex("third-party app")]) == Some(0)
                && parity_count(MIRACENA_STEP, &[ex(" ")]) == Some(2),
        ),
        (
            "ci-parity: stale exclusion is reported".to_string(),
            parity_count(STENIO_STEP, &[ex("third-party app")]) == Some(1),
        ),
        (
            "ci-compile: mutation, lock + cargo entry + workflow without cargo fires".to_string(),
            compile_count(Some(GOVERNANCE_YML), "ci-compile-bad", &none) == Some(1),
        ),
        (
            "ci-compile: adding a cargo check on pull_request is green".to_string(),
            compile_count(Some(CARGO_YML), "ci-compile-good", &none) == Some(0),
        ),
        (
            "ci-compile: cargo only on push still fires".to_string(),
            compile_count(Some(PUSH_ONLY_YML), "ci-compile-push", &none) == Some(1),
        ),
        (
            "ci-compile: repo without CI fires; declared exception with a reason is green"
                .to_string(),
            compile_count(None, "ci-compile-noci", &none) == Some(1)
                && compile_count(
                    None,
                    "ci-compile-ex",
                    &cfg_with(compile_exclusion("scripts-only repo")),
                ) == Some(0),
        ),
        (
            "ci-compile: exception without a reason does not silence".to_string(),
            compile_count(
                None,
                "ci-compile-noreason",
                &cfg_with(compile_exclusion(" ")),
            ) == Some(2),
        ),
        (
            "ci-scope: mutation, Frappe DocTypes and a workflow that runs only fork and a tag fires"
                .to_string(),
            scope_count(Some(FORK_ONLY_YML), true, "ci-scope-bad") == Some(1),
        ),
        (
            "ci-scope: a pass with `--scope frappe` is green".to_string(),
            scope_count(Some(FRAPPE_PASS_YML), true, "ci-scope-pass") == Some(0),
        ),
        (
            "ci-scope: the stenio-check action with `scope: frappe` and `--scope=frappe` are green"
                .to_string(),
            scope_count(Some(FRAPPE_ACTION_YML), true, "ci-scope-action") == Some(0)
                && scope_count(Some(FRAPPE_EQ_YML), true, "ci-scope-eq") == Some(0),
        ),
        (
            "ci-scope: inert without workflows and for a repo without a Frappe app".to_string(),
            scope_count(None, true, "ci-scope-noci") == Some(0)
                && scope_count(Some(FORK_ONLY_YML), false, "ci-scope-nofrappe") == Some(0),
        ),
        (
            "ci-compile: inert without a dependabot cargo entry".to_string(),
            tree(
                &[("Cargo.toml", "[package]\n"), ("Cargo.lock", "# l\n")],
                "ci-compile-inert",
                &none,
            )
            .is_some_and(|v| v.is_empty()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_cases_pass() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn triggers_read_string_list_and_mapping() {
        for (yaml, pr) in [
            ("on: pull_request\njobs: {}\n", true),
            ("on: [push, pull_request]\njobs: {}\n", true),
            (
                "on:\n  pull_request:\n    branches: [main]\njobs: {}\n",
                true,
            ),
            ("on:\n  push:\njobs: {}\n", false),
        ] {
            assert_eq!(parse_workflow("w", yaml).map(|w| w.pull_request), Some(pr));
        }
    }

    #[test]
    fn compile_regex_covers_common_forms() {
        for ok in [
            "cargo check --locked",
            "cargo +nightly test",
            "cargo build --release",
            "cargo clippy -- -D warnings",
            "docker build .",
        ] {
            assert!(compiles_text(ok), "{ok}");
        }
        for no in ["cargo fmt --check", "cargo audit", "echo cargo"] {
            assert!(!compiles_text(no), "{no}");
        }
    }
}
